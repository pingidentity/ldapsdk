/*
 * Copyright 2008-2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2011 UnboundID Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util.ssl;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL trust manager that will interactively prompt the
 * user to determine whether to trust any certificate that is presented to it.
 * It provides the ability to cache information about certificates that had been
 * previously trusted so that the user is not prompted about the same
 * certificate repeatedly, and it can be configured to store trusted
 * certificates in a file so that the trust information can be persisted.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PromptTrustManager
       implements X509TrustManager
{
  // Indicates whether to examine the validity dates for the certificate in
  // addition to whether the certificate has been previously trusted.
  private final boolean examineValidityDates;

  // The set of previously-accepted certificates.  The certificates will be
  // mapped from an all-lowercase hexadecimal string representation of the
  // certificate signature to a flag that indicates whether the certificate has
  // already been manually trusted even if it is outside of the validity window.
  private final ConcurrentHashMap<String,Boolean> acceptedCerts;

  // The input stream from which the user input will be read.
  private final InputStream in;

  // The print stream that will be used to display the prompt.
  private final PrintStream out;

  // The path to the file to which the set of accepted certificates should be
  // persisted.
  private final String acceptedCertsFile;



  /**
   * Creates a new instance of this prompt trust manager.  It will cache trust
   * information in memory but not on disk.
   */
  public PromptTrustManager()
  {
    this(null, true, null, null);
  }



  /**
   * Creates a new instance of this prompt trust manager.  It may optionally
   * cache trust information on disk.
   *
   * @param  acceptedCertsFile  The path to a file in which the certificates
   *                            that have been previously accepted will be
   *                            cached.  It may be {@code null} if the cache
   *                            should only be maintained in memory.
   */
  public PromptTrustManager(final String acceptedCertsFile)
  {
    this(acceptedCertsFile, true, null, null);
  }



  /**
   * Creates a new instance of this prompt trust manager.  It may optionally
   * cache trust information on disk, and may also be configured to examine or
   * ignore validity dates.
   *
   * @param  acceptedCertsFile     The path to a file in which the certificates
   *                               that have been previously accepted will be
   *                               cached.  It may be {@code null} if the cache
   *                               should only be maintained in memory.
   * @param  examineValidityDates  Indicates whether to reject certificates if
   *                               the current time is outside the validity
   *                               window for the certificate.
   * @param  in                    The input stream that will be used to read
   *                               input from the user.  If this is {@code null}
   *                               then {@code System.in} will be used.
   * @param  out                   The print stream that will be used to display
   *                               the prompt to the user.  If this is
   *                               {@code null} then System.out will be used.
   */
  public PromptTrustManager(final String acceptedCertsFile,
                            final boolean examineValidityDates,
                            final InputStream in, final PrintStream out)
  {
    this.acceptedCertsFile    = acceptedCertsFile;
    this.examineValidityDates = examineValidityDates;

    if (in == null)
    {
      this.in = System.in;
    }
    else
    {
      this.in = in;
    }

    if (out == null)
    {
      this.out = System.out;
    }
    else
    {
      this.out = out;
    }

    acceptedCerts = new ConcurrentHashMap<String,Boolean>();

    if (acceptedCertsFile != null)
    {
      BufferedReader r = null;
      try
      {
        final File f = new File(acceptedCertsFile);
        if (f.exists())
        {
          r = new BufferedReader(new FileReader(f));
          while (true)
          {
            final String line = r.readLine();
            if (line == null)
            {
              break;
            }
            acceptedCerts.put(line, false);
          }
        }
      }
      catch (Exception e)
      {
        debugException(e);
      }
      finally
      {
        if (r != null)
        {
          try
          {
            r.close();
          }
          catch (Exception e)
          {
            debugException(e);
          }
        }
      }
    }
  }



  /**
   * Writes an updated copy of the trusted certificate cache to disk.
   *
   * @throws  IOException  If a problem occurs.
   */
  private void writeCacheFile()
          throws IOException
  {
    final File tempFile = new File(acceptedCertsFile + ".new");

    BufferedWriter w = null;
    try
    {
      w = new BufferedWriter(new FileWriter(tempFile));

      for (final String certBytes : acceptedCerts.keySet())
      {
        w.write(certBytes);
        w.newLine();
      }
    }
    finally
    {
      if (w != null)
      {
        w.close();
      }
    }

    final File cacheFile = new File(acceptedCertsFile);
    if (cacheFile.exists())
    {
      final File oldFile = new File(acceptedCertsFile + ".previous");
      if (oldFile.exists())
      {
        oldFile.delete();
      }

      cacheFile.renameTo(oldFile);
    }

    tempFile.renameTo(cacheFile);
  }



  /**
   * Performs the necessary validity check for the provided certificate array.
   *
   * @param  chain  The chain of certificates for which to make the
   *                determination.
   *
   * @throws  CertificateException  If the provided certificate chain should not
   *                                be trusted.
   */
  private synchronized void checkCertificateChain(final X509Certificate[] chain)
          throws CertificateException
  {
    // See if the certificate or any of its issuers exists in the cache.  If so,
    // then check the validity dates if necessary and allow it.
    final Date currentDate = new Date();
    for (final X509Certificate c : chain)
    {
      final String certBytes = toLowerCase(toHex(c.getSignature()));
      final Boolean acceptedWithValidity = acceptedCerts.get(certBytes);

      if (acceptedWithValidity == null)
      {
        continue;
      }

      if (acceptedWithValidity || (! examineValidityDates))
      {
        return;
      }

      if (currentDate.before(c.getNotBefore()) ||
          currentDate.after(c.getNotAfter()))
      {
        // The certificate isn't valid, so we need to prompt the user.
        break;
      }
      else
      {
        // The certificate is cached and within the validity window, so we'll
        // accept it.
        return;
      }
    }

    // If we've gotten here, then we couldn't find anything in the cache, or the
    // certificate isn't in the validity window so we will need to prompt the
    // user.
    final X509Certificate c = chain[0];

    out.println(INFO_PROMPT_HEADING.get());
    out.println(INFO_PROMPT_SUBJECT.get(
         String.valueOf(c.getSubjectX500Principal())));
    out.println(INFO_PROMPT_ISSUER.get(
         String.valueOf(c.getIssuerX500Principal())));
    out.println(INFO_PROMPT_VALIDITY.get(
         String.valueOf(c.getNotBefore()), String.valueOf(c.getNotAfter())));

    boolean outsideValidityWindow = false;
    if (currentDate.before(c.getNotBefore()))
    {
      outsideValidityWindow = true;
      out.println();
      out.println(WARNING_PROMPT_NOT_YET_VALID.get());
      out.println();
    }
    else if (currentDate.after(c.getNotAfter()))
    {
      outsideValidityWindow = true;
      out.println();
      out.println(WARNING_PROMPT_EXPIRED.get());
      out.println();
    }

    final BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    while (true)
    {
      try
      {
        out.println();
        out.println(INFO_PROMPT_MESSAGE.get());
        out.flush();
        final String line = reader.readLine();
        if (line.equalsIgnoreCase("y") || line.equalsIgnoreCase("yes"))
        {
          // The certificate should be considered trusted.
          break;
        }
        else if (line.equalsIgnoreCase("n") || line.equalsIgnoreCase("no"))
        {
          // The certificate should not be trusted.
          throw new CertificateException(
               ERR_CERTIFICATE_REJECTED_BY_USER.get());
        }
      }
      catch (CertificateException ce)
      {
        throw ce;
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }

    final String certBytes = toLowerCase(toHex(c.getSignature()));
    acceptedCerts.put(certBytes, outsideValidityWindow);

    if (acceptedCertsFile != null)
    {
      try
      {
        writeCacheFile();
      }
      catch (Exception e)
      {
        debugException(e);
      }
    }
  }



  /**
   * Indicate whether to prompt about certificates contained in the cache if the
   * current time is outside the validity window for the certificate.
   *
   * @return  {@code true} if the certificate validity time should be examined
   *          for cached certificates and the user should be prompted if they
   *          are expired or not yet valid, or {@code false} if cached
   *          certificates should be accepted even outside of the validity
   *          window.
   */
  public boolean examineValidityDates()
  {
    return examineValidityDates;
  }



  /**
   * Checks to determine whether the provided client certificate chain should be
   * trusted.
   *
   * @param  chain     The client certificate chain for which to make the
   *                   determination.
   * @param  authType  The authentication type based on the client certificate.
   *
   * @throws  CertificateException  If the provided client certificate chain
   *                                should not be trusted.
   */
  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateChain(chain);
  }



  /**
   * Checks to determine whether the provided server certificate chain should be
   * trusted.
   *
   * @param  chain     The server certificate chain for which to make the
   *                   determination.
   * @param  authType  The key exchange algorithm used.
   *
   * @throws  CertificateException  If the provided server certificate chain
   *                                should not be trusted.
   */
  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateChain(chain);
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.  This
   * will always return an empty array.
   *
   * @return  The accepted issuer certificates for this trust manager.
   */
  public X509Certificate[] getAcceptedIssuers()
  {
    return new X509Certificate[0];
  }
}
