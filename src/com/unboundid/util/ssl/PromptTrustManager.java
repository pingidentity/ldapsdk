/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.nio.file.Files;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.cert.CertException;

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
  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  // Indicates whether to examine the validity dates for the certificate in
  // addition to whether the certificate has been previously trusted.
  private final boolean examineValidityDates;

  // The set of previously-accepted certificates.  The certificates will be
  // mapped from an all-lowercase hexadecimal string representation of the
  // certificate signature to a flag that indicates whether the certificate has
  // already been manually trusted even if it is outside of the validity window.
  @NotNull private final ConcurrentHashMap<String,Boolean> acceptedCerts;

  // The input stream from which the user input will be read.
  @NotNull private final InputStream in;

  // A list of the addresses that the client is expected to use to connect to
  // one of the target servers.
  @NotNull private final List<String> expectedAddresses;

  // The print stream that will be used to display the prompt.
  @NotNull private final PrintStream out;

  // The path to the file to which the set of accepted certificates should be
  // persisted.
  @Nullable private final String acceptedCertsFile;



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
  public PromptTrustManager(@Nullable final String acceptedCertsFile)
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
  public PromptTrustManager(@Nullable final String acceptedCertsFile,
                            final boolean examineValidityDates,
                            @Nullable final InputStream in,
                            @Nullable final PrintStream out)
  {
    this(acceptedCertsFile, examineValidityDates,
         Collections.<String>emptyList(), in, out);
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
   * @param  expectedAddress       An optional address that the client is
   *                               expected to use to connect to the target
   *                               server.  This may be {@code null} if no
   *                               expected address is available, if this trust
   *                               manager is only expected to be used to
   *                               validate client certificates, or if no server
   *                               address validation should be performed.  If a
   *                               non-{@code null} value is provided, then the
   *                               trust manager may issue a warning if the
   *                               certificate does not contain that address.
   * @param  in                    The input stream that will be used to read
   *                               input from the user.  If this is {@code null}
   *                               then {@code System.in} will be used.
   * @param  out                   The print stream that will be used to display
   *                               the prompt to the user.  If this is
   *                               {@code null} then System.out will be used.
   */
  public PromptTrustManager(@Nullable final String acceptedCertsFile,
                            final boolean examineValidityDates,
                            @Nullable final String expectedAddress,
                            @Nullable final InputStream in,
                            @Nullable final PrintStream out)
  {
    this(acceptedCertsFile, examineValidityDates,
         (expectedAddress == null)
              ? Collections.<String>emptyList()
              : Collections.singletonList(expectedAddress),
         in, out);
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
   * @param  expectedAddresses     An optional collection of the addresses that
   *                               the client is expected to use to connect to
   *                               one of the target servers.  This may be
   *                               {@code null} or empty if no expected
   *                               addresses are available, if this trust
   *                               manager is only expected to be used to
   *                               validate client certificates, or if no server
   *                               address validation should be performed.  If a
   *                               non-empty collection is provided, then the
   *                               trust manager may issue a warning if the
   *                               certificate does not contain any of these
   *                               addresses.
   * @param  in                    The input stream that will be used to read
   *                               input from the user.  If this is {@code null}
   *                               then {@code System.in} will be used.
   * @param  out                   The print stream that will be used to display
   *                               the prompt to the user.  If this is
   *                               {@code null} then System.out will be used.
   */
  public PromptTrustManager(@Nullable final String acceptedCertsFile,
              final boolean examineValidityDates,
              @Nullable final Collection<String> expectedAddresses,
              @Nullable final InputStream in,
              @Nullable final PrintStream out)
  {
    this.acceptedCertsFile    = acceptedCertsFile;
    this.examineValidityDates = examineValidityDates;

    if (expectedAddresses == null)
    {
      this.expectedAddresses = Collections.emptyList();
    }
    else
    {
      this.expectedAddresses =
           Collections.unmodifiableList(new ArrayList<>(expectedAddresses));
    }

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

    acceptedCerts = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(20));

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
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      finally
      {
        if (r != null)
        {
          try
          {
            r.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
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
        Files.delete(oldFile.toPath());
      }

      Files.move(cacheFile.toPath(), oldFile.toPath());
    }

    Files.move(tempFile.toPath(), cacheFile.toPath());
  }



  /**
   * Indicates whether this trust manager would interactively prompt the user
   * about whether to trust the provided certificate chain.
   *
   * @param  chain  The chain of certificates for which to make the
   *                determination.
   *
   * @return  {@code true} if this trust manger would interactively prompt the
   *          user about whether to trust the certificate chain, or
   *          {@code false} if not (e.g., because the certificate is already
   *          known to be trusted).
   */
  public synchronized boolean wouldPrompt(
                                   @NotNull final X509Certificate[] chain)
  {
    try
    {
      final String cacheKey = getCacheKey(chain[0]);
      return PromptTrustManagerProcessor.shouldPrompt(cacheKey,
           convertChain(chain), false, examineValidityDates, acceptedCerts,
           null).getFirst();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }
  }



  /**
   * Performs the necessary validity check for the provided certificate array.
   *
   * @param  chain       The chain of certificates for which to make the
   *                     determination.
   * @param  serverCert  Indicates whether the certificate was presented as a
   *                     server certificate or as a client certificate.
   *
   * @throws  CertificateException  If the provided certificate chain should not
   *                                be trusted.
   */
  private synchronized void checkCertificateChain(
                                 @NotNull final X509Certificate[] chain,
                                 final boolean serverCert)
          throws CertificateException
  {
    final com.unboundid.util.ssl.cert.X509Certificate[] convertedChain =
         convertChain(chain);

    final String cacheKey = getCacheKey(chain[0]);
    final ObjectPair<Boolean,List<String>> shouldPromptResult =
         PromptTrustManagerProcessor.shouldPrompt(cacheKey, convertedChain,
              serverCert, examineValidityDates, acceptedCerts,
              expectedAddresses);

    if (! shouldPromptResult.getFirst())
    {
      return;
    }

    if (serverCert)
    {
      out.println(INFO_PROMPT_SERVER_HEADING.get());
    }
    else
    {
      out.println(INFO_PROMPT_CLIENT_HEADING.get());
    }

    out.println();
    out.println("     " +
         INFO_PROMPT_SUBJECT.get(convertedChain[0].getSubjectDN()));
    out.println("     " +
         INFO_PROMPT_VALID_FROM.get(PromptTrustManagerProcessor.formatDate(
              convertedChain[0].getNotBeforeDate())));
    out.println("     " +
         INFO_PROMPT_VALID_TO.get(PromptTrustManagerProcessor.formatDate(
              convertedChain[0].getNotAfterDate())));

    try
    {
      final byte[] sha1Fingerprint = convertedChain[0].getSHA1Fingerprint();
      final StringBuilder buffer = new StringBuilder();
      StaticUtils.toHex(sha1Fingerprint, ":", buffer);
      out.println("     " + INFO_PROMPT_SHA1_FINGERPRINT.get(buffer));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }
    try
    {
      final byte[] sha256Fingerprint = convertedChain[0].getSHA256Fingerprint();
      final StringBuilder buffer = new StringBuilder();
      StaticUtils.toHex(sha256Fingerprint, ":", buffer);
      out.println("     " + INFO_PROMPT_SHA256_FINGERPRINT.get(buffer));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }


    for (int i=1; i < chain.length; i++)
    {
      out.println("     -");
      out.println("     " +
           INFO_PROMPT_ISSUER_SUBJECT.get(i, convertedChain[i].getSubjectDN()));
      out.println("     " +
           INFO_PROMPT_VALID_FROM.get(PromptTrustManagerProcessor.formatDate(
                convertedChain[i].getNotBeforeDate())));
      out.println("     " +
           INFO_PROMPT_VALID_TO.get(PromptTrustManagerProcessor.formatDate(
                convertedChain[i].getNotAfterDate())));

      try
      {
        final byte[] sha1Fingerprint = convertedChain[i].getSHA1Fingerprint();
        final StringBuilder buffer = new StringBuilder();
        StaticUtils.toHex(sha1Fingerprint, ":", buffer);
        out.println("     " + INFO_PROMPT_SHA1_FINGERPRINT.get(buffer));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      try
      {
        final byte[] sha256Fingerprint =
             convertedChain[i].getSHA256Fingerprint();
        final StringBuilder buffer = new StringBuilder();
        StaticUtils.toHex(sha256Fingerprint, ":", buffer);
        out.println("     " + INFO_PROMPT_SHA256_FINGERPRINT.get(buffer));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    for (final String warningMessage : shouldPromptResult.getSecond())
    {
      out.println();
      for (final String line :
           StaticUtils.wrapLine(warningMessage,
                (StaticUtils.TERMINAL_WIDTH_COLUMNS - 1)))
      {
        out.println(line);
      }
    }

    final BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    while (true)
    {
      try
      {
        out.println();
        out.print(INFO_PROMPT_MESSAGE.get() + ' ');
        out.flush();
        final String line = reader.readLine();
        if (line == null)
        {
          // The input stream has been closed, so we can't prompt for trust,
          // and should assume it is not trusted.
          throw new CertificateException(
               ERR_CERTIFICATE_REJECTED_BY_END_OF_STREAM.get(
                    SSLUtil.certificateToString(chain[0])));
        }
        else if (line.equalsIgnoreCase("y") || line.equalsIgnoreCase("yes"))
        {
          // The certificate should be considered trusted.
          break;
        }
        else if (line.equalsIgnoreCase("n") || line.equalsIgnoreCase("no"))
        {
          // The certificate should not be trusted.
          throw new CertificateException(
               ERR_CERTIFICATE_REJECTED_BY_USER.get(
                    SSLUtil.certificateToString(chain[0])));
        }
      }
      catch (final CertificateException ce)
      {
        throw ce;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    boolean isOutsideValidityWindow = false;
    for (final com.unboundid.util.ssl.cert.X509Certificate c : convertedChain)
    {
      if (! c.isWithinValidityWindow())
      {
        isOutsideValidityWindow = true;
        break;
      }
    }

    acceptedCerts.put(cacheKey, isOutsideValidityWindow);

    if (acceptedCertsFile != null)
    {
      try
      {
        writeCacheFile();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
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
   * Retrieves a list of the addresses that the client is expected to use to
   * communicate with the server, if available.
   *
   * @return  A list of the addresses that the client is expected to use to
   *          communicate with the server, or an empty list if this is not
   *          available or applicable.
   */
  @NotNull()
  public List<String> getExpectedAddresses()
  {
    return expectedAddresses;
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
  @Override()
  public void checkClientTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    checkCertificateChain(chain, false);
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
  @Override()
  public void checkServerTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    checkCertificateChain(chain, true);
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.  This
   * will always return an empty array.
   *
   * @return  The accepted issuer certificates for this trust manager.
   */
  @Override()
  @NotNull()
  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }



  /**
   * Retrieves the cache key used to identify the provided certificate in the
   * map of accepted certificates.
   *
   * @param  certificate  The certificate for which to get the cache key.
   *
   * @return  The generated cache key.
   */
  @NotNull()
  static String getCacheKey(@NotNull final Certificate certificate)
  {
    final X509Certificate x509Certificate = (X509Certificate) certificate;
    return StaticUtils.toLowerCase(
         StaticUtils.toHex(x509Certificate.getSignature()));
  }



  /**
   * Converts the provided certificate chain from Java's representation of
   * X.509 certificates to the LDAP SDK's version.
   *
   * @param  chain  The chain to be converted.
   *
   * @return  The converted certificate chain.
   *
   * @throws  CertificateException  If a problem occurs while performing the
   *                                conversion.
   */
  @NotNull()
  static com.unboundid.util.ssl.cert.X509Certificate[] convertChain(
              @NotNull final Certificate[] chain)
         throws CertificateException
  {
    final com.unboundid.util.ssl.cert.X509Certificate[] convertedChain =
         new com.unboundid.util.ssl.cert.X509Certificate[chain.length];
    for (int i=0; i < chain.length; i++)
    {
      try
      {
        convertedChain[i] = new com.unboundid.util.ssl.cert.X509Certificate(
             chain[i].getEncoded());
      }
      catch (final CertException ce)
      {
        Debug.debugException(ce);
        throw new CertificateException(ce.getMessage(), ce);
      }
    }

    return convertedChain;
  }
}
