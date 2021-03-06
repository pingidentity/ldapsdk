/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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



import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.X509PEMFileReader;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an implementation of an X.509 trust manager that can
 * obtain information about trusted issuers from one or more PEM files.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PEMFileTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final   long serialVersionUID = 1973401278035832777L;



  // The map of trusted certificates read from the PEM files.
  @NotNull private final Map<com.unboundid.util.ssl.cert.X509Certificate,
     X509Certificate> trustedCertificates;



  /**
   * Creates a new PEM file trust manager that will read trusted certificate
   * information from the specified PEM files.
   *
   * @param  pemFiles  The PEM files from which to read the trusted certificate
   *                   information.  It must not be {@code null} or empty, and
   *                   all files must exist.  Each element may be a file (which
   *                   may contain one or more PEM-formatted certificates) or a
   *                   directory (in which case all of the files in that
   *                   directory, including subdirectories will be recursively
   *                   processed).
   *
   * @throws  KeyStoreException  If a problem occurs while trying to read or
   *                             decode any of the certificates.
   */
  public PEMFileTrustManager(@NotNull final File... pemFiles)
         throws KeyStoreException
  {
    this(StaticUtils.toList(pemFiles));
  }



  /**
   * Creates a new PEM file trust manager that will read trusted certificate
   * information from the specified PEM files.
   *
   * @param  pemFiles  The PEM files from which to read the trusted certificate
   *                   information.  It must not be {@code null} or empty, and
   *                   all files must exist.  Each element may be a file (which
   *                   may contain one or more PEM-formatted certificates) or a
   *                   directory (in which case all of the files in that
   *                   directory, including subdirectories will be recursively
   *                   processed).
   *
   * @throws  KeyStoreException  If a problem occurs while trying to read or
   *                             decode any of the certificates.
   */
  public PEMFileTrustManager(@NotNull final List<File> pemFiles)
         throws KeyStoreException
  {
    Validator.ensureNotNullWithMessage(pemFiles,
         "PEMFileTrustManager.pemFiles must not be null.");
    Validator.ensureFalse(pemFiles.isEmpty(),
         "PEMFileTrustManager.pemFiles must not be empty.");

    final Map<com.unboundid.util.ssl.cert.X509Certificate,X509Certificate>
         certMap = new HashMap<>();
    for (final File f : pemFiles)
    {
      readTrustedCertificates(f, certMap);
    }

    trustedCertificates = Collections.unmodifiableMap(certMap);
  }



  /**
   * Reads trusted certificate information from the specified PEM file.
   *
   * @param  f  The PEM file to examine.  It must not be {@code null}, and it
   *            must reference a file that exists.  If it is a directory, then
   *            all files contained in it (including subdirectories) will be
   *            recursively processed.
   * @param  m  The map to be updated wth the certificates read from the PEM
   *            files.  It must not be {@code null} and must be updatable.
   *
   * @throws  KeyStoreException  If a problem is encountered while reading
   *                             trusted certificate information from the
   *                             specified file.
   */
  private static void readTrustedCertificates(@NotNull final File f,
               @NotNull final Map<com.unboundid.util.ssl.cert.X509Certificate,
                    X509Certificate> m)
          throws KeyStoreException
  {
    if (! f.exists())
    {
      throw new KeyStoreException(
           ERR_PEM_FILE_TRUST_MANAGER_NO_SUCH_FILE.get(f.getAbsolutePath()));
    }

    try
    {
      if (f.isDirectory())
      {
        for (final File fileInDir : f.listFiles())
        {
          readTrustedCertificates(fileInDir, m);
        }
      }
      else
      {
        try (X509PEMFileReader r = new X509PEMFileReader(f))
        {
          boolean readCert = false;
          while (true)
          {
            final com.unboundid.util.ssl.cert.X509Certificate cert =
                 r.readCertificate();
            if (cert == null)
            {
              if (! readCert)
              {
                throw new KeyStoreException(
                     ERR_PEM_FILE_TRUST_MANAGER_EMPTY_FILE.get(
                          f.getAbsolutePath()));
              }

              break;
            }

            readCert = true;

            final X509Certificate c = (X509Certificate) cert.toCertificate();
            m.put(cert, c);
          }
        }
      }
    }
    catch (final KeyStoreException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final IOException e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PEM_FILE_TRUST_MANAGER_ERROR_READING_FILE.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PEM_FILE_TRUST_MANAGER_ERROR_PARSING_CERT.get(
                f.getAbsolutePath(), e.getMessage()),
           e);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new KeyStoreException(
           ERR_PEM_FILE_TRUST_MANAGER_ERROR_PROCESSING_FILE.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Determines whether the provided client certificate chain should be
   * considered trusted based on the trusted certificate information read from
   * PEM files.
   *
   * @param  chain     The client certificate chain for which to make the
   *                   determination.  It must not be {@code null} or empty.
   * @param  authType  The type of authentication to use based on the client
   *                   certificate.  It must not be {@code null}.
   *
   * @throws  CertificateException  If the provided certificate chain should not
   *                                be considered trusted.
   */
  @Override()
  public void checkClientTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    try
    {
      checkTrusted(chain);
    }
    catch (final CertificateException e)
    {
      Debug.debugException(e);
      throw new CertificateException(
           ERR_PEM_FILE_TRUST_MANAGER_CLIENT_NOT_TRUSTED.get(e.getMessage()),
           e);
    }
  }



  /**
   * Determines whether the provided server certificate chain should be
   * considered trusted based on the trusted certificate information read from
   * PEM files.
   *
   * @param  chain     The server certificate chain for which to make the
   *                   determination.  It must not be {@code null} or empty.
   * @param  authType  The type of authentication to use based on the server
   *                   certificate.  It must not be {@code null}.
   *
   * @throws  CertificateException  If the provided certificate chain should not
   *                                be considered trusted.
   */
  @Override()
  public void checkServerTrusted(@NotNull final X509Certificate[] chain,
                                 @NotNull final String authType)
         throws CertificateException
  {
    try
    {
      checkTrusted(chain);
    }
    catch (final CertificateException e)
    {
      Debug.debugException(e);
      throw new CertificateException(
           ERR_PEM_FILE_TRUST_MANAGER_SERVER_NOT_TRUSTED.get(e.getMessage()),
           e);
    }
  }



  /**
   * Determines whether the provided certificate chain should be considered
   * trusted based on the trusted certificate information read from PEM files.
   * Note that this method assumes that the trusted certificate information read
   * from PEM files should be authoritative, and therefore doesn't perform some
   * types of validation (like ensuring that all issuer certificates are trusted
   * rather than validating that at least one is trusted, or checking extensions
   * like basic constraints).
   *
   * @param  chain  The certificate chain for which to make the determination.
   *                It must not be {@code null} or empty.
   *
   * @throws  CertificateException  If the provided certificate chain should not
   *                                be considered trusted.
   */
  private void checkTrusted(@NotNull final X509Certificate[] chain)
          throws CertificateException
  {
    // If the chain is null or empty, then it cannot be trusted.
    if ((chain == null) || (chain.length == 0))
    {
      throw new CertificateException(
           ERR_PEM_FILE_TRUST_MANAGER_EMPTY_CHAIN.get());
    }


    // Iterate through all the certificates in the chain, parsing them using the
    // LDAP SDK's X.509 certificate representation, and performing all of the
    // following validation:
    //
    // - Make sure that the certificate is within the validity window.
    //
    // - Make sure that each subsequent certificate in the chain is the issuer
    //   for the previous certificate.
    //
    // - Check to see whether at least one of the certificates in the chain
    //   matches one read from the set of PEM files.
    boolean foundCertificate = false;
    com.unboundid.util.ssl.cert.X509Certificate firstCertificate = null;
    com.unboundid.util.ssl.cert.X509Certificate previousCertificate = null;
    for (final X509Certificate c : chain)
    {
      final com.unboundid.util.ssl.cert.X509Certificate parsedCertificate;
      try
      {
        parsedCertificate = new com.unboundid.util.ssl.cert.X509Certificate(
             c.getEncoded());
      }
      catch (final CertException e)
      {
        Debug.debugException(e);
        throw new CertificateException(
             ERR_PEM_FILE_TRUST_MANAGER_CANNOT_PARSE_CERT_FROM_CHAIN.get(
                  c.getSubjectX500Principal().getName(X500Principal.RFC2253),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }

      if (firstCertificate == null)
      {
        firstCertificate = parsedCertificate;
      }

      if (! parsedCertificate.isWithinValidityWindow())
      {
        throw new CertificateException(
             ERR_PEM_FILE_TRUST_MANAGER_CERT_NOT_VALID.get(
                  String.valueOf(parsedCertificate.getSubjectDN()),
                  StaticUtils.encodeRFC3339Time(
                       parsedCertificate.getNotBeforeDate()),
                  StaticUtils.encodeRFC3339Time(
                       parsedCertificate.getNotAfterDate())));
      }

      if ((previousCertificate != null) &&
           (! parsedCertificate.isIssuerFor(previousCertificate)))
      {
        throw new CertificateException(
             ERR_PEM_FILE_TRUST_MANAGER_CERT_NOT_ISSUER.get(
                  String.valueOf(parsedCertificate.getSubjectDN()),
                  String.valueOf(previousCertificate.getSubjectDN())));
      }

      foundCertificate |= trustedCertificates.containsKey(parsedCertificate);
      previousCertificate = parsedCertificate;
    }


    // If we didn't find any of the presented certificates in the trust store,
    // then it may be that an incomplete chain was presented.  If the last
    // certificate in the chain is not self-signed, then check to see if any of
    // the certificates in the trust store were an issuer for that certificate.
    if ((! foundCertificate) && (! previousCertificate.isSelfSigned()))
    {
      for (final com.unboundid.util.ssl.cert.X509Certificate c :
           trustedCertificates.keySet())
      {
        if (c.isIssuerFor(previousCertificate))
        {
          foundCertificate = true;
          break;
        }
      }
    }

    if (! foundCertificate)
    {
      throw new CertificateException(ERR_PEM_FILE_TRUST_MANAGER_NOT_TRUSTED.get(
           String.valueOf(firstCertificate.getSubjectDN())));
    }
  }



  /**
   * Retrieves an array of the issuer certificates that will be considered
   * trusted.
   *
   * @return  An array of the issuer certificates that will be considered
   *          trusted, or an empty array if no issuers will be trusted.
   */
  @Override()
  @NotNull()
  public X509Certificate[] getAcceptedIssuers()
  {
    // Include all certificates that are currently within their validity window.
    final long currentTime = System.currentTimeMillis();
    final List<X509Certificate> certList =
         new ArrayList<>(trustedCertificates.size());
    for (final Map.Entry<com.unboundid.util.ssl.cert.X509Certificate,
              X509Certificate> e : trustedCertificates.entrySet())
    {
      if (e.getKey().isWithinValidityWindow(currentTime))
      {
        certList.add(e.getValue());
      }
    }

    final X509Certificate[] certArray = new X509Certificate[certList.size()];
    return certList.toArray(certArray);
  }
}
