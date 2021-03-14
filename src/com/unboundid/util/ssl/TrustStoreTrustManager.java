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



import java.io.File;
import java.io.FileInputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL trust manager that will consult a specified trust
 * store file to determine whether to trust a certificate that is presented to
 * it.  By default, it will use the default trust store format for the JVM
 * (e.g., "JKS" for Sun-provided Java implementations), but alternate formats
 * like PKCS12 may be used.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TrustStoreTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4093869102727719415L;



  // Indicates whether to automatically trust expired or not-yet-valid
  // certificates.
  private final boolean examineValidityDates;

  // The PIN to use to access the trust store.
  @Nullable private final char[] trustStorePIN;

  // The path to the trust store file.
  @NotNull private final String trustStoreFile;

  // The format to use for the trust store file.
  @NotNull private final String trustStoreFormat;



  /**
   * Creates a new instance of this trust store trust manager that will trust
   * all certificates in the specified file within the validity window. It will
   * use the default trust store format and will not provide a PIN when
   * attempting to read the trust store.
   *
   * @param  trustStoreFile  The path to the trust store file to use.  It must
   *                         not be {@code null}.
   */
  public TrustStoreTrustManager(@NotNull final File trustStoreFile)
  {
    this(trustStoreFile.getAbsolutePath(), null, null, true);
  }



  /**
   * Creates a new instance of this trust store trust manager that will trust
   * all certificates in the specified file within the validity window. It will
   * use the default trust store format and will not provide a PIN when
   * attempting to read the trust store.
   *
   * @param  trustStoreFile  The path to the trust store file to use.  It must
   *                         not be {@code null}.
   */
  public TrustStoreTrustManager(@NotNull final String trustStoreFile)
  {
    this(trustStoreFile, null, null, true);
  }



  /**
   * Creates a new instance of this trust store trust manager that will trust
   * all certificates in the specified file with the specified constraints.
   *
   * @param  trustStoreFile        The path to the trust store file to use.  It
   *                               must not be {@code null}.
   * @param  trustStorePIN         The PIN to use to access the contents of the
   *                               trust store.  It may be {@code null} if no
   *                               PIN is required.
   * @param  trustStoreFormat      The format to use for the trust store.  It
   *                               may be {@code null} if the default format
   *                               should be used.
   * @param  examineValidityDates  Indicates whether to reject certificates if
   *                               the current time is outside the validity
   *                               window for the certificate.
   */
  public TrustStoreTrustManager(@NotNull final File trustStoreFile,
                                @Nullable final char[] trustStorePIN,
                                @Nullable final String trustStoreFormat,
                                final boolean examineValidityDates)
  {
    this(trustStoreFile.getAbsolutePath(), trustStorePIN, trustStoreFormat,
         examineValidityDates);
  }



  /**
   * Creates a new instance of this trust store trust manager that will trust
   * all certificates in the specified file with the specified constraints.
   *
   * @param  trustStoreFile        The path to the trust store file to use.  It
   *                               must not be {@code null}.
   * @param  trustStorePIN         The PIN to use to access the contents of the
   *                               trust store.  It may be {@code null} if no
   *                               PIN is required.
   * @param  trustStoreFormat      The format to use for the trust store.  It
   *                               may be {@code null} if the default format
   *                               should be used.
   * @param  examineValidityDates  Indicates whether to reject certificates if
   *                               the current time is outside the validity
   *                               window for the certificate.
   */
  public TrustStoreTrustManager(@NotNull final String trustStoreFile,
                                @Nullable final char[] trustStorePIN,
                                @Nullable final String trustStoreFormat,
                                final boolean examineValidityDates)
  {
    Validator.ensureNotNull(trustStoreFile);

    this.trustStoreFile       = trustStoreFile;
    this.trustStorePIN        = trustStorePIN;
    this.examineValidityDates = examineValidityDates;

    if (trustStoreFormat == null)
    {
      this.trustStoreFormat = CryptoHelper.getDefaultKeyStoreType();
    }
    else
    {
      this.trustStoreFormat = trustStoreFormat;
    }
  }



  /**
   * Retrieves the path to the trust store file to use.
   *
   * @return  The path to the trust store file to use.
   */
  @NotNull()
  public String getTrustStoreFile()
  {
    return trustStoreFile;
  }



  /**
   * Retrieves the name of the trust store file format.
   *
   * @return  The name of the trust store file format.
   */
  @NotNull()
  public String getTrustStoreFormat()
  {
    return trustStoreFormat;
  }



  /**
   * Indicate whether to reject certificates if the current time is outside the
   * validity window for the certificate.
   *
   * @return  {@code true} if the certificate validity time should be examined
   *          and certificates should be rejected if they are expired or not
   *          yet valid, or {@code false} if certificates should be accepted
   *          even outside of the validity window.
   */
  public boolean examineValidityDates()
  {
    return examineValidityDates;
  }



  /**
   * Retrieves a set of trust managers that may be used to determine whether the
   * provided certificate chain should be trusted.  It will also check the
   * validity of the provided certificates.
   *
   * @param  chain  The certificate chain for which to make the determination.
   *
   * @return  The set of trust managers that may be used to make the
   *          determination.
   *
   * @throws  CertificateException  If the provided client certificate chain
   *                                should not be trusted.
   */
  @NotNull()
  private X509TrustManager[] getTrustManagers(
                                  @NotNull final X509Certificate[] chain)
          throws CertificateException
  {
    if (examineValidityDates)
    {
      final Date d = new Date();
      for (final X509Certificate c : chain)
      {
        c.checkValidity(d);
      }
    }

    final File f = new File(trustStoreFile);
    if (! f.exists())
    {
      throw new CertificateException(
           ERR_TRUSTSTORE_NO_SUCH_FILE.get(trustStoreFile));
    }

    final KeyStore ks;
    try
    {
      ks = CryptoHelper.getKeyStore(trustStoreFormat);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new CertificateException(
           ERR_TRUSTSTORE_UNSUPPORTED_FORMAT.get(trustStoreFormat), e);
    }

    try (FileInputStream inputStream = new FileInputStream(f))
    {
      ks.load(inputStream, trustStorePIN);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new CertificateException(
           ERR_TRUSTSTORE_CANNOT_LOAD.get(trustStoreFile, trustStoreFormat,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final TrustManagerFactory factory = CryptoHelper.getTrustManagerFactory();
      factory.init(ks);
      final TrustManager[] trustManagers = factory.getTrustManagers();
      final X509TrustManager[] x509TrustManagers =
           new X509TrustManager[trustManagers.length];
      for (int i=0; i < trustManagers.length; i++)
      {
        x509TrustManagers[i] = (X509TrustManager) trustManagers[i];
      }
      return x509TrustManagers;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new CertificateException(
           ERR_TRUSTSTORE_CANNOT_GET_TRUST_MANAGERS.get(trustStoreFile,
                trustStoreFormat, StaticUtils.getExceptionMessage(e)),
           e);
    }
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
    for (final X509TrustManager m : getTrustManagers(chain))
    {
      m.checkClientTrusted(chain, authType);
    }
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
    for (final X509TrustManager m : getTrustManagers(chain))
    {
      m.checkServerTrusted(chain, authType);
    }
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
}
