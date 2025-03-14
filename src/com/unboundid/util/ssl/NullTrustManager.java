/*
 * Copyright 2020-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2025 Ping Identity Corporation
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
 * Copyright (C) 2020-2025 Ping Identity Corporation
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



import java.io.Serializable;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL trust manager that will not trust any
 * certificates.  It is primarily useful for testing purposes.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NullTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  /**
   * A singleton instance of this trust manager.
   */
  @NotNull private static final NullTrustManager INSTANCE =
       new NullTrustManager();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2435783503919293156L;



  /**
   * Creates a new instance of this trust all trust manager that will trust
   * any certificate, including certificates that are expired or not yet valid.
   */
  private NullTrustManager()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the singleton instance of this class.
   *
   * @return  The singleton instance of this class.
   */
  @NotNull()
  public static NullTrustManager getInstance()
  {
    return INSTANCE;
  }



  /**
   * Checks to determine whether the provided client certificate chain should be
   * trusted.  A certificate will only be rejected (by throwing a
   * {@link CertificateException}) if certificate validity dates should be
   * examined and the certificate or any of its issuers is outside of the
   * validity window.
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
    throw new CertificateException(
         ERR_NULL_TRUST_MANAGER_CERT_NOT_TRUSTED.get());
  }



  /**
   * Checks to determine whether the provided server certificate chain should be
   * trusted.  A certificate will only be rejected (by throwing a
   * {@link CertificateException}) if certificate validity dates should be
   * examined and the certificate or any of its issuers is outside of the
   * validity window.
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
    throw new CertificateException(
         ERR_NULL_TRUST_MANAGER_CERT_NOT_TRUSTED.get());
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
