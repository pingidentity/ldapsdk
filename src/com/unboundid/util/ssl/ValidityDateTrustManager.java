/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2018 Ping Identity Corporation
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



import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an SSL trust manager that merely checks to see whether
 * a presented certificate is currently within its validity time window (i.e.,
 * the current time is not earlier than the certificate's notBefore timestamp
 * and not later than the certificate's notAfter timestamp).
 * <BR><BR>
 * Note that no other elements of the certificate are examined, so it is
 * strongly recommended that this trust manager be used in an
 * {@link AggregateTrustManager} in conjunction with other trust managers that
 * perform other forms of validation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ValidityDateTrustManager
       implements X509TrustManager
{
  /**
   * A pre-allocated empty certificate array.
   */
  private static final X509Certificate[] NO_CERTIFICATES =
       new X509Certificate[0];



  /**
   * Creates a new validity date trust manager.
   */
  public ValidityDateTrustManager()
  {
    // No implementation is required.
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
  public void checkClientTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateValidity(chain[0]);
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
  public void checkServerTrusted(final X509Certificate[] chain,
                                 final String authType)
         throws CertificateException
  {
    checkCertificateValidity(chain[0]);
  }



  /**
   * Checks the provided certificate to determine whether the current time is
   * within the certificate's validity window.
   *
   * @param  c  The certificate to be checked.
   *
   * @throws  CertificateException  If the presented certificate is outside the
   *                                validity window.
   */
  private static void checkCertificateValidity(final X509Certificate c)
         throws CertificateException
  {
    final Date currentTime = new Date();
    final Date notBefore   = c.getNotBefore();
    final Date notAfter    = c.getNotAfter();

    if (currentTime.before(notBefore))
    {
      throw new CertificateException(ERR_VALIDITY_TOO_EARLY.get(
           c.getSubjectX500Principal().getName(X500Principal.RFC2253),
           String.valueOf(notBefore)));
    }

    if (currentTime.after(c.getNotAfter()))
    {
      throw new CertificateException(ERR_VALIDITY_TOO_LATE.get(
           c.getSubjectX500Principal().getName(X500Principal.RFC2253),
           String.valueOf(notAfter)));
    }
  }



  /**
   * Retrieves the accepted issuer certificates for this trust manager.  This
   * will always return an empty array.
   *
   * @return  The accepted issuer certificates for this trust manager.
   */
  @Override()
  public X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
