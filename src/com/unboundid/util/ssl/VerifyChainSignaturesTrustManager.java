/*
 * Copyright 2026 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2026 Ping Identity Corporation
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
 * Copyright (C) 2026 Ping Identity Corporation
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
import javax.net.ssl.X509TrustManager;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.X509Certificate;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class provides an X.509 trust manager implementation that can be used to
 * verify signatures in a certificate chain.  It will verify that self-signed
 * certificates have valid signatures, and that in a multi-certificate chain,
 * each subsequent certificate in the chain is the correct signer for the
 * previous certificate in that chain.
 * <BR><BR>
 * Note that this trust manager should not be used on its own, since it only
 * validates the certificate chain that was actually presented by the peer.
 * If the presented chain is incomplete (which is acceptable if there is reason
 * to expect that the peer can complete the chain using its own set of trusted
 * issuers), then this trust manager will not attempt to verify that the last
 * certificate presented by the peer was actually signed by one of those
 * trusted issuers.  And even in the case where the full chain is presented,
 * this trust manager only attempts to verify that each subsequent certificate
 * is the one used to sign the previous one, and does not attempt to make any
 * determination about whether any of the end-entity or issuer certificates are
 * trustworthy.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VerifyChainSignaturesTrustManager
       implements X509TrustManager, Serializable
{
  /**
   * A pre-allocated empty certificate array.
   */
  @NotNull private static final java.security.cert.X509Certificate[]
       NO_CERTIFICATES = new java.security.cert.X509Certificate[0];



  /**
   * The singleton instance of this trust manager.
   */
  @NotNull private static final VerifyChainSignaturesTrustManager INSTANCE =
       new VerifyChainSignaturesTrustManager();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2712657207894506440L;



  /**
   * Creates a new instance of this trust manager.
   */
  private VerifyChainSignaturesTrustManager()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this issuer chain trust manager.
   *
   * @return  A singleton instance of this issuer chain trust manager.
   */
  @NotNull()
  public static VerifyChainSignaturesTrustManager getInstance()
  {
    return INSTANCE;
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
  public void checkClientTrusted(
                   @NotNull final java.security.cert.X509Certificate[] chain,
                   @NotNull final String authType)
         throws CertificateException
  {
    validateIssuerChain(chain);
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
  public void checkServerTrusted(
                   @NotNull final java.security.cert.X509Certificate[] chain,
                   @NotNull final String authType)
         throws CertificateException
  {
    validateIssuerChain(chain);
  }



  /**
   * Ensures that the certificates in the provided array represent a valid chain
   * of issuer certificates.
   *
   * @param  chain  The certificate chain to validate.
   *
   * @throws  CertificateException  If the provided array does not represent a
   *                                valid chain of issuer certificates.
   */
  private void validateIssuerChain(
                    @NotNull final java.security.cert.X509Certificate[] chain)
           throws CertificateException
  {
    // If the provided chain is null or empty, then we can't perform any
    // validation, so we'll have to consider it acceptable.
    if ((chain == null) || (chain.length < 1))
    {
      return;
    }


    // Convert the certificates in the provided chain to use the LDAP SDK's
    // representation of the certificates.
    final X509Certificate[] sdkChain = new X509Certificate[chain.length];
    for (int i=0; i < chain.length; i++)
    {
      try
      {
        sdkChain[i] = new X509Certificate(chain[i].getEncoded());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new CertificateException(
             ERR_ISSUER_CHAIN_TRUST_CANNOT_PARSE_CERT.get(
                  String.valueOf(chain[i].getSubjectX500Principal()), i,
                  StaticUtils.getExceptionMessage(e)));
      }
    }


    // If the chain only contains a single certificate, then check to see if
    // it's self-signed.  If so, then validate its signature.  If not, then we
    // can't perform any validation.
    if (sdkChain.length == 1)
    {
      if (sdkChain[0].isSelfSigned())
      {
        try
        {
          sdkChain[0].verifySignature(sdkChain[0]);
        }
        catch (final CertException e)
        {
          Debug.debugException(e);
          throw new CertificateException(e.getMessage(), e);
        }
      }
      else
      {
        return;
      }
    }


    // Iterate through the chain, ensuring that each subsequent certificate is
    // the issuer for the previous one.
    X509Certificate previousCertificate = sdkChain[0];
    for (int i=1; i < sdkChain.length; i++)
    {
      final X509Certificate subsequentCertificate = sdkChain[i];

      // If the previous certificate is self-signed, then the subsequent
      // certificate can't be its issuer.
      if (previousCertificate.isSelfSigned())
      {
        throw new CertificateException(
             ERR_ISSUER_CHAIN_TRUST_NON_FINAL_SELF_SIGNED.get(
                  String.valueOf(previousCertificate.getSubjectDN()),
                  (i-1), sdkChain.length,
                  String.valueOf(subsequentCertificate.getSubjectDN())));
      }


      // Ensure that the previous certificate is actually signed by the
      // subsequent certificate.
      try
      {
        previousCertificate.verifySignature(subsequentCertificate);
      }
      catch (final CertException e)
      {
        Debug.debugException(e);
        throw new CertificateException(e.getMessage(), e);
      }

      previousCertificate = subsequentCertificate;
    }


    // If the last certificate in the chain is self-signed, then verify its
    // signature.
    if (previousCertificate.isSelfSigned())
    {
      try
      {
        previousCertificate.verifySignature(previousCertificate);
      }
      catch (final CertException e)
      {
        Debug.debugException(e);
        throw new CertificateException(e.getMessage(), e);
      }
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
  public java.security.cert.X509Certificate[] getAcceptedIssuers()
  {
    return NO_CERTIFICATES;
  }
}
