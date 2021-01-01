/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.math.BigInteger;
import java.util.List;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class serves as a proxy that provides access to selected package-private
 * methods in classes in the {@code com.unboundid.util.ssl.cert} package so that
 * they may be called by code in other packages in the LDAP SDK (including in
 * unit tests).  Neither this class nor the methods it contains may be used
 * outside of the LDAP SDK.
 */
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InternalCertHelper
{
  /**
   * Prevent this class from being instantiated.
   */
  private InternalCertHelper()
  {
    // No implementation is required.
  }



  /**
   * Creates a new X.509 certificate with the provided information.  This is
   * primarily intended for unit testing and other internal use.
   *
   * @param  version                       The version number for the
   *                                       certificate.
   * @param  serialNumber                  The serial number for the
   *                                       certificate.  This must not be
   *                                       {@code null}.
   * @param  signatureAlgorithmOID         The signature algorithm OID for the
   *                                       certificate.  This must not be
   *                                       {@code null}.
   * @param  signatureAlgorithmParameters  The encoded signature algorithm
   *                                       parameters for the certificate.  This
   *                                       may be {@code null} if there are no
   *                                       parameters.
   * @param  signatureValue                The encoded signature for the
   *                                       certificate.  This must not be
   *                                       {@code null}.
   * @param  issuerDN                      The issuer DN for the certificate.
   *                                       This must not be {@code null}.
   * @param  notBefore                     The validity start time for the
   *                                       certificate.
   * @param  notAfter                      The validity end time for the
   *                                       certificate.
   * @param  subjectDN                     The subject DN for the certificate.
   *                                       This must not be {@code null}.
   * @param  publicKeyAlgorithmOID         The OID of the public key algorithm
   *                                       for the certificate.  This must not
   *                                       be {@code null}.
   * @param  publicKeyAlgorithmParameters  The encoded public key algorithm
   *                                       parameters for the certificate.  This
   *                                       may be {@code null} if there are no
   *                                       parameters.
   * @param  encodedPublicKey              The encoded public key for the
   *                                       certificate.  This must not be
   *                                       {@code null}.
   * @param  decodedPublicKey              The decoded public key for the
   *                                       certificate.  This may be
   *                                       {@code null} if it is not available.
   * @param  issuerUniqueID                The issuer unique ID for the
   *                                       certificate.  This may be
   *                                       {@code null} if the certificate does
   *                                       not have an issuer unique ID.
   * @param  subjectUniqueID               The subject unique ID for the
   *                                       certificate.  This may be
   *                                       {@code null} if the certificate does
   *                                       not have a subject unique ID.
   * @param  extensions                    The set of extensions to include in
   *                                       the certificate.  This must not be
   *                                       {@code null} but may be empty.
   *
   * @return  The X.509 certificate that was created.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate.
   */
  @InternalUseOnly()
  @NotNull()
  public static X509Certificate createX509Certificate(
                     @NotNull final X509CertificateVersion version,
                     @NotNull final BigInteger serialNumber,
                     @NotNull final OID signatureAlgorithmOID,
                     @Nullable final ASN1Element signatureAlgorithmParameters,
                     @NotNull final ASN1BitString signatureValue,
                     @NotNull final DN issuerDN, final long notBefore,
                     final long notAfter, @NotNull final DN subjectDN,
                     @NotNull final OID publicKeyAlgorithmOID,
                     @Nullable final ASN1Element publicKeyAlgorithmParameters,
                     @NotNull final ASN1BitString encodedPublicKey,
                     @Nullable final DecodedPublicKey decodedPublicKey,
                     @Nullable final ASN1BitString issuerUniqueID,
                     @Nullable final ASN1BitString subjectUniqueID,
                     @NotNull final X509CertificateExtension... extensions)
       throws CertException
  {
    return new X509Certificate(version, serialNumber, signatureAlgorithmOID,
         signatureAlgorithmParameters, signatureValue, issuerDN, notBefore,
         notAfter, subjectDN, publicKeyAlgorithmOID,
         publicKeyAlgorithmParameters, encodedPublicKey, decodedPublicKey,
         issuerUniqueID, subjectUniqueID, extensions);
  }



  /**
   * Creates a new PKCS #10 certificate signing request with the provided
   * information.  This is primarily intended for unit testing and other
   * internal use.
   *
   * @param  version                       The version number for the
   *                                       certificate signing request.
   * @param  signatureAlgorithmOID         The signature algorithm OID for the
   *                                       request.  This must not be
   *                                       {@code null}.
   * @param  signatureAlgorithmParameters  The encoded signature algorithm
   *                                       parameters for the request.  This
   *                                       may be {@code null} if there are no
   *                                       parameters.
   * @param  signatureValue                The encoded signature for the
   *                                       request.  This must not be
   *                                       {@code null}.
   * @param  subjectDN                     The subject DN for the request.  This
   *                                       This must not be {@code null}.
   * @param  publicKeyAlgorithmOID         The OID of the public key algorithm
   *                                       for the request.  This must not be
   *                                       {@code null}.
   * @param  publicKeyAlgorithmParameters  The encoded public key algorithm
   *                                       parameters for the request.  This may
   *                                       be {@code null} if there are no
   *                                       parameters.
   * @param  encodedPublicKey              The encoded public key for the
   *                                       request.  This must not be
   *                                       {@code null}.
   * @param  decodedPublicKey              The decoded public key for the
   *                                       request.  This may be {@code null} if
   *                                       it is not available.
   * @param  nonExtensionAttributes        Any attributes to include in the
   *                                       request other than the set of
   *                                       extensions.  This may be {@code null}
   *                                       or empty if no additional attributes
   *                                       are needed.
   * @param  extensions                    The set of extensions included in the
   *                                       request.  This must not be
   *                                       {@code null} but may be empty.
   *
   * @return  The PKCS #10 certificate signing request that was created.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate signing request.
   */
  @InternalUseOnly()
  @NotNull()
  public static PKCS10CertificateSigningRequest
                     createPKCS10CertificateSigningRequest(
         @NotNull final PKCS10CertificateSigningRequestVersion version,
         @NotNull final OID signatureAlgorithmOID,
         @Nullable final ASN1Element signatureAlgorithmParameters,
         @NotNull final ASN1BitString signatureValue,
         @NotNull final DN subjectDN,
         @NotNull final OID publicKeyAlgorithmOID,
         @Nullable final ASN1Element publicKeyAlgorithmParameters,
         @NotNull final ASN1BitString encodedPublicKey,
         @Nullable final DecodedPublicKey decodedPublicKey,
         @Nullable final List<ObjectPair<OID,ASN1Set>> nonExtensionAttributes,
         @NotNull final X509CertificateExtension... extensions)
         throws CertException
  {
    return new PKCS10CertificateSigningRequest(version, signatureAlgorithmOID,
         signatureAlgorithmParameters, signatureValue, subjectDN,
         publicKeyAlgorithmOID, publicKeyAlgorithmParameters, encodedPublicKey,
         decodedPublicKey, nonExtensionAttributes, extensions);
  }



  /**
   * Creates a new PKCS #8 private key with the provided information.
   *
   * @param  version                        The PKCS #8 private key version.
   *                                        This must not be {@code null}.
   * @param  privateKeyAlgorithmOID         The OID for the private key
   *                                        algorithm.  This must not be
   *                                        {@code null}.
   * @param  privateKeyAlgorithmParameters  The ASN.1 element with the encoded
   *                                        private key algorithm parameters.
   *                                        This may be {@code null} if there
   *                                        are no parameters.
   * @param  encodedPrivateKey              The encoded representation of the
   *                                        private key.  This must not be
   *                                        {@code null}.
   * @param  decodedPrivateKey              The decoded representation of the
   *                                        private key.  This may be
   *                                        {@code null} if the decoded
   *                                        representation is not available.
   * @param  attributesElement              The attributes element to include in
   *                                        the private key.  This may be
   *                                        {@code null} if no attributes
   *                                        element should be included.
   * @param  publicKey                      The public key to include in the
   *                                        private key.  This may be
   *                                        {@code null} if no public key should
   *                                        be included.
   *
   * @return  The PKCS #8 private key that was created.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         private key.
   */
  @InternalUseOnly()
  @NotNull()
  public static PKCS8PrivateKey createPKCS8PrivateKey(
                     @NotNull final PKCS8PrivateKeyVersion version,
                     @NotNull final OID privateKeyAlgorithmOID,
                     @Nullable final ASN1Element privateKeyAlgorithmParameters,
                     @NotNull final ASN1OctetString encodedPrivateKey,
                     @Nullable final DecodedPrivateKey decodedPrivateKey,
                     @Nullable final ASN1Element attributesElement,
                     @Nullable final ASN1BitString publicKey)
         throws CertException
  {
    return new PKCS8PrivateKey(version, privateKeyAlgorithmOID,
         privateKeyAlgorithmParameters, encodedPrivateKey, decodedPrivateKey,
         attributesElement, publicKey);
  }
}
