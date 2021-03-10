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



import java.io.Serializable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides support for decoding a PKCS #10 certificate signing
 * request (aka certification request or CSR) as defined in
 * <A HREF="https://www.ietf.org/rfc/rfc2986.txt">RFC 2986</A>.  The certificate
 * signing request is encoded using the ASN.1 Distinguished Encoding Rules
 * (DER), which is a subset of BER, and is supported by the code in the
 * {@code com.unboundid.asn1} package.  The ASN.1 specification is as follows:
 * <PRE>
 *   CertificationRequest ::= SEQUENCE {
 *        certificationRequestInfo CertificationRequestInfo,
 *        signatureAlgorithm AlgorithmIdentifier,
 *        signature          BIT STRING
 *   }
 *
 *   CertificationRequestInfo ::= SEQUENCE {
 *        version       INTEGER { v1(0) } (v1,...),
 *        subject       Name,
 *        subjectPKInfo SubjectPublicKeyInfo,
 *        attributes    [0] Attributes
 *   }
 *
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *        algorithm        AlgorithmIdentifier,
 *        subjectPublicKey BIT STRING
 *   }
 *
 *   PKInfoAlgorithms ALGORITHM ::= {
 *        ...  -- add any locally defined algorithms here -- }
 *
 *   Attributes ::= SET OF Attribute
 *
 *   CRIAttributes  ATTRIBUTE  ::= {
 *        ... -- add any locally defined attributes here -- }
 *
 *   Attribute ::= SEQUENCE {
 *        type   OBJECT IDENTIFIER,
 *        values SET SIZE(1..MAX)
 *   }
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *        algorithm          OBJECT IDENTIFIER,
 *        parameters         ANY OPTIONAL
 *   }
 *
 *   SignatureAlgorithms ALGORITHM ::= {
 *        ... -- add any locally defined algorithms here -- }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PKCS10CertificateSigningRequest
       implements Serializable
{
  /**
   * The DER type for the attributes element.
   */
  private static final byte TYPE_ATTRIBUTES = (byte) 0xA0;



  /**
   * The OID for the request attribute that holds the set of requested
   * certificate extensions.
   */
  @NotNull private static final OID  ATTRIBUTE_OID_EXTENSIONS =
       new OID("1.2.840.113549.1.9.14");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1665446530589389194L;



  // The signature value for the request.
  @NotNull private final ASN1BitString signatureValue;

  // The encoded public key for the request.
  @NotNull private final ASN1BitString encodedPublicKey;

  // The ASN.1 element with the encoded public key algorithm parameters.
  @Nullable private final ASN1Element publicKeyAlgorithmParameters;

  // The ASN.1 element with the encoded signature algorithm parameters.
  @Nullable private final ASN1Element signatureAlgorithmParameters;

  // The bytes that comprise the encoded representation of the PKCS #10
  // certificate signing request.
  @NotNull private final byte[] pkcs10CertificateSigningRequestBytes;

  // The decoded public key for this request, if available.
  @Nullable private final DecodedPublicKey decodedPublicKey;

  // The subject DN for the request.
  @NotNull private final DN subjectDN;

  // The list of attributes for the request.
  @NotNull private final List<ObjectPair<OID,ASN1Set>> requestAttributes;

  // The list of extensions for the request.
  @NotNull private final List<X509CertificateExtension> extensions;

  // The OID for the public key algorithm.
  @NotNull private final OID publicKeyAlgorithmOID;

  // The OID for the signature algorithm.
  @NotNull private final OID signatureAlgorithmOID;

  // The PKCS #10 certificate signing request version.
  @NotNull private final PKCS10CertificateSigningRequestVersion version;

  // The public key algorithm name that corresponds with the public key
  // algorithm OID, if available.
  @Nullable private final String publicKeyAlgorithmName;

  // The signature algorithm name that corresponds with the signature algorithm
  // OID, if available.
  @Nullable private final String signatureAlgorithmName;



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
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate signing request.
   */
  PKCS10CertificateSigningRequest(
       @NotNull final PKCS10CertificateSigningRequestVersion version,
       @NotNull final OID signatureAlgorithmOID,
       @Nullable final ASN1Element signatureAlgorithmParameters,
       @NotNull final ASN1BitString signatureValue,
       @NotNull final DN subjectDN, @NotNull final OID publicKeyAlgorithmOID,
       @Nullable final ASN1Element publicKeyAlgorithmParameters,
       @NotNull final ASN1BitString encodedPublicKey,
       @Nullable final DecodedPublicKey decodedPublicKey,
       @Nullable final List<ObjectPair<OID,ASN1Set>> nonExtensionAttributes,
       @NotNull final X509CertificateExtension... extensions)
       throws CertException
  {
    this.version = version;
    this.signatureAlgorithmOID = signatureAlgorithmOID;
    this.signatureAlgorithmParameters = signatureAlgorithmParameters;
    this.signatureValue = signatureValue;
    this.subjectDN = subjectDN;
    this.publicKeyAlgorithmOID = publicKeyAlgorithmOID;
    this.publicKeyAlgorithmParameters = publicKeyAlgorithmParameters;
    this.encodedPublicKey = encodedPublicKey;
    this.decodedPublicKey = decodedPublicKey;
    this.extensions = StaticUtils.toList(extensions);

    final SignatureAlgorithmIdentifier signatureAlgorithmIdentifier =
         SignatureAlgorithmIdentifier.forOID(signatureAlgorithmOID);
    if (signatureAlgorithmIdentifier == null)
    {
      signatureAlgorithmName = null;
    }
    else
    {
      signatureAlgorithmName =
           signatureAlgorithmIdentifier.getUserFriendlyName();
    }

    final PublicKeyAlgorithmIdentifier publicKeyAlgorithmIdentifier =
         PublicKeyAlgorithmIdentifier.forOID(publicKeyAlgorithmOID);
    if (publicKeyAlgorithmIdentifier == null)
    {
      publicKeyAlgorithmName = null;
    }
    else
    {
      publicKeyAlgorithmName = publicKeyAlgorithmIdentifier.getName();
    }

    final ArrayList<ObjectPair<OID, ASN1Set>> attrs = new ArrayList<>(10);
    if (nonExtensionAttributes != null)
    {
      attrs.addAll(nonExtensionAttributes);
    }

    if (extensions.length > 0)
    {
      final ArrayList<ASN1Element> extensionElements =
           new ArrayList<>(extensions.length);
      for (final X509CertificateExtension e : extensions)
      {
        extensionElements.add(e.encode());
      }

      attrs.add(new ObjectPair<>(ATTRIBUTE_OID_EXTENSIONS,
           new ASN1Set(new ASN1Sequence(extensionElements))));
    }

    requestAttributes = Collections.unmodifiableList(attrs);

    pkcs10CertificateSigningRequestBytes = encode().encode();
  }



  /**
   * Decodes the contents of the provided byte array as a PKCS #10 certificate
   * signing request.
   *
   * @param  encodedRequest  The byte array containing the encoded PKCS #10
   *                         certificate signing request.  This must not be
   *                         {@code null}.
   *
   * @throws  CertException  If the contents of the provided byte array could
   *                         not be decoded as a valid PKCS #10 certificate
   *                         signing request.
   */
  public PKCS10CertificateSigningRequest(
              @NotNull final byte[] encodedRequest)
         throws CertException
  {
    pkcs10CertificateSigningRequestBytes = encodedRequest;

    final ASN1Element[] requestElements;
    try
    {
      requestElements =
           ASN1Sequence.decodeAsSequence(encodedRequest).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_NOT_SEQUENCE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (requestElements.length != 3)
    {
      throw new CertException(
           ERR_CSR_DECODE_UNEXPECTED_SEQUENCE_ELEMENT_COUNT.get(
                requestElements.length));
    }

    final ASN1Element[] requestInfoElements;
    try
    {
      requestInfoElements =
           ASN1Sequence.decodeAsSequence(requestElements[0]).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_FIRST_ELEMENT_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final int versionIntValue =
           requestInfoElements[0].decodeAsInteger().intValue();
      version = PKCS10CertificateSigningRequestVersion.valueOf(versionIntValue);
      if (version == null)
      {
        throw new CertException(
             ERR_CSR_DECODE_UNSUPPORTED_VERSION.get(version));
      }
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_CANNOT_PARSE_VERSION.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      subjectDN = X509Certificate.decodeName(requestInfoElements[1]);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_CANNOT_PARSE_SUBJECT_DN.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final ASN1Element[] subjectPublicKeyInfoElements =
           requestInfoElements[2].decodeAsSequence().elements();
      final ASN1Element[] publicKeyAlgorithmElements =
           subjectPublicKeyInfoElements[0].decodeAsSequence().elements();
      publicKeyAlgorithmOID =
           publicKeyAlgorithmElements[0].decodeAsObjectIdentifier().getOID();
      if (publicKeyAlgorithmElements.length > 1)
      {
        publicKeyAlgorithmParameters = publicKeyAlgorithmElements[1];
      }
      else
      {
        publicKeyAlgorithmParameters = null;
      }

      encodedPublicKey = subjectPublicKeyInfoElements[1].decodeAsBitString();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_CANNOT_PARSE_PUBLIC_KEY_INFO.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final PublicKeyAlgorithmIdentifier publicKeyAlgorithmIdentifier =
         PublicKeyAlgorithmIdentifier.forOID(publicKeyAlgorithmOID);
    if (publicKeyAlgorithmIdentifier == null)
    {
      publicKeyAlgorithmName = null;
      decodedPublicKey = null;
    }
    else
    {
      publicKeyAlgorithmName = publicKeyAlgorithmIdentifier.getName();

      DecodedPublicKey pk = null;
      switch (publicKeyAlgorithmIdentifier)
      {
        case RSA:
          try
          {
            pk = new RSAPublicKey(encodedPublicKey);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
          break;

        case EC:
          try
          {
            pk = new EllipticCurvePublicKey(encodedPublicKey);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
          break;
      }

      decodedPublicKey = pk;
    }

    final ArrayList<ObjectPair<OID,ASN1Set>> attrList = new ArrayList<>(10);
    final ArrayList<X509CertificateExtension> extList = new ArrayList<>(10);
    if (requestInfoElements.length > 3)
    {
      for (int i=3; i < requestInfoElements.length; i++)
      {
        final ASN1Element element = requestInfoElements[i];
        if (element.getType() == TYPE_ATTRIBUTES)
        {
          try
          {
            for (final ASN1Element attrSetElement :
                 element.decodeAsSet().elements())
            {
              final ASN1Element[] attrElements =
                   attrSetElement.decodeAsSequence().elements();
              final OID attrOID =
                   attrElements[0].decodeAsObjectIdentifier().getOID();
              final ASN1Set attrValues = attrElements[1].decodeAsSet();
              attrList.add(new ObjectPair<>(attrOID, attrValues));
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_CSR_DECODE_CANNOT_PARSE_ATTRS.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }

          for (final ObjectPair<OID,ASN1Set> p : attrList)
          {
            if (p.getFirst().equals(ATTRIBUTE_OID_EXTENSIONS))
            {
              try
              {
                for (final ASN1Element extElement :
                     p.getSecond().elements()[0].decodeAsSequence().elements())
                {
                  extList.add(X509CertificateExtension.decode(extElement));
                }
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
                throw new CertException(
                     ERR_CSR_DECODE_CANNOT_PARSE_EXT_ATTR.get(
                          p.getFirst(), StaticUtils.getExceptionMessage(e)),
                     e);
              }
            }
          }
        }
      }
    }

    requestAttributes = Collections.unmodifiableList(attrList);
    extensions = Collections.unmodifiableList(extList);


    try
    {
      final ASN1Element[] signatureAlgorithmElements =
           requestElements[1].decodeAsSequence().elements();
      signatureAlgorithmOID =
           signatureAlgorithmElements[0].decodeAsObjectIdentifier().getOID();
      if (signatureAlgorithmElements.length > 1)
      {
        signatureAlgorithmParameters = signatureAlgorithmElements[1];
      }
      else
      {
        signatureAlgorithmParameters = null;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_CANNOT_PARSE_SIG_ALG.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final SignatureAlgorithmIdentifier signatureAlgorithmIdentifier =
         SignatureAlgorithmIdentifier.forOID(signatureAlgorithmOID);
    if (signatureAlgorithmIdentifier == null)
    {
      signatureAlgorithmName = null;
    }
    else
    {
      signatureAlgorithmName =
           signatureAlgorithmIdentifier.getUserFriendlyName();
    }

    try
    {
      signatureValue = requestElements[2].decodeAsBitString();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_DECODE_CANNOT_PARSE_SIG_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this PKCS #10 certificate signing request to an ASN.1 element.
   *
   * @return  The encoded PKCS #10 certificate signing request.
   *
   * @throws  CertException  If a problem is encountered while trying to encode
   *                         the PKCS #10 certificate signing request.
   */
  @NotNull()
  private ASN1Element encode()
          throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> requestInfoElements = new ArrayList<>(4);
      requestInfoElements.add(new ASN1Integer(version.getIntValue()));
      requestInfoElements.add(X509Certificate.encodeName(subjectDN));

      if (publicKeyAlgorithmParameters == null)
      {
        requestInfoElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID)),
             encodedPublicKey));
      }
      else
      {
        requestInfoElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID),
                  publicKeyAlgorithmParameters),
             encodedPublicKey));
      }

      final ArrayList<ASN1Element> attrElements =
           new ArrayList<>(requestAttributes.size());
      for (final ObjectPair<OID,ASN1Set> attr : requestAttributes)
      {
        attrElements.add(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(attr.getFirst()),
                  attr.getSecond()));
      }

      requestInfoElements.add(new ASN1Set(TYPE_ATTRIBUTES, attrElements));


      final ArrayList<ASN1Element> certificationRequestElements =
           new ArrayList<>(3);
      certificationRequestElements.add(new ASN1Sequence(requestInfoElements));

      if (signatureAlgorithmParameters == null)
      {
        certificationRequestElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(signatureAlgorithmOID)));
      }
      else
      {
        certificationRequestElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(signatureAlgorithmOID),
             signatureAlgorithmParameters));
      }

      certificationRequestElements.add(signatureValue);

      return new ASN1Sequence(certificationRequestElements);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_ENCODE_ERROR.get(toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Generates a PKCS #10 certificate signing request with the provided
   * information.
   *
   * @param  signatureAlgorithm  The algorithm to use to generate the signature.
   *                             This must not be {@code null}.
   * @param  keyPair             The key pair to use for the certificate signing
   *                             request.  This must not be {@code null}.
   * @param  subjectDN           The subject DN for the certificate signing
   *                             request.  This must not be {@code null}.
   * @param  extensions          The set of extensions to include in the
   *                             certificate signing request.  This may be
   *                             {@code null} or empty if the request should not
   *                             include any custom extensions.
   *
   * @return  The generated PKCS #10 certificate signing request.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate signing request.
   */
  @NotNull()
  public static PKCS10CertificateSigningRequest
                     generateCertificateSigningRequest(
              @NotNull final SignatureAlgorithmIdentifier signatureAlgorithm,
              @NotNull final KeyPair keyPair, @NotNull final DN subjectDN,
              @Nullable final X509CertificateExtension... extensions)
         throws CertException
  {
    // Extract the parameters and encoded public key from the generated key
    // pair.  And while we're at it, generate a subject key identifier from
    // the encoded public key.
    DecodedPublicKey decodedPublicKey = null;
    final ASN1BitString encodedPublicKey;
    final ASN1Element publicKeyAlgorithmParameters;
    final byte[] subjectKeyIdentifier;
    final OID publicKeyAlgorithmOID;
    try
    {
      final ASN1Element[] pkElements = ASN1Sequence.decodeAsSequence(
           keyPair.getPublic().getEncoded()).elements();
      final ASN1Element[] pkAlgIDElements = ASN1Sequence.decodeAsSequence(
           pkElements[0]).elements();
      publicKeyAlgorithmOID =
           pkAlgIDElements[0].decodeAsObjectIdentifier().getOID();
      if (pkAlgIDElements.length == 1)
      {
        publicKeyAlgorithmParameters = null;
      }
      else
      {
        publicKeyAlgorithmParameters = pkAlgIDElements[1];
      }

      encodedPublicKey = pkElements[1].decodeAsBitString();

      try
      {
        if (publicKeyAlgorithmOID.equals(
             PublicKeyAlgorithmIdentifier.RSA.getOID()))
        {
          decodedPublicKey = new RSAPublicKey(encodedPublicKey);
        }
        else if (publicKeyAlgorithmOID.equals(
             PublicKeyAlgorithmIdentifier.EC.getOID()))
        {
          decodedPublicKey = new EllipticCurvePublicKey(encodedPublicKey);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      final MessageDigest sha256 = CryptoHelper.getMessageDigest(
           SubjectKeyIdentifierExtension.
                SUBJECT_KEY_IDENTIFIER_DIGEST_ALGORITHM);
      subjectKeyIdentifier = sha256.digest(encodedPublicKey.getBytes());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_GEN_CANNOT_PARSE_KEY_PAIR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Construct the set of all extensions for the certificate.
    final ArrayList<X509CertificateExtension> extensionList =
         new ArrayList<>(10);
    extensionList.add(new SubjectKeyIdentifierExtension(false,
         new ASN1OctetString(subjectKeyIdentifier)));
    if (extensions != null)
    {
      for (final X509CertificateExtension e : extensions)
      {
        if (! e.getOID().equals(SubjectKeyIdentifierExtension.
             SUBJECT_KEY_IDENTIFIER_OID))
        {
          extensionList.add(e);
        }
      }
    }

    final X509CertificateExtension[] allExtensions =
         new X509CertificateExtension[extensionList.size()];
    extensionList.toArray(allExtensions);


    final ASN1BitString encodedSignature = generateSignature(signatureAlgorithm,
         keyPair.getPrivate(), subjectDN, publicKeyAlgorithmOID,
         publicKeyAlgorithmParameters, encodedPublicKey, allExtensions);

    return new PKCS10CertificateSigningRequest(
         PKCS10CertificateSigningRequestVersion.V1, signatureAlgorithm.getOID(),
         null, encodedSignature, subjectDN, publicKeyAlgorithmOID,
         publicKeyAlgorithmParameters, encodedPublicKey, decodedPublicKey,
         null, allExtensions);
  }



  /**
   * Generates a signature for the certificate signing request with the provided
   * information.
   *
   * @param  signatureAlgorithm            The signature algorithm to use to
   *                                       generate the signature.  This must
   *                                       not be {@code null}.
   * @param  privateKey                    The private key to use to sign the
   *                                       certificate signing request.  This
   *                                       must not be {@code null}.
   * @param  subjectDN                     The subject DN for the certificate
   *                                       signing request.  This must not be
   *                                       {@code null}.
   * @param  publicKeyAlgorithmOID         The OID for the public key algorithm.
   *                                       This must not be {@code null}.
   * @param  publicKeyAlgorithmParameters  The encoded public key algorithm
   *                                       parameters.  This may be
   *                                       {@code null} if no parameters are
   *                                       needed.
   * @param  encodedPublicKey              The encoded representation of the
   *                                       public key.  This must not be
   *                                       {@code null}.
   * @param  extensions                    The set of extensions to include in
   *                                       the certificate signing request.
   *                                       This must not be {@code null} but
   *                                       may be empty.
   *
   * @return  An encoded representation of the generated signature.
   *
   * @throws  CertException  If a problem is encountered while generating the
   *                         certificate.
   */
  @NotNull()
  private static ASN1BitString generateSignature(
               @NotNull final SignatureAlgorithmIdentifier signatureAlgorithm,
               @NotNull final PrivateKey privateKey,
               @NotNull final DN subjectDN,
               @NotNull final OID publicKeyAlgorithmOID,
               @Nullable final ASN1Element publicKeyAlgorithmParameters,
               @NotNull final ASN1BitString encodedPublicKey,
               @NotNull final X509CertificateExtension... extensions)
          throws CertException
  {
    // Get and initialize the signature generator.
    final Signature signature;
    try
    {
      signature = CryptoHelper.getSignature(signatureAlgorithm.getJavaName());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_GEN_SIGNATURE_CANNOT_GET_SIGNATURE_GENERATOR.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      signature.initSign(privateKey);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_GEN_SIGNATURE_CANNOT_INIT_SIGNATURE_GENERATOR.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Construct the requestInfo element of the certificate signing request and
    // compute its signature.
    try
    {
      final ArrayList<ASN1Element> requestInfoElements = new ArrayList<>(4);
      requestInfoElements.add(new ASN1Integer(
           PKCS10CertificateSigningRequestVersion.V1.getIntValue()));
      requestInfoElements.add(X509Certificate.encodeName(subjectDN));

      if (publicKeyAlgorithmParameters == null)
      {
        requestInfoElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID)),
             encodedPublicKey));
      }
      else
      {
        requestInfoElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID),
                  publicKeyAlgorithmParameters),
             encodedPublicKey));
      }

      final ArrayList<ASN1Element> attrElements = new ArrayList<>(1);
      if ((extensions != null) && (extensions.length > 0))
      {
        final ArrayList<ASN1Element> extensionElements =
             new ArrayList<>(extensions.length);
        for (final X509CertificateExtension e : extensions)
        {
          extensionElements.add(e.encode());
        }

        attrElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(ATTRIBUTE_OID_EXTENSIONS),
             new ASN1Set(new ASN1Sequence(extensionElements))));
      }
      requestInfoElements.add(new ASN1Set(TYPE_ATTRIBUTES, attrElements));

      final byte[] certificationRequestInfoBytes =
           new ASN1Sequence(requestInfoElements).encode();
      signature.update(certificationRequestInfoBytes);
      final byte[] signatureBytes = signature.sign();

      return new ASN1BitString(ASN1BitString.getBitsForBytes(signatureBytes));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_GEN_SIGNATURE_CANNOT_COMPUTE.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the bytes that comprise the encoded representation of this
   * PKCS #10 certificate signing request.
   *
   * @return  The bytes that comprise the encoded representation of this
   *          PKCS #10 certificate signing request.
   */
  @NotNull()
  public byte[] getPKCS10CertificateSigningRequestBytes()
  {
    return pkcs10CertificateSigningRequestBytes;
  }



  /**
   * Retrieves the certificate signing request version.
   *
   * @return  The certificate signing request version.
   */
  @NotNull()
  public PKCS10CertificateSigningRequestVersion getVersion()
  {
    return version;
  }



  /**
   * Retrieves the certificate signing request signature algorithm OID.
   *
   * @return  The certificate signing request signature algorithm OID.
   */
  @NotNull()
  public OID getSignatureAlgorithmOID()
  {
    return signatureAlgorithmOID;
  }



  /**
   * Retrieves the certificate signing request signature algorithm name, if
   * available.
   *
   * @return  The certificate signing request signature algorithm name, or
   *          {@code null} if the signature algorithm OID does not correspond to
   *          any known algorithm name.
   */
  @Nullable()
  public String getSignatureAlgorithmName()
  {
    return signatureAlgorithmName;
  }



  /**
   * Retrieves the signature algorithm name if it is available, or the string
   * representation of the signature algorithm OID if not.
   *
   * @return  The signature algorithm name or OID.
   */
  @NotNull()
  public String getSignatureAlgorithmNameOrOID()
  {
    if (signatureAlgorithmName != null)
    {
      return signatureAlgorithmName;
    }
    else
    {
      return signatureAlgorithmOID.toString();
    }
  }



  /**
   * Retrieves the encoded signature algorithm parameters, if present.
   *
   * @return  The encoded signature algorithm parameters, or {@code null} if
   *          there are no signature algorithm parameters.
   */
  @Nullable()
  public ASN1Element getSignatureAlgorithmParameters()
  {
    return signatureAlgorithmParameters;
  }



  /**
   * Retrieves the certificate signing request subject DN.
   *
   * @return  The certificate signing request subject DN.
   */
  @NotNull()
  public DN getSubjectDN()
  {
    return subjectDN;
  }



  /**
   * Retrieves the certificate signing request public key algorithm OID.
   *
   * @return  The certificate signing request public key algorithm OID.
   */
  @NotNull()
  public OID getPublicKeyAlgorithmOID()
  {
    return publicKeyAlgorithmOID;
  }



  /**
   * Retrieves the certificate signing request public key algorithm name, if
   * available.
   *
   * @return  The certificate signing request public key algorithm name, or
   *          {@code null} if the public key algorithm OID does not correspond
   *          to any known algorithm name.
   */
  @Nullable()
  public String getPublicKeyAlgorithmName()
  {
    return publicKeyAlgorithmName;
  }



  /**
   * Retrieves the public key algorithm name if it is available, or the string
   * representation of the public key algorithm OID if not.
   *
   * @return  The signature algorithm name or OID.
   */
  @NotNull()
  public String getPublicKeyAlgorithmNameOrOID()
  {
    if (publicKeyAlgorithmName != null)
    {
      return publicKeyAlgorithmName;
    }
    else
    {
      return publicKeyAlgorithmOID.toString();
    }
  }



  /**
   * Retrieves the encoded public key algorithm parameters, if present.
   *
   * @return  The encoded public key algorithm parameters, or {@code null} if
   *          there are no public key algorithm parameters.
   */
  @Nullable()
  public ASN1Element getPublicKeyAlgorithmParameters()
  {
    return publicKeyAlgorithmParameters;
  }



  /**
   * Retrieves the encoded public key as a bit string.
   *
   * @return  The encoded public key as a bit string.
   */
  @NotNull()
  public ASN1BitString getEncodedPublicKey()
  {
    return encodedPublicKey;
  }



  /**
   * Retrieves a decoded representation of the public key, if available.
   *
   * @return  A decoded representation of the public key, or {@code null} if the
   *          public key could not be decoded.
   */
  @Nullable()
  public DecodedPublicKey getDecodedPublicKey()
  {
    return decodedPublicKey;
  }



  /**
   * Retrieves the encoded request attributes included in the certificate
   * signing request.
   *
   * @return  The encoded request attributes included in the certificate signing
   *          request.
   */
  @NotNull()
  public List<ObjectPair<OID,ASN1Set>> getRequestAttributes()
  {
    return requestAttributes;
  }



  /**
   * Retrieves the list of certificate extensions included in the certificate
   * signing request.
   *
   * @return  The list of certificate extensions included in the certificate
   *          signing request.
   */
  @NotNull()
  public List<X509CertificateExtension> getExtensions()
  {
    return extensions;
  }



  /**
   * Retrieves the signature value for the certificate signing request.
   *
   * @return  The signature value for the certificate signing request.
   */
  @NotNull()
  public ASN1BitString getSignatureValue()
  {
    return signatureValue;
  }



  /**
   * Verifies the signature for this certificate signing request.
   *
   * @throws  CertException  If the certificate signing request's signature
   *                         could not be verified.
   */
  public void verifySignature()
         throws CertException
  {
    // Generate the public key for this certificate signing request.
    final PublicKey publicKey;
    try
    {
      final byte[] encodedPublicKeyBytes;
      if (publicKeyAlgorithmParameters == null)
      {
        encodedPublicKeyBytes = new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID)),
             encodedPublicKey).encode();
      }
      else
      {
        encodedPublicKeyBytes = new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID),
                  publicKeyAlgorithmParameters),
             encodedPublicKey).encode();
      }

      final KeyFactory keyFactory =
           CryptoHelper.getKeyFactory(getPublicKeyAlgorithmNameOrOID());
      publicKey = keyFactory.generatePublic(
           new X509EncodedKeySpec(encodedPublicKeyBytes));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_VERIFY_SIGNATURE_CANNOT_GET_PUBLIC_KEY.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Get and initialize the signature generator.
    final Signature signature;
    final SignatureAlgorithmIdentifier signatureAlgorithm;
    try
    {
      signatureAlgorithm =
           SignatureAlgorithmIdentifier.forOID(signatureAlgorithmOID);
      signature = CryptoHelper.getSignature(signatureAlgorithm.getJavaName());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_VERIFY_SIGNATURE_CANNOT_GET_SIGNATURE_VERIFIER.get(
                getSignatureAlgorithmNameOrOID(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      signature.initVerify(publicKey);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_VERIFY_SIGNATURE_CANNOT_INIT_SIGNATURE_VERIFIER.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Construct the requestInfo element of the certificate signing request and
    // compute its signature.
    final boolean signatureIsValid;
    try
    {
      final ASN1Element[] requestInfoElements =
           ASN1Sequence.decodeAsSequence(
                pkcs10CertificateSigningRequestBytes).elements();
      final byte[] requestInfoBytes = requestInfoElements[0].encode();
      signature.update(requestInfoBytes);
      signatureIsValid = signature.verify(signatureValue.getBytes());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CSR_VERIFY_SIGNATURE_ERROR.get(subjectDN,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (! signatureIsValid)
    {
      throw new CertException(
           ERR_CSR_VERIFY_SIGNATURE_NOT_VALID.get(subjectDN));
    }
  }



  /**
   * Retrieves a string representation of the decoded X.509 certificate.
   *
   * @return  A string representation of the decoded X.509 certificate.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the decoded X.509 certificate to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PKCS10CertificateSigningRequest(version='");
    buffer.append(version.getName());
    buffer.append("', subjectDN='");
    buffer.append(subjectDN);
    buffer.append("', publicKeyAlgorithmOID='");
    buffer.append(publicKeyAlgorithmOID.toString());
    buffer.append('\'');

    if (publicKeyAlgorithmName != null)
    {
      buffer.append(", publicKeyAlgorithmName='");
      buffer.append(publicKeyAlgorithmName);
      buffer.append('\'');
    }

    buffer.append(", subjectPublicKey=");
    if (decodedPublicKey == null)
    {
      buffer.append('\'');

      try
      {
        StaticUtils.toHex(encodedPublicKey.getBytes(), ":", buffer);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        encodedPublicKey.toString(buffer);
      }

      buffer.append('\'');
    }
    else
    {
      decodedPublicKey.toString(buffer);

      if (decodedPublicKey instanceof EllipticCurvePublicKey)
      {
        try
        {
          final OID namedCurveOID =
               publicKeyAlgorithmParameters.decodeAsObjectIdentifier().getOID();
          buffer.append(", ellipticCurvePublicKeyParameters=namedCurve='");
          buffer.append(NamedCurve.getNameOrOID(namedCurveOID));
          buffer.append('\'');
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    buffer.append(", signatureAlgorithmOID='");
    buffer.append(signatureAlgorithmOID.toString());
    buffer.append('\'');

    if (signatureAlgorithmName != null)
    {
      buffer.append(", signatureAlgorithmName='");
      buffer.append(signatureAlgorithmName);
      buffer.append('\'');
    }

    if (! extensions.isEmpty())
    {
      buffer.append(", extensions={");

      final Iterator<X509CertificateExtension> iterator = extensions.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(", signatureValue='");

    try
    {
      StaticUtils.toHex(signatureValue.getBytes(), ":", buffer);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      buffer.append(signatureValue.toString());
    }

    buffer.append("')");
  }



  /**
   * Retrieves a list of the lines that comprise a PEM representation of this
   * PKCS #10 certificate signing request.
   *
   * @return  A list of the lines that comprise a PEM representation of this
   *          PKCS #10 certificate signing request.
   */
  @NotNull()
  public List<String> toPEM()
  {
    final ArrayList<String> lines = new ArrayList<>(10);
    lines.add("-----BEGIN CERTIFICATE REQUEST-----");

    final String csrBase64 =
         Base64.encode(pkcs10CertificateSigningRequestBytes);
    lines.addAll(StaticUtils.wrapLine(csrBase64, 64));

    lines.add("-----END CERTIFICATE REQUEST-----");

    return Collections.unmodifiableList(lines);
  }



  /**
   * Retrieves a multi-line string containing a PEM representation of this
   * PKCS #10 certificate signing request.
   *
   * @return  A multi-line string containing a PEM representation of this
   *          PKCS #10 certificate signing request.
   */
  @NotNull()
  public String toPEMString()
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("-----BEGIN CERTIFICATE REQUEST-----");
    buffer.append(StaticUtils.EOL);

    final String csrBase64 =
         Base64.encode(pkcs10CertificateSigningRequestBytes);
    for (final String line : StaticUtils.wrapLine(csrBase64, 64))
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }
    buffer.append("-----END CERTIFICATE REQUEST-----");
    buffer.append(StaticUtils.EOL);

    return buffer.toString();
  }
}
