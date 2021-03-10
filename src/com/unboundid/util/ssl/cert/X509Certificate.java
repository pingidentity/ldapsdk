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



import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1GeneralizedTime;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.asn1.ASN1UTCTime;
import com.unboundid.asn1.ASN1UTF8String;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides support for decoding an X.509 certificate as defined in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A>.  The certificate
 * is encoded using the ASN.1 Distinguished Encoding Rules (DER), which is a
 * subset of BER, and is supported by the code in the
 * {@code com.unboundid.asn1} package.  The ASN.1 specification is as follows:
 * <PRE>
 *   Certificate  ::=  SEQUENCE  {
 *        tbsCertificate       TBSCertificate,
 *        signatureAlgorithm   AlgorithmIdentifier,
 *        signatureValue       BIT STRING  }
 *
 *   TBSCertificate  ::=  SEQUENCE  {
 *        version         [0]  EXPLICIT Version DEFAULT v1,
 *        serialNumber         CertificateSerialNumber,
 *        signature            AlgorithmIdentifier,
 *        issuer               Name,
 *        validity             Validity,
 *        subject              Name,
 *        subjectPublicKeyInfo SubjectPublicKeyInfo,
 *        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                             -- If present, version MUST be v2 or v3
 *        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                             -- If present, version MUST be v2 or v3
 *        extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                             -- If present, version MUST be v3
 *        }
 *
 *   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 *
 *   CertificateSerialNumber  ::=  INTEGER
 *
 *   Validity ::= SEQUENCE {
 *        notBefore      Time,
 *        notAfter       Time }
 *
 *   Time ::= CHOICE {
 *        utcTime        UTCTime,
 *        generalTime    GeneralizedTime }
 *
 *   UniqueIdentifier  ::=  BIT STRING
 *
 *   SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *        algorithm            AlgorithmIdentifier,
 *        subjectPublicKey     BIT STRING  }
 *
 *   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 *   Extension  ::=  SEQUENCE  {
 *        extnID      OBJECT IDENTIFIER,
 *        critical    BOOLEAN DEFAULT FALSE,
 *        extnValue   OCTET STRING
 *                    -- contains the DER encoding of an ASN.1 value
 *                    -- corresponding to the extension type identified
 *                    -- by extnID
 *        }
 *
 *   AlgorithmIdentifier  ::=  SEQUENCE  {
 *        algorithm               OBJECT IDENTIFIER,
 *        parameters              ANY DEFINED BY algorithm OPTIONAL  }
 *
 *   Name ::= CHOICE { -- only one possibility for now --
 *     rdnSequence  RDNSequence }
 *
 *   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *   RelativeDistinguishedName ::=
 *     SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *   AttributeTypeAndValue ::= SEQUENCE {
 *     type     AttributeType,
 *     value    AttributeValue }
 *
 *   AttributeType ::= OBJECT IDENTIFIER
 *
 *   AttributeValue ::= ANY -- DEFINED BY AttributeType
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class X509Certificate
       implements Serializable
{
  /**
   * The DER type for the version number element, which is explicitly typed.
   */
  private static final byte TYPE_EXPLICIT_VERSION = (byte) 0xA0;



  /**
   * The DER type for the issuer unique ID element, which is implicitly typed.
   */
  private static final byte TYPE_IMPLICIT_ISSUER_UNIQUE_ID = (byte) 0x81;



  /**
   * The DER type for the subject unique ID element, which is implicitly typed.
   */
  private static final byte TYPE_IMPLICIT_SUBJECT_UNIQUE_ID = (byte) 0x82;



  /**
   * The DER type for the extensions element, which is explicitly typed.
   */
  private static final byte TYPE_EXPLICIT_EXTENSIONS = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4680448103099282243L;



  // The issuer unique identifier for the certificate.
  @Nullable private final ASN1BitString issuerUniqueID;

  // The signature value for the certificate.
  @NotNull private final ASN1BitString signatureValue;

  // The encoded certificate public key.
  @NotNull private final ASN1BitString encodedPublicKey;

  // The subject unique identifier for the certificate.
  @Nullable private final ASN1BitString subjectUniqueID;

  // The ASN.1 element with the encoded public key algorithm parameters.
  @Nullable private final ASN1Element publicKeyAlgorithmParameters;

  // The ASN.1 element with the encoded signature algorithm parameters.
  @Nullable private final ASN1Element signatureAlgorithmParameters;

  // The certificate serial number.
  @NotNull private final BigInteger serialNumber;

  // The bytes that comprise the encoded representation of the X.509
  // certificate.
  @NotNull private final byte[] x509CertificateBytes;

  // The decoded public key for this certificate, if available.
  @Nullable private final DecodedPublicKey decodedPublicKey;

  // The issuer DN for the certificate.
  @NotNull private final DN issuerDN;

  // The subject DN for the certificate.
  @NotNull private final DN subjectDN;

  // The list of extensions for the certificate.
  @NotNull private final List<X509CertificateExtension> extensions;

  // The time that indicates the end of the certificate validity window.
  private final long notAfter;

  // The time that indicates the beginning of the certificate validity window.
  private final long notBefore;

  // The OID for the public key algorithm.
  @NotNull private final OID publicKeyAlgorithmOID;

  // The OID for the signature algorithm.
  @NotNull private final OID signatureAlgorithmOID;

  // The public key algorithm name that corresponds with the public key
  // algorithm OID, if available.
  @Nullable private final String publicKeyAlgorithmName;

  // The signature algorithm name that corresponds with the signature algorithm
  // OID, if available.
  @Nullable private final String signatureAlgorithmName;

  // The X.509 certificate version.
  @NotNull private final X509CertificateVersion version;



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
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate.
   */
  X509Certificate(@NotNull final X509CertificateVersion version,
                  @NotNull final BigInteger serialNumber,
                  @NotNull final OID signatureAlgorithmOID,
                  @Nullable final ASN1Element signatureAlgorithmParameters,
                  @NotNull final ASN1BitString signatureValue,
                  @NotNull final DN issuerDN, final long notBefore,
                  final long notAfter,
                  @NotNull final DN subjectDN,
                  @NotNull final OID publicKeyAlgorithmOID,
                  @Nullable final ASN1Element publicKeyAlgorithmParameters,
                  @NotNull final ASN1BitString encodedPublicKey,
                  @Nullable final DecodedPublicKey decodedPublicKey,
                  @Nullable final ASN1BitString issuerUniqueID,
                  @Nullable final ASN1BitString subjectUniqueID,
                  @NotNull final X509CertificateExtension... extensions)
       throws CertException
  {
    this.version = version;
    this.serialNumber = serialNumber;
    this.signatureAlgorithmOID = signatureAlgorithmOID;
    this.signatureAlgorithmParameters = signatureAlgorithmParameters;
    this.signatureValue = signatureValue;
    this.issuerDN = issuerDN;
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    this.subjectDN = subjectDN;
    this.publicKeyAlgorithmOID = publicKeyAlgorithmOID;
    this.publicKeyAlgorithmParameters = publicKeyAlgorithmParameters;
    this.encodedPublicKey = encodedPublicKey;
    this.decodedPublicKey = decodedPublicKey;
    this.issuerUniqueID = issuerUniqueID;
    this.subjectUniqueID = subjectUniqueID;
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

    x509CertificateBytes = encode().encode();
  }



  /**
   * Decodes the contents of the provided byte array as an X.509 certificate.
   *
   * @param  encodedCertificate  The byte array containing the encoded X.509
   *                             certificate.  This must not be {@code null}.
   *
   * @throws  CertException  If the contents of the provided byte array could
   *                         not be decoded as a valid X.509 certificate.
   */
  public X509Certificate(@NotNull final byte[] encodedCertificate)
         throws CertException
  {
    x509CertificateBytes = encodedCertificate;

    final ASN1Element[] certificateElements;
    try
    {
      certificateElements =
           ASN1Sequence.decodeAsSequence(encodedCertificate).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_NOT_SEQUENCE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (certificateElements.length != 3)
    {
      throw new CertException(
           ERR_CERT_DECODE_UNEXPECTED_SEQUENCE_ELEMENT_COUNT.get(
                certificateElements.length));
    }

    final ASN1Element[] tbsCertificateElements;
    try
    {
      tbsCertificateElements =
           ASN1Sequence.decodeAsSequence(certificateElements[0]).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_FIRST_ELEMENT_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    int tbsCertificateElementIndex;
    try
    {
      // The version element may or may not be present in a certificate.  If it
      // is present, then it will be explicitly tagged, which means that it's a
      // constructed element with the DER-encoded integer inside it.  If it is
      // absent, then a default version of v1 will be used.
      if ((tbsCertificateElements[0].getType() & 0xFF) == 0xA0)
      {
        final int versionIntValue = ASN1Integer.decodeAsInteger(
             tbsCertificateElements[0].getValue()).intValue();
        version = X509CertificateVersion.valueOf(versionIntValue);
        if (version == null)
        {
          throw new CertException(
               ERR_CERT_DECODE_UNSUPPORTED_VERSION.get(version));
        }

        tbsCertificateElementIndex = 1;
      }
      else
      {
        version = X509CertificateVersion.V1;
        tbsCertificateElementIndex = 0;
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
           ERR_CERT_DECODE_CANNOT_PARSE_VERSION.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      serialNumber = tbsCertificateElements[tbsCertificateElementIndex++].
           decodeAsBigInteger().getBigIntegerValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_CANNOT_PARSE_SERIAL_NUMBER.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final ASN1Element[] signatureAlgorithmElements =
           tbsCertificateElements[tbsCertificateElementIndex++].
                decodeAsSequence().elements();
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
           ERR_CERT_DECODE_CANNOT_PARSE_SIG_ALG.get(
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
      issuerDN =
           decodeName(tbsCertificateElements[tbsCertificateElementIndex++]);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_CANNOT_PARSE_ISSUER_DN.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final ASN1Element[] validityElements =
           tbsCertificateElements[tbsCertificateElementIndex++].
                decodeAsSequence().elements();
      switch (validityElements[0].getType())
      {
        case ASN1Constants.UNIVERSAL_UTC_TIME_TYPE:
          notBefore = decodeUTCTime(validityElements[0]);
          break;
        case ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE:
          notBefore = validityElements[0].decodeAsGeneralizedTime().getTime();
          break;
        default:
          throw new CertException(
               ERR_CERT_DECODE_NOT_BEFORE_UNEXPECTED_TYPE.get(
                    StaticUtils.toHex(validityElements[0].getType()),
                    StaticUtils.toHex(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE),
                    StaticUtils.toHex(ASN1Constants.
                         UNIVERSAL_GENERALIZED_TIME_TYPE)));
      }

      switch (validityElements[1].getType())
      {
        case ASN1Constants.UNIVERSAL_UTC_TIME_TYPE:
          notAfter = decodeUTCTime(validityElements[1]);
          break;
        case ASN1Constants.UNIVERSAL_GENERALIZED_TIME_TYPE:
          notAfter = validityElements[1].decodeAsGeneralizedTime().getTime();
          break;
        default:
          throw new CertException(
               ERR_CERT_DECODE_NOT_AFTER_UNEXPECTED_TYPE.get(
                    StaticUtils.toHex(validityElements[0].getType()),
                    StaticUtils.toHex(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE),
                    StaticUtils.toHex(ASN1Constants.
                         UNIVERSAL_GENERALIZED_TIME_TYPE)));
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
           ERR_CERT_DECODE_COULD_NOT_PARSE_VALIDITY.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      subjectDN =
           decodeName(tbsCertificateElements[tbsCertificateElementIndex++]);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_CANNOT_PARSE_SUBJECT_DN.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final ASN1Element[] subjectPublicKeyInfoElements =
           tbsCertificateElements[tbsCertificateElementIndex++].
                decodeAsSequence().elements();
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
           ERR_CERT_DECODE_CANNOT_PARSE_PUBLIC_KEY_INFO.get(
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

    ASN1BitString issuerID = null;
    ASN1BitString subjectID = null;
    final ArrayList<X509CertificateExtension> extList = new ArrayList<>(10);
    for (;
         tbsCertificateElementIndex < tbsCertificateElements.length;
         tbsCertificateElementIndex++)
    {
      switch (tbsCertificateElements[tbsCertificateElementIndex].getType())
      {
        case (byte) 0x81:
          try
          {
            issuerID = tbsCertificateElements[tbsCertificateElementIndex].
                 decodeAsBitString();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_CERT_DECODE_CANNOT_PARSE_ISSUER_UNIQUE_ID.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;
        case (byte) 0x82:
          try
          {
            subjectID = tbsCertificateElements[tbsCertificateElementIndex].
                 decodeAsBitString();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_CERT_DECODE_CANNOT_PARSE_SUBJECT_UNIQUE_ID.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;
        case (byte) 0xA3:
          try
          {
            // This element is explicitly tagged.
            final ASN1Element[] extensionElements = ASN1Sequence.
                 decodeAsSequence(tbsCertificateElements[
                      tbsCertificateElementIndex].getValue()).elements();
            for (final ASN1Element extensionElement : extensionElements)
            {
              extList.add(X509CertificateExtension.decode(extensionElement));
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_CERT_DECODE_CANNOT_PARSE_EXTENSION.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;
      }
    }

    issuerUniqueID = issuerID;
    subjectUniqueID = subjectID;
    extensions = Collections.unmodifiableList(extList);

    try
    {
      final ASN1Element[] signatureAlgorithmElements =
           certificateElements[1].decodeAsSequence().elements();
      final OID oid =
           signatureAlgorithmElements[0].decodeAsObjectIdentifier().getOID();
      if (! oid.equals(signatureAlgorithmOID))
      {
        throw new CertException(
             ERR_CERT_DECODE_SIG_ALG_MISMATCH.get(
                  signatureAlgorithmOID.toString(), oid.toString()));
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
           ERR_CERT_DECODE_CANNOT_PARSE_SIG_ALG.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      signatureValue = certificateElements[2].decodeAsBitString();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_CANNOT_PARSE_SIG_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Decodes the provided ASN.1 element as an X.509 name.
   *
   * @param  element  The ASN.1 element to decode.
   *
   * @return  The DN created from the decoded X.509 name.
   *
   * @throws  CertException  If a problem is encountered while trying to decode
   *                         the X.509 name.
   */
  @NotNull()
  static DN decodeName(@NotNull final ASN1Element element)
         throws CertException
  {
    Schema schema;
    try
    {
      schema = Schema.getDefaultStandardSchema();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      schema = null;
    }

    final ASN1Element[] rdnElements;
    try
    {
      rdnElements = ASN1Sequence.decodeAsSequence(element).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_DECODE_NAME_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final ArrayList<RDN> rdns = new ArrayList<>(rdnElements.length);
    for (int i=0; i < rdnElements.length; i++)
    {
      try
      {
        final ASN1Element[] attributeSetElements =
             rdnElements[i].decodeAsSet().elements();
        final String[] attributeNames = new String[attributeSetElements.length];
        final byte[][] attributeValues =
             new byte[attributeSetElements.length][];
        for (int j=0; j < attributeSetElements.length; j++)
        {
          final ASN1Element[] attributeTypeAndValueElements =
               ASN1Sequence.decodeAsSequence(attributeSetElements[j]).
                    elements();

          final OID attributeTypeOID = attributeTypeAndValueElements[0].
               decodeAsObjectIdentifier().getOID();
          final AttributeTypeDefinition attributeType =
               schema.getAttributeType(attributeTypeOID.toString());
          if (attributeType == null)
          {
            attributeNames[j] = attributeTypeOID.toString();
          }
          else
          {
            attributeNames[j] = attributeType.getNameOrOID().toUpperCase();
          }

          attributeValues[j] = attributeTypeAndValueElements[1].
               decodeAsOctetString().getValue();
        }

        rdns.add(new RDN(attributeNames, attributeValues, schema));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new CertException(
             ERR_CERT_DECODE_CANNOT_PARSE_NAME_SEQUENCE_ELEMENT.get(i,
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    Collections.reverse(rdns);
    return new DN(rdns);
  }



  /**
   * Decodes the provided ASN.1 element as a UTC time element and retrieves the
   * corresponding time.  As per the X.509 specification, the resulting value
   * will be guaranteed to fall between the years 1950 and 2049.
   *
   * @param  element  The ASN.1 element to decode as a UTC time value.
   *
   * @return  The decoded time value.
   *
   * @throws  ASN1Exception  If the provided element cannot be decoded as a UTC
   *                         time element.
   */
  private static long decodeUTCTime(@NotNull final ASN1Element element)
          throws ASN1Exception
  {
    final long timeValue = ASN1UTCTime.decodeAsUTCTime(element).getTime();

    final GregorianCalendar calendar = new GregorianCalendar();
    calendar.setTimeInMillis(timeValue);

    final int year = calendar.get(Calendar.YEAR);
    if (year < 1949)
    {
      calendar.set(Calendar.YEAR, (year + 100));
    }
    else if (year > 2050)
    {
      calendar.set(Calendar.YEAR, (year - 100));
    }

    return calendar.getTimeInMillis();
  }



  /**
   * Encodes this X.509 certificate to an ASN.1 element.
   *
   * @return  The encoded X.509 certificate.
   *
   * @throws  CertException  If a problem is encountered while trying to encode
   *                         the X.509 certificate.
   */
  @NotNull()
  ASN1Element encode()
       throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> tbsCertificateElements = new ArrayList<>(10);

      if (version != X509CertificateVersion.V1)
      {
        tbsCertificateElements.add(new ASN1Element(TYPE_EXPLICIT_VERSION,
             new ASN1Integer(version.getIntValue()).encode()));
      }

      tbsCertificateElements.add(new ASN1BigInteger(serialNumber));

      if (signatureAlgorithmParameters == null)
      {
        tbsCertificateElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(signatureAlgorithmOID)));
      }
      else
      {
        tbsCertificateElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(signatureAlgorithmOID),
             signatureAlgorithmParameters));
      }


      tbsCertificateElements.add(encodeName(issuerDN));
      tbsCertificateElements.add(encodeValiditySequence(notBefore, notAfter));
      tbsCertificateElements.add(encodeName(subjectDN));

      if (publicKeyAlgorithmParameters == null)
      {
        tbsCertificateElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID)),
             encodedPublicKey));
      }
      else
      {
        tbsCertificateElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID),
                  publicKeyAlgorithmParameters),
             encodedPublicKey));
      }

      if (issuerUniqueID != null)
      {
        tbsCertificateElements.add(new ASN1BitString(
             TYPE_IMPLICIT_ISSUER_UNIQUE_ID, issuerUniqueID.getBits()));
      }

      if (subjectUniqueID != null)
      {
        tbsCertificateElements.add(new ASN1BitString(
             TYPE_IMPLICIT_SUBJECT_UNIQUE_ID, subjectUniqueID.getBits()));
      }

      if (! extensions.isEmpty())
      {
        final ArrayList<ASN1Element> extensionElements =
             new ArrayList<>(extensions.size());
        for (final X509CertificateExtension e : extensions)
        {
          extensionElements.add(e.encode());
        }
        tbsCertificateElements.add(new ASN1Element(TYPE_EXPLICIT_EXTENSIONS,
             new ASN1Sequence(extensionElements).encode()));
      }

      final ArrayList<ASN1Element> certificateElements = new ArrayList<>(3);
      certificateElements.add(new ASN1Sequence(tbsCertificateElements));

      if (signatureAlgorithmParameters == null)
      {
        certificateElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(signatureAlgorithmOID)));
      }
      else
      {
        certificateElements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(signatureAlgorithmOID),
             signatureAlgorithmParameters));
      }

      certificateElements.add(signatureValue);

      return new ASN1Sequence(certificateElements);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_ENCODE_ERROR.get(toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided DN as an X.509 name for inclusion in an encoded
   * certificate.
   *
   * @param  dn  The DN to encode.
   *
   * @return  The encoded X.509 name.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         provided DN as an X.509 name.
   */
  @NotNull()
  static ASN1Element encodeName(@NotNull final DN dn)
         throws CertException
  {
    final Schema schema;
    try
    {
      schema = Schema.getDefaultStandardSchema();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_ENCODE_NAME_CANNOT_GET_SCHEMA.get(String.valueOf(dn),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final RDN[] rdns = dn.getRDNs();
    final ArrayList<ASN1Element> rdnSequenceElements =
         new ArrayList<>(rdns.length);
    for (int i=rdns.length - 1; i >= 0; i--)
    {
      final RDN rdn =rdns[i];
      final String[] names = rdn.getAttributeNames();
      final String[] values = rdn.getAttributeValues();

      final ArrayList<ASN1Element> rdnElements = new ArrayList<>(names.length);
      for (int j=0; j < names.length; j++)
      {
        final AttributeTypeDefinition at = schema.getAttributeType(names[j]);
        if (at == null)
        {
          throw new CertException(ERR_CERT_ENCODE_NAME_UNKNOWN_ATTR_TYPE.get(
               String.valueOf(dn), names[j]));
        }

        try
        {
          rdnElements.add(new ASN1Sequence(
               new ASN1ObjectIdentifier(at.getOID()),
               new ASN1UTF8String(values[j])));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new CertException(
               ERR_CERT_ENCODE_NAME_ERROR.get(String.valueOf(dn),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      rdnSequenceElements.add(new ASN1Set(rdnElements));
    }

    return new ASN1Sequence(rdnSequenceElements);
  }



  /**
   * Encodes the certificate validity sequence, using a UTC time encoding if
   * both notBefore and notAfter values fall within the range 1950-2049, and
   * using generalized time if either value falls outside that range.
   *
   * @param  notBefore  The notBefore value to include in the sequence.
   * @param  notAfter   The notAfter value to include in the sequence.
   *
   * @return  The encoded validity sequence.
   */
  @NotNull()
  static ASN1Sequence encodeValiditySequence(final long notBefore,
                                             final long notAfter)
  {
    final GregorianCalendar notBeforeCalendar = new GregorianCalendar();
    notBeforeCalendar.setTimeInMillis(notBefore);
    final int notBeforeYear = notBeforeCalendar.get(Calendar.YEAR);

    final GregorianCalendar notAfterCalendar = new GregorianCalendar();
    notAfterCalendar.setTimeInMillis(notAfter);
    final int notAfterYear = notAfterCalendar.get(Calendar.YEAR);

    if ((notBeforeYear >= 1950) && (notBeforeYear <= 2049) &&
        (notAfterYear >= 1950) && (notAfterYear <= 2049))
    {
      return new ASN1Sequence(
           new ASN1UTCTime(notBefore),
           new ASN1UTCTime(notAfter));
    }
    else
    {
      return new ASN1Sequence(
           new ASN1GeneralizedTime(notBefore),
           new ASN1GeneralizedTime(notAfter));
    }
  }



  /**
   * Generates a self-signed X.509 certificate with the provided information.
   *
   * @param  signatureAlgorithm  The algorithm to use to generate the signature.
   *                             This must not be {@code null}.
   * @param  publicKeyAlgorithm  The algorithm to use to generate the key pair.
   *                             This must not be {@code null}.
   * @param  keySizeBits         The size of the key to generate, in bits.
   * @param  subjectDN           The subject DN for the certificate.  This must
   *                             not be {@code null}.
   * @param  notBefore           The validity start time for the certificate.
   * @param  notAfter            The validity end time for the certificate.
   * @param  extensions          The set of extensions to include in the
   *                             certificate.  This may be {@code null} or empty
   *                             if the certificate should not include any
   *                             custom extensions.  Note that the generated
   *                             certificate will automatically include a
   *                             {@link SubjectKeyIdentifierExtension}, so that
   *                             should not be provided.
   *
   * @return  An {@code ObjectPair} that contains both the self-signed
   *          certificate and its corresponding key pair.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate.
   */
  @NotNull()
  public static ObjectPair<X509Certificate,KeyPair>
                     generateSelfSignedCertificate(
              @NotNull final SignatureAlgorithmIdentifier signatureAlgorithm,
              @NotNull final PublicKeyAlgorithmIdentifier publicKeyAlgorithm,
              final int keySizeBits,
              @NotNull final DN subjectDN,
              final long notBefore, final long notAfter,
              @Nullable final X509CertificateExtension... extensions)
         throws CertException
  {
    // Generate the key pair for the certificate.
    final KeyPairGenerator keyPairGenerator;
    try
    {
      keyPairGenerator =
           CryptoHelper.getKeyPairGenerator(publicKeyAlgorithm.getName());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_GEN_SELF_SIGNED_CANNOT_GET_KEY_GENERATOR.get(
                publicKeyAlgorithm.getName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      keyPairGenerator.initialize(keySizeBits);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_GEN_SELF_SIGNED_INVALID_KEY_SIZE.get(keySizeBits,
                publicKeyAlgorithm.getName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final KeyPair keyPair;
    try
    {
      keyPair = keyPairGenerator.generateKeyPair();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_GEN_SELF_SIGNED_CANNOT_GENERATE_KEY_PAIR.get(
                keySizeBits, publicKeyAlgorithm.getName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Generate the certificate and return it along with the key pair.
    final X509Certificate certificate = generateSelfSignedCertificate(
         signatureAlgorithm, keyPair, subjectDN, notBefore, notAfter,
         extensions);
    return new ObjectPair<>(certificate, keyPair);
  }



  /**
   * Generates a self-signed X.509 certificate with the provided information.
   *
   * @param  signatureAlgorithm  The algorithm to use to generate the signature.
   *                             This must not be {@code null}.
   * @param  keyPair             The key pair for the certificate.  This must
   *                             not be {@code null}.
   * @param  subjectDN           The subject DN for the certificate.  This must
   *                             not be {@code null}.
   * @param  notBefore           The validity start time for the certificate.
   * @param  notAfter            The validity end time for the certificate.
   * @param  extensions          The set of extensions to include in the
   *                             certificate.  This may be {@code null} or empty
   *                             if the certificate should not include any
   *                             custom extensions.  Note that the generated
   *                             certificate will automatically include a
   *                             {@link SubjectKeyIdentifierExtension}, so that
   *                             should not be provided.
   *
   * @return  An {@code ObjectPair} that contains both the self-signed
   *          certificate and its corresponding key pair.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate.
   */
  @NotNull()
  public static X509Certificate generateSelfSignedCertificate(
              @NotNull final SignatureAlgorithmIdentifier signatureAlgorithm,
              @NotNull final KeyPair keyPair, @NotNull final DN subjectDN,
              final long notBefore, final long notAfter,
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
           ERR_CERT_GEN_SELF_SIGNED_CANNOT_PARSE_KEY_PAIR.get(
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


    // Encode the tbsCertificate sequence for the certificate and use it to
    // generate the certificate's signature.
    final BigInteger serialNumber = generateSerialNumber();
    final ASN1BitString encodedSignature = generateSignature(signatureAlgorithm,
         keyPair.getPrivate(), serialNumber, subjectDN, notBefore, notAfter,
         subjectDN, publicKeyAlgorithmOID, publicKeyAlgorithmParameters,
         encodedPublicKey, allExtensions);


    // Construct and return the signed certificate and the private key.
    return new X509Certificate(X509CertificateVersion.V3, serialNumber,
         signatureAlgorithm.getOID(), null, encodedSignature, subjectDN,
         notBefore, notAfter, subjectDN, publicKeyAlgorithmOID,
         publicKeyAlgorithmParameters, encodedPublicKey, decodedPublicKey, null,
         null, allExtensions);
  }



  /**
   * Generates an issuer-signed X.509 certificate with the provided information.
   *
   * @param  signatureAlgorithm
   *              The algorithm to use to generate the signature.  This must not
   *              be {@code null}.
   * @param  issuerCertificate
   *              The certificate for the issuer.  This must not be
   *              {@code null}.
   * @param  issuerPrivateKey
   *              The private key for the issuer.  This  must not be
   *              {@code null}.
   * @param  publicKeyAlgorithmOID
   *              The OID for the certificate's public key algorithm.  This must
   *              not be {@code null}.
   * @param  publicKeyAlgorithmParameters
   *              The encoded public key algorithm parameters for the
   *              certificate.  This may be {@code null} if there are no
   *              parameters.
   * @param  encodedPublicKey
   *              The encoded public key for the certificate.  This must not be
   *              {@code null}.
   * @param  decodedPublicKey
   *              The decoded public key for the certificate.  This may be
   *              {@code null} if it is not available.
   * @param  subjectDN
   *              The subject DN for the certificate.  This must not be
   *              {@code null}.
   * @param  notBefore
   *              The validity start time for the certificate.
   * @param  notAfter
   *              The validity end time for the certificate.
   * @param  extensions
   *              The set of extensions to include in the certificate.  This
   *              may be {@code null} or empty if the certificate should not
   *              include any custom extensions.  Note that the generated
   *              certificate will automatically include a
   *              {@link SubjectKeyIdentifierExtension}, so that should not be
   *              provided.  In addition, if the issuer certificate includes its
   *              own {@code SubjectKeyIdentifierExtension}, then its value will
   *              be used to generate an
   *              {@link AuthorityKeyIdentifierExtension}.
   *
   * @return  The issuer-signed certificate.
   *
   * @throws  CertException  If a problem is encountered while creating the
   *                         certificate.
   */
  @NotNull()
  public static X509Certificate generateIssuerSignedCertificate(
              @NotNull final SignatureAlgorithmIdentifier signatureAlgorithm,
              @NotNull final X509Certificate issuerCertificate,
              @NotNull final PrivateKey issuerPrivateKey,
              @NotNull final OID publicKeyAlgorithmOID,
              @Nullable final ASN1Element publicKeyAlgorithmParameters,
              @NotNull final ASN1BitString encodedPublicKey,
              @Nullable final DecodedPublicKey decodedPublicKey,
              @NotNull final DN subjectDN,
              final long notBefore, final long notAfter,
              @NotNull final X509CertificateExtension... extensions)
         throws CertException
  {
    // Generate a subject key identifier from the encoded public key.
    final byte[] subjectKeyIdentifier;
    try
    {
      final MessageDigest sha256 = CryptoHelper.getMessageDigest(
           SubjectKeyIdentifierExtension.
                SUBJECT_KEY_IDENTIFIER_DIGEST_ALGORITHM);
      subjectKeyIdentifier = sha256.digest(encodedPublicKey.getBytes());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_GEN_ISSUER_SIGNED_CANNOT_GENERATE_KEY_ID.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // If the issuer certificate contains a subject key identifier, then
    // extract it to use as the authority key identifier.
    ASN1OctetString authorityKeyIdentifier = null;
    for (final X509CertificateExtension e : issuerCertificate.extensions)
    {
      if (e instanceof SubjectKeyIdentifierExtension)
      {
        authorityKeyIdentifier =
             ((SubjectKeyIdentifierExtension) e).getKeyIdentifier();
      }
    }


    // Construct the set of all extensions for the certificate.
    final ArrayList<X509CertificateExtension> extensionList =
         new ArrayList<>(10);
    extensionList.add(new SubjectKeyIdentifierExtension(false,
         new ASN1OctetString(subjectKeyIdentifier)));

    if (authorityKeyIdentifier == null)
    {
      extensionList.add(new AuthorityKeyIdentifierExtension(false, null,
           new GeneralNamesBuilder().addDirectoryName(
                issuerCertificate.subjectDN).build(),
           issuerCertificate.serialNumber));
    }
    else
    {
      extensionList.add(new AuthorityKeyIdentifierExtension(false,
           authorityKeyIdentifier, null, null));
    }

    if (extensions != null)
    {
      for (final X509CertificateExtension e : extensions)
      {
        if (e.getOID().equals(
             SubjectKeyIdentifierExtension.SUBJECT_KEY_IDENTIFIER_OID) ||
            e.getOID().equals(
                 AuthorityKeyIdentifierExtension.AUTHORITY_KEY_IDENTIFIER_OID))
        {
          continue;
        }

        extensionList.add(e);
      }
    }

    final X509CertificateExtension[] allExtensions =
         new X509CertificateExtension[extensionList.size()];
    extensionList.toArray(allExtensions);


    // Encode the tbsCertificate sequence for the certificate and use it to
    // generate the certificate's signature.
    final BigInteger serialNumber = generateSerialNumber();
    final ASN1BitString encodedSignature = generateSignature(signatureAlgorithm,
         issuerPrivateKey, serialNumber, issuerCertificate.subjectDN, notBefore,
         notAfter, subjectDN, publicKeyAlgorithmOID,
         publicKeyAlgorithmParameters, encodedPublicKey, allExtensions);


    // Construct and return the signed certificate.
    return new X509Certificate(X509CertificateVersion.V3, serialNumber,
         signatureAlgorithm.getOID(), null, encodedSignature,
         issuerCertificate.subjectDN, notBefore, notAfter, subjectDN,
         publicKeyAlgorithmOID, publicKeyAlgorithmParameters, encodedPublicKey,
         decodedPublicKey, null, null, allExtensions);
  }



  /**
   * Generates a serial number for the certificate.
   *
   * @return  The generated serial number.
   */
  @NotNull()
  private static BigInteger generateSerialNumber()
  {
    final UUID uuid = UUID.randomUUID();
    final long msb = uuid.getMostSignificantBits() & 0x7FFF_FFFF_FFFF_FFFFL;
    final long lsb = uuid.getLeastSignificantBits() & 0x7FFF_FFFF_FFFF_FFFFL;
    return BigInteger.valueOf(msb).shiftLeft(64).add(BigInteger.valueOf(lsb));
  }



  /**
   * Generates a signature for the certificate with the provided information.
   *
   * @param  signatureAlgorithm            The signature algorithm to use to
   *                                       generate the signature.  This must
   *                                       not be {@code null}.
   * @param  privateKey                    The private key to use to sign the
   *                                       certificate.  This must not be
   *                                       {@code null}.
   * @param  serialNumber                  The serial number for the
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
   *                                       the certificate.  This must not be
   *                                       {@code null} but may be empty.
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
               @NotNull final BigInteger serialNumber,
               @NotNull final DN issuerDN, final long notBefore,
               final long notAfter, @NotNull final DN subjectDN,
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
           ERR_CERT_GEN_SIGNATURE_CANNOT_GET_SIGNATURE_GENERATOR.get(
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
           ERR_CERT_GEN_SIGNATURE_CANNOT_INIT_SIGNATURE_GENERATOR.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Construct the tbsCertificate element of the certificate and compute its
    // signature.
    try
    {
      final ArrayList<ASN1Element> tbsCertificateElements = new ArrayList<>(8);
      tbsCertificateElements.add(new ASN1Element(TYPE_EXPLICIT_VERSION,
           new ASN1Integer(X509CertificateVersion.V3.getIntValue()).encode()));
      tbsCertificateElements.add(new ASN1BigInteger(serialNumber));
      tbsCertificateElements.add(new ASN1Sequence(
           new ASN1ObjectIdentifier(signatureAlgorithm.getOID())));
      tbsCertificateElements.add(encodeName(issuerDN));
      tbsCertificateElements.add(encodeValiditySequence(notBefore, notAfter));
      tbsCertificateElements.add(encodeName(subjectDN));

      if (publicKeyAlgorithmParameters == null)
      {
        tbsCertificateElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID)),
             encodedPublicKey));
      }
      else
      {
        tbsCertificateElements.add(new ASN1Sequence(
             new ASN1Sequence(
                  new ASN1ObjectIdentifier(publicKeyAlgorithmOID),
                  publicKeyAlgorithmParameters),
             encodedPublicKey));
      }

      final ArrayList<ASN1Element> extensionElements =
           new ArrayList<>(extensions.length);
      for (final X509CertificateExtension e : extensions)
      {
        extensionElements.add(e.encode());
      }
      tbsCertificateElements.add(new ASN1Element(TYPE_EXPLICIT_EXTENSIONS,
           new ASN1Sequence(extensionElements).encode()));

      final byte[] tbsCertificateBytes =
           new ASN1Sequence(tbsCertificateElements).encode();
      signature.update(tbsCertificateBytes);
      final byte[] signatureBytes = signature.sign();

      return new ASN1BitString(ASN1BitString.getBitsForBytes(signatureBytes));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_GEN_SIGNATURE_CANNOT_COMPUTE.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the bytes that comprise the encoded representation of this X.509
   * certificate.
   *
   * @return  The bytes that comprise the encoded representation of this X.509
   *          certificate.
   */
  @NotNull()
  public byte[] getX509CertificateBytes()
  {
    return x509CertificateBytes;
  }



  /**
   * Retrieves the certificate version.
   *
   * @return  The certificate version.
   */
  @NotNull()
  public X509CertificateVersion getVersion()
  {
    return version;
  }



  /**
   * Retrieves the certificate serial number.
   *
   * @return  The certificate serial number.
   */
  @NotNull()
  public BigInteger getSerialNumber()
  {
    return serialNumber;
  }



  /**
   * Retrieves the certificate signature algorithm OID.
   *
   * @return  The certificate signature algorithm OID.
   */
  @NotNull()
  public OID getSignatureAlgorithmOID()
  {
    return signatureAlgorithmOID;
  }



  /**
   * Retrieves the certificate signature algorithm name, if available.
   *
   * @return  The certificate signature algorithm name, or {@code null} if the
   *          signature algorithm OID does not correspond to any known algorithm
   *          name.
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
   * Retrieves the certificate issuer DN.
   *
   * @return  The certificate issuer DN.
   */
  @NotNull()
  public DN getIssuerDN()
  {
    return issuerDN;
  }



  /**
   * Retrieves the certificate validity start time as the number of milliseconds
   * since the epoch (January 1, 1970 UTC).
   *
   * @return  The certificate validity start time as the number of milliseconds
   *          since the epoch.
   */
  public long getNotBeforeTime()
  {
    return notBefore;
  }



  /**
   * Retrieves the certificate validity start time as a {@code Date}.
   *
   * @return  The certificate validity start time as a {@code Date}.
   */
  @NotNull()
  public Date getNotBeforeDate()
  {
    return new Date(notBefore);
  }



  /**
   * Retrieves the certificate validity end time as the number of milliseconds
   * since the epoch (January 1, 1970 UTC).
   *
   * @return  The certificate validity end time as the number of milliseconds
   *          since the epoch.
   */
  public long getNotAfterTime()
  {
    return notAfter;
  }



  /**
   * Retrieves the certificate validity end time as a {@code Date}.
   *
   * @return  The certificate validity end time as a {@code Date}.
   */
  @NotNull()
  public Date getNotAfterDate()
  {
    return new Date(notAfter);
  }



  /**
   * Indicates whether the current time is within the certificate's validity
   * window.
   *
   * @return  {@code true} if the current time is within the certificate's
   *          validity window, or {@code false} if not.
   */
  public boolean isWithinValidityWindow()
  {
    return isWithinValidityWindow(System.currentTimeMillis());
  }



  /**
   * Indicates whether the provided {@code Date} represents a time within the
   * certificate's validity window.
   *
   * @param  date  The {@code Date} for which to make the determination.  It
   *               must not be {@code null}.
   *
   * @return  {@code true} if the provided {@code Date} is within the
   *          certificate's validity window, or {@code false} if not.
   */
  public boolean isWithinValidityWindow(@NotNull final Date date)
  {
    return isWithinValidityWindow(date.getTime());
  }



  /**
   * Indicates whether the specified time is within the certificate's validity
   * window.
   *
   * @param  time  The time to for which to make the determination.
   *
   * @return  {@code true} if the specified time is within the certificate's
   *          validity window, or {@code false} if not.
   */
  public boolean isWithinValidityWindow(final long time)
  {
    return ((time >= notBefore) && (time <= notAfter));
  }



  /**
   * Retrieves the certificate subject DN.
   *
   * @return  The certificate subject DN.
   */
  @NotNull()
  public DN getSubjectDN()
  {
    return subjectDN;
  }



  /**
   * Retrieves the certificate public key algorithm OID.
   *
   * @return  The certificate public key algorithm OID.
   */
  @NotNull()
  public OID getPublicKeyAlgorithmOID()
  {
    return publicKeyAlgorithmOID;
  }



  /**
   * Retrieves the certificate public key algorithm name, if available.
   *
   * @return  The certificate public key algorithm name, or {@code null} if the
   *          public key algorithm OID does not correspond to any known
   *          algorithm name.
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
   * Retrieves the issuer unique identifier for the certificate, if any.
   *
   * @return  The issuer unique identifier for the certificate, or {@code null}
   *          if there is none.
   */
  @Nullable()
  public ASN1BitString getIssuerUniqueID()
  {
    return issuerUniqueID;
  }



  /**
   * Retrieves the subject unique identifier for the certificate, if any.
   *
   * @return  The subject unique identifier for the certificate, or {@code null}
   *          if there is none.
   */
  @Nullable()
  public ASN1BitString getSubjectUniqueID()
  {
    return subjectUniqueID;
  }



  /**
   * Retrieves the list of certificate extensions.
   *
   * @return  The list of certificate extensions.
   */
  @NotNull()
  public List<X509CertificateExtension> getExtensions()
  {
    return extensions;
  }



  /**
   * Retrieves the signature value for the certificate.
   *
   * @return  The signature value for the certificate.
   */
  @NotNull()
  public ASN1BitString getSignatureValue()
  {
    return signatureValue;
  }



  /**
   * Verifies the signature for this certificate.
   *
   * @param  issuerCertificate  The issuer certificate for this certificate.  It
   *                            may be {@code null} if this is a self-signed
   *                            certificate.  It must not be {@code null} if it
   *                            is not a self-signed certificate.
   *
   * @throws  CertException  If the certificate signature could not be verified.
   */
  public void verifySignature(@Nullable final X509Certificate issuerCertificate)
         throws CertException
  {
    // Get the issuer certificate.  If the certificate is self-signed, then it
    // might be the current certificate.
    final X509Certificate issuer;
    if (issuerCertificate == null)
    {
      if (isSelfSigned())
      {
        issuer = this;
      }
      else
      {
        throw new CertException(
             ERR_CERT_VERIFY_SIGNATURE_ISSUER_CERT_NOT_PROVIDED.get());
      }
    }
    else
    {
      issuer = issuerCertificate;
    }


    // Get the public key from the issuer certificate.
    final PublicKey publicKey;
    try
    {
      publicKey = issuer.toCertificate().getPublicKey();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_VERIFY_SIGNATURE_CANNOT_GET_PUBLIC_KEY.get(
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
           ERR_CERT_VERIFY_SIGNATURE_CANNOT_GET_SIGNATURE_VERIFIER.get(
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
           ERR_CERT_VERIFY_SIGNATURE_CANNOT_INIT_SIGNATURE_VERIFIER.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Construct the tbsCertificate element of the certificate and compute its
    // signature.
    try
    {
      final ASN1Element[] x509CertificateElements =
           ASN1Sequence.decodeAsSequence(x509CertificateBytes).elements();
      final byte[] tbsCertificateBytes = x509CertificateElements[0].encode();
      signature.update(tbsCertificateBytes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_GEN_SIGNATURE_CANNOT_COMPUTE.get(
                signatureAlgorithm.getJavaName(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    try
    {
      if (! signature.verify(signatureValue.getBytes()))
      {
        throw new CertException(
             ERR_CERT_VERIFY_SIGNATURE_NOT_VALID.get(subjectDN));
      }
    }
    catch (final CertException ce)
    {
      Debug.debugException(ce);
      throw ce;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_VERIFY_SIGNATURE_ERROR.get(subjectDN,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the bytes that comprise a SHA-1 fingerprint of this certificate.
   *
   * @return  The bytes that comprise a SHA-1 fingerprint of this certificate.
   *
   * @throws  CertException  If a problem is encountered while computing the
   *                         fingerprint.
   */
  @NotNull()
  public byte[] getSHA1Fingerprint()
         throws CertException
  {
    return getFingerprint("SHA-1");
  }



  /**
   * Retrieves the bytes that comprise a 256-bit SHA-2 fingerprint of this
   * certificate.
   *
   * @return  The bytes that comprise a 256-bit SHA-2 fingerprint of this
   *          certificate.
   *
   * @throws  CertException  If a problem is encountered while computing the
   *                         fingerprint.
   */
  @NotNull()
  public byte[] getSHA256Fingerprint()
         throws CertException
  {
    return getFingerprint("SHA-256");
  }



  /**
   * Retrieves the bytes that comprise a fingerprint of this certificate.
   *
   * @param  digestAlgorithm  The digest algorithm to use to generate the
   *                          fingerprint.
   *
   * @return  The bytes that comprise a fingerprint of this certificate.
   *
   * @throws  CertException  If a problem is encountered while computing the
   *                         fingerprint.
   */
  @NotNull()
  private byte[] getFingerprint(@NotNull final String digestAlgorithm)
          throws CertException
  {
    try
    {
      final MessageDigest digest =
           CryptoHelper.getMessageDigest(digestAlgorithm);
      return digest.digest(x509CertificateBytes);
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      throw new CertException(
           ERR_CERT_CANNOT_COMPUTE_FINGERPRINT.get(digestAlgorithm,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Indicates whether this certificate is self-signed.  The following criteria
   * will be used to make the determination:
   * <OL>
   *   <LI>
   *     If the certificate has both subject key identifier and authority
   *     key identifier extensions, then it will be considered self-signed if
   *     and only if the subject key identifier matches the authority key
   *     identifier.
   *   </LI>
   *   <LI>
   *     If the certificate does not have both a subject key identifier and an
   *     authority key identifier, then it will be considered self-signed if and
   *     only if its subject DN matches its issuer DN.
   *   </LI>
   * </OL>
   *
   * @return  {@code true} if this certificate is self-signed, or {@code false}
   *          if it is not.
   */
  public boolean isSelfSigned()
  {
    AuthorityKeyIdentifierExtension akie = null;
    SubjectKeyIdentifierExtension skie = null;
    for (final X509CertificateExtension e : extensions)
    {
      if (e instanceof AuthorityKeyIdentifierExtension)
      {
        akie = (AuthorityKeyIdentifierExtension) e;
      }
      else if (e instanceof SubjectKeyIdentifierExtension)
      {
        skie = (SubjectKeyIdentifierExtension) e;
      }
    }

    if ((akie != null) && (skie != null))
    {
      return ((akie.getKeyIdentifier() != null) &&
           Arrays.equals(akie.getKeyIdentifier().getValue(),
                skie.getKeyIdentifier().getValue()));
    }
    else
    {
      return subjectDN.equals(issuerDN);
    }
  }



  /**
   * Indicates whether this certificate is the issuer for the provided
   * certificate.  In order for this to be true, the following conditions must
   * be met:
   * <OL>
   *   <LI>
   *     The subject DN of this certificate must match the issuer DN for the
   *     provided certificate.
   *   </LI>
   *   <LI>
   *     If the provided certificate has an authority key identifier extension,
   *     then this certificate must have a subject key identifier extension with
   *     a matching identifier value.
   *   </LI>
   * </OL>
   *
   * @param  c  The certificate for which to make the determination.  This must
   *            not be {@code null}.
   *
   * @return  {@code true} if this certificate is considered the issuer for the
   *          provided certificate, or {@code } false if not.
   */
  public boolean isIssuerFor(@NotNull final X509Certificate c)
  {
    return isIssuerFor(c, null);
  }



  /**
   * Indicates whether this certificate is the issuer for the provided
   * certificate.  In order for this to be true, the following conditions must
   * be met:
   * <OL>
   *   <LI>
   *     The subject DN of this certificate must match the issuer DN for the
   *     provided certificate.
   *   </LI>
   *   <LI>
   *     If the provided certificate has an authority key identifier extension,
   *     then this certificate must have a subject key identifier extension with
   *     a matching identifier value.
   *   </LI>
   * </OL>
   *
   * @param  c               The certificate for which to make the
   *                         determination.  This must not be {@code null}.
   * @param  nonMatchReason  An optional buffer that may be updated with the
   *                         reason that this certificate is not considered the
   *                         issuer for the provided certificate.  This may be
   *                         {@code null} if the caller does not require a
   *                         reason.
   *
   * @return  {@code true} if this certificate is considered the issuer for the
   *          provided certificate, or {@code } false if not.
   */
  public boolean isIssuerFor(@NotNull final X509Certificate c,
                             @Nullable final StringBuilder nonMatchReason)
  {
    if (! c.issuerDN.equals(subjectDN))
    {
      if (nonMatchReason != null)
      {
        nonMatchReason.append(INFO_CERT_IS_ISSUER_FOR_DN_MISMATCH.get(
             subjectDN, c.subjectDN, issuerDN));
      }

      return false;
    }


    byte[] authorityKeyIdentifier = null;
    for (final X509CertificateExtension extension : c.extensions)
    {
      if (extension instanceof AuthorityKeyIdentifierExtension)
      {
        final AuthorityKeyIdentifierExtension akie =
             (AuthorityKeyIdentifierExtension) extension;
        if (akie.getKeyIdentifier() != null)
        {
          authorityKeyIdentifier = akie.getKeyIdentifier().getValue();
          break;
        }
      }
    }

    if (authorityKeyIdentifier != null)
    {
      boolean matchFound = false;
      for (final X509CertificateExtension extension : extensions)
      {
        if (extension instanceof SubjectKeyIdentifierExtension)
        {
          final SubjectKeyIdentifierExtension skie =
               (SubjectKeyIdentifierExtension) extension;
          matchFound = Arrays.equals(authorityKeyIdentifier,
               skie.getKeyIdentifier().getValue());
          break;
        }
      }

      if (! matchFound)
      {
        if (nonMatchReason != null)
        {
          nonMatchReason.append(INFO_CERT_IS_ISSUER_FOR_KEY_ID_MISMATCH.get(
               subjectDN, c.subjectDN));
        }

        return false;
      }
    }


    return true;
  }



  /**
   * Converts this X.509 certificate object to a Java {@code Certificate}
   * object.
   *
   * @return  The Java {@code Certificate} object that corresponds to this
   *          X.509 certificate.
   *
   * @throws  CertificateException  If a problem is encountered while performing
   *                                the conversion.
   */
  @NotNull()
  public Certificate toCertificate()
         throws CertificateException
  {
    return CryptoHelper.getCertificateFactory("X.509").generateCertificate(
         new ByteArrayInputStream(x509CertificateBytes));
  }



  /**
   * Retrieves a hash code for this certificate.
   *
   * @return  A hash code for this certificate.
   */
  @Override()
  public int hashCode()
  {
    return Arrays.hashCode(x509CertificateBytes);
  }



  /**
   * Indicates whether the provided object is considered equal to this X.509
   * certificate.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          X.509 certificate, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof X509Certificate))
    {
      return false;
    }

    final X509Certificate c = (X509Certificate) o;
    return Arrays.equals(x509CertificateBytes, c.x509CertificateBytes);
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
    buffer.append("X509Certificate(version='");
    buffer.append(version.getName());
    buffer.append("', serialNumber='");
    StaticUtils.toHex(serialNumber.toByteArray(), ":", buffer);
    buffer.append("', signatureAlgorithmOID='");
    buffer.append(signatureAlgorithmOID.toString());
    buffer.append('\'');

    if (signatureAlgorithmName != null)
    {
      buffer.append(", signatureAlgorithmName='");
      buffer.append(signatureAlgorithmName);
      buffer.append('\'');
    }

    buffer.append(", issuerDN='");
    buffer.append(issuerDN.toString());
    buffer.append("', notBefore='");
    buffer.append(StaticUtils.encodeGeneralizedTime(notBefore));
    buffer.append("', notAfter='");
    buffer.append(StaticUtils.encodeGeneralizedTime(notAfter));
    buffer.append("', subjectDN='");
    buffer.append(subjectDN.toString());
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

    if (issuerUniqueID != null)
    {
      buffer.append(", issuerUniqueID='");
      buffer.append(issuerUniqueID.toString());
      buffer.append('\'');
    }

    if (subjectUniqueID != null)
    {
      buffer.append(", subjectUniqueID='");
      buffer.append(subjectUniqueID.toString());
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
   * X.509 certificate.
   *
   * @return  A list of the lines that comprise a PEM representation of this
   *          X.509 certificate.
   */
  @NotNull()
  public List<String> toPEM()
  {
    final ArrayList<String> lines = new ArrayList<>(10);
    lines.add("-----BEGIN CERTIFICATE-----");

    final String certBase64 = Base64.encode(x509CertificateBytes);
    lines.addAll(StaticUtils.wrapLine(certBase64, 64));

    lines.add("-----END CERTIFICATE-----");

    return Collections.unmodifiableList(lines);
  }



  /**
   * Retrieves a multi-line string containing a PEM representation of this X.509
   * certificate.
   *
   * @return  A multi-line string containing a PEM representation of this X.509
   *          certificate.
   */
  @NotNull()
  public String toPEMString()
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("-----BEGIN CERTIFICATE-----");
    buffer.append(StaticUtils.EOL);

    final String certBase64 = Base64.encode(x509CertificateBytes);
    for (final String line : StaticUtils.wrapLine(certBase64, 64))
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }
    buffer.append("-----END CERTIFICATE-----");
    buffer.append(StaticUtils.EOL);

    return buffer.toString();
  }
}
