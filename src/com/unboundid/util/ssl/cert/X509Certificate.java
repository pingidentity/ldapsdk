/*
 * Copyright 2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017 Ping Identity Corporation
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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.asn1.ASN1UTCTime;
import com.unboundid.asn1.ASN1UTF8String;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.OID;
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
  private static final long serialVersionUID = 8167230740443252L;



  // The issuer unique identifier for the certificate.
  private final ASN1BitString issuerUniqueID;

  // The signature value for the certificate.
  private final ASN1BitString signatureValue;

  // The encoded certificate public key.
  private final ASN1BitString encodedPublicKey;

  // The subject unique identifier for the certificate.
  private final ASN1BitString subjectUniqueID;

  // The ASN.1 element with the encoded public key algorithm parameters.
  private final ASN1Element publicKeyAlgorithmParameters;

  // The ASN.1 element with the encoded signature algorithm parameters.
  private final ASN1Element signatureAlgorithmParameters;

  // The certificate serial number.
  private final BigInteger serialNumber;

  // The bytes that comprise the encoded representation of the X.509
  // certificate.
  private final byte[] x509CertificateBytes;

  // The decoded public key for this certificate, if available.
  private final DecodedPublicKey decodedPublicKey;

  // The issuer DN for the certificate.
  private final DN issuerDN;

  // The subject DN for the certificate.
  private final DN subjectDN;

  // The list of extensions for the certificate.
  private final List<X509CertificateExtension> extensions;

  // The time that indicates the end of the certificate validity window.
  private final long notAfter;

  // The time that indicates the beginning of the certificate validity window.
  private final long notBefore;

  // The OID for the public key algorithm.
  private final OID publicKeyAlgorithmOID;

  // The OID for the signature algorithm.
  private final OID signatureAlgorithmOID;

  // The public key algorithm name that corresponds with the public key
  // algorithm OID, if available.
  private final String publicKeyAlgorithmName;

  // The signature algorithm name that corresponds with the signature algorithm
  // OID, if available.
  private final String signatureAlgorithmName;

  // The X.509 certificate version.
  private final X509CertificateVersion version;



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
  X509Certificate(final X509CertificateVersion version,
                  final BigInteger serialNumber,
                  final OID signatureAlgorithmOID,
                  final ASN1Element signatureAlgorithmParameters,
                  final ASN1BitString signatureValue,
                  final DN issuerDN, final long notBefore, final long notAfter,
                  final DN subjectDN, final OID publicKeyAlgorithmOID,
                  final ASN1Element publicKeyAlgorithmParameters,
                  final ASN1BitString encodedPublicKey,
                  final DecodedPublicKey decodedPublicKey,
                  final ASN1BitString issuerUniqueID,
                  final ASN1BitString subjectUniqueID,
                  final X509CertificateExtension... extensions)
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
      signatureAlgorithmName = signatureAlgorithmIdentifier.getName();
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
  public X509Certificate(final byte[] encodedCertificate)
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
      signatureAlgorithmName = signatureAlgorithmIdentifier.getName();
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
          notBefore = validityElements[0].decodeAsUTCTime().getTime();
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
          notAfter = validityElements[1].decodeAsUTCTime().getTime();
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
              final ASN1Element[] extElements =
                   extensionElement.decodeAsSequence().elements();
              final OID oid =
                   extElements[0].decodeAsObjectIdentifier().getOID();

              final boolean isCritical;
              final byte[] value;
              if (extElements[1].getType() ==
                   ASN1Constants.UNIVERSAL_BOOLEAN_TYPE)
              {
                isCritical = extElements[1].decodeAsBoolean().booleanValue();
                value = extElements[2].decodeAsOctetString().getValue();
              }
              else
              {
                isCritical = false;
                value = extElements[1].decodeAsOctetString().getValue();
              }

              X509CertificateExtension extension =
                   new X509CertificateExtension(oid, isCritical, value);
              if (oid.equals(AuthorityKeyIdentifierExtension.
                   AUTHORITY_KEY_IDENTIFIER_OID))
              {
                try
                {
                  extension = new AuthorityKeyIdentifierExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(SubjectKeyIdentifierExtension.
                   SUBJECT_KEY_IDENTIFIER_OID))
              {
                try
                {
                  extension = new SubjectKeyIdentifierExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(KeyUsageExtension.KEY_USAGE_OID))
              {
                try
                {
                  extension = new KeyUsageExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(SubjectAlternativeNameExtension.
                   SUBJECT_ALTERNATIVE_NAME_OID))
              {
                try
                {
                  extension = new SubjectAlternativeNameExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(IssuerAlternativeNameExtension.
                   ISSUER_ALTERNATIVE_NAME_OID))
              {
                try
                {
                  extension = new IssuerAlternativeNameExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(BasicConstraintsExtension.
                   BASIC_CONSTRAINTS_OID))
              {
                try
                {
                  extension = new BasicConstraintsExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(ExtendedKeyUsageExtension.
                   EXTENDED_KEY_USAGE_OID))
              {
                try
                {
                  extension = new ExtendedKeyUsageExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }
              else if (oid.equals(CRLDistributionPointsExtension.
                   CRL_DISTRIBUTION_POINTS_OID))
              {
                try
                {
                  extension = new CRLDistributionPointsExtension(extension);
                }
                catch (final Exception e)
                {
                  Debug.debugException(e);
                }
              }

              extList.add(extension);
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
  static DN decodeName(final ASN1Element element)
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
   * Encodes this X.509 certificate to an ASN.1 element.
   *
   * @return  The encoded X.509 certificate.
   *
   * @throws  CertException  If a problem is encountered while trying to encode
   *                         the X.509 certificate.
   */
  ASN1Element encode()
       throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> tbsCertificateElements =
           new ArrayList<ASN1Element>(10);

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
      tbsCertificateElements.add(new ASN1Sequence(
           new ASN1UTCTime(notBefore),
           new ASN1UTCTime(notAfter)));
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
  static ASN1Element encodeName(final DN dn)
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
   * Retrieves the bytes that comprise the encoded representation of this X.509
   * certificate.
   *
   * @return  The bytes that comprise the encoded representation of this X.509
   *          certificate.
   */
  public byte[] getX509CertificateBytes()
  {
    return x509CertificateBytes;
  }



  /**
   * Retrieves the certificate version.
   *
   * @return  The certificate version.
   */
  public X509CertificateVersion getVersion()
  {
    return version;
  }



  /**
   * Retrieves the certificate serial number.
   *
   * @return  The certificate serial number.
   */
  public BigInteger getSerialNumber()
  {
    return serialNumber;
  }



  /**
   * Retrieves the certificate signature algorithm OID.
   *
   * @return  The certificate signature algorithm OID.
   */
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
  public ASN1Element getSignatureAlgorithmParameters()
  {
    return signatureAlgorithmParameters;
  }



  /**
   * Retrieves the certificate issuer DN.
   *
   * @return  The certificate issuer DN.
   */
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
  public Date getNotAfterDate()
  {
    return new Date(notAfter);
  }



  /**
   * Retrieves the certificate subject DN.
   *
   * @return  The certificate subject DN.
   */
  public DN getSubjectDN()
  {
    return subjectDN;
  }



  /**
   * Retrieves the certificate public key algorithm OID.
   *
   * @return  The certificate public key algorithm OID.
   */
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
  public ASN1Element getPublicKeyAlgorithmParameters()
  {
    return publicKeyAlgorithmParameters;
  }



  /**
   * Retrieves the encoded public key as a bit string.
   *
   * @return  The encoded public key as a bit string.
   */
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
  public ASN1BitString getSubjectUniqueID()
  {
    return subjectUniqueID;
  }



  /**
   * Retrieves the list of certificate extensions.
   *
   * @return  The list of certificate extensions.
   */
  public List<X509CertificateExtension> getExtensions()
  {
    return extensions;
  }



  /**
   * Retrieves the signature value for the certificate.
   *
   * @return  The signature value for the certificate.
   */
  public ASN1BitString getSignatureValue()
  {
    return signatureValue;
  }



  /**
   * Retrieves the bytes that comprise a SHA-1 fingerprint of this certificate.
   *
   * @return  The bytes that comprise a SHA-1 fingerprint of this certificate.
   *
   * @throws  CertException  If a problem is encountered while computing the
   *                         fingerprint.
   */
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
  private byte[] getFingerprint(final String digestAlgorithm)
          throws CertException
  {
    try
    {
      final MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
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
   * Retrieves a string representation of the decoded X.509 certificate.
   *
   * @return  A string representation of the decoded X.509 certificate.
   */
  @Override()
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
  public void toString(final StringBuilder buffer)
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
}
