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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.Base64;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides support for decoding an X.509 private key encoded in the
 * PKCS #8 format as defined in
 * <A HREF="https://www.ietf.org/rfc/rfc5958.txt">RFC 5958</A>.  The private key
 * is encoded using the ASN.1 Distinguished Encoding Rules (DER), which is a
 * subset of BER, and is supported by the code in the
 * {@code com.unboundid.asn1} package.  The ASN.1 specification is as follows:
 * <PRE>
 *   OneAsymmetricKey ::= SEQUENCE {
 *     version                   Version,
 *     privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
 *     privateKey                PrivateKey,
 *     attributes            [0] Attributes OPTIONAL,
 *     ...,
 *     [[2: publicKey        [1] PublicKey OPTIONAL ]],
 *     ...
 *   }
 *
 *   PrivateKeyInfo ::= OneAsymmetricKey
 *
 *   -- PrivateKeyInfo is used by [P12]. If any items tagged as version
 *   -- 2 are used, the version must be v2, else the version should be
 *   -- v1. When v1, PrivateKeyInfo is the same as it was in [RFC5208].
 *
 *   Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
 *
 *   PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
 *                                      { PUBLIC-KEY,
 *                                        { PrivateKeyAlgorithms } }
 *
 *   PrivateKey ::= OCTET STRING
 *                     -- Content varies based on type of key. The
 *                     -- algorithm identifier dictates the format of
 *                     -- the key.
 *
 *   PublicKey ::= BIT STRING
 *                     -- Content varies based on type of key. The
 *                     -- algorithm identifier dictates the format of
 *                     -- the key.
 *
 *   Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
 *
 *   OneAsymmetricKeyAttributes ATTRIBUTE ::= {
 *     ... -- For local profiles
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PKCS8PrivateKey
       implements Serializable
{
  /**
   * The DER type for the attributes element of the private key.
   */
  private static final byte TYPE_ATTRIBUTES = (byte) 0xA0;



  /**
   * The DER type for the public key element of the private key.
   */
  private static final byte TYPE_PUBLIC_KEY = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5551171525811450486L;



  // The corresponding public key, if available.
  @Nullable private final ASN1BitString publicKey;

  // The ASN.1 element with the encoded set of attributes.
  @Nullable private final ASN1Element attributesElement;

  // The ASN.1 element with the encoded private key algorithm parameters.
  @Nullable private final ASN1Element privateKeyAlgorithmParameters;

  // The encoded representation of the private key.
  @NotNull private final ASN1OctetString encodedPrivateKey;

  // The bytes that comprise the encoded representation of the PKCS #8 private
  // key.
  @NotNull private final byte[] pkcs8PrivateKeyBytes;

  // The decoded representation of the private key, if available.
  @Nullable private final DecodedPrivateKey decodedPrivateKey;

  // The OID for the private key algorithm.
  @NotNull private final OID privateKeyAlgorithmOID;

  // The PKCS #8 private key version.
  @NotNull private final PKCS8PrivateKeyVersion version;

  // The private key algorithm name that corresponds with the private key
  // algorithm OID, if available.
  @Nullable private final String privateKeyAlgorithmName;



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
   * @throws  CertException  If a problem is encountered while creating the
   *                         private key.
   */
  PKCS8PrivateKey(@NotNull final PKCS8PrivateKeyVersion version,
                  @NotNull final OID privateKeyAlgorithmOID,
                  @Nullable final ASN1Element privateKeyAlgorithmParameters,
                  @NotNull final ASN1OctetString encodedPrivateKey,
                  @Nullable final DecodedPrivateKey decodedPrivateKey,
                  @Nullable final ASN1Element attributesElement,
                  @Nullable final ASN1BitString publicKey)
       throws CertException
  {
    this.version = version;
    this.privateKeyAlgorithmOID = privateKeyAlgorithmOID;
    this.privateKeyAlgorithmParameters = privateKeyAlgorithmParameters;
    this.encodedPrivateKey = encodedPrivateKey;
    this.decodedPrivateKey = decodedPrivateKey;
    this.attributesElement = attributesElement;
    this.publicKey = publicKey;

    final PublicKeyAlgorithmIdentifier identifier =
         PublicKeyAlgorithmIdentifier.forOID(privateKeyAlgorithmOID);
    if (identifier == null)
    {
      privateKeyAlgorithmName = null;
    }
    else
    {
      privateKeyAlgorithmName = identifier.getName();
    }

    pkcs8PrivateKeyBytes = encode().encode();
  }



  /**
   * Decodes the contents of the provided byte array as a PKCS #8 private key.
   *
   * @param  privateKeyBytes  The byte array containing the encoded PKCS #8
   *                          private key.
   *
   * @throws  CertException  If the contents of the provided byte array could
   *                         not be decoded as a valid PKCS #8 private key.
   */
  public PKCS8PrivateKey(@NotNull final byte[] privateKeyBytes)
         throws CertException
  {
    pkcs8PrivateKeyBytes = privateKeyBytes;

    final ASN1Element[] privateKeyElements;
    try
    {
      privateKeyElements =
           ASN1Sequence.decodeAsSequence(privateKeyBytes).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PRIVATE_KEY_DECODE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (privateKeyElements.length < 3)
    {
      throw new CertException(
           ERR_PRIVATE_KEY_DECODE_NOT_ENOUGH_ELEMENTS.get(
                privateKeyElements.length));
    }

    try
    {
      final int versionIntValue =
           privateKeyElements[0].decodeAsInteger().intValue();
      version = PKCS8PrivateKeyVersion.valueOf(versionIntValue);
      if (version == null)
      {
        throw new CertException(
             ERR_PRIVATE_KEY_DECODE_UNSUPPORTED_VERSION.get(versionIntValue));
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
           ERR_PRIVATE_KEY_DECODE_CANNOT_PARSE_VERSION.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    try
    {
      final ASN1Element[] privateKeyAlgorithmElements =
           privateKeyElements[1].decodeAsSequence().elements();
      privateKeyAlgorithmOID =
           privateKeyAlgorithmElements[0].decodeAsObjectIdentifier().getOID();
      if (privateKeyAlgorithmElements.length > 1)
      {
        privateKeyAlgorithmParameters = privateKeyAlgorithmElements[1];
      }
      else
      {
        privateKeyAlgorithmParameters = null;
      }

      encodedPrivateKey = privateKeyElements[2].decodeAsOctetString();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PRIVATE_KEY_DECODE_CANNOT_PARSE_ALGORITHM.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    final PublicKeyAlgorithmIdentifier privateKeyAlgorithmIdentifier =
         PublicKeyAlgorithmIdentifier.forOID(privateKeyAlgorithmOID);
    if (privateKeyAlgorithmIdentifier == null)
    {
      privateKeyAlgorithmName = null;
      decodedPrivateKey = null;
    }
    else
    {
      privateKeyAlgorithmName = privateKeyAlgorithmIdentifier.getName();

      DecodedPrivateKey pk = null;
      switch (privateKeyAlgorithmIdentifier)
      {
        case RSA:
          try
          {
            pk = new RSAPrivateKey(encodedPrivateKey);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
          break;

        case EC:
          try
          {
            pk = new EllipticCurvePrivateKey(encodedPrivateKey);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
          break;
      }

      decodedPrivateKey = pk;
    }

    ASN1BitString pk = null;
    ASN1Element attrsElement = null;
    for (int i=3; i < privateKeyElements.length; i++)
    {
      final ASN1Element element = privateKeyElements[i];
      switch (element.getType())
      {
        case TYPE_ATTRIBUTES:
          attrsElement = element;
          break;
        case TYPE_PUBLIC_KEY:
          try
          {
            pk = ASN1BitString.decodeAsBitString(element);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new CertException(
                 ERR_PRIVATE_KEY_DECODE_CANNOT_PARSE_PUBLIC_KEY.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
          break;
      }
    }

    attributesElement = attrsElement;
    publicKey = pk;
  }



  /**
   * Wraps the provided RSA private key bytes inside a full PKCS #8 encoded
   * private key.
   *
   * @param  rsaPrivateKeyBytes  The bytes that comprise just the RSA private
   *                             key.
   *
   * @return  The bytes that comprise a PKCS #8 encoded representation of the
   *          provided RSA private key.
   *
   * @throws  CertException  If a problem is encountered while trying to wrap
   *                         the private key.
   */
  @NotNull()
  static byte[] wrapRSAPrivateKey(@NotNull final byte[] rsaPrivateKeyBytes)
         throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> elements = new ArrayList<>(5);
      elements.add(new ASN1Integer(PKCS8PrivateKeyVersion.V1.getIntValue()));
      elements.add(new ASN1Sequence(new ASN1ObjectIdentifier(
           PublicKeyAlgorithmIdentifier.RSA.getOID())));
      elements.add(new ASN1OctetString(rsaPrivateKeyBytes));
      return new ASN1Sequence(elements).encode();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PRIVATE_KEY_WRAP_RSA_KEY_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this PKCS #8 private key to an ASN.1 element.
   *
   * @return  The encoded PKCS #8 private key.
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
      final ArrayList<ASN1Element> elements = new ArrayList<>(5);
      elements.add(new ASN1Integer(version.getIntValue()));

      if (privateKeyAlgorithmParameters == null)
      {
        elements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(privateKeyAlgorithmOID)));
      }
      else
      {
        elements.add(new ASN1Sequence(
             new ASN1ObjectIdentifier(privateKeyAlgorithmOID),
             privateKeyAlgorithmParameters));
      }

      elements.add(encodedPrivateKey);

      if (attributesElement != null)
      {
        elements.add(new ASN1Element(TYPE_ATTRIBUTES,
             attributesElement.getValue()));
      }

      if (publicKey != null)
      {
        elements.add(new ASN1BitString(TYPE_PUBLIC_KEY, publicKey.getBits()));
      }

      return new ASN1Sequence(elements);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PRIVATE_KEY_ENCODE_ERROR.get(toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the bytes that comprise the encoded representation of this
   * PKCS #8 private key.
   *
   * @return  The bytes that comprise the encoded representation of this PKCS #8
   *          private key.
   */
  @NotNull()
  public byte[] getPKCS8PrivateKeyBytes()
  {
    return pkcs8PrivateKeyBytes;
  }



  /**
   * Retrieves the private key version.
   *
   * @return  The private key version.
   */
  @NotNull()
  public PKCS8PrivateKeyVersion getVersion()
  {
    return version;
  }



  /**
   * Retrieves the private key algorithm OID.
   *
   * @return  The private key algorithm OID.
   */
  @NotNull()
  public OID getPrivateKeyAlgorithmOID()
  {
    return privateKeyAlgorithmOID;
  }



  /**
   * Retrieves the private key algorithm name, if available.
   *
   * @return  The private key algorithm name, or {@code null} if private key
   *          algorithm OID is not recognized.
   */
  @Nullable()
  public String getPrivateKeyAlgorithmName()
  {
    return privateKeyAlgorithmName;
  }



  /**
   * Retrieves the private key algorithm name, if available, or a string
   * representation of the OID if the name is not available.
   *
   * @return  The private key algorithm name if it is available, or a string
   *          representation of the private key algorithm OID if it is not.
   */
  @NotNull()
  public String getPrivateKeyAlgorithmNameOrOID()
  {
    if (privateKeyAlgorithmName == null)
    {
      return privateKeyAlgorithmOID.toString();
    }
    else
    {
      return privateKeyAlgorithmName;
    }
  }



  /**
   * Retrieves the encoded private key algorithm parameters, if present.
   *
   * @return  The encoded private key algorithm parameters, or {@code null} if
   *          there are no private key algorithm parameters.
   */
  @Nullable()
  public ASN1Element getPrivateKeyAlgorithmParameters()
  {
    return privateKeyAlgorithmParameters;
  }



  /**
   * Retrieves the encoded private key data.
   *
   * @return  The encoded private key data.
   */
  @NotNull()
  public ASN1OctetString getEncodedPrivateKey()
  {
    return encodedPrivateKey;
  }



  /**
   * Retrieves the decoded private key, if available.
   *
   * @return  The decoded private key, or {@code null} if the decoded key is
   *          not available.
   */
  @Nullable()
  public DecodedPrivateKey getDecodedPrivateKey()
  {
    return decodedPrivateKey;
  }



  /**
   * Retrieves an ASN.1 element containing an encoded set of private key
   * attributes, if available.
   *
   * @return  An ASN.1 element containing an encoded set of private key
   *          attributes, or {@code null} if the private key does not have any
   *          attributes.
   */
  @Nullable()
  public ASN1Element getAttributesElement()
  {
    return attributesElement;
  }



  /**
   * Retrieves the public key included in the private key, if available.
   *
   * @return  The public key included in the private key, or {@code null} if the
   *          private key does not include a public key.
   */
  @Nullable()
  public ASN1BitString getPublicKey()
  {
    return publicKey;
  }



  /**
   * Converts this PKCS #8 private key object to a Java {@code PrivateKey}
   * object.
   *
   * @return  The Java {@code PrivateKey} object that corresponds to this
   *          PKCS #8 private key.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    performing the conversion.
   */
  @NotNull()
  public PrivateKey toPrivateKey()
         throws GeneralSecurityException
  {
    final KeyFactory keyFactory =
         CryptoHelper.getKeyFactory(getPrivateKeyAlgorithmNameOrOID());
    return keyFactory.generatePrivate(
         new PKCS8EncodedKeySpec(pkcs8PrivateKeyBytes));
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
    buffer.append("PKCS8PrivateKey(version='");
    buffer.append(version.getName());
    buffer.append("', privateKeyAlgorithmOID=");
    buffer.append(privateKeyAlgorithmOID.toString());
    buffer.append('\'');

    if (privateKeyAlgorithmName != null)
    {
      buffer.append(", privateKeyAlgorithmName='");
      buffer.append(privateKeyAlgorithmName);
      buffer.append('\'');
    }

    if (decodedPrivateKey == null)
    {
      buffer.append(", encodedPrivateKey='");
      StaticUtils.toHex(encodedPrivateKey.getValue(), ":", buffer);
      buffer.append('\'');
    }
    else
    {
      buffer.append(", decodedPrivateKey=");
      decodedPrivateKey.toString(buffer);


      if (decodedPrivateKey instanceof EllipticCurvePrivateKey)
      {
        try
        {
          final OID namedCurveOID = privateKeyAlgorithmParameters.
               decodeAsObjectIdentifier().getOID();
          buffer.append(", ellipticCurvePrivateKeyParameters=namedCurve='");
          buffer.append(NamedCurve.getNameOrOID(namedCurveOID));
          buffer.append('\'');
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    buffer.append("')");
  }



  /**
   * Retrieves a list of the lines that comprise a PEM representation of this
   * certificate signing request.
   *
   * @return  A list of the lines that comprise a PEM representation of this
   *          certificate signing request.
   */
  @NotNull()
  public List<String> toPEM()
  {
    final ArrayList<String> lines = new ArrayList<>(10);
    lines.add("-----BEGIN PRIVATE KEY-----");

    final String keyBase64 = Base64.encode(pkcs8PrivateKeyBytes);
    lines.addAll(StaticUtils.wrapLine(keyBase64, 64));

    lines.add("-----END PRIVATE KEY-----");

    return Collections.unmodifiableList(lines);
  }



  /**
   * Retrieves a multi-line string containing a PEM representation of this
   * certificate signing request.
   *
   * @return  A multi-line string containing a PEM representation of this
   *          certificate signing request.
   */
  @NotNull()
  public String toPEMString()
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("-----BEGIN PRIVATE KEY-----");
    buffer.append(StaticUtils.EOL);

    final String keyBase64 = Base64.encode(pkcs8PrivateKeyBytes);
    for (final String line : StaticUtils.wrapLine(keyBase64, 64))
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }
    buffer.append("-----END PRIVATE KEY-----");
    buffer.append(StaticUtils.EOL);

    return buffer.toString();
  }
}
