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



import java.util.ArrayList;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
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
 * This class provides a data structure for representing the information
 * contained in an elliptic curve private key.  As per
 * <A HREF="https://www.ietf.org/rfc/rfc5915.txt">RFC 5915</A> section 3,
 * an elliptic curve private key is encoded as follows:
 * <PRE>
 *   ECPrivateKey ::= SEQUENCE {
 *     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *     privateKey     OCTET STRING,
 *     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *     publicKey  [1] BIT STRING OPTIONAL
 *   }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EllipticCurvePrivateKey
       extends DecodedPrivateKey
{
  /**
   * The DER type for the parameters element of the private key sequence.
   */
  private static final byte TYPE_PARAMETERS = (byte) 0xA0;



  /**
   * The DER type for the public key element of the private key sequence.
   */
  private static final byte TYPE_PUBLIC_KEY = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7102211426269543850L;



  // The public key that corresponds to the private key.
  @Nullable private final ASN1BitString publicKey;

  // The bytes that make up the actual private key.
  @NotNull private final byte[] privateKeyBytes;

  // The version number for the private key.
  private final int version;

  // The OID for the named curve.
  @Nullable private final OID namedCurveOID;



  /**
   * Creates a new elliptic curve decoded private key from the provided
   * information.
   *
   * @param  version          The version number for the private key.
   * @param  privateKeyBytes  The bytes that make up the actual private key.
   *                          This must not be {@code null}.
   * @param  namedCurveOID    The OID for the named curve.  This may be
   *                          {@code null} if it is not to be included in the
   *                          private key.
   * @param  publicKey        The encoded public key.  This may be {@code null}
   *                          if it is not to be included in the private key.
   */
  EllipticCurvePrivateKey(final int version,
                          @NotNull final byte[] privateKeyBytes,
                          @Nullable final OID namedCurveOID,
                          @Nullable final ASN1BitString publicKey)
  {
    this.version = version;
    this.privateKeyBytes = privateKeyBytes;
    this.namedCurveOID = namedCurveOID;
    this.publicKey = publicKey;
  }



  /**
   * Creates a new elliptic curve decoded private key from the provided octet
   * string.
   *
   * @param  encodedPrivateKey  The encoded private key to be decoded as an
   *                            elliptic curve private key.
   *
   * @throws  CertException  If the provided private key cannot be decoded as an
   *                         elliptic curve private key.
   */
  EllipticCurvePrivateKey(@NotNull final ASN1OctetString encodedPrivateKey)
       throws CertException
  {
    try
    {
      final ASN1Element[] elements = ASN1Sequence.decodeAsSequence(
           encodedPrivateKey.getValue()).elements();
      version = elements[0].decodeAsInteger().intValue();

      if ((version != 1))
      {
        throw new CertException(
             ERR_EC_PRIVATE_KEY_UNSUPPORTED_VERSION.get(version));
      }

      privateKeyBytes = elements[1].decodeAsOctetString().getValue();

      ASN1BitString pubKey = null;
      OID curveOID = null;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_PARAMETERS:
            curveOID = elements[i].decodeAsObjectIdentifier().getOID();
            break;
          case TYPE_PUBLIC_KEY:
            pubKey = elements[i].decodeAsBitString();
            break;
        }
      }

      namedCurveOID = curveOID;
      publicKey = pubKey;
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
           ERR_EC_PRIVATE_KEY_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes this elliptic curve private key.
   *
   * @return  The encoded representation of this private key.
   *
   * @throws  CertException  If a problem is encountered while encoding this
   *                         private key.
   */
  @NotNull()
  ASN1OctetString encode()
       throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> elements = new ArrayList<>(4);
      elements.add(new ASN1Integer(version));
      elements.add(new ASN1OctetString(privateKeyBytes));

      if (namedCurveOID != null)
      {
        elements.add(new ASN1ObjectIdentifier(TYPE_PARAMETERS, namedCurveOID));
      }

      if (publicKey != null)
      {
        elements.add(new ASN1BitString(TYPE_PUBLIC_KEY, publicKey.getBits()));
      }

      return new ASN1OctetString(new ASN1Sequence(elements).encode());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_EC_PRIVATE_KEY_CANNOT_ENCODE.get(toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the version for the elliptic curve private key.
   *
   * @return  The version for the elliptic curve private key.
   */
  public int getVersion()
  {
    return version;
  }



  /**
   * Retrieves the bytes that make up the actual elliptic curve private key.
   *
   * @return  The bytes that make up the actual elliptic curve private key.
   */
  @NotNull()
  public byte[] getPrivateKeyBytes()
  {
    return privateKeyBytes;
  }



  /**
   * Retrieves the OID for the named curve with which this private key is
   * associated, if available.
   *
   * @return  The OID for the named curve with which this private key is
   *          associated, or {@code null} if it was not included in the encoded
   *          key.
   */
  @Nullable()
  public OID getNamedCurveOID()
  {
    return namedCurveOID;
  }



  /**
   * Retrieves the encoded public key with which this private key is associated,
   * if available.
   *
   * @return  The encoded public key with which this private key is associated,
   *          or {@code null} if it was not included in the encoded key.
   */
  @Nullable()
  public ASN1BitString getPublicKey()
  {
    return publicKey;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("EllipticCurvePrivateKey(version=");
    buffer.append(version);
    buffer.append(", privateKeyBytes=");
    StaticUtils.toHex(privateKeyBytes, ":", buffer);

    if (namedCurveOID != null)
    {
      buffer.append(", namedCurveOID='");
      buffer.append(namedCurveOID.toString());
      buffer.append('\'');

      final NamedCurve namedCurve = NamedCurve.forOID(namedCurveOID);
      if (namedCurve != null)
      {
        buffer.append(", namedCurveName='");
        buffer.append(namedCurve.getName());
        buffer.append('\'');
      }
    }

    if (publicKey != null)
    {
      try
      {
        final byte[] publicKeyBytes = publicKey.getBytes();
        buffer.append(", publicKeyBytes=");
        StaticUtils.toHex(publicKeyBytes, ":", buffer);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        buffer.append(", publicKeyBitString=");
        publicKey.toString(buffer);
      }
    }

    buffer.append(')');
  }
}
