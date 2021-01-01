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
import java.util.ArrayList;

import com.unboundid.asn1.ASN1BigInteger;
import com.unboundid.asn1.ASN1Element;
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
 * This class provides an implementation of the authority key identifier X.509
 * certificate extension as described in
 * <A HREF="https://www.ietf.org/rfc/rfc5280.txt">RFC 5280</A> section 4.2.1.1.
 * The OID for this extension is 2.5.29.35 and the value has the following
 * encoding:
 * <PRE>
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 * </PRE>
 * The actual format of the key identifier is not specified, although RFC 5280
 * does specify a couple of possibilities.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AuthorityKeyIdentifierExtension
       extends X509CertificateExtension
{
  /**
   * The OID (2.5.29.35) for authority key identifier extensions.
   */
  @NotNull public static final OID AUTHORITY_KEY_IDENTIFIER_OID =
       new OID("2.5.29.35");



  /**
   * The DER type for the key identifier element in the value sequence.
   */
  private static final byte TYPE_KEY_IDENTIFIER = (byte) 0x80;



  /**
   * The DER type for the authority cert issuer element in the value sequence.
   */
  private static final byte TYPE_AUTHORITY_CERT_ISSUER = (byte) 0xA1;



  /**
   * The DER type for the authority cert serial number element in the value
   * sequence.
   */
  private static final byte TYPE_AUTHORITY_CERT_SERIAL_NUMBER = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8913323557731547122L;



  // The key identifier for this extension.
  @Nullable private final ASN1OctetString keyIdentifier;

  // The serial number for the authority certificate.
  @Nullable private final BigInteger authorityCertSerialNumber;

  // General names for the authority certificate.
  @Nullable private final GeneralNames authorityCertIssuer;



  /**
   * Creates a new authority key identifier extension with the provided
   * information.
   *
   * @param  isCritical                 Indicates whether this extension should
   *                                    be considered critical.
   * @param  keyIdentifier              The key identifier.  This may be
   *                                    {@code null} if it should not be
   *                                    included in the extension.
   * @param  authorityCertIssuer        The authority certificate issuer.  This
   *                                    may be {@code null} if it should not be
   *                                    included in the extension.
   * @param  authorityCertSerialNumber  The authority certificate serial number.
   *                                    This may be {@code null} if it should
   *                                    not be included in the extension.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         value.
   */
  AuthorityKeyIdentifierExtension(final boolean isCritical,
       @Nullable final ASN1OctetString keyIdentifier,
       @Nullable final GeneralNames authorityCertIssuer,
       @Nullable final BigInteger authorityCertSerialNumber)
       throws CertException
  {
    super(AUTHORITY_KEY_IDENTIFIER_OID, isCritical,
         encodeValue(keyIdentifier, authorityCertIssuer,
              authorityCertSerialNumber));

    this.keyIdentifier = keyIdentifier;
    this.authorityCertIssuer = authorityCertIssuer;
    this.authorityCertSerialNumber = authorityCertSerialNumber;
  }



  /**
   * Creates a new authority key identifier extension from the provided generic
   * extension.
   *
   * @param  extension  The extension to decode as a subject key identifier
   *                    extension.
   *
   * @throws  CertException  If the provided extension cannot be decoded as a
   *                         subject alternative name extension.
   */
  AuthorityKeyIdentifierExtension(
       @NotNull final X509CertificateExtension extension)
       throws CertException
  {
    super(extension);

    try
    {
      ASN1OctetString keyID = null;
      BigInteger serialNumber = null;
      GeneralNames generalNames = null;

      for (final ASN1Element element :
           ASN1Sequence.decodeAsSequence(extension.getValue()).elements())
      {
        switch (element.getType())
        {
          case TYPE_KEY_IDENTIFIER:
            keyID = element.decodeAsOctetString();
            break;
          case TYPE_AUTHORITY_CERT_ISSUER:
            final ASN1Element generalNamesElement =
                 ASN1Element.decode(element.getValue());
            generalNames = new GeneralNames(generalNamesElement);
            break;
          case TYPE_AUTHORITY_CERT_SERIAL_NUMBER:
            serialNumber = element.decodeAsBigInteger().getBigIntegerValue();
            break;
        }
      }

      keyIdentifier = keyID;
      authorityCertIssuer = generalNames;
      authorityCertSerialNumber = serialNumber;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_AUTHORITY_KEY_ID_EXTENSION_CANNOT_PARSE.get(
                String.valueOf(extension), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information for use as the value of this extension.
   *
   * @param  keyIdentifier              The key identifier.  This may be
   *                                    {@code null} if it should not be
   *                                    included in the extension.
   * @param  authorityCertIssuer        The authority certificate issuer.  This
   *                                    may be {@code null} if it should not be
   *                                    included in the extension.
   * @param  authorityCertSerialNumber  The authority certificate serial number.
   *                                    This may be {@code null} if it should
   *                                    not be included in the extension.
   *
   * @return  The encoded value.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         value.
   */
  @NotNull()
  private static byte[] encodeValue(
               @Nullable final ASN1OctetString keyIdentifier,
               @Nullable final GeneralNames authorityCertIssuer,
               @Nullable final BigInteger authorityCertSerialNumber)
          throws CertException
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    if (keyIdentifier != null)
    {
      elements.add(new ASN1OctetString(TYPE_KEY_IDENTIFIER,
           keyIdentifier.getValue()));
    }

    if (authorityCertIssuer != null)
    {
      elements.add(new ASN1Element(TYPE_AUTHORITY_CERT_ISSUER,
           authorityCertIssuer.encode().encode()));
    }

    if (authorityCertSerialNumber != null)
    {
      elements.add(new ASN1BigInteger(TYPE_AUTHORITY_CERT_SERIAL_NUMBER,
           authorityCertSerialNumber));
    }

    return new ASN1Sequence(elements).encode();
  }



  /**
   * Retrieves the key identifier for this extension, if available.
   *
   * @return  The key identifier for this extension, or {@code null} if it
   *          was not included in the extension.
   */
  @Nullable()
  public ASN1OctetString getKeyIdentifier()
  {
    return keyIdentifier;
  }



  /**
   * Retrieves the general names for the authority certificate, if available.
   *
   * @return  The general names for the authority certificate, or {@code null}
   *          if it was not included in the extension.
   */
  @Nullable()
  public GeneralNames getAuthorityCertIssuer()
  {
    return authorityCertIssuer;
  }



  /**
   * Retrieves the serial number for the authority certificate, if available.
   *
   * @return  The serial number for the authority certificate, or {@code null}
   *          if it was not included in the extension.
   */
  @Nullable()
  public BigInteger getAuthorityCertSerialNumber()
  {
    return authorityCertSerialNumber;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtensionName()
  {
    return INFO_AUTHORITY_KEY_ID_EXTENSION_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AuthorityKeyIdentifierExtension(oid='");
    buffer.append(getOID());
    buffer.append("', isCritical=");
    buffer.append(isCritical());

    if (keyIdentifier != null)
    {
      buffer.append(", keyIdentifierBytes='");
      StaticUtils.toHex(keyIdentifier.getValue(), ":", buffer);
      buffer.append('\'');
    }

    if (authorityCertIssuer != null)
    {
      buffer.append(", authorityCertIssuer=");
      authorityCertIssuer.toString(buffer);
    }

    if (authorityCertSerialNumber != null)
    {
      buffer.append(", authorityCertSerialNumber='");
      StaticUtils.toHex(authorityCertSerialNumber.toByteArray(), ":", buffer);
      buffer.append('\'');
    }


    buffer.append(')');
  }
}
