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
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class represents a data structure that holds information about an X.509
 * certificate extension.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class X509CertificateExtension
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4044598072050168580L;



  // Indicates whether this extension is considered critical.
  private final boolean isCritical;

  // The value for this extension.
  @NotNull private final byte[] value;

  // The OID for this extension.
  @NotNull private final OID oid;



  /**
   * Creates a new X.509 certificate extension that wraps the provided
   * extension.
   *
   * @param  extension  The extension to wrap.
   */
  protected X509CertificateExtension(
                 @NotNull final X509CertificateExtension extension)
  {
    oid = extension.oid;
    isCritical = extension.isCritical;
    value = extension.value;
  }



  /**
   * Creates a new X.509 certificate extension with the provided information.
   *
   * @param  oid         The OID for this extension.
   * @param  isCritical  Indicates whether this extension is considered
   *                     critical.
   * @param  value       The value for this extension.
   */
  public X509CertificateExtension(@NotNull final OID oid,
                                  final boolean isCritical,
                                  @NotNull final byte[] value)
  {
    this.oid = oid;
    this.isCritical = isCritical;
    this.value = value;
  }



  /**
   * Decodes the provided ASN.1 element as an X.509 certificate extension.
   *
   * @param  extensionElement  The ASN.1 element containing the encoded
   *                           extension.
   *
   * @return  The decoded extension.
   *
   * @throws  CertException  If a problem is encountered while attempting to
   *                         decode the extension.
   */
  @NotNull()
  static X509CertificateExtension decode(
              @NotNull final ASN1Element extensionElement)
         throws CertException
  {
    final OID oid;
    final X509CertificateExtension extension;
    try
    {
      final ASN1Element[] elements =
           extensionElement.decodeAsSequence().elements();
      oid = elements[0].decodeAsObjectIdentifier().getOID();

      final boolean isCritical;
      final byte[] value;
      if (elements[1].getType() == ASN1Constants.UNIVERSAL_BOOLEAN_TYPE)
      {
        isCritical = elements[1].decodeAsBoolean().booleanValue();
        value = elements[2].decodeAsOctetString().getValue();
      }
      else
      {
        isCritical = false;
        value = elements[1].decodeAsOctetString().getValue();
      }

      extension = new X509CertificateExtension(oid, isCritical, value);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_EXTENSION_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (oid.equals(AuthorityKeyIdentifierExtension.
         AUTHORITY_KEY_IDENTIFIER_OID))
    {
      try
      {
        return new AuthorityKeyIdentifierExtension(extension);
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
        return new SubjectKeyIdentifierExtension(extension);
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
        return new KeyUsageExtension(extension);
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
        return new SubjectAlternativeNameExtension(extension);
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
        return new IssuerAlternativeNameExtension(extension);
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
        return new BasicConstraintsExtension(extension);
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
        return new ExtendedKeyUsageExtension(extension);
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
        return new CRLDistributionPointsExtension(extension);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return extension;
  }



  /**
   * Retrieves the OID for this extension.
   *
   * @return  The OID for this extension.
   */
  @NotNull()
  public final OID getOID()
  {
    return oid;
  }



  /**
   * Indicates whether this extension is considered critical.
   *
   * @return  {@code true} if this extension is considered critical, or
   *          {@code false} if not.
   */
  public final boolean isCritical()
  {
    return isCritical;
  }



  /**
   * Retrieves the value for this extension.
   *
   * @return  The value for this extension.
   */
  @NotNull()
  public final byte[] getValue()
  {
    return value;
  }



  /**
   * Encodes this extension to an ASN.1 element suitable for inclusion in an
   * encoded X.509 certificate.
   *
   * @return  The encoded representation of this extension.
   *
   * @throws  CertException  If a problem is encountered while encoding the
   *                         extension.
   */
  @NotNull()
  ASN1Sequence encode()
       throws CertException
  {
    try
    {
      final ArrayList<ASN1Element> elements = new ArrayList<>(3);
      elements.add(new ASN1ObjectIdentifier(oid));

      if (isCritical)
      {
        elements.add(ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT);
      }

      elements.add(new ASN1OctetString(value));
      return new ASN1Sequence(elements);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_EXTENSION_ENCODE_ERROR.get(toString(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the name for this extension.
   *
   * @return  The name for this extension.
   */
  @NotNull()
  public String getExtensionName()
  {
    return oid.toString();
  }



  /**
   * Retrieves a string representation of this extension.
   *
   * @return  A string representation of this extension.
   */
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this certificate extension to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("X509CertificateExtension(oid='");
    buffer.append(oid.toString());
    buffer.append("', isCritical=");
    buffer.append(isCritical);

    if (StaticUtils.isPrintableString(value))
    {
      buffer.append(", value='");
      buffer.append(StaticUtils.toUTF8String(value));
      buffer.append('\'');
    }
    else
    {
      buffer.append(", valueLength=");
      buffer.append(value.length);
    }

    buffer.append(')');
  }
}
