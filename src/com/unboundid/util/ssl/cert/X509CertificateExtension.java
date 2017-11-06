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
import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
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
  private static final long serialVersionUID = 7869863894132271667L;



  // Indicates whether this extension is considered critical.
  private final boolean isCritical;

  // The value for this extension.
  private final byte[] value;

  // The OID for this extension.
  private final OID oid;



  /**
   * Creates a new X.509 certificate extension that wraps the provided
   * extension.
   *
   * @param  extension  The extension to wrap.
   */
  protected X509CertificateExtension(final X509CertificateExtension extension)
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
  public X509CertificateExtension(final OID oid, final boolean isCritical,
                                  final byte[] value)
  {
    this.oid = oid;
    this.isCritical = isCritical;
    this.value = value;
  }



  /**
   * Retrieves the OID for this extension.
   *
   * @return  The OID for this extension.
   */
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
  public String getExtensionName()
  {
    return oid.toString();
  }



  /**
   * Retrieves a string representation of this extension.
   *
   * @return  A string representation of this extension.
   */
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
  public void toString(final StringBuilder buffer)
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
