/*
 * Copyright 2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.Comparator;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents a single name-value pair
 * that may appear in a relative distinguished name.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RDNNameValuePair
       implements Comparable<RDNNameValuePair>, Comparator<RDNNameValuePair>,
                  Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8780852504883527870L;



  // The attribute value for this name-value pair.
  private final ASN1OctetString attributeValue;

  // The schema to use to generate the normalized string representation of this
  // name-value pair, if any.
  private final Schema schema;

  // The attribute name for this name-value pair.
  private final String attributeName;

  // The all-lowercase representation of the attribute name for this name-value
  // pair.
  private volatile String lowerAttributeName;

  // The normalized string representation for this RDN name-value pair.
  private volatile String normalizedString;

  // The string representation for this RDN name-value pair.
  private volatile String stringRepresentation;



  /**
   * Creates a new RDN name-value pair with the provided information.
   *
   * @param attributeName  The attribute name for this name-value pair.  It must
   *                       not be {@code null}.
   * @param attributeValue The attribute value for this name-value pair.  It
   *                       must not be {@code null}.
   * @param schema         The schema to use to generate the normalized string
   *                       representation of this name-value pair, if any.  It
   *                       may be {@code null} if no schema is available.
   */
  RDNNameValuePair(final String attributeName,
                   final ASN1OctetString attributeValue, final Schema schema)
  {
    this.attributeName = attributeName;
    this.attributeValue = attributeValue;
    this.schema = schema;

    lowerAttributeName = null;
    normalizedString = null;
    stringRepresentation = null;
  }



  /**
   * Retrieves the attribute name for this name-value pair.
   *
   * @return The attribute name for this name-value pair.
   */
  public String getAttributeName()
  {
    return attributeName;
  }



  /**
   * Retrieves an all-lowercase representation of the attribute name.
   *
   * @return An all-lowercase representation of the attribute name.
   */
  String getLowercaseAttributeName()
  {
    if (lowerAttributeName == null)
    {
      lowerAttributeName = StaticUtils.toLowerCase(attributeName);
    }

    return lowerAttributeName;
  }



  /**
   * Retrieves the string representation of the attribute value for this
   * name-value pair.
   *
   * @return The string representation of the attribute value for this
   * name-value pair.
   */
  public String getAttributeValue()
  {
    return attributeValue.stringValue();
  }



  /**
   * Retrieves the bytes that comprise the attribute value for this name-value
   * pair.
   *
   * @return The bytes that comprise the attribute value for this name-value
   * pair.
   */
  public byte[] getAttributeValueBytes()
  {
    return attributeValue.getValue();
  }



  /**
   * Retrieves the raw attribute value for this name-value pair.
   *
   * @return The raw attribute value for this name-value pair.
   */
  public ASN1OctetString getRawAttributeValue()
  {
    return attributeValue;
  }



  /**
   * Retrieves an integer value that represents the order in which this RDN
   * name-value pair should be placed in relation to the provided RDN name-value
   * pair in a sorted list.
   *
   * @param p The RDN name-value pair to be ordered relative to this RDN
   *          name-value pair.  It must not be {@code null}.
   *
   * @return A negative integer if this RDN name-value pair should be ordered
   * before the provided RDN name-value pair, a positive integer if this RDN
   * name-value pair should be ordered after the provided RDN name-value pair,
   * or zero if this RDN name-value pair is logically equivalent to the provided
   * RDN name-value pair.
   */
  @Override()
  public int compareTo(final RDNNameValuePair p)
  {
    final String thisLowerName = getLowercaseAttributeName();
    final String thatLowerName = p.getLowercaseAttributeName();
    final int nameComparison = thisLowerName.compareTo(thatLowerName);
    if (nameComparison != 0)
    {
      return nameComparison;
    }

    final String thisNormalizedString = toNormalizedString();
    final String thatNormalizedString = p.toNormalizedString();
    return thisNormalizedString.compareTo(thatNormalizedString);
  }



  /**
   * Retrieves an integer value that represents the order in which the provided
   * RDN name-value pairs should be placed in a sorted list.
   *
   * @param p1 The first RDN name-value pair to compare.  It must not be {@code
   *           null}.
   * @param p2 The second RDN name-value pair to compare.  It must not be {@code
   *           null}.
   *
   * @return A negative integer if the first RDN name-value pair should be
   * ordered before the second RDN name-value pair, a positive integer if the
   * first RDN name-value pair should be ordered after the second RDN name-value
   * pair, or zero if the provided RDN name-value pairs are logically
   * equivalent.
   */
  @Override()
  public int compare(final RDNNameValuePair p1, final RDNNameValuePair p2)
  {
    return p1.compareTo(p2);
  }



  /**
   * Retrieves a hash code for this RDN name-value pair.
   *
   * @return A hash code for this RDN name-value pair.
   */
  @Override()
  public int hashCode()
  {
    return toNormalizedString().hashCode();
  }



  /**
   * Indicates whether the provided object is considered logically equivalent to
   * this RDN name-value pair.
   *
   * @param o The object for which to make the determination.
   *
   * @return {@code true} if the provided object is an RDN name-value pair that
   * is logically equivalent to this RDN name-value pair, or {@code false} if
   * not.
   */
  public boolean equals(final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof RDNNameValuePair))
    {
      return false;
    }

    final RDNNameValuePair p = (RDNNameValuePair) o;
    return toNormalizedString().equals(p.toNormalizedString());
  }



  /**
   * Retrieves a string representation of this RDN name-value pair.
   *
   * @return  A string representation of this RDN name-value pair.
   */
  @Override()
  public String toString()
  {
    if (stringRepresentation == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer, false);
      stringRepresentation = buffer.toString();
    }

    return stringRepresentation;
  }



  /**
   * Retrieves a string representation of this RDN name-value pair with minimal
   * encoding for special characters.  Only those characters specified in RFC
   * 4514 section 2.4 will be escaped.  No escaping will be used for non-ASCII
   * characters or non-printable ASCII characters.
   *
   * @return  A string representation of this RDN name-value pair with minimal
   *          encoding for special characters.
   */
  public String toMinimallyEncodedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer, true);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this RDN name-value pair to the provided
   * buffer.
   *
   * @param  buffer            The buffer to which the string representation is
   *                           to be appended.
   * @param  minimizeEncoding  Indicates whether to restrict the encoding of
   *                           special characters to the bare minimum required
   *                           by LDAP (as per RFC 4514 section 2.4).  If this
   *                           is {@code true}, then only leading and trailing
   *                           spaces, double quotes, plus signs, commas,
   *                           semicolons, greater-than, less-than, and
   *                           backslash characters will be encoded.
   */
  public void toString(final StringBuilder buffer,
                       final boolean minimizeEncoding)
  {
    if ((stringRepresentation != null) && (! minimizeEncoding))
    {
      buffer.append(stringRepresentation);
      return;
    }

    final boolean bufferWasEmpty = (buffer.length() == 0);

    buffer.append(attributeName);
    buffer.append('=');
    RDN.appendValue(buffer, attributeValue, minimizeEncoding);

    if (bufferWasEmpty && (! minimizeEncoding))
    {
      stringRepresentation = buffer.toString();
    }
  }



  /**
   * Retrieves a normalized string representation of this RDN name-value pair.
   *
   * @return  A normalized string representation of this RDN name-value pair.
   */
  public String toNormalizedString()
  {
    if (normalizedString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toNormalizedString(buffer);
      normalizedString = buffer.toString();
    }

    return normalizedString;
  }



  /**
   * Appends a normalized string representation of this RDN name-value pair to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the normalized string representation
   *                 should be appended.  It must not be {@code null}.
   */
  public void toNormalizedString(final StringBuilder buffer)
  {
    buffer.append(getLowercaseAttributeName());
    buffer.append('=');
    RDN.appendNormalizedValue(buffer, attributeName, attributeValue, schema);
  }
}
