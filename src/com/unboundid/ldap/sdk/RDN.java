/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding information about an LDAP
 * relative distinguished name (RDN).  An RDN consists of one or more
 * attribute name-value pairs.  See
 * <A HREF="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</A> for more
 * information about representing DNs and RDNs as strings.  See the
 * documentation in the {@link DN} class for more information about DNs and
 * RDNs.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RDN
       implements Comparable<RDN>, Comparator<RDN>, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2923419812807188487L;



  // The set of attribute values for this RDN.
  @NotNull private final ASN1OctetString[] attributeValues;

  // The schema to use to generate the normalized string representation of this
  // RDN, if any.
  @Nullable private final Schema schema;

  // The name-value pairs that comprise this RDN.
  @Nullable private volatile SortedSet<RDNNameValuePair> nameValuePairs;

  // The normalized string representation for this RDN.
  @Nullable private volatile String normalizedString;

  // The user-defined string representation for this RDN.
  @Nullable private volatile String rdnString;

  // The set of attribute names for this RDN.
  @NotNull private final String[] attributeNames;



  /**
   * Creates a new single-valued RDN with the provided information.
   *
   * @param  attributeName   The attribute name for this RDN.  It must not be
   *                         {@code null}.
   * @param  attributeValue  The attribute value for this RDN.  It must not be
   *                         {@code null}.
   */
  public RDN(@NotNull final String attributeName,
             @NotNull final String attributeValue)
  {
    this(attributeName, attributeValue, null);
  }



  /**
   * Creates a new single-valued RDN with the provided information.
   *
   * @param  attributeName   The attribute name for this RDN.  It must not be
   *                         {@code null}.
   * @param  attributeValue  The attribute value for this RDN.  It must not be
   *                         {@code null}.
   * @param  schema          The schema to use to generate the normalized string
   *                         representation of this RDN.  It may be {@code null}
   *                         if no schema is available.
   */
  public RDN(@NotNull final String attributeName,
             @NotNull final String attributeValue,
             @Nullable final Schema schema)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    this.schema = schema;

    attributeNames  = new String[] { attributeName };
    attributeValues =
         new ASN1OctetString[] { new ASN1OctetString(attributeValue) };

    nameValuePairs = null;
    normalizedString = null;
    rdnString = null;
  }



  /**
   * Creates a new single-valued RDN with the provided information.
   *
   * @param  attributeName   The attribute name for this RDN.  It must not be
   *                         {@code null}.
   * @param  attributeValue  The attribute value for this RDN.  It must not be
   *                         {@code null}.
   */
  public RDN(@NotNull final String attributeName,
             @NotNull final byte[] attributeValue)
  {
    this(attributeName, attributeValue, null);
  }



  /**
   * Creates a new single-valued RDN with the provided information.
   *
   * @param  attributeName   The attribute name for this RDN.  It must not be
   *                         {@code null}.
   * @param  attributeValue  The attribute value for this RDN.  It must not be
   *                         {@code null}.
   * @param  schema          The schema to use to generate the normalized string
   *                         representation of this RDN.  It may be {@code null}
   *                         if no schema is available.
   */
  public RDN(@NotNull final String attributeName,
             @NotNull final byte[] attributeValue,
             @Nullable final Schema schema)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    this.schema = schema;

    attributeNames  = new String[] { attributeName };
    attributeValues =
         new ASN1OctetString[] { new ASN1OctetString(attributeValue) };

    nameValuePairs = null;
    normalizedString = null;
    rdnString = null;
  }



  /**
   * Creates a new (potentially multivalued) RDN.  The set of names must have
   * the same number of elements as the set of values, and there must be at
   * least one element in each array.
   *
   * @param  attributeNames   The set of attribute names for this RDN.  It must
   *                          not be {@code null} or empty.
   * @param  attributeValues  The set of attribute values for this RDN.  It must
   *                          not be {@code null} or empty.
   */
  public RDN(@NotNull final String[] attributeNames,
             @NotNull final String[] attributeValues)
  {
    this(attributeNames, attributeValues, null);
  }



  /**
   * Creates a new (potentially multivalued) RDN.  The set of names must have
   * the same number of elements as the set of values, and there must be at
   * least one element in each array.
   *
   * @param  attributeNames   The set of attribute names for this RDN.  It must
   *                          not be {@code null} or empty.
   * @param  attributeValues  The set of attribute values for this RDN.  It must
   *                          not be {@code null} or empty.
   * @param  schema           The schema to use to generate the normalized
   *                          string representation of this RDN.  It may be
   *                          {@code null} if no schema is available.
   */
  public RDN(@NotNull final String[] attributeNames,
             @NotNull final String[] attributeValues,
             @Nullable final Schema schema)
  {
    Validator.ensureNotNull(attributeNames, attributeValues);
    Validator.ensureTrue(attributeNames.length == attributeValues.length,
         "RDN.attributeNames and attributeValues must be the same size.");
    Validator.ensureTrue(attributeNames.length > 0,
         "RDN.attributeNames must not be empty.");

    this.attributeNames = attributeNames;
    this.schema         = schema;

    this.attributeValues = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < attributeValues.length; i++)
    {
      this.attributeValues[i] = new ASN1OctetString(attributeValues[i]);
    }

    nameValuePairs = null;
    normalizedString = null;
    rdnString = null;
  }



  /**
   * Creates a new (potentially multivalued) RDN.  The set of names must have
   * the same number of elements as the set of values, and there must be at
   * least one element in each array.
   *
   * @param  attributeNames   The set of attribute names for this RDN.  It must
   *                          not be {@code null} or empty.
   * @param  attributeValues  The set of attribute values for this RDN.  It must
   *                          not be {@code null} or empty.
   */
  public RDN(@NotNull final String[] attributeNames,
             @NotNull final byte[][] attributeValues)
  {
    this(attributeNames, attributeValues, null);
  }



  /**
   * Creates a new (potentially multivalued) RDN.  The set of names must have
   * the same number of elements as the set of values, and there must be at
   * least one element in each array.
   *
   * @param  attributeNames   The set of attribute names for this RDN.  It must
   *                          not be {@code null} or empty.
   * @param  attributeValues  The set of attribute values for this RDN.  It must
   *                          not be {@code null} or empty.
   * @param  schema           The schema to use to generate the normalized
   *                          string representation of this RDN.  It may be
   *                          {@code null} if no schema is available.
   */
  public RDN(@NotNull final String[] attributeNames,
             @NotNull final byte[][] attributeValues,
             @Nullable final Schema schema)
  {
    Validator.ensureNotNull(attributeNames, attributeValues);
    Validator.ensureTrue(attributeNames.length == attributeValues.length,
         "RDN.attributeNames and attributeValues must be the same size.");
    Validator.ensureTrue(attributeNames.length > 0,
         "RDN.attributeNames must not be empty.");

    this.attributeNames = attributeNames;
    this.schema         = schema;

    this.attributeValues = new ASN1OctetString[attributeValues.length];
    for (int i=0; i < attributeValues.length; i++)
    {
      this.attributeValues[i] = new ASN1OctetString(attributeValues[i]);
    }

    nameValuePairs = null;
    normalizedString = null;
    rdnString = null;
  }



  /**
   * Creates a new single-valued RDN with the provided information.
   *
   * @param  attributeName   The name to use for this RDN.
   * @param  attributeValue  The value to use for this RDN.
   * @param  schema          The schema to use to generate the normalized string
   *                         representation of this RDN.  It may be {@code null}
   *                         if no schema is available.
   * @param  rdnString       The string representation for this RDN.
   */
  RDN(@NotNull final String attributeName,
      @NotNull final ASN1OctetString attributeValue,
      @Nullable final Schema schema, @NotNull final String rdnString)
  {
    this.rdnString = rdnString;
    this.schema    = schema;

    attributeNames  = new String[] { attributeName };
    attributeValues = new ASN1OctetString[] { attributeValue };

    nameValuePairs = null;
    normalizedString = null;
  }



  /**
   * Creates a new potentially multivalued RDN with the provided information.
   *
   * @param  attributeNames   The set of names to use for this RDN.
   * @param  attributeValues  The set of values to use for this RDN.
   * @param  rdnString        The string representation for this RDN.
   * @param  schema           The schema to use to generate the normalized
   *                          string representation of this RDN.  It may be
   *                          {@code null} if no schema is available.
   */
  RDN(@NotNull final String[] attributeNames,
      @NotNull final ASN1OctetString[] attributeValues,
      @Nullable final Schema schema, @NotNull final String rdnString)
  {
    this.rdnString = rdnString;
    this.schema    = schema;

    this.attributeNames  = attributeNames;
    this.attributeValues = attributeValues;

    nameValuePairs = null;
    normalizedString = null;
  }



  /**
   * Creates a new RDN from the provided string representation.
   *
   * @param  rdnString  The string representation to use for this RDN.  It must
   *                    not be empty or {@code null}.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         RDN.
   */
  public RDN(@NotNull final String rdnString)
         throws LDAPException
  {
    this(rdnString, (Schema) null, false);
  }



  /**
   * Creates a new RDN from the provided string representation.
   *
   * @param  rdnString  The string representation to use for this RDN.  It must
   *                    not be empty or {@code null}.
   * @param  schema     The schema to use to generate the normalized string
   *                    representation of this RDN.  It may be {@code null} if
   *                    no schema is available.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         RDN.
   */
  public RDN(@NotNull final String rdnString, @Nullable final Schema schema)
         throws LDAPException
  {
    this(rdnString, schema, false);
  }



  /**
   * Creates a new RDN from the provided string representation.
   *
   * @param  rdnString           The string representation to use for this RDN.
   *                             It must not be empty or {@code null}.
   * @param  schema              The schema to use to generate the normalized
   *                             string representation of this RDN.  It may be
   *                             {@code null} if no schema is available.
   * @param  strictNameChecking  Indicates whether to verify that all attribute
   *                             type names are valid as per RFC 4514.  If this
   *                             is {@code false}, then some technically invalid
   *                             characters may be accepted in attribute type
   *                             names.  If this is {@code true}, then names
   *                             must be strictly compliant.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         RDN.
   */
  public RDN(@NotNull final String rdnString, @Nullable final Schema schema,
             final boolean strictNameChecking)
         throws LDAPException
  {
    Validator.ensureNotNull(rdnString);

    this.rdnString = rdnString;
    this.schema    = schema;

    nameValuePairs = null;
    normalizedString = null;

    int pos = 0;
    final int length = rdnString.length();

    // First, skip over any leading spaces.
    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }

    // Read until we find a space or an equal sign.
    int attrStartPos = pos;
    while (pos < length)
    {
      final char c = rdnString.charAt(pos);
      if ((c == ' ') || (c == '='))
      {
        break;
      }

      pos++;
    }

    // Extract the attribute name, and optionally verify that it is valid.
    String attrName = rdnString.substring(attrStartPos, pos);
    if (attrName.isEmpty())
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
           ERR_RDN_NO_ATTR_NAME.get(rdnString));
    }

    if (strictNameChecking)
    {
      if (! (Attribute.nameIsValid(attrName) ||
           StaticUtils.isNumericOID(attrName)))
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_INVALID_ATTR_NAME.get(rdnString, attrName));
      }
    }


    // Skip over any spaces between the attribute name and the equal sign.
    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }

    if ((pos >= length) || (rdnString.charAt(pos) != '='))
    {
      // We didn't find an equal sign.
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
           ERR_RDN_NO_EQUAL_SIGN.get(rdnString, attrName));
    }


    // The next character is the equal sign.  Skip it, and then skip over any
    // spaces between it and the attribute value.
    pos++;
    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }


    // Look at the next character.  If it is an octothorpe (#), then the value
    // must be a hex-encoded BER element, which we'll need to parse and take the
    // value of that element.  Otherwise, it's a regular string (although
    // possibly containing escaped or quoted characters).
    ASN1OctetString value;
    if (pos >= length)
    {
      value = new ASN1OctetString();
    }
    else if (rdnString.charAt(pos) == '#')
    {
      // It is a hex-encoded value, so we'll read until we find the end of the
      // string or the first non-hex character, which must be either a space or
      // a plus sign.
      final byte[] valueArray = readHexString(rdnString, ++pos);

      try
      {
        value = ASN1OctetString.decodeAsOctetString(valueArray);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_HEX_STRING_NOT_BER_ENCODED.get(rdnString, attrName), e);
      }

      pos += (valueArray.length * 2);
    }
    else
    {
      // It is a string value, which potentially includes escaped characters.
      final StringBuilder buffer = new StringBuilder();
      pos = readValueString(rdnString, pos, buffer);
      value = new ASN1OctetString(buffer.toString());
    }


    // Skip over any spaces until we find a plus sign or the end of the value.
    while ((pos < length) && (rdnString.charAt(pos) == ' '))
    {
      pos++;
    }

    if (pos >= length)
    {
      // It's a single-valued RDN, so we have everything that we need.
      attributeNames  = new String[] { attrName };
      attributeValues = new ASN1OctetString[] { value };
      return;
    }

    // It's a multivalued RDN, so create temporary lists to hold the names and
    // values.
    final ArrayList<String> nameList = new ArrayList<>(5);
    final ArrayList<ASN1OctetString> valueList = new ArrayList<>(5);
    nameList.add(attrName);
    valueList.add(value);

    if (rdnString.charAt(pos) == '+')
    {
      pos++;
    }
    else
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
           ERR_RDN_VALUE_NOT_FOLLOWED_BY_PLUS.get(rdnString));
    }

    if (pos >= length)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
           ERR_RDN_PLUS_NOT_FOLLOWED_BY_AVP.get(rdnString));
    }

    int numValues = 1;
    while (pos < length)
    {
      // Skip over any spaces between the plus sign and the attribute name.
      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      attrStartPos = pos;
      while (pos < length)
      {
        final char c = rdnString.charAt(pos);
        if ((c == ' ') || (c == '='))
        {
          break;
        }

        pos++;
      }

      // Extract and validate the attribute type name.
      attrName = rdnString.substring(attrStartPos, pos);
      if (attrName.isEmpty())
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_NO_ATTR_NAME.get(rdnString));
      }

      if (strictNameChecking)
      {
        if (! (Attribute.nameIsValid(attrName) ||
             StaticUtils.isNumericOID(attrName)))
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_INVALID_ATTR_NAME.get(rdnString, attrName));
        }
      }

      // Skip over any spaces between the attribute name and the equal sign.
      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      if ((pos >= length) || (rdnString.charAt(pos) != '='))
      {
        // We didn't find an equal sign.
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_NO_EQUAL_SIGN.get(rdnString, attrName));
      }

      // The next character is the equal sign.  Skip it, and then skip over any
      // spaces between it and the attribute value.
      pos++;
      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      // Look at the next character.  If it is an octothorpe (#), then the value
      // must be a hex-encoded BER element, which we'll need to parse and take
      // the value of that element.  Otherwise, it's a regular string (although
      // possibly containing escaped or quoted characters).
      if (pos >= length)
      {
        value = new ASN1OctetString();
      }
      else if (rdnString.charAt(pos) == '#')
      {
        // It is a hex-encoded value, so we'll read until we find the end of the
        // string or the first non-hex character, which must be either a space
        // or a plus sign.
        final byte[] valueArray = readHexString(rdnString, ++pos);

        try
        {
          value = ASN1OctetString.decodeAsOctetString(valueArray);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_HEX_STRING_NOT_BER_ENCODED.get(rdnString, attrName), e);
        }

        pos += (valueArray.length * 2);
      }
      else
      {
        // It is a string value, which potentially includes escaped characters.
        final StringBuilder buffer = new StringBuilder();
        pos = readValueString(rdnString, pos, buffer);
        value = new ASN1OctetString(buffer.toString());
      }


      // Skip over any spaces until we find a plus sign or the end of the value.
      while ((pos < length) && (rdnString.charAt(pos) == ' '))
      {
        pos++;
      }

      nameList.add(attrName);
      valueList.add(value);
      numValues++;

      if (pos >= length)
      {
        // We're at the end of the value, so break out of the loop.
        break;
      }
      else
      {
        // Skip over the plus sign and loop again to read another name-value
        // pair.
        if (rdnString.charAt(pos) == '+')
        {
          pos++;
        }
        else
        {
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_VALUE_NOT_FOLLOWED_BY_PLUS.get(rdnString));
        }
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_PLUS_NOT_FOLLOWED_BY_AVP.get(rdnString));
      }
    }

    attributeNames  = new String[numValues];
    attributeValues = new ASN1OctetString[numValues];
    for (int i=0; i < numValues; i++)
    {
      attributeNames[i]  = nameList.get(i);
      attributeValues[i] = valueList.get(i);
    }
  }



  /**
   * Parses a hex-encoded RDN value from the provided string.  Reading will
   * continue until the end of the string is reached or a non-escaped plus sign
   * is encountered.  After returning, the caller should increment its position
   * by two times the length of the value array.
   *
   * @param  rdnString  The string to be parsed.  It must not be {@code null}.
   * @param  startPos   The position at which to start reading the value.  It
   *                    should be the position immediately after the octothorpe
   *                    at the start of the hex-encoded value.
   *
   * @return  A byte array containing the parsed value.
   *
   * @throws  LDAPException  If an error occurs while reading the value (e.g.,
   *                         if it contains non-hex characters, or has an odd
   *                         number of characters.
   */
  @NotNull()
  static byte[] readHexString(@NotNull final String rdnString,
                              final int startPos)
         throws LDAPException
  {
    final int length = rdnString.length();
    int pos = startPos;

    final ByteBuffer buffer = ByteBuffer.allocate(length-pos);
hexLoop:
    while (pos < length)
    {
      final byte hexByte;
      switch (rdnString.charAt(pos++))
      {
        case '0':
          hexByte = 0x00;
          break;
        case '1':
          hexByte = 0x10;
          break;
        case '2':
          hexByte = 0x20;
          break;
        case '3':
          hexByte = 0x30;
          break;
        case '4':
          hexByte = 0x40;
          break;
        case '5':
          hexByte = 0x50;
          break;
        case '6':
          hexByte = 0x60;
          break;
        case '7':
          hexByte = 0x70;
          break;
        case '8':
          hexByte = (byte) 0x80;
          break;
        case '9':
          hexByte = (byte) 0x90;
          break;
        case 'a':
        case 'A':
          hexByte = (byte) 0xA0;
          break;
        case 'b':
        case 'B':
          hexByte = (byte) 0xB0;
          break;
        case 'c':
        case 'C':
          hexByte = (byte) 0xC0;
          break;
        case 'd':
        case 'D':
          hexByte = (byte) 0xD0;
          break;
        case 'e':
        case 'E':
          hexByte = (byte) 0xE0;
          break;
        case 'f':
        case 'F':
          hexByte = (byte) 0xF0;
          break;
        case ' ':
        case '+':
        case ',':
        case ';':
          // This indicates that we've reached the end of the hex string.
          break hexLoop;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_INVALID_HEX_CHAR.get(rdnString, rdnString.charAt(pos-1),
                    (pos-1)));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_MISSING_HEX_CHAR.get(rdnString));
      }

      switch (rdnString.charAt(pos++))
      {
        case '0':
          buffer.put(hexByte);
          break;
        case '1':
          buffer.put((byte) (hexByte | 0x01));
          break;
        case '2':
          buffer.put((byte) (hexByte | 0x02));
          break;
        case '3':
          buffer.put((byte) (hexByte | 0x03));
          break;
        case '4':
          buffer.put((byte) (hexByte | 0x04));
          break;
        case '5':
          buffer.put((byte) (hexByte | 0x05));
          break;
        case '6':
          buffer.put((byte) (hexByte | 0x06));
          break;
        case '7':
          buffer.put((byte) (hexByte | 0x07));
          break;
        case '8':
          buffer.put((byte) (hexByte | 0x08));
          break;
        case '9':
          buffer.put((byte) (hexByte | 0x09));
          break;
        case 'a':
        case 'A':
          buffer.put((byte) (hexByte | 0x0A));
          break;
        case 'b':
        case 'B':
          buffer.put((byte) (hexByte | 0x0B));
          break;
        case 'c':
        case 'C':
          buffer.put((byte) (hexByte | 0x0C));
          break;
        case 'd':
        case 'D':
          buffer.put((byte) (hexByte | 0x0D));
          break;
        case 'e':
        case 'E':
          buffer.put((byte) (hexByte | 0x0E));
          break;
        case 'f':
        case 'F':
          buffer.put((byte) (hexByte | 0x0F));
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_INVALID_HEX_CHAR.get(rdnString, rdnString.charAt(pos-1),
                    (pos-1)));
      }
    }

    buffer.flip();
    final byte[] valueArray = new byte[buffer.limit()];
    buffer.get(valueArray);
    return valueArray;
  }



  /**
   * Reads a string value from the provided RDN string.  Reading will continue
   * until the end of the string is reached or until a non-escaped plus sign is
   * encountered.
   *
   * @param  rdnString  The string from which to read the value.
   * @param  startPos   The position in the RDN string at which to start reading
   *                    the value.
   * @param  buffer     The buffer into which the parsed value should be
   *                    placed.
   *
   * @return  The position at which the caller should continue reading when
   *          parsing the RDN.
   *
   * @throws  LDAPException  If a problem occurs while reading the value.
   */
  static int readValueString(@NotNull final String rdnString,
                             final int startPos,
                             @NotNull final StringBuilder buffer)
          throws LDAPException
  {
    final int length = rdnString.length();
    int pos = startPos;

    boolean inQuotes = false;
valueLoop:
    while (pos < length)
    {
      char c = rdnString.charAt(pos);
      switch (c)
      {
        case '\\':
          // It's an escaped value.  It can either be followed by a single
          // character (e.g., backslash, space, octothorpe, equals, double
          // quote, plus sign, comma, semicolon, less than, or greater-than), or
          // two hex digits.  If it is followed by hex digits, then continue
          // reading to see if there are more of them.
          if ((pos+1) >= length)
          {
            throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                 ERR_RDN_ENDS_WITH_BACKSLASH.get(rdnString));
          }
          else
          {
            pos++;
            c = rdnString.charAt(pos);
            if (StaticUtils.isHex(c))
            {
              // We need to subtract one from the resulting position because
              // it will be incremented later.
              pos = readEscapedHexString(rdnString, pos, buffer) - 1;
            }
            else
            {
              buffer.append(c);
            }
          }
          break;

        case '"':
          if (inQuotes)
          {
            // This should be the end of the value.  If it's not, then fail.
            pos++;
            while (pos < length)
            {
              c = rdnString.charAt(pos);
              if ((c == '+') || (c == ',') || (c == ';'))
              {
                break;
              }
              else if (c != ' ')
              {
                throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                     ERR_RDN_CHAR_OUTSIDE_QUOTES.get(rdnString, c, (pos-1)));
              }

              pos++;
            }

            inQuotes = false;
            break valueLoop;
          }
          else
          {
            // This should be the first character of the value.
            if (pos == startPos)
            {
              inQuotes = true;
            }
            else
            {
              throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
                   ERR_RDN_UNEXPECTED_DOUBLE_QUOTE.get(rdnString, pos));
            }
          }
          break;

        case ',':
        case ';':
        case '+':
          // This denotes the end of the value, if it's not in quotes.
          if (inQuotes)
          {
            buffer.append(c);
          }
          else
          {
            break valueLoop;
          }
          break;

        default:
          // This is a normal character that should be added to the buffer.
          buffer.append(c);
          break;
      }

      pos++;
    }


    // If the value started with a quotation mark, then make sure it was closed.
    if (inQuotes)
    {
      throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
           ERR_RDN_UNCLOSED_DOUBLE_QUOTE.get(rdnString));
    }


    // If the value ends with any unescaped trailing spaces, then trim them off.
    int bufferPos = buffer.length() - 1;
    int rdnStrPos = pos - 2;
    while ((bufferPos > 0) && (buffer.charAt(bufferPos) == ' '))
    {
      if (rdnString.charAt(rdnStrPos) == '\\')
      {
        break;
      }
      else
      {
        buffer.deleteCharAt(bufferPos--);
        rdnStrPos--;
      }
    }

    return pos;
  }



  /**
   * Reads one or more hex-encoded bytes from the specified portion of the RDN
   * string.
   *
   * @param  rdnString  The string from which the data is to be read.
   * @param  startPos   The position at which to start reading.  This should be
   *                    the first hex character immediately after the initial
   *                    backslash.
   * @param  buffer     The buffer to which the decoded string portion should be
   *                    appended.
   *
   * @return  The position at which the caller may resume parsing.
   *
   * @throws  LDAPException  If a problem occurs while reading hex-encoded
   *                         bytes.
   */
  private static int readEscapedHexString(@NotNull final String rdnString,
                                          final int startPos,
                                          @NotNull final StringBuilder buffer)
          throws LDAPException
  {
    final int length = rdnString.length();
    int pos = startPos;

    final ByteBuffer byteBuffer = ByteBuffer.allocate(length - pos);
    while (pos < length)
    {
      final byte b;
      switch (rdnString.charAt(pos++))
      {
        case '0':
          b = 0x00;
          break;
        case '1':
          b = 0x10;
          break;
        case '2':
          b = 0x20;
          break;
        case '3':
          b = 0x30;
          break;
        case '4':
          b = 0x40;
          break;
        case '5':
          b = 0x50;
          break;
        case '6':
          b = 0x60;
          break;
        case '7':
          b = 0x70;
          break;
        case '8':
          b = (byte) 0x80;
          break;
        case '9':
          b = (byte) 0x90;
          break;
        case 'a':
        case 'A':
          b = (byte) 0xA0;
          break;
        case 'b':
        case 'B':
          b = (byte) 0xB0;
          break;
        case 'c':
        case 'C':
          b = (byte) 0xC0;
          break;
        case 'd':
        case 'D':
          b = (byte) 0xD0;
          break;
        case 'e':
        case 'E':
          b = (byte) 0xE0;
          break;
        case 'f':
        case 'F':
          b = (byte) 0xF0;
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_INVALID_HEX_CHAR.get(rdnString, rdnString.charAt(pos-1),
                    (pos-1)));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
             ERR_RDN_MISSING_HEX_CHAR.get(rdnString));
      }

      switch (rdnString.charAt(pos++))
      {
        case '0':
          byteBuffer.put(b);
          break;
        case '1':
          byteBuffer.put((byte) (b | 0x01));
          break;
        case '2':
          byteBuffer.put((byte) (b | 0x02));
          break;
        case '3':
          byteBuffer.put((byte) (b | 0x03));
          break;
        case '4':
          byteBuffer.put((byte) (b | 0x04));
          break;
        case '5':
          byteBuffer.put((byte) (b | 0x05));
          break;
        case '6':
          byteBuffer.put((byte) (b | 0x06));
          break;
        case '7':
          byteBuffer.put((byte) (b | 0x07));
          break;
        case '8':
          byteBuffer.put((byte) (b | 0x08));
          break;
        case '9':
          byteBuffer.put((byte) (b | 0x09));
          break;
        case 'a':
        case 'A':
          byteBuffer.put((byte) (b | 0x0A));
          break;
        case 'b':
        case 'B':
          byteBuffer.put((byte) (b | 0x0B));
          break;
        case 'c':
        case 'C':
          byteBuffer.put((byte) (b | 0x0C));
          break;
        case 'd':
        case 'D':
          byteBuffer.put((byte) (b | 0x0D));
          break;
        case 'e':
        case 'E':
          byteBuffer.put((byte) (b | 0x0E));
          break;
        case 'f':
        case 'F':
          byteBuffer.put((byte) (b | 0x0F));
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_DN_SYNTAX,
               ERR_RDN_INVALID_HEX_CHAR.get(rdnString, rdnString.charAt(pos-1),
                    (pos-1)));
      }

      if (((pos+1) < length) && (rdnString.charAt(pos) == '\\') &&
          StaticUtils.isHex(rdnString.charAt(pos+1)))
      {
        // It appears that there are more hex-encoded bytes to follow, so keep
        // reading.
        pos++;
        continue;
      }
      else
      {
        break;
      }
    }

    byteBuffer.flip();
    final byte[] byteArray = new byte[byteBuffer.limit()];
    byteBuffer.get(byteArray);
    buffer.append(StaticUtils.toUTF8String(byteArray));
    return pos;
  }



  /**
   * Indicates whether the provided string represents a valid RDN.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string represents a valid RDN, or
   *          {@code false} if not.
   */
  public static boolean isValidRDN(@NotNull final String s)
  {
    return isValidRDN(s, false);
  }



  /**
   * Indicates whether the provided string represents a valid RDN.
   *
   * @param  s                   The string for which to make the determination.
   *                             It must not be {@code null}.
   * @param  strictNameChecking  Indicates whether to verify that all attribute
   *                             type names are valid as per RFC 4514.  If this
   *                             is {@code false}, then some technically invalid
   *                             characters may be accepted in attribute type
   *                             names.  If this is {@code true}, then names
   *                             must be strictly compliant.
   *
   * @return  {@code true} if the provided string represents a valid RDN, or
   *          {@code false} if not.
   */
  public static boolean isValidRDN(@NotNull final String s,
                                   final boolean strictNameChecking)
  {
    try
    {
      new RDN(s, null, strictNameChecking);
      return true;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return false;
    }
  }



  /**
   * Indicates whether this RDN contains multiple values.
   *
   * @return  {@code true} if this RDN contains multiple values, or
   *          {@code false} if not.
   */
  public boolean isMultiValued()
  {
    return (attributeNames.length != 1);
  }



  /**
   * Retrieves the number of values for this RDN.
   *
   * @return  The number of values for this RDN.
   */
  public int getValueCount()
  {
    return attributeNames.length;
  }



  /**
   * Retrieves an array of the attributes that comprise this RDN.
   *
   * @return  An array of the attributes that comprise this RDN.
   */
  @NotNull()
  public Attribute[] getAttributes()
  {
    final Attribute[] attrs = new Attribute[attributeNames.length];
    for (int i=0; i < attrs.length; i++)
    {
      attrs[i] = new Attribute(attributeNames[i], schema,
           new ASN1OctetString[] {  attributeValues[i] });
    }

    return attrs;
  }



  /**
   * Retrieves the set of attribute names for this RDN.
   *
   * @return  The set of attribute names for this RDN.
   */
  @NotNull()
  public String[] getAttributeNames()
  {
    return attributeNames;
  }



  /**
   * Retrieves the set of attribute values for this RDN.
   *
   * @return  The set of attribute values for this RDN.
   */
  @NotNull()
  public String[] getAttributeValues()
  {
    final String[] stringValues = new String[attributeValues.length];
    for (int i=0; i < stringValues.length; i++)
    {
      stringValues[i] = attributeValues[i].stringValue();
    }

    return stringValues;
  }



  /**
   * Retrieves the set of attribute values for this RDN.
   *
   * @return  The set of attribute values for this RDN.
   */
  @NotNull()
  public byte[][] getByteArrayAttributeValues()
  {
    final byte[][] byteValues = new byte[attributeValues.length][];
    for (int i=0; i < byteValues.length; i++)
    {
      byteValues[i] = attributeValues[i].getValue();
    }

    return byteValues;
  }



  /**
   * Retrieves a sorted set of the name-value pairs that comprise this RDN.
   *
   * @return  A sorted set of the name-value pairs that comprise this RDN.
   */
  @NotNull()
  public SortedSet<RDNNameValuePair> getNameValuePairs()
  {
    if (nameValuePairs == null)
    {
      final SortedSet<RDNNameValuePair> s = new TreeSet<>();
      for (int i=0; i < attributeNames.length; i++)
      {
        s.add(new RDNNameValuePair(attributeNames[i], attributeValues[i],
             schema));
      }

      nameValuePairs = Collections.unmodifiableSortedSet(s);
    }

    return nameValuePairs;
  }



  /**
   * Retrieves the schema that will be used for this RDN, if any.
   *
   * @return  The schema that will be used for this RDN, or {@code null} if none
   *          has been provided.
   */
  @Nullable()
  Schema getSchema()
  {
    return schema;
  }



  /**
   * Indicates whether this RDN contains the specified attribute.
   *
   * @param  attributeName  The name of the attribute for which to make the
   *                        determination.
   *
   * @return  {@code true} if RDN contains the specified attribute, or
   *          {@code false} if not.
   */
  public boolean hasAttribute(@NotNull final String attributeName)
  {
    for (final RDNNameValuePair nameValuePair : getNameValuePairs())
    {
      if (nameValuePair.hasAttributeName(attributeName))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether this RDN contains the specified attribute value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.
   * @param  attributeValue  The attribute value for which to make the
   *                         determination.
   *
   * @return  {@code true} if RDN contains the specified attribute, or
   *          {@code false} if not.
   */
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final String attributeValue)
  {
    for (final RDNNameValuePair nameValuePair : getNameValuePairs())
    {
      if (nameValuePair.hasAttributeName(attributeName) &&
           nameValuePair.hasAttributeValue(attributeValue))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether this RDN contains the specified attribute value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.
   * @param  attributeValue  The attribute value for which to make the
   *                         determination.
   *
   * @return  {@code true} if RDN contains the specified attribute, or
   *          {@code false} if not.
   */
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final byte[] attributeValue)
  {
    for (final RDNNameValuePair nameValuePair : getNameValuePairs())
    {
      if (nameValuePair.hasAttributeName(attributeName) &&
           nameValuePair.hasAttributeValue(attributeValue))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Retrieves a string representation of this RDN.
   *
   * @return  A string representation of this RDN.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    if (rdnString == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer, false);
      rdnString = buffer.toString();
    }

    return rdnString;
  }



  /**
   * Retrieves a string representation of this RDN with minimal encoding for
   * special characters.  Only those characters specified in RFC 4514 section
   * 2.4 will be escaped.  No escaping will be used for non-ASCII characters or
   * non-printable ASCII characters.
   *
   * @return  A string representation of this RDN with minimal encoding for
   *          special characters.
   */
  @NotNull()
  public String toMinimallyEncodedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer, true);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this RDN to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation is to be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    toString(buffer, false);
  }



  /**
   * Appends a string representation of this RDN to the provided buffer.
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
  public void toString(@NotNull final StringBuilder buffer,
                       final boolean minimizeEncoding)
  {
    if ((rdnString != null) && (! minimizeEncoding))
    {
      buffer.append(rdnString);
      return;
    }

    for (int i=0; i < attributeNames.length; i++)
    {
      if (i > 0)
      {
        buffer.append('+');
      }

      buffer.append(attributeNames[i]);
      buffer.append('=');
      appendValue(buffer, attributeValues[i], minimizeEncoding);
    }
  }



  /**
   * Appends an appropriately escaped version of the provided value to the given
   * buffer.
   *
   * @param  buffer            The buffer to which the value should be appended.
   *                           It must not be {@code null}.
   * @param  value             The value to be appended in an appropriately
   *                           escaped form.  It must not be {@code null}.
   * @param  minimizeEncoding  Indicates whether to restrict the encoding of
   *                           special characters to the bare minimum required
   *                           by LDAP (as per RFC 4514 section 2.4).  If this
   *                           is {@code true}, then only leading and trailing
   *                           spaces, double quotes, plus signs, commas,
   *                           semicolons, greater-than, less-than, and
   *                           backslash characters will be encoded.
   */
  static void appendValue(@NotNull final StringBuilder buffer,
                          @NotNull final ASN1OctetString value,
                          final boolean minimizeEncoding)
  {
    final String valueString = value.stringValue();
    final int length = valueString.length();
    for (int j=0; j < length; j++)
    {
      final char c = valueString.charAt(j);
      switch (c)
      {
        case '\\':
        case '=':
        case '"':
        case '+':
        case ',':
        case ';':
        case '<':
        case '>':
          // These characters will always be escaped.
          buffer.append('\\');
          buffer.append(c);
          break;

        case '#':
          // Escape the octothorpe only if it's the first character.
          if (j == 0)
          {
            buffer.append("\\#");
          }
          else
          {
            buffer.append('#');
          }
          break;

        case ' ':
          // Escape this space only if it's the first or last character.
          if ((j == 0) || ((j+1) == length))
          {
            buffer.append("\\ ");
          }
          else
          {
            buffer.append(' ');
          }
          break;

        case '\u0000':
          buffer.append("\\00");
          break;

        default:
          // If it's not a printable ASCII character, then hex-encode it
          // unless we're using minimized encoding.
          if ((! minimizeEncoding) && ((c < ' ') || (c > '~')))
          {
            StaticUtils.hexEncode(c, buffer);
          }
          else
          {
            buffer.append(c);
          }
          break;
      }
    }
  }



  /**
   * Retrieves a normalized string representation of this RDN.
   *
   * @return  A normalized string representation of this RDN.
   */
  @NotNull()
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
   * Appends a normalized string representation of this RDN to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the normalized string representation is
   *                 to be appended.
   */
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    if (attributeNames.length == 1)
    {
      // It's a single-valued RDN, so there is no need to sort anything.
      final String name = normalizeAttrName(attributeNames[0]);
      buffer.append(name);
      buffer.append('=');
      appendNormalizedValue(buffer, name, attributeValues[0], schema);
    }
    else
    {
      // It's a multivalued RDN, so we need to sort the components.
      final Iterator<RDNNameValuePair> iterator =
           getNameValuePairs().iterator();
      while (iterator.hasNext())
      {
        buffer.append(iterator.next().toNormalizedString());
        if (iterator.hasNext())
        {
          buffer.append('+');
        }
      }
    }
  }



  /**
   * Obtains a normalized representation of the provided attribute name.
   *
   * @param  name  The name of the attribute for which to create the normalized
   *               representation.
   *
   * @return  A normalized representation of the provided attribute name.
   */
  @NotNull()
  private String normalizeAttrName(@NotNull final String name)
  {
    String n = name;
    if (schema != null)
    {
      final AttributeTypeDefinition at = schema.getAttributeType(name);
      if (at != null)
      {
        n = at.getNameOrOID();
      }
    }
    return StaticUtils.toLowerCase(n);
  }



  /**
   * Retrieves a normalized string representation of the RDN with the provided
   * string representation.
   *
   * @param  s  The string representation of the RDN to normalize.  It must not
   *            be {@code null}.
   *
   * @return  The normalized string representation of the RDN with the provided
   *          string representation.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as an RDN.
   */
  @NotNull()
  public static String normalize(@NotNull final String s)
         throws LDAPException
  {
    return normalize(s, null);
  }



  /**
   * Retrieves a normalized string representation of the RDN with the provided
   * string representation.
   *
   * @param  s       The string representation of the RDN to normalize.  It must
   *                 not be {@code null}.
   * @param  schema  The schema to use to generate the normalized string
   *                 representation of the RDN.  It may be {@code null} if no
   *                 schema is available.
   *
   * @return  The normalized string representation of the RDN with the provided
   *          string representation.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as an RDN.
   */
  @NotNull()
  public static String normalize(@NotNull final String s,
                                 @Nullable final Schema schema)
         throws LDAPException
  {
    return new RDN(s, schema).toNormalizedString();
  }



  /**
   * Appends a normalized string representation of the provided attribute value
   * to the given buffer.
   *
   * @param  buffer         The buffer to which the value should be appended.
   *                        It must not be {@code null}.
   * @param  attributeName  The name of the attribute whose value is to be
   *                        normalized.  It must not be {@code null}.
   * @param  value          The value to be normalized.  It must not be
   *                        {@code null}.
   * @param  schema         The schema to use to generate the normalized
   *                        representation of the value.  It may be {@code null}
   *                        if no schema is available.
   */
  static void appendNormalizedValue(@NotNull final StringBuilder buffer,
                                    @NotNull final String attributeName,
                                    @NotNull final ASN1OctetString value,
                                    @Nullable final Schema schema)
  {
    final MatchingRule matchingRule =
         MatchingRule.selectEqualityMatchingRule(attributeName, schema);

    ASN1OctetString rawNormValue;
    try
    {
      rawNormValue = matchingRule.normalize(value);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      rawNormValue =
           new ASN1OctetString(StaticUtils.toLowerCase(value.stringValue()));
    }

    final String valueString = rawNormValue.stringValue();
    final int length = valueString.length();
    for (int i=0; i < length; i++)
    {
      final char c = valueString.charAt(i);

      switch (c)
      {
        case '\\':
        case '=':
        case '"':
        case '+':
        case ',':
        case ';':
        case '<':
        case '>':
          buffer.append('\\');
          buffer.append(c);
          break;

        case '#':
          // Escape the octothorpe only if it's the first character.
          if (i == 0)
          {
            buffer.append("\\#");
          }
          else
          {
            buffer.append('#');
          }
          break;

        case ' ':
          // Escape this space only if it's the first or last character.
          if ((i == 0) || ((i+1) == length))
          {
            buffer.append("\\ ");
          }
          else
          {
            buffer.append(' ');
          }
          break;

        default:
          // If it's a printable ASCII character that isn't covered by one of
          // the above options, then just append it to the buffer.  Otherwise,
          // hex-encode all bytes that comprise its UTF-8 representation, which
          // might require special handling if it requires two Java characters
          // to encode the Unicode character.
          if ((c >= ' ') && (c <= '~'))
          {
            buffer.append(c);
          }
          else if (Character.isHighSurrogate(c))
          {
            if (((i+1) < length) &&
                 Character.isLowSurrogate(valueString.charAt(i+1)))
            {
              final char c2 = valueString.charAt(++i);
              final int codePoint = Character.toCodePoint(c, c2);
              StaticUtils.hexEncode(codePoint, buffer);
            }
            else
            {
              // This should never happen.
              StaticUtils.hexEncode(c, buffer);
            }
          }
          else
          {
            StaticUtils.hexEncode(c, buffer);
          }
          break;
      }
    }
  }



  /**
   * Retrieves a hash code for this RDN.
   *
   * @return  The hash code for this RDN.
   */
  @Override()
  public int hashCode()
  {
    return toNormalizedString().hashCode();
  }



  /**
   * Indicates whether this RDN is equal to the provided object.  The given
   * object will only be considered equal to this RDN if it is also an RDN with
   * the same set of names and values.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object can be considered equal to
   *          this RDN, or {@code false} if not.
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

    if (! (o instanceof RDN))
    {
      return false;
    }

    final RDN rdn = (RDN) o;
    return (toNormalizedString().equals(rdn.toNormalizedString()));
  }



  /**
   * Indicates whether the RDN with the provided string representation is equal
   * to this RDN.
   *
   * @param  s  The string representation of the DN to compare with this RDN.
   *
   * @return  {@code true} if the DN with the provided string representation is
   *          equal to this RDN, or {@code false} if not.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as an RDN.
   */
  public boolean equals(@Nullable final String s)
         throws LDAPException
  {
    if (s == null)
    {
      return false;
    }

    return equals(new RDN(s, schema));
  }



  /**
   * Indicates whether the two provided strings represent the same RDN.
   *
   * @param  s1  The string representation of the first RDN for which to make
   *             the determination.  It must not be {@code null}.
   * @param  s2  The string representation of the second RDN for which to make
   *             the determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the provided strings represent the same RDN, or
   *          {@code false} if not.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as an RDN.
   */
  public static boolean equals(@NotNull final String s1,
                               @NotNull final String s2)
         throws LDAPException
  {
    return new RDN(s1).equals(new RDN(s2));
  }



  /**
   * Compares the provided RDN to this RDN to determine their relative order in
   * a sorted list.
   *
   * @param  rdn  The RDN to compare against this RDN.  It must not be
   *              {@code null}.
   *
   * @return  A negative integer if this RDN should come before the provided RDN
   *          in a sorted list, a positive integer if this RDN should come after
   *          the provided RDN in a sorted list, or zero if the provided RDN
   *          can be considered equal to this RDN.
   */
  @Override()
  public int compareTo(@NotNull final RDN rdn)
  {
    return compare(this, rdn);
  }



  /**
   * Compares the provided RDN values to determine their relative order in a
   * sorted list.
   *
   * @param  rdn1  The first RDN to be compared.  It must not be {@code null}.
   * @param  rdn2  The second RDN to be compared.  It must not be {@code null}.
   *
   * @return  A negative integer if the first RDN should come before the second
   *          RDN in a sorted list, a positive integer if the first RDN should
   *          come after the second RDN in a sorted list, or zero if the two RDN
   *          values can be considered equal.
   */
  @Override()
  public int compare(@NotNull final RDN rdn1, @NotNull final RDN rdn2)
  {
    Validator.ensureNotNull(rdn1, rdn2);

    final Iterator<RDNNameValuePair> iterator1 =
         rdn1.getNameValuePairs().iterator();
    final Iterator<RDNNameValuePair> iterator2 =
         rdn2.getNameValuePairs().iterator();

    while (iterator1.hasNext())
    {
      if (iterator2.hasNext())
      {
        final RDNNameValuePair p1 = iterator1.next();
        final RDNNameValuePair p2 = iterator2.next();
        final int compareValue = p1.compareTo(p2);
        if (compareValue != 0)
        {
          return compareValue;
        }
      }
      else
      {
        return 1;
      }
    }

    if (iterator2.hasNext())
    {
      return -1;
    }
    else
    {
      return 0;
    }
  }



  /**
   * Compares the RDN values with the provided string representations to
   * determine their relative order in a sorted list.
   *
   * @param  s1  The string representation of the first RDN to be compared.  It
   *             must not be {@code null}.
   * @param  s2  The string representation of the second RDN to be compared.  It
   *             must not be {@code null}.
   *
   * @return  A negative integer if the first RDN should come before the second
   *          RDN in a sorted list, a positive integer if the first RDN should
   *          come after the second RDN in a sorted list, or zero if the two RDN
   *          values can be considered equal.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as an RDN.
   */
  public static int compare(@NotNull final String s1,
                            @NotNull final String s2)
         throws LDAPException
  {
    return compare(s1, s2, null);
  }



  /**
   * Compares the RDN values with the provided string representations to
   * determine their relative order in a sorted list.
   *
   * @param  s1      The string representation of the first RDN to be compared.
   *                 It must not be {@code null}.
   * @param  s2      The string representation of the second RDN to be compared.
   *                 It must not be {@code null}.
   * @param  schema  The schema to use to generate the normalized string
   *                 representations of the RDNs.  It may be {@code null} if no
   *                 schema is available.
   *
   * @return  A negative integer if the first RDN should come before the second
   *          RDN in a sorted list, a positive integer if the first RDN should
   *          come after the second RDN in a sorted list, or zero if the two RDN
   *          values can be considered equal.
   *
   * @throws  LDAPException  If either of the provided strings cannot be parsed
   *                         as an RDN.
   */
  public static int compare(@NotNull final String s1, @NotNull final String s2,
                            @Nullable final Schema schema)
         throws LDAPException
  {
    return new RDN(s1, schema).compareTo(new RDN(s2, schema));
  }
}
