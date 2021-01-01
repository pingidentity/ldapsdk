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
package com.unboundid.ldap.sdk.schema;



import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.schema.SchemaMessages.*;



/**
 * This class provides a superclass for all schema element types, and defines a
 * number of utility methods that may be used when parsing schema element
 * strings.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class SchemaElement
       implements Serializable
{
  /**
   * Indicates whether schema elements will be permitted to use an empty
   * quoted string as the value of the {@code DESC} component.
   */
  private static boolean allowEmptyDescription = Boolean.getBoolean(
         "com.unboundid.ldap.sdk.schema.AllowEmptyDescription");



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8249972237068748580L;



  /**
   * Indicates whether to allow schema elements to contain an empty string as
   * the value for the {@code DESC} component.  Although quoted strings are not
   * allowed in schema elements as per RFC 4512 section 4.1, some directory
   * servers allow it, and it may be necessary to support schema definitions
   * used in conjunction with those servers.
   * <BR><BR>
   * The LDAP SDK does not allow empty schema element descriptions by default,
   * but it may be updated to allow it using either the
   * {@link #setAllowEmptyDescription} method or by setting the value of the
   * {@code com.unboundid.ldap.sdk.schema.AllowEmptyDescription} system property
   * to {@code true} before this class is loaded.
   *
   * @return  {@code true} if the LDAP SDK should allow schema elements with
   *          empty descriptions, or {@code false} if not.
   */
  public static boolean allowEmptyDescription()
  {
    return allowEmptyDescription;
  }



  /**
   * Specifies whether to allow schema elements to contain an empty string as
   * the value for the {@code DESC} component.  If specified, this will override
   * the value of the
   * {@code com.unboundid.ldap.sdk.schema.AllowEmptyDescription} system
   * property.
   *
   * @param  allowEmptyDescription  Indicates whether to allow schema elements
   *                                to contain an empty string as the value for
   *                                the {@code DESC} component.
   */
  public static void setAllowEmptyDescription(
                          final boolean allowEmptyDescription)
  {
    SchemaElement.allowEmptyDescription = allowEmptyDescription;
  }



  /**
   * Skips over any any spaces in the provided string.
   *
   * @param  s         The string in which to skip the spaces.
   * @param  startPos  The position at which to start skipping spaces.
   * @param  length    The position of the end of the string.
   *
   * @return  The position of the next non-space character in the string.
   *
   * @throws  LDAPException  If the end of the string was reached without
   *                         finding a non-space character.
   */
  static int skipSpaces(@NotNull final String s, final int startPos,
                        final int length)
         throws LDAPException
  {
    int pos = startPos;
    while ((pos < length) && (s.charAt(pos) == ' '))
    {
      pos++;
    }

    if (pos >= length)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SCHEMA_ELEM_SKIP_SPACES_NO_CLOSE_PAREN.get(s));
    }

    return pos;
  }



  /**
   * Reads one or more hex-encoded bytes from the specified portion of the RDN
   * string.
   *
   * @param  s              The string from which the data is to be read.
   * @param  startPos       The position at which to start reading.  This should
   *                        be the first hex character immediately after the
   *                        initial backslash.
   * @param  length         The position of the end of the string.
   * @param  componentName  The name of the component in the schema element
   *                        definition whose value is being read.
   * @param  buffer         The buffer to which the decoded string portion
   *                        should be appended.
   *
   * @return  The position at which the caller may resume parsing.
   *
   * @throws  LDAPException  If a problem occurs while reading hex-encoded
   *                         bytes.
   */
  private static int readEscapedHexString(@NotNull final String s,
                                          final int startPos,
                                          final int length,
                                          @NotNull final String componentName,
                                          @NotNull final StringBuilder buffer)
          throws LDAPException
  {
    int pos    = startPos;

    final ByteBuffer byteBuffer = ByteBuffer.allocate(length - pos);
    while (pos < length)
    {
      final byte b;
      switch (s.charAt(pos++))
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
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_SCHEMA_ELEM_INVALID_HEX_CHAR.get(s, s.charAt(pos-1),
                    (pos-1), componentName));
      }

      if (pos >= length)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_SCHEMA_ELEM_MISSING_HEX_CHAR.get(s, componentName));
      }

      switch (s.charAt(pos++))
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
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_SCHEMA_ELEM_INVALID_HEX_CHAR.get(s, s.charAt(pos-1),
                    (pos-1), componentName));
      }

      if (((pos+1) < length) && (s.charAt(pos) == '\\') &&
          StaticUtils.isHex(s.charAt(pos+1)))
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
   * Reads a single-quoted string from the provided string.
   *
   * @param  s              The string from which to read the single-quoted
   *                        string.
   * @param  startPos       The position at which to start reading.
   * @param  length         The position of the end of the string.
   * @param  componentName  The name of the component in the schema element
   *                        definition whose value is being read.
   * @param  buffer         The buffer into which the single-quoted string
   *                        should be placed (without the surrounding single
   *                        quotes).
   *
   * @return  The position of the first space immediately following the closing
   *          quote.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         read the single-quoted string.
   */
  static int readQDString(@NotNull final String s, final int startPos,
                          final int length, @NotNull final String componentName,
                          @NotNull final StringBuilder buffer)
      throws LDAPException
  {
    // The first character must be a single quote.
    if (s.charAt(startPos) != '\'')
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SCHEMA_ELEM_EXPECTED_SINGLE_QUOTE.get(s, startPos,
                componentName));
    }

    // Read until we find the next closing quote.  If we find any hex-escaped
    // characters along the way, then decode them.
    int pos = startPos + 1;
    while (pos < length)
    {
      final char c = s.charAt(pos++);
      if (c == '\'')
      {
        // This is the end of the quoted string.
        break;
      }
      else if (c == '\\')
      {
        // This designates the beginning of one or more hex-encoded bytes.
        if (pos >= length)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_ENDS_WITH_BACKSLASH.get(s, componentName));
        }

        pos = readEscapedHexString(s, pos, length, componentName, buffer);
      }
      else
      {
        buffer.append(c);
      }
    }

    if ((pos >= length) || ((s.charAt(pos) != ' ') && (s.charAt(pos) != ')')))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SCHEMA_ELEM_NO_CLOSING_PAREN.get(s, componentName));
    }

    if (buffer.length() == 0)
    {
      if (! (allowEmptyDescription && componentName.equalsIgnoreCase("DESC")))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SCHEMA_ELEM_EMPTY_QUOTES.get(s, componentName));
      }
    }

    return pos;
  }



  /**
   * Reads one a set of one or more single-quoted strings from the provided
   * string.  The value to read may be either a single string enclosed in
   * single quotes, or an opening parenthesis followed by a space followed by
   * one or more space-delimited single-quoted strings, followed by a space and
   * a closing parenthesis.
   *
   * @param  s              The string from which to read the single-quoted
   *                        strings.
   * @param  startPos       The position at which to start reading.
   * @param  length         The position of the end of the string.
   * @param  componentName  The name of the component in the schema element
   *                        definition whose value is being read.
   * @param  valueList      The list into which the values read may be placed.
   *
   * @return  The position of the first space immediately following the end of
   *          the values.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         read the single-quoted strings.
   */
  static int readQDStrings(@NotNull final String s, final int startPos,
                           final int length,
                           @NotNull final String componentName,
                           @NotNull final ArrayList<String> valueList)
      throws LDAPException
  {
    // Look at the first character.  It must be either a single quote or an
    // opening parenthesis.
    char c = s.charAt(startPos);
    if (c == '\'')
    {
      // It's just a single value, so use the readQDString method to get it.
      final StringBuilder buffer = new StringBuilder();
      final int returnPos = readQDString(s, startPos, length, componentName,
           buffer);
      valueList.add(buffer.toString());
      return returnPos;
    }
    else if (c == '(')
    {
      int pos = startPos + 1;
      while (true)
      {
        pos = skipSpaces(s, pos, length);
        c = s.charAt(pos);
        if (c == ')')
        {
          // This is the end of the value list.
          pos++;
          break;
        }
        else if (c == '\'')
        {
          // This is the next value in the list.
          final StringBuilder buffer = new StringBuilder();
          pos = readQDString(s, pos, length, componentName, buffer);
          valueList.add(buffer.toString());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_EXPECTED_QUOTE_OR_PAREN.get(s, startPos,
                    componentName));
        }
      }

      if (valueList.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SCHEMA_ELEM_EMPTY_STRING_LIST.get(s, componentName));
      }

      if ((pos >= length) ||
          ((s.charAt(pos) != ' ') && (s.charAt(pos) != ')')))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SCHEMA_ELEM_NO_SPACE_AFTER_QUOTE.get(s, componentName));
      }

      return pos;
    }
    else
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SCHEMA_ELEM_EXPECTED_QUOTE_OR_PAREN.get(s, startPos,
                componentName));
    }
  }



  /**
   * Reads an OID value from the provided string.  The OID value may be either a
   * numeric OID or a string name.  This implementation will be fairly lenient
   * with regard to the set of characters that may be present, and it will
   * allow the OID to be enclosed in single quotes.
   *
   * @param  s         The string from which to read the OID string.
   * @param  startPos  The position at which to start reading.
   * @param  length    The position of the end of the string.
   * @param  buffer    The buffer into which the OID string should be placed.
   *
   * @return  The position of the first space immediately following the OID
   *          string.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         read the OID string.
   */
  static int readOID(@NotNull final String s, final int startPos,
                     final int length, @NotNull final StringBuilder buffer)
      throws LDAPException
  {
    // Read until we find the first space.
    int pos = startPos;
    boolean lastWasQuote = false;
    while (pos < length)
    {
      final char c = s.charAt(pos);
      if ((c == ' ') || (c == '$') || (c == ')'))
      {
        if (buffer.length() == 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_EMPTY_OID.get(s));
        }

        return pos;
      }
      else if (((c >= 'a') && (c <= 'z')) ||
               ((c >= 'A') && (c <= 'Z')) ||
               ((c >= '0') && (c <= '9')) ||
               (c == '-') || (c == '.') || (c == '_') ||
               (c == '{') || (c == '}'))
      {
        if (lastWasQuote)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_UNEXPECTED_CHAR_IN_OID.get(s, (pos-1)));
        }

        buffer.append(c);
      }
      else if (c == '\'')
      {
        if (buffer.length() != 0)
        {
          lastWasQuote = true;
        }
      }
      else
      {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_UNEXPECTED_CHAR_IN_OID.get(s, pos));
      }

      pos++;
    }


    // We hit the end of the string before finding a space.
    throw new LDAPException(ResultCode.DECODING_ERROR,
         ERR_SCHEMA_ELEM_NO_SPACE_AFTER_OID.get(s));
  }



  /**
   * Reads one a set of one or more OID strings from the provided string.  The
   * value to read may be either a single OID string or an opening parenthesis
   * followed by a space followed by one or more space-delimited OID strings,
   * followed by a space and a closing parenthesis.
   *
   * @param  s              The string from which to read the OID strings.
   * @param  startPos       The position at which to start reading.
   * @param  length         The position of the end of the string.
   * @param  componentName  The name of the component in the schema element
   *                        definition whose value is being read.
   * @param  valueList      The list into which the values read may be placed.
   *
   * @return  The position of the first space immediately following the end of
   *          the values.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         read the OID strings.
   */
  static int readOIDs(@NotNull final String s, final int startPos,
                      final int length, @NotNull final String componentName,
                      @NotNull final ArrayList<String> valueList)
      throws LDAPException
  {
    // Look at the first character.  If it's an opening parenthesis, then read
    // a list of OID strings.  Otherwise, just read a single string.
    char c = s.charAt(startPos);
    if (c == '(')
    {
      int pos = startPos + 1;
      while (true)
      {
        pos = skipSpaces(s, pos, length);
        c = s.charAt(pos);
        if (c == ')')
        {
          // This is the end of the value list.
          pos++;
          break;
        }
        else if (c == '$')
        {
          // This is the delimiter before the next value in the list.
          pos++;
          pos = skipSpaces(s, pos, length);
          final StringBuilder buffer = new StringBuilder();
          pos = readOID(s, pos, length, buffer);
          valueList.add(buffer.toString());
        }
        else if (valueList.isEmpty())
        {
          // This is the first value in the list.
          final StringBuilder buffer = new StringBuilder();
          pos = readOID(s, pos, length, buffer);
          valueList.add(buffer.toString());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_SCHEMA_ELEM_UNEXPECTED_CHAR_IN_OID_LIST.get(s, pos,
                    componentName));
        }
      }

      if (valueList.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SCHEMA_ELEM_EMPTY_OID_LIST.get(s, componentName));
      }

      if (pos >= length)
      {
        // Technically, there should be a space after the closing parenthesis,
        // but there are known cases in which servers (like Active Directory)
        // omit this space, so we'll be lenient and allow a missing space.  But
        // it can't possibly be the end of the schema element definition, so
        // that's still an error.
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SCHEMA_ELEM_NO_SPACE_AFTER_OID_LIST.get(s, componentName));
      }

      return pos;
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      final int returnPos = readOID(s, startPos, length, buffer);
      valueList.add(buffer.toString());
      return returnPos;
    }
  }



  /**
   * Appends a properly-encoded representation of the provided value to the
   * given buffer.
   *
   * @param  value   The value to be encoded and placed in the buffer.
   * @param  buffer  The buffer to which the encoded value is to be appended.
   */
  static void encodeValue(@NotNull final String value,
                          @NotNull final StringBuilder buffer)
  {
    final int length = value.length();
    for (int i=0; i < length; i++)
    {
      final char c = value.charAt(i);
      if ((c < ' ') || (c > '~') || (c == '\\') || (c == '\''))
      {
        StaticUtils.hexEncode(c, buffer);
      }
      else
      {
        buffer.append(c);
      }
    }
  }



  /**
   * Retrieves the type of schema element that this object represents.
   *
   * @return  The type of schema element that this object represents.
   */
  @NotNull()
  public abstract SchemaElementType getSchemaElementType();



  /**
   * Retrieves a hash code for this schema element.
   *
   * @return  A hash code for this schema element.
   */
  public abstract int hashCode();



  /**
   * Indicates whether the provided object is equal to this schema element.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object may be considered equal to
   *          this schema element, or {@code false} if not.
   */
  public abstract boolean equals(@Nullable Object o);



  /**
   * Indicates whether the two extension maps are equivalent.
   *
   * @param  m1  The first schema element to examine.
   * @param  m2  The second schema element to examine.
   *
   * @return  {@code true} if the provided extension maps are equivalent, or
   *          {@code false} if not.
   */
  protected static boolean extensionsEqual(
                                @NotNull final Map<String,String[]> m1,
                                @NotNull final Map<String,String[]> m2)
  {
    if (m1.isEmpty())
    {
      return m2.isEmpty();
    }

    if (m1.size() != m2.size())
    {
      return false;
    }

    for (final Map.Entry<String,String[]> e : m1.entrySet())
    {
      final String[] v1 = e.getValue();
      final String[] v2 = m2.get(e.getKey());
      if (! StaticUtils.arraysEqualOrderIndependent(v1, v2))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Converts the provided collection of strings to an array.
   *
   * @param  c  The collection to convert to an array.  It may be {@code null}.
   *
   * @return  A string array if the provided collection is non-{@code null}, or
   *          {@code null} if the provided collection is {@code null}.
   */
  @Nullable()
  static String[] toArray(@Nullable final Collection<String> c)
  {
    if (c == null)
    {
      return null;
    }

    return c.toArray(StaticUtils.NO_STRINGS);
  }



  /**
   * Retrieves a string representation of this schema element, in the format
   * described in RFC 4512.
   *
   * @return  A string representation of this schema element, in the format
   *          described in RFC 4512.
   */
  @Override()
  @NotNull()
  public abstract String toString();
}
