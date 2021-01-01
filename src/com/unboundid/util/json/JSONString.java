/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a JSON value that represents a
 * string of Unicode characters.  The string representation of a JSON string
 * must start and end with the double quotation mark character, and a Unicode
 * (preferably UTF-8) representation of the string between the quotes.  The
 * following special characters must be escaped:
 * <UL>
 *   <LI>
 *     The double quotation mark (Unicode character U+0022) must be escaped as
 *     either {@code \"} or {@code \}{@code u0022}.
 *   </LI>
 *   <LI>
 *     The backslash (Unicode character U+005C) must be escaped as either
 *     {@code \\} or {@code \}{@code u005C}.
 *   </LI>
 *   <LI>
 *     All ASCII control characters (Unicode characters U+0000 through U+001F)
 *     must be escaped.  They can all be escaped by prefixing the
 *     four-hexadecimal-digit Unicode character code with {@code \}{@code u},
 *     like {@code \}{@code u0000} to represent the ASCII null character U+0000.
 *     For certain characters, a more user-friendly escape sequence is also
 *     defined:
 *     <UL>
 *       <LI>
 *         The horizontal tab character can be escaped as either {@code \t} or
 *         {@code \}{@code u0009}.
 *       </LI>
 *       <LI>
 *         The newline character can be escaped as either {@code \n} or
 *         {@code \}{@code u000A}.
 *       </LI>
 *       <LI>
 *         The formfeed character can be escaped as either {@code \f} or
 *         {@code \}{@code u000C}.
 *       </LI>
 *       <LI>
 *         The carriage return character can be escaped as either {@code \r} or
 *         {@code \}{@code u000D}.
 *       </LI>
 *     </UL>
 *   </LI>
 * </UL>
 * In addition, any other character may optionally be escaped by placing the
 * {@code \}{@code u} prefix in front of each four-hexadecimal digit sequence in
 * the UTF-16 representation of that character.  For example, the "LATIN SMALL
 * LETTER N WITH TILDE" character U+00F1 may be escaped as
 * {@code \}{@code u00F1}, while the "MUSICAL SYMBOL G CLEF" character U+1D11E
 * may be escaped as {@code \}{@code uD834}{@code \}{@code uDD1E}.  And while
 * the forward slash character is not required to be escaped in JSON strings, it
 * can be escaped using {@code \/} as a more human-readable alternative to
 * {@code \}{@code u002F}.
 * <BR><BR>
 * The string provided to the {@link #JSONString(String)} constructor should not
 * have any escaping performed, and the string returned by the
 * {@link #stringValue()} method will not have any escaping performed.  These
 * methods work with the Java string that is represented by the JSON string.
 * <BR><BR>
 * If this JSON string was parsed from the string representation of a JSON
 * object, then the value returned by the {@link #toString()} method (or
 * appended to the buffer provided to the {@link #toString(StringBuilder)}
 * method) will be the string representation used in the JSON object that was
 * parsed.  Otherwise, this class will generate an appropriate string
 * representation, which will be surrounded by quotation marks and will have the
 * minimal required encoding applied.
 * <BR><BR>
 * The string returned by the {@link #toNormalizedString()} method (or appended
 * to the buffer provided to the {@link #toNormalizedString(StringBuilder)}
 * method) will be generated by converting it to lowercase, surrounding it with
 * quotation marks, and using the {@code \}{@code u}-style escaping for all
 * characters other than the following (as contained in the LDAP printable
 * character set defined in <A HREF="http://www.ietf.org/rfc/rfc4517.txt">RFC
 * 4517</A> section 3.2, and indicated by the
 * {@link StaticUtils#isPrintable(char)} method):
 * <UL>
 *   <LI>All uppercase ASCII alphabetic letters (U+0041 through U+005A).</LI>
 *   <LI>All lowercase ASCII alphabetic letters (U+0061 through U+007A).</LI>
 *   <LI>All ASCII numeric digits (U+0030 through U+0039).</LI>
 *   <LI>The ASCII space character U+0020.</LI>
 *   <LI>The ASCII single quote (aka apostrophe) character U+0027.</LI>
 *   <LI>The ASCII left parenthesis character U+0028.</LI>
 *   <LI>The ASCII right parenthesis character U+0029.</LI>
 *   <LI>The ASCII plus sign character U+002B.</LI>
 *   <LI>The ASCII comma character U+002C.</LI>
 *   <LI>The ASCII minus sign (aka hyphen) character U+002D.</LI>
 *   <LI>The ASCII period character U+002E.</LI>
 *   <LI>The ASCII forward slash character U+002F.</LI>
 *   <LI>The ASCII colon character U+003A.</LI>
 *   <LI>The ASCII equals sign character U+003D.</LI>
 *   <LI>The ASCII question mark character U+003F.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONString
       extends JSONValue
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4677194657299153890L;



  // The JSON-formatted string representation for this JSON string.  It will be
  // surrounded by quotation marks and any necessary escaping will have been
  // performed.
  @Nullable private String jsonStringRepresentation;

  // The string value for this object.
  @NotNull private final String value;



  /**
   * Creates a new JSON string.
   *
   * @param  value  The string to represent in this JSON value.  It must not be
   *                {@code null}.
   */
  public JSONString(@NotNull final String value)
  {
    this.value = value;
    jsonStringRepresentation = null;
  }



  /**
   * Creates a new JSON string.  This method should be used for strings parsed
   * from the string representation of a JSON object.
   *
   * @param  javaString  The Java string to represent.
   * @param  jsonString  The JSON string representation to use for the Java
   *                     string.
   */
  JSONString(@NotNull final String javaString, @NotNull final String jsonString)
  {
    value = javaString;
    jsonStringRepresentation = jsonString;
  }



  /**
   * Retrieves the string value for this object.  This will be the interpreted
   * value, without the surrounding quotation marks or escaping.
   *
   * @return  The string value for this object.
   */
  @NotNull()
  public String stringValue()
  {
    return value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    return stringValue().hashCode();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == this)
    {
      return true;
    }

    if (o instanceof JSONString)
    {
      final JSONString s = (JSONString) o;
      return value.equals(s.value);
    }

    return false;
  }



  /**
   * Indicates whether the value of this JSON string matches that of the
   * provided string, optionally ignoring differences in capitalization.
   *
   * @param  s           The JSON string to compare against this JSON string.
   *                     It must not be {@code null}.
   * @param  ignoreCase  Indicates whether to ignore differences in
   *                     capitalization.
   *
   * @return  {@code true} if the value of this JSON string matches the value of
   *          the provided string (optionally ignoring differences in
   *          capitalization), or {@code false} if not.
   */
  public boolean equals(@NotNull final JSONString s, final boolean ignoreCase)
  {
    if (ignoreCase)
    {
      return value.equalsIgnoreCase(s.value);
    }
    else
    {
      return value.equals(s.value);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@NotNull final JSONValue v,
                        final boolean ignoreFieldNameCase,
                        final boolean ignoreValueCase,
                        final boolean ignoreArrayOrder)
  {
    return ((v instanceof JSONString) &&
         equals((JSONString) v, ignoreValueCase));
  }



  /**
   * Retrieves a string representation of this JSON string as it should appear
   * in a JSON object, including the surrounding quotation marks and any
   * appropriate escaping  To obtain the string to which this value refers
   * without the surrounding quotation marks or escaping, use the
   * {@link #stringValue()} method.
   * <BR><BR>
   * If the object containing this string was decoded from a string, then this
   * method will use the same string representation as in that original object.
   * Otherwise, the string representation will be constructed.
   *
   * @return  A string representation of this value as it should appear in a
   *          JSON object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    if (jsonStringRepresentation == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer);
      jsonStringRepresentation = buffer.toString();
    }

    return jsonStringRepresentation;
  }



  /**
   * Appends a string representation of this JSON string as it should appear
   * in a JSON object, including the surrounding quotation marks and any
   * appropriate escaping, to the provided buffer.  To obtain the string to
   * which this value refers without the surrounding quotation marks or
   * escaping, use the {@link #stringValue()} method.
   * <BR><BR>
   * If the object containing this string was decoded from a string, then this
   * method will use the same string representation as in that original object.
   * Otherwise, the string representation will be constructed.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    if (jsonStringRepresentation != null)
    {
      buffer.append(jsonStringRepresentation);
    }
    else
    {
      final boolean emptyBufferProvided = (buffer.length() == 0);
      encodeString(value, buffer);

      if (emptyBufferProvided)
      {
        jsonStringRepresentation = buffer.toString();
      }
    }
  }



  /**
   * Retrieves a single-line representation of this JSON string as it should
   * appear in a JSON object, including the surrounding quotation marks and any
   * appropriate escaping.  To obtain the string to which this value refers
   * without the surrounding quotation marks or escaping, use the
   * {@link #stringValue()} method.
   *
   * @return  A single-line representation of this value as it should appear in
   *          a JSON object.
   */
  @Override()
  @NotNull()
  public String toSingleLineString()
  {
    return toString();
  }



  /**
   * Appends a single-line string representation of this JSON string as it
   * should appear in a JSON object, including the surrounding quotation marks
   * and any appropriate escaping, to the provided buffer.  To obtain the string
   * to which this value refers without the surrounding quotation marks or
   * escaping, use the {@link #stringValue()} method.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toSingleLineString(@NotNull final StringBuilder buffer)
  {
    toString(buffer);
  }



  /**
   * Appends a minimally-escaped JSON representation of the provided string to
   * the given buffer.  When escaping is required, the most user-friendly form
   * of escaping will be used.
   *
   * @param  s       The string to be encoded.
   * @param  buffer  The buffer to which the encoded representation should be
   *                 appended.
   */
  static void encodeString(@NotNull final String s,
                           @NotNull final StringBuilder buffer)
  {
    buffer.append('"');

    for (final char c : s.toCharArray())
    {
      switch (c)
      {
        case '"':
          buffer.append("\\\"");
          break;
        case '\\':
          buffer.append("\\\\");
          break;
        case '\b': // backspace
          buffer.append("\\b");
          break;
        case '\f': // formfeed
          buffer.append("\\f");
          break;
        case '\n': // newline
          buffer.append("\\n");
          break;
        case '\r': // carriage return
          buffer.append("\\r");
          break;
        case '\t': // horizontal tab
          buffer.append("\\t");
          break;
        default:
          if (c <= '\u001F')
          {
            buffer.append("\\u");
            buffer.append(String.format("%04X", (int) c));
          }
          else
          {
            buffer.append(c);
          }
          break;
      }
    }

    buffer.append('"');
  }



  /**
   * Appends a minimally-escaped JSON representation of the provided string to
   * the given buffer.  When escaping is required, the most user-friendly form
   * of escaping will be used.
   *
   * @param  s       The string to be encoded.
   * @param  buffer  The buffer to which the encoded representation should be
   *                 appended.
   */
  static void encodeString(@NotNull final String s,
                           @NotNull final ByteStringBuffer buffer)
  {
    buffer.append('"');

    for (final char c : s.toCharArray())
    {
      switch (c)
      {
        case '"':
          buffer.append("\\\"");
          break;
        case '\\':
          buffer.append("\\\\");
          break;
        case '\b': // backspace
          buffer.append("\\b");
          break;
        case '\f': // formfeed
          buffer.append("\\f");
          break;
        case '\n': // newline
          buffer.append("\\n");
          break;
        case '\r': // carriage return
          buffer.append("\\r");
          break;
        case '\t': // horizontal tab
          buffer.append("\\t");
          break;
        default:
          if (c <= '\u001F')
          {
            buffer.append("\\u");
            buffer.append(String.format("%04X", (int) c));
          }
          else
          {
            buffer.append(c);
          }
          break;
      }
    }

    buffer.append('"');
  }



  /**
   * Retrieves a normalized representation of this JSON string as it should
   * appear in a JSON object, including the surrounding quotes and any
   * appropriate escaping.  The normalized representation will use the unescaped
   * ASCII representation of all of the following characters:
   * <UL>
   *   <LI>The letters a through z (ASCII character codes 0x61 through
   *       0x7A).</LI>
   *   <LI>The digits 0 through 9 (ASCII character codes 0x30 through
   *       0x39).</LI>
   *   <LI>The space (ASCII character code 0x20).</LI>
   *   <LI>The single quote (ASCII character code 0x27).</LI>
   *   <LI>The left parenthesis (ASCII character code 0x28).</LI>
   *   <LI>The right parenthesis (ASCII character code 0x29).</LI>
   *   <LI>The plus sign (ASCII character code 0x2B).</LI>
   *   <LI>The comma (ASCII character code 0x2C).</LI>
   *   <LI>The hyphen (ASCII character code 0x2D).</LI>
   *   <LI>The period (ASCII character code 0x2E).</LI>
   *   <LI>The forward slash (ASCII character code 0x2F).</LI>
   *   <LI>The colon (ASCII character code 0x3A).</LI>
   *   <LI>The equal sign (ASCII character code 0x3D).</LI>
   *   <LI>The question mark (ASCII character code 0x3F).</LI>
   * </UL>
   * All characters except those listed above will be escaped using their
   * Unicode representation.
   *
   * @return  A normalized representation of this JSON string as it should
   *          appear in a JSON object, including
   */
  @Override()
  @NotNull()
  public String toNormalizedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toNormalizedString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a normalized representation of this JSON string as it should
   * appear in a JSON object, including the surrounding quotes and any
   * appropriate escaping, to the provided buffer.  The normalized
   * representation will use the unescaped ASCII representation of all of the
   * following characters:
   * <UL>
   *   <LI>The letters a through z (ASCII character codes 0x61 through
   *       0x7A).</LI>
   *   <LI>The digits 0 through 9 (ASCII character codes 0x30 through
   *       0x39).</LI>
   *   <LI>The space (ASCII character code 0x20).</LI>
   *   <LI>The single quote (ASCII character code 0x27).</LI>
   *   <LI>The left parenthesis (ASCII character code 0x28).</LI>
   *   <LI>The right parenthesis (ASCII character code 0x29).</LI>
   *   <LI>The plus sign (ASCII character code 0x2B).</LI>
   *   <LI>The comma (ASCII character code 0x2C).</LI>
   *   <LI>The hyphen (ASCII character code 0x2D).</LI>
   *   <LI>The period (ASCII character code 0x2E).</LI>
   *   <LI>The forward slash (ASCII character code 0x2F).</LI>
   *   <LI>The colon (ASCII character code 0x3A).</LI>
   *   <LI>The equal sign (ASCII character code 0x3D).</LI>
   *   <LI>The question mark (ASCII character code 0x3F).</LI>
   * </UL>
   * All characters except those listed above will be escaped using their
   * Unicode representation.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    toNormalizedString(buffer, false, true, false);
  }



  /**
   * Retrieves a normalized representation of this JSON string as it should
   * appear in a JSON object, including the surrounding quotes and any
   * appropriate escaping.  The normalized representation will use the unescaped
   * ASCII representation of all of the following characters:
   * <UL>
   *   <LI>The letters a through z (ASCII character codes 0x61 through
   *       0x7A).</LI>
   *   <LI>The letters A through Z (ASCII character codes 0x41 through 0x5A).
   *       These characters will only be used if {@code ignoreValueCase} is
   *       {@code false}.</LI>
   *   <LI>The digits 0 through 9 (ASCII character codes 0x30 through
   *       0x39).</LI>
   *   <LI>The space (ASCII character code 0x20).</LI>
   *   <LI>The single quote (ASCII character code 0x27).</LI>
   *   <LI>The left parenthesis (ASCII character code 0x28).</LI>
   *   <LI>The right parenthesis (ASCII character code 0x29).</LI>
   *   <LI>The plus sign (ASCII character code 0x2B).</LI>
   *   <LI>The comma (ASCII character code 0x2C).</LI>
   *   <LI>The hyphen (ASCII character code 0x2D).</LI>
   *   <LI>The period (ASCII character code 0x2E).</LI>
   *   <LI>The forward slash (ASCII character code 0x2F).</LI>
   *   <LI>The colon (ASCII character code 0x3A).</LI>
   *   <LI>The equal sign (ASCII character code 0x3D).</LI>
   *   <LI>The question mark (ASCII character code 0x3F).</LI>
   * </UL>
   * All characters except those listed above will be escaped using their
   * Unicode representation.
   *
   * @param  ignoreFieldNameCase  Indicates whether field names should be
   *                              treated in a case-sensitive (if {@code false})
   *                              or case-insensitive (if {@code true}) manner.
   * @param  ignoreValueCase      Indicates whether string field values should
   *                              be treated in a case-sensitive (if
   *                              {@code false}) or case-insensitive (if
   *                              {@code true}) manner.
   * @param  ignoreArrayOrder     Indicates whether the order of elements in an
   *                              array should be considered significant (if
   *                              {@code false}) or insignificant (if
   *                              {@code true}).
   *
   * @return  A normalized representation of this JSON string as it should
   *          appear in a JSON object, including
   */
  @Override()
  @NotNull()
  public String toNormalizedString(final boolean ignoreFieldNameCase,
                                   final boolean ignoreValueCase,
                                   final boolean ignoreArrayOrder)
  {
    final StringBuilder buffer = new StringBuilder();
    toNormalizedString(buffer, ignoreFieldNameCase, ignoreValueCase,
         ignoreArrayOrder);
    return buffer.toString();
  }



  /**
   * Appends a normalized representation of this JSON string as it should
   * appear in a JSON object, including the surrounding quotes and any
   * appropriate escaping, to the provided buffer.  The normalized
   * representation will use the unescaped ASCII representation of all of the
   * following characters:
   * <UL>
   *   <LI>The letters a through z (ASCII character codes 0x61 through
   *       0x7A).</LI>
   *   <LI>The letters A through Z (ASCII character codes 0x41 through 0x5A).
   *       These characters will only be used if {@code ignoreValueCase} is
   *       {@code false}.</LI>
   *   <LI>The digits 0 through 9 (ASCII character codes 0x30 through
   *       0x39).</LI>
   *   <LI>The space (ASCII character code 0x20).</LI>
   *   <LI>The single quote (ASCII character code 0x27).</LI>
   *   <LI>The left parenthesis (ASCII character code 0x28).</LI>
   *   <LI>The right parenthesis (ASCII character code 0x29).</LI>
   *   <LI>The plus sign (ASCII character code 0x2B).</LI>
   *   <LI>The comma (ASCII character code 0x2C).</LI>
   *   <LI>The hyphen (ASCII character code 0x2D).</LI>
   *   <LI>The period (ASCII character code 0x2E).</LI>
   *   <LI>The forward slash (ASCII character code 0x2F).</LI>
   *   <LI>The colon (ASCII character code 0x3A).</LI>
   *   <LI>The equal sign (ASCII character code 0x3D).</LI>
   *   <LI>The question mark (ASCII character code 0x3F).</LI>
   * </UL>
   * All characters except those listed above will be escaped using their
   * Unicode representation.
   *
   * @param  buffer               The buffer to which the information should be
   *                              appended.
   * @param  ignoreFieldNameCase  Indicates whether field names should be
   *                              treated in a case-sensitive (if {@code false})
   *                              or case-insensitive (if {@code true}) manner.
   * @param  ignoreValueCase      Indicates whether string field values should
   *                              be treated in a case-sensitive (if
   *                              {@code false}) or case-insensitive (if
   *                              {@code true}) manner.
   * @param  ignoreArrayOrder     Indicates whether the order of elements in an
   *                              array should be considered significant (if
   *                              {@code false}) or insignificant (if
   *                              {@code true}).
   */
  @Override()
  public void toNormalizedString(@NotNull final StringBuilder buffer,
                                 final boolean ignoreFieldNameCase,
                                 final boolean ignoreValueCase,
                                 final boolean ignoreArrayOrder)
  {
    buffer.append('"');

    final char[] charArray;
    if (ignoreValueCase)
    {
      charArray = StaticUtils.toLowerCase(value).toCharArray();
    }
    else
    {
      charArray = value.toCharArray();
    }

    for (final char c : charArray)
    {
      if (StaticUtils.isPrintable(c))
      {
        buffer.append(c);
      }
      else
      {
        buffer.append("\\u");
        buffer.append(String.format("%04X", (int) c));
      }
    }

    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final JSONBuffer buffer)
  {
    buffer.appendString(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final String fieldName,
                                 @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, value);
  }
}
