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



import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides an implementation of a JSON value that represents an
 * object with zero or more name-value pairs.  In each pair, the name is a JSON
 * string and the value is any type of JSON value ({@code null}, {@code true},
 * {@code false}, number, string, array, or object).  Although the ECMA-404
 * specification does not explicitly forbid a JSON object from having multiple
 * fields with the same name, RFC 7159 section 4 states that field names should
 * be unique, and this implementation does not support objects in which multiple
 * fields have the same name.  Note that this uniqueness constraint only applies
 * to the fields directly contained within an object, and does not prevent an
 * object from having a field value that is an object (or that is an array
 * containing one or more objects) that use a field name that is also in use
 * in the outer object.  Similarly, if an array contains multiple JSON objects,
 * then there is no restriction preventing the same field names from being
 * used in separate objects within that array.
 * <BR><BR>
 * The string representation of a JSON object is an open curly brace (U+007B)
 * followed by a comma-delimited list of the name-value pairs that comprise the
 * fields in that object and a closing curly brace (U+007D).  Each name-value
 * pair is represented as a JSON string followed by a colon and the appropriate
 * string representation of the value.  There must not be a comma between the
 * last field and the closing curly brace.  There may optionally be any amount
 * of whitespace (where whitespace characters include the ASCII space,
 * horizontal tab, line feed, and carriage return characters) after the open
 * curly brace, on either or both sides of the colon separating a field name
 * from its value, on either or both sides of commas separating fields, and
 * before the closing curly brace.  The order in which fields appear in the
 * string representation is not considered significant.
 * <BR><BR>
 * The string representation returned by the {@link #toString()} method (or
 * appended to the buffer provided to the {@link #toString(StringBuilder)}
 * method) will include one space before each field name and one space before
 * the closing curly brace.  There will not be any space on either side of the
 * colon separating the field name from its value, and there will not be any
 * space between a field value and the comma that follows it.  The string
 * representation of each field name will use the same logic as the
 * {@link JSONString#toString()} method, and the string representation of each
 * field value will be obtained using that value's {@code toString} method.
 * <BR><BR>
 * The normalized string representation will not include any optional spaces,
 * and the normalized string representation of each field value will be obtained
 * using that value's {@code toNormalizedString} method.  Field names will be
 * treated in a case-sensitive manner, but all characters outside the LDAP
 * printable character set will be escaped using the {@code \}{@code u}-style
 * Unicode encoding.  The normalized string representation will have fields
 * listed in lexicographic order.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONObject
       extends JSONValue
{
  /**
   * A pre-allocated empty JSON object.
   */
  @NotNull public static final JSONObject EMPTY_OBJECT = new JSONObject(
       Collections.<String,JSONValue>emptyMap());



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4209509956709292141L;



  // A counter to use in decode processing.
  private int decodePos;

  // The hash code for this JSON object.
  @Nullable private Integer hashCode;

  // The set of fields for this JSON object.
  @NotNull private final Map<String,JSONValue> fields;

  // The string representation for this JSON object.
  @Nullable private String stringRepresentation;

  // A buffer to use in decode processing.
  @Nullable private final StringBuilder decodeBuffer;



  /**
   * Creates a new JSON object with the provided fields.
   *
   * @param  fields  The fields to include in this JSON object.  It may be
   *                 {@code null} or empty if this object should not have any
   *                 fields.
   */
  public JSONObject(@Nullable final JSONField... fields)
  {
    if ((fields == null) || (fields.length == 0))
    {
      this.fields = Collections.emptyMap();
    }
    else
    {
      final LinkedHashMap<String,JSONValue> m =
           new LinkedHashMap<>(StaticUtils.computeMapCapacity(fields.length));
      for (final JSONField f : fields)
      {
        m.put(f.getName(), f.getValue());
      }
      this.fields = Collections.unmodifiableMap(m);
    }

    hashCode = null;
    stringRepresentation = null;

    // We don't need to decode anything.
    decodePos = -1;
    decodeBuffer = null;
  }



  /**
   * Creates a new JSON object with the provided fields.
   *
   * @param  fields  The set of fields for this JSON object.  It may be
   *                 {@code null} or empty if there should not be any fields.
   */
  public JSONObject(@Nullable final Map<String,JSONValue> fields)
  {
    if (fields == null)
    {
      this.fields = Collections.emptyMap();
    }
    else
    {
      this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    hashCode = null;
    stringRepresentation = null;

    // We don't need to decode anything.
    decodePos = -1;
    decodeBuffer = null;
  }



  /**
   * Creates a new JSON object parsed from the provided string.
   *
   * @param  stringRepresentation  The string to parse as a JSON object.  It
   *                               must represent exactly one JSON object.
   *
   * @throws  JSONException  If the provided string cannot be parsed as a valid
   *                         JSON object.
   */
  public JSONObject(@NotNull final String stringRepresentation)
         throws JSONException
  {
    this.stringRepresentation = stringRepresentation;

    final char[] chars = stringRepresentation.toCharArray();
    decodePos = 0;
    decodeBuffer = new StringBuilder(chars.length);

    // The JSON object must start with an open curly brace.
    final Object firstToken = readToken(chars);
    if (! firstToken.equals('{'))
    {
      throw new JSONException(ERR_OBJECT_DOESNT_START_WITH_BRACE.get(
           stringRepresentation));
    }

    final LinkedHashMap<String,JSONValue> m =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    readObject(chars, m);
    fields = Collections.unmodifiableMap(m);

    skipWhitespace(chars);
    if (decodePos < chars.length)
    {
      throw new JSONException(ERR_OBJECT_DATA_BEYOND_END.get(
           stringRepresentation, decodePos));
    }
  }



  /**
   * Creates a new JSON object with the provided information.
   *
   * @param  fields                The set of fields for this JSON object.
   * @param  stringRepresentation  The string representation for the JSON
   *                               object.
   */
  JSONObject(@NotNull final LinkedHashMap<String,JSONValue> fields,
             @NotNull final String stringRepresentation)
  {
    this.fields = Collections.unmodifiableMap(fields);
    this.stringRepresentation = stringRepresentation;

    hashCode = null;
    decodePos = -1;
    decodeBuffer = null;
  }



  /**
   * Reads a token from the provided character array, skipping over any
   * insignificant whitespace that may be before the token.  The token that is
   * returned will be one of the following:
   * <UL>
   *   <LI>A {@code Character} that is an opening curly brace.</LI>
   *   <LI>A {@code Character} that is a closing curly brace.</LI>
   *   <LI>A {@code Character} that is an opening square bracket.</LI>
   *   <LI>A {@code Character} that is a closing square bracket.</LI>
   *   <LI>A {@code Character} that is a colon.</LI>
   *   <LI>A {@code Character} that is a comma.</LI>
   *   <LI>A {@link JSONBoolean}.</LI>
   *   <LI>A {@link JSONNull}.</LI>
   *   <LI>A {@link JSONNumber}.</LI>
   *   <LI>A {@link JSONString}.</LI>
   * </UL>
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @return  The token that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the
   *                         token.
   */
  @NotNull()
  private Object readToken(@NotNull final char[] chars)
          throws JSONException
  {
    skipWhitespace(chars);

    final char c = readCharacter(chars, false);
    switch (c)
    {
      case '{':
      case '}':
      case '[':
      case ']':
      case ':':
      case ',':
        // This is a token character that we will return as-is.
        decodePos++;
        return c;

      case '"':
        // This is the start of a JSON string.
        return readString(chars);

      case 't':
      case 'f':
        // This is the start of a JSON true or false value.
        return readBoolean(chars);

      case 'n':
        // This is the start of a JSON null value.
        return readNull(chars);

      case '-':
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        // This is the start of a JSON number value.
        return readNumber(chars);

      default:
        // This is not a valid JSON token.
        throw new JSONException(ERR_OBJECT_INVALID_FIRST_TOKEN_CHAR.get(
             new String(chars), String.valueOf(c), decodePos));

    }
  }



  /**
   * Skips over any valid JSON whitespace at the current position in the
   * provided array.
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @throws  JSONException  If a problem is encountered while skipping
   *                         whitespace.
   */
  private void skipWhitespace(@NotNull final char[] chars)
          throws JSONException
  {
    while (decodePos < chars.length)
    {
      switch (chars[decodePos])
      {
        // The space, tab, newline, and carriage return characters are
        // considered valid JSON whitespace.
        case ' ':
        case '\t':
        case '\n':
        case '\r':
          decodePos++;
          break;

        // Technically, JSON does not provide support for comments.  But this
        // implementation will accept three types of comments:
        // - Comments that start with /* and end with */ (potentially spanning
        //   multiple lines).
        // - Comments that start with // and continue until the end of the line.
        // - Comments that start with # and continue until the end of the line.
        // All comments will be ignored by the parser.
        case '/':
          final int commentStartPos = decodePos;
          if ((decodePos+1) >= chars.length)
          {
            return;
          }
          else if (chars[decodePos+1] == '/')
          {
            decodePos += 2;

            // Keep reading until we encounter a newline or carriage return, or
            // until we hit the end of the string.
            while (decodePos < chars.length)
            {
              if ((chars[decodePos] == '\n') || (chars[decodePos] == '\r'))
              {
                break;
              }
              decodePos++;
            }
            break;
          }
          else if (chars[decodePos+1] == '*')
          {
            decodePos += 2;

            // Keep reading until we encounter "*/".  We must encounter "*/"
            // before hitting the end of the string.
            boolean closeFound = false;
            while (decodePos < chars.length)
            {
              if (chars[decodePos] == '*')
              {
                if (((decodePos+1) < chars.length) &&
                    (chars[decodePos+1] == '/'))
                {
                  closeFound = true;
                  decodePos += 2;
                  break;
                }
              }
              decodePos++;
            }

            if (! closeFound)
            {
              throw new JSONException(ERR_OBJECT_UNCLOSED_COMMENT.get(
                   new String(chars), commentStartPos));
            }
            break;
          }
          else
          {
            return;
          }

        case '#':
          // Keep reading until we encounter a newline or carriage return, or
          // until we hit the end of the string.
          while (decodePos < chars.length)
          {
            if ((chars[decodePos] == '\n') || (chars[decodePos] == '\r'))
            {
              break;
            }
            decodePos++;
          }
          break;

        default:
          return;
      }
    }
  }



  /**
   * Reads the character at the specified position and optionally advances the
   * position.
   *
   * @param  chars            The characters that comprise the string
   *                          representation of the JSON object.
   * @param  advancePosition  Indicates whether to advance the value of the
   *                          position indicator after reading the character.
   *                          If this is {@code false}, then this method will be
   *                          used to "peek" at the next character without
   *                          consuming it.
   *
   * @return  The character that was read.
   *
   * @throws  JSONException  If the end of the value was encountered when a
   *                         character was expected.
   */
  private char readCharacter(@NotNull final char[] chars,
                             final boolean advancePosition)
          throws JSONException
  {
    if (decodePos >= chars.length)
    {
      throw new JSONException(
           ERR_OBJECT_UNEXPECTED_END_OF_STRING.get(new String(chars)));
    }

    final char c = chars[decodePos];
    if (advancePosition)
    {
      decodePos++;
    }
    return c;
  }



  /**
   * Reads a JSON string staring at the specified position in the provided
   * character array.
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @return  The JSON string that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         string.
   */
  @NotNull()
  private JSONString readString(@NotNull final char[] chars)
          throws JSONException
  {
    // Create a buffer to hold the string.  Note that if we've gotten here then
    // we already know that the character at the provided position is a quote,
    // so we can read past it in the process.
    final int startPos = decodePos++;
    decodeBuffer.setLength(0);
    while (true)
    {
      final char c = readCharacter(chars, true);
      if (c == '\\')
      {
        final int escapedCharPos = decodePos;
        final char escapedChar = readCharacter(chars, true);
        switch (escapedChar)
        {
          case '"':
          case '\\':
          case '/':
            decodeBuffer.append(escapedChar);
            break;
          case 'b':
            decodeBuffer.append('\b');
            break;
          case 'f':
            decodeBuffer.append('\f');
            break;
          case 'n':
            decodeBuffer.append('\n');
            break;
          case 'r':
            decodeBuffer.append('\r');
            break;
          case 't':
            decodeBuffer.append('\t');
            break;

          case 'u':
            final char[] hexChars =
            {
              readCharacter(chars, true),
              readCharacter(chars, true),
              readCharacter(chars, true),
              readCharacter(chars, true)
            };
            try
            {
              decodeBuffer.append(
                   (char) Integer.parseInt(new String(hexChars), 16));
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new JSONException(
                   ERR_OBJECT_INVALID_UNICODE_ESCAPE.get(new String(chars),
                        escapedCharPos),
                   e);
            }
            break;

          default:
            throw new JSONException(ERR_OBJECT_INVALID_ESCAPED_CHAR.get(
                 new String(chars), escapedChar, escapedCharPos));
        }
      }
      else if (c == '"')
      {
        return new JSONString(decodeBuffer.toString(),
             new String(chars, startPos, (decodePos - startPos)));
      }
      else
      {
        if (c <= '\u001F')
        {
          throw new JSONException(ERR_OBJECT_UNESCAPED_CONTROL_CHAR.get(
               new String(chars), String.format("%04X", (int) c),
               (decodePos - 1)));
        }

        decodeBuffer.append(c);
      }
    }
  }



  /**
   * Reads a JSON Boolean staring at the specified position in the provided
   * character array.
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @return  The JSON Boolean that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         Boolean.
   */
  @NotNull()
  private JSONBoolean readBoolean(@NotNull final char[] chars)
          throws JSONException
  {
    final int startPos = decodePos;
    final char firstCharacter = readCharacter(chars, true);
    if (firstCharacter == 't')
    {
      if ((readCharacter(chars, true) == 'r') &&
          (readCharacter(chars, true) == 'u') &&
          (readCharacter(chars, true) == 'e'))
      {
        return JSONBoolean.TRUE;
      }
    }
    else if (firstCharacter == 'f')
    {
      if ((readCharacter(chars, true) == 'a') &&
          (readCharacter(chars, true) == 'l') &&
          (readCharacter(chars, true) == 's') &&
          (readCharacter(chars, true) == 'e'))
      {
        return JSONBoolean.FALSE;
      }
    }

    throw new JSONException(ERR_OBJECT_UNABLE_TO_PARSE_BOOLEAN.get(
         new String(chars), startPos));
  }



  /**
   * Reads a JSON null staring at the specified position in the provided
   * character array.
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @return  The JSON null that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         null.
   */
  @NotNull()
  private JSONNull readNull(@NotNull final char[] chars)
          throws JSONException
  {
    final int startPos = decodePos;
    if ((readCharacter(chars, true) == 'n') &&
        (readCharacter(chars, true) == 'u') &&
        (readCharacter(chars, true) == 'l') &&
        (readCharacter(chars, true) == 'l'))
    {
      return JSONNull.NULL;
    }

    throw new JSONException(ERR_OBJECT_UNABLE_TO_PARSE_NULL.get(
         new String(chars), startPos));
  }



  /**
   * Reads a JSON number staring at the specified position in the provided
   * character array.
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @return  The JSON number that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         number.
   */
  @NotNull()
  private JSONNumber readNumber(@NotNull final char[] chars)
          throws JSONException
  {
    // Read until we encounter whitespace, a comma, a closing square bracket, or
    // a closing curly brace.  Then try to parse what we read as a number.
    final int startPos = decodePos;
    decodeBuffer.setLength(0);

    while (true)
    {
      final char c = readCharacter(chars, true);
      switch (c)
      {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case ',':
        case ']':
        case '}':
          // We need to decrement the position indicator since the last one we
          // read wasn't part of the number.
          decodePos--;
          return new JSONNumber(decodeBuffer.toString());

        default:
          decodeBuffer.append(c);
      }
    }
  }



  /**
   * Reads a JSON array starting at the specified position in the provided
   * character array.  Note that this method assumes that the opening square
   * bracket has already been read.
   *
   * @param  chars  The characters that comprise the string representation of
   *                the JSON object.
   *
   * @return  The JSON array that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         array.
   */
  @NotNull()
  private JSONArray readArray(@NotNull final char[] chars)
          throws JSONException
  {
    // The opening square bracket will have already been consumed, so read
    // JSON values until we hit a closing square bracket.
    final ArrayList<JSONValue> values = new ArrayList<>(10);
    boolean firstToken = true;
    while (true)
    {
      // If this is the first time through, it is acceptable to find a closing
      // square bracket.  Otherwise, we expect to find a JSON value, an opening
      // square bracket to denote the start of an embedded array, or an opening
      // curly brace to denote the start of an embedded JSON object.
      int p = decodePos;
      Object token = readToken(chars);
      if (token instanceof JSONValue)
      {
        values.add((JSONValue) token);
      }
      else if (token.equals('['))
      {
        values.add(readArray(chars));
      }
      else if (token.equals('{'))
      {
        final LinkedHashMap<String,JSONValue> fieldMap =
             new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
        values.add(readObject(chars, fieldMap));
      }
      else if (token.equals(']') && firstToken)
      {
        // It's an empty array.
        return JSONArray.EMPTY_ARRAY;
      }
      else
      {
        throw new JSONException(
             ERR_OBJECT_INVALID_TOKEN_WHEN_ARRAY_VALUE_EXPECTED.get(
                  new String(chars), String.valueOf(token), p));
      }

      firstToken = false;


      // If we've gotten here, then we found a JSON value.  It must be followed
      // by either a comma (to indicate that there's at least one more value) or
      // a closing square bracket (to denote the end of the array).
      p = decodePos;
      token = readToken(chars);
      if (token.equals(']'))
      {
        return new JSONArray(values);
      }
      else if (! token.equals(','))
      {
        throw new JSONException(
             ERR_OBJECT_INVALID_TOKEN_WHEN_ARRAY_COMMA_OR_BRACKET_EXPECTED.get(
                  new String(chars), String.valueOf(token), p));
      }
    }
  }



  /**
   * Reads a JSON object starting at the specified position in the provided
   * character array.  Note that this method assumes that the opening curly
   * brace has already been read.
   *
   * @param  chars   The characters that comprise the string representation of
   *                 the JSON object.
   * @param  fields  The map into which to place the fields that are read.  The
   *                 returned object will include an unmodifiable view of this
   *                 map, but the caller may use the map directly if desired.
   *
   * @return  The JSON object that was read.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         object.
   */
  @NotNull()
  private JSONObject readObject(@NotNull final char[] chars,
                                @NotNull final Map<String,JSONValue> fields)
          throws JSONException
  {
    boolean firstField = true;
    while (true)
    {
      // Read the next token.  It must be a JSONString, unless we haven't read
      // any fields yet in which case it can be a closing curly brace to
      // indicate that it's an empty object.
      int p = decodePos;
      final String fieldName;
      Object token = readToken(chars);
      if (token instanceof JSONString)
      {
        fieldName = ((JSONString) token).stringValue();
        if (fields.containsKey(fieldName))
        {
          throw new JSONException(ERR_OBJECT_DUPLICATE_FIELD.get(
               new String(chars), fieldName));
        }
      }
      else if (firstField && token.equals('}'))
      {
        return new JSONObject(fields);
      }
      else
      {
        throw new JSONException(ERR_OBJECT_EXPECTED_STRING.get(
             new String(chars), String.valueOf(token), p));
      }
      firstField = false;

      // Read the next token.  It must be a colon.
      p = decodePos;
      token = readToken(chars);
      if (! token.equals(':'))
      {
        throw new JSONException(ERR_OBJECT_EXPECTED_COLON.get(new String(chars),
             String.valueOf(token), p));
      }

      // Read the next token.  It must be one of the following:
      // - A JSONValue
      // - An opening square bracket, designating the start of an array.
      // - An opening curly brace, designating the start of an object.
      p = decodePos;
      token = readToken(chars);
      if (token instanceof JSONValue)
      {
        fields.put(fieldName, (JSONValue) token);
      }
      else if (token.equals('['))
      {
        final JSONArray a = readArray(chars);
        fields.put(fieldName, a);
      }
      else if (token.equals('{'))
      {
        final LinkedHashMap<String,JSONValue> m =
             new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
        final JSONObject o = readObject(chars, m);
        fields.put(fieldName, o);
      }
      else
      {
        throw new JSONException(ERR_OBJECT_EXPECTED_VALUE.get(new String(chars),
             String.valueOf(token), p, fieldName));
      }

      // Read the next token.  It must be either a comma (to indicate that
      // there will be another field) or a closing curly brace (to indicate
      // that the end of the object has been reached).
      p = decodePos;
      token = readToken(chars);
      if (token.equals('}'))
      {
        return new JSONObject(fields);
      }
      else if (! token.equals(','))
      {
        throw new JSONException(ERR_OBJECT_EXPECTED_COMMA_OR_CLOSE_BRACE.get(
             new String(chars), String.valueOf(token), p));
      }
    }
  }



  /**
   * Retrieves a map of the fields contained in this JSON object.
   *
   * @return  A map of the fields contained in this JSON object.
   */
  @NotNull()
  public Map<String,JSONValue> getFields()
  {
    return fields;
  }



  /**
   * Retrieves the value for the specified field.
   *
   * @param  name  The name of the field for which to retrieve the value.  It
   *               will be treated in a case-sensitive manner.
   *
   * @return  The value for the specified field, or {@code null} if the
   *          requested field is not present in the JSON object.
   */
  @Nullable()
  public JSONValue getField(@NotNull final String name)
  {
    return fields.get(name);
  }



  /**
   * Retrieves the value of the specified field as a string.
   *
   * @param  name  The name of the field for which to retrieve the string value.
   *               It will be treated in a case-sensitive manner.
   *
   * @return  The value of the specified field as a string, or {@code null} if
   *          this JSON object does not have a field with the specified name, or
   *          if the value of that field is not a string.
   */
  @Nullable()
  public String getFieldAsString(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONString)))
    {
      return null;
    }

    return ((JSONString) value).stringValue();
  }



  /**
   * Retrieves the value of the specified field as a Boolean.
   *
   * @param  name  The name of the field for which to retrieve the Boolean
   *               value.  It will be treated in a case-sensitive manner.
   *
   * @return  The value of the specified field as a Boolean, or {@code null} if
   *          this JSON object does not have a field with the specified name, or
   *          if the value of that field is not a Boolean.
   */
  @Nullable()
  public Boolean getFieldAsBoolean(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONBoolean)))
    {
      return null;
    }

    return ((JSONBoolean) value).booleanValue();
  }



  /**
   * Retrieves the value of the specified field as an integer.
   *
   * @param  name  The name of the field for which to retrieve the integer
   *               value.  It will be treated in a case-sensitive manner.
   *
   * @return  The value of the specified field as an integer, or {@code null} if
   *          this JSON object does not have a field with the specified name, or
   *          if the value of that field is not a number that can be exactly
   *          represented as an integer.
   */
  @Nullable()
  public Integer getFieldAsInteger(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONNumber)))
    {
      return null;
    }

    try
    {
      final JSONNumber number = (JSONNumber) value;
      return number.getValue().intValueExact();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value of the specified field as a long.
   *
   * @param  name  The name of the field for which to retrieve the long value.
   *               It will be treated in a case-sensitive manner.
   *
   * @return  The value of the specified field as a long, or {@code null} if
   *          this JSON object does not have a field with the specified name, or
   *          if the value of that field is not a number that can be exactly
   *          represented as a long.
   */
  @Nullable()
  public Long getFieldAsLong(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONNumber)))
    {
      return null;
    }

    try
    {
      final JSONNumber number = (JSONNumber) value;
      return number.getValue().longValueExact();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value of the specified field as a BigDecimal.
   *
   * @param  name  The name of the field for which to retrieve the BigDecimal
   *               value.  It will be treated in a case-sensitive manner.
   *
   * @return  The value of the specified field as a BigDecimal, or {@code null}
   *          if this JSON object does not have a field with the specified name,
   *          or if the value of that field is not a number.
   */
  @Nullable()
  public BigDecimal getFieldAsBigDecimal(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONNumber)))
    {
      return null;
    }

    return ((JSONNumber) value).getValue();
  }



  /**
   * Retrieves the value of the specified field as a JSON object.
   *
   * @param  name  The name of the field for which to retrieve the value.  It
   *               will be treated in a case-sensitive manner.
   *
   * @return  The value of the specified field as a JSON object, or {@code null}
   *          if this JSON object does not have a field with the specified name,
   *          or if the value of that field is not an object.
   */
  @Nullable()
  public JSONObject getFieldAsObject(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONObject)))
    {
      return null;
    }

    return (JSONObject) value;
  }



  /**
   * Retrieves a list of the elements in the specified array field.
   *
   * @param  name  The name of the field for which to retrieve the array values.
   *               It will be treated in a case-sensitive manner.
   *
   * @return  A list of the elements in the specified array field, or
   *          {@code null} if this JSON object does not have a field with the
   *          specified name, or if the value of that field is not an array.
   */
  @Nullable()
  public List<JSONValue> getFieldAsArray(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    if ((value == null) || (! (value instanceof JSONArray)))
    {
      return null;
    }

    return ((JSONArray) value).getValues();
  }



  /**
   * Indicates whether this JSON object has a null field with the specified
   * name.
   *
   * @param  name  The name of the field for which to make the determination.
   *               It will be treated in a case-sensitive manner.
   *
   * @return  {@code true} if this JSON object has a null field with the
   *          specified name, or {@code false} if this JSON object does not have
   *          a field with the specified name, or if the value of that field is
   *          not a null.
   */
  public boolean hasNullField(@NotNull final String name)
  {
    final JSONValue value = fields.get(name);
    return ((value != null) && (value instanceof JSONNull));
  }



  /**
   * Indicates whether this JSON object has a field with the specified name.
   *
   * @param  fieldName  The name of the field for which to make the
   *                    determination.  It will be treated in a case-sensitive
   *                    manner.
   *
   * @return  {@code true} if this JSON object has a field with the specified
   *          name, or {@code false} if not.
   */
  public boolean hasField(@NotNull final String fieldName)
  {
    return fields.containsKey(fieldName);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    if (hashCode == null)
    {
      int hc = 0;
      for (final Map.Entry<String,JSONValue> e : fields.entrySet())
      {
        hc += e.getKey().hashCode() + e.getValue().hashCode();
      }

      hashCode = hc;
    }

    return hashCode;
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

    if (o instanceof JSONObject)
    {
      final JSONObject obj = (JSONObject) o;
      return fields.equals(obj.fields);
    }

    return false;
  }



  /**
   * Indicates whether this JSON object is considered equal to the provided
   * object, subject to the specified constraints.
   *
   * @param  o                    The object to compare against this JSON
   *                              object.  It must not be {@code null}.
   * @param  ignoreFieldNameCase  Indicates whether to ignore differences in
   *                              capitalization in field names.
   * @param  ignoreValueCase      Indicates whether to ignore differences in
   *                              capitalization in values that are JSON
   *                              strings.
   * @param  ignoreArrayOrder     Indicates whether to ignore differences in the
   *                              order of elements within an array.
   *
   * @return  {@code true} if this JSON object is considered equal to the
   *          provided object (subject to the specified constraints), or
   *          {@code false} if not.
   */
  public boolean equals(@NotNull final JSONObject o,
                        final boolean ignoreFieldNameCase,
                        final boolean ignoreValueCase,
                        final boolean ignoreArrayOrder)
  {
    // See if we can do a straight-up Map.equals.  If so, just do that.
    if ((! ignoreFieldNameCase) && (! ignoreValueCase) && (! ignoreArrayOrder))
    {
      return fields.equals(o.fields);
    }

    // Make sure they have the same number of fields.
    if (fields.size() != o.fields.size())
    {
      return false;
    }

    // Optimize for the case in which we field names are case sensitive.
    if (! ignoreFieldNameCase)
    {
      for (final Map.Entry<String,JSONValue> e : fields.entrySet())
      {
        final JSONValue thisValue = e.getValue();
        final JSONValue thatValue = o.fields.get(e.getKey());
        if (thatValue == null)
        {
          return false;
        }

        if (! thisValue.equals(thatValue, ignoreFieldNameCase, ignoreValueCase,
             ignoreArrayOrder))
        {
          return false;
        }
      }

      return true;
    }


    // If we've gotten here, then we know that we need to treat field names in
    // a case-insensitive manner.  Create a new map that we can remove fields
    // from as we find matches.  This can help avoid false-positive matches in
    // which multiple fields in the first map match the same field in the second
    // map (e.g., because they have field names that differ only in case and
    // values that are logically equivalent).  It also makes iterating through
    // the values faster as we make more progress.
    final HashMap<String,JSONValue> thatMap = new HashMap<>(o.fields);
    final Iterator<Map.Entry<String,JSONValue>> thisIterator =
         fields.entrySet().iterator();
    while (thisIterator.hasNext())
    {
      final Map.Entry<String,JSONValue> thisEntry = thisIterator.next();
      final String thisFieldName = thisEntry.getKey();
      final JSONValue thisValue = thisEntry.getValue();

      final Iterator<Map.Entry<String,JSONValue>> thatIterator =
           thatMap.entrySet().iterator();

      boolean found = false;
      while (thatIterator.hasNext())
      {
        final Map.Entry<String,JSONValue> thatEntry = thatIterator.next();
        final String thatFieldName = thatEntry.getKey();
        if (! thisFieldName.equalsIgnoreCase(thatFieldName))
        {
          continue;
        }

        final JSONValue thatValue = thatEntry.getValue();
        if (thisValue.equals(thatValue, ignoreFieldNameCase, ignoreValueCase,
             ignoreArrayOrder))
        {
          found = true;
          thatIterator.remove();
          break;
        }
      }

      if (! found)
      {
        return false;
      }
    }

    return true;
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
    return ((v instanceof JSONObject) &&
         equals((JSONObject) v, ignoreFieldNameCase, ignoreValueCase,
              ignoreArrayOrder));
  }



  /**
   * Retrieves a string representation of this JSON object.  If this object was
   * decoded from a string, then the original string representation will be
   * used.  Otherwise, a single-line string representation will be constructed.
   *
   * @return  A string representation of this JSON object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    if (stringRepresentation == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer);
      stringRepresentation = buffer.toString();
    }

    return stringRepresentation;
  }



  /**
   * Appends a string representation of this JSON object to the provided buffer.
   * If this object was decoded from a string, then the original string
   * representation will be used.  Otherwise, a single-line string
   * representation will be constructed.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    if (stringRepresentation != null)
    {
      buffer.append(stringRepresentation);
      return;
    }

    buffer.append("{ ");

    final Iterator<Map.Entry<String,JSONValue>> iterator =
         fields.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<String,JSONValue> e = iterator.next();
      JSONString.encodeString(e.getKey(), buffer);
      buffer.append(':');
      e.getValue().toString(buffer);

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
      buffer.append(' ');
    }

    buffer.append('}');
  }



  /**
   * Retrieves a user-friendly string representation of this JSON object that
   * may be formatted across multiple lines for better readability.  The last
   * line will not include a trailing line break.
   *
   * @return  A user-friendly string representation of this JSON object that may
   *          be formatted across multiple lines for better readability.
   */
  @NotNull()
  public String toMultiLineString()
  {
    final JSONBuffer jsonBuffer = new JSONBuffer(null, 0, true);
    appendToJSONBuffer(jsonBuffer);
    return jsonBuffer.toString();
  }



  /**
   * Retrieves a single-line string representation of this JSON object.
   *
   * @return  A single-line string representation of this JSON object.
   */
  @Override()
  @NotNull
  public String toSingleLineString()
  {
    final StringBuilder buffer = new StringBuilder();
    toSingleLineString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of this JSON object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toSingleLineString(@NotNull final StringBuilder buffer)
  {
    buffer.append("{ ");

    final Iterator<Map.Entry<String,JSONValue>> iterator =
         fields.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<String,JSONValue> e = iterator.next();
      JSONString.encodeString(e.getKey(), buffer);
      buffer.append(':');
      e.getValue().toSingleLineString(buffer);

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
      buffer.append(' ');
    }

    buffer.append('}');
  }



  /**
   * Retrieves a normalized string representation of this JSON object.  The
   * normalized representation of the JSON object will have the following
   * characteristics:
   * <UL>
   *   <LI>It will not include any line breaks.</LI>
   *   <LI>It will not include any spaces around the enclosing braces.</LI>
   *   <LI>It will not include any spaces around the commas used to separate
   *       fields.</LI>
   *   <LI>Field names will be treated in a case-sensitive manner and will not
   *       be altered.</LI>
   *   <LI>Field values will be normalized.</LI>
   *   <LI>Fields will be listed in lexicographic order by field name.</LI>
   * </UL>
   *
   * @return  A normalized string representation of this JSON object.
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
   * Appends a normalized string representation of this JSON object to the
   * provided buffer.  The normalized representation of the JSON object will
   * have the following characteristics:
   * <UL>
   *   <LI>It will not include any line breaks.</LI>
   *   <LI>It will not include any spaces around the enclosing braces.</LI>
   *   <LI>It will not include any spaces around the commas used to separate
   *       fields.</LI>
   *   <LI>Field names will be treated in a case-sensitive manner and will not
   *       be altered.</LI>
   *   <LI>Field values will be normalized.</LI>
   *   <LI>Fields will be listed in lexicographic order by field name.</LI>
   * </UL>
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    toNormalizedString(buffer, false, true, false);
  }



  /**
   * Retrieves a normalized string representation of this JSON object.  The
   * normalized representation of the JSON object will have the following
   * characteristics:
   * <UL>
   *   <LI>It will not include any line breaks.</LI>
   *   <LI>It will not include any spaces around the enclosing braces.</LI>
   *   <LI>It will not include any spaces around the commas used to separate
   *       fields.</LI>
   *   <LI>Case sensitivity of field names and values will be controlled by
   *       argument values.
   *   <LI>Fields will be listed in lexicographic order by field name.</LI>
   * </UL>
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
   * @return  A normalized string representation of this JSON object.
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
   * Appends a normalized string representation of this JSON object to the
   * provided buffer.  The normalized representation of the JSON object will
   * have the following characteristics:
   * <UL>
   *   <LI>It will not include any line breaks.</LI>
   *   <LI>It will not include any spaces around the enclosing braces.</LI>
   *   <LI>It will not include any spaces around the commas used to separate
   *       fields.</LI>
   *   <LI>Field names will be treated in a case-sensitive manner and will not
   *       be altered.</LI>
   *   <LI>Field values will be normalized.</LI>
   *   <LI>Fields will be listed in lexicographic order by field name.</LI>
   * </UL>
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
    // The normalized representation needs to have the fields in a predictable
    // order, which we will accomplish using the lexicographic ordering that a
    // TreeMap will provide.  Field names may or may not be treated in a
    // case-sensitive manner, but we still need to construct a normalized way of
    // escaping non-printable characters in each field.
    final TreeMap<String,String> m = new TreeMap<>();
    for (final Map.Entry<String,JSONValue> e : fields.entrySet())
    {
      m.put(
           new JSONString(e.getKey()).toNormalizedString(false,
                ignoreFieldNameCase, false),
           e.getValue().toNormalizedString(ignoreFieldNameCase, ignoreValueCase,
                ignoreArrayOrder));
    }

    buffer.append('{');
    final Iterator<Map.Entry<String,String>> iterator = m.entrySet().iterator();
    while (iterator.hasNext())
    {
      final Map.Entry<String,String> e = iterator.next();
      buffer.append(e.getKey());
      buffer.append(':');
      buffer.append(e.getValue());

      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append('}');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final JSONBuffer buffer)
  {
    buffer.beginObject();

    for (final Map.Entry<String,JSONValue> field : fields.entrySet())
    {
      final String name = field.getKey();
      final JSONValue value = field.getValue();
      value.appendToJSONBuffer(name, buffer);
    }

    buffer.endObject();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final String fieldName,
                                 @NotNull final JSONBuffer buffer)
  {
    buffer.beginObject(fieldName);

    for (final Map.Entry<String,JSONValue> field : fields.entrySet())
    {
      final String name = field.getKey();
      final JSONValue value = field.getValue();
      value.appendToJSONBuffer(name, buffer);
    }

    buffer.endObject();
  }
}
