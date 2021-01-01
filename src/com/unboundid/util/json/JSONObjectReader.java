/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides a mechanism for reading JSON objects from an input
 * stream.  It assumes that any non-ASCII data that may be read from the input
 * stream is encoded as UTF-8.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class JSONObjectReader
       implements Closeable
{
  // The buffer used to hold the bytes of the object currently being read.
  @NotNull private final ByteStringBuffer currentObjectBytes;

  // A buffer to use to hold strings being decoded.
  @NotNull private final ByteStringBuffer stringBuffer;

  // The input stream from which JSON objects will be read.
  @NotNull private final InputStream inputStream;



  /**
   * Creates a new JSON object reader that will read objects from the provided
   * input stream.
   *
   * @param  inputStream  The input stream from which the data should be read.
   */
  public JSONObjectReader(@NotNull final InputStream inputStream)
  {
    this(inputStream, true);
  }



  /**
   * Creates a new JSON object reader that will read objects from the provided
   * input stream.
   *
   * @param  inputStream        The input stream from which the data should be
   *                            read.
   * @param  bufferInputStream  Indicates whether to buffer the input stream.
   *                            This should be {@code false} if the input stream
   *                            could be used for any purpose other than reading
   *                            JSON objects after one or more objects are read.
   */
  public JSONObjectReader(@NotNull final InputStream inputStream,
                          final boolean bufferInputStream)
  {
    if (bufferInputStream && (! (inputStream instanceof BufferedInputStream)))
    {
      this.inputStream = new BufferedInputStream(inputStream);
    }
    else
    {
      this.inputStream = inputStream;
    }

    currentObjectBytes = new ByteStringBuffer();
    stringBuffer = new ByteStringBuffer();
  }



  /**
   * Reads the next JSON object from the input stream.
   *
   * @return  The JSON object that was read, or {@code null} if the end of the
   *          end of the stream has been reached.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If the data read
   */
  @Nullable()
  public JSONObject readObject()
         throws IOException, JSONException
  {
    // Skip over any whitespace before the beginning of the next object.
    skipWhitespace();
    currentObjectBytes.clear();


    // The JSON object must start with an open curly brace.
    final Object firstToken = readToken(true);
    if (firstToken == null)
    {
      return null;
    }

    if (! firstToken.equals('{'))
    {
      throw new JSONException(ERR_OBJECT_READER_ILLEGAL_START_OF_OBJECT.get(
           String.valueOf(firstToken)));
    }

    final LinkedHashMap<String,JSONValue> m =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    readObject(m);

    return new JSONObject(m, currentObjectBytes.toString());
  }



  /**
   * Closes this JSON object reader and the underlying input stream.
   *
   * @throws  IOException  If a problem is encountered while closing the
   *                       underlying input stream.
   */
  @Override()
  public void close()
         throws IOException
  {
    inputStream.close();
  }



  /**
   * Reads a token from the input stream, skipping over any insignificant
   * whitespace that may be before the token.  The token that is returned will
   * be one of the following:
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
   * @param  allowEndOfStream  Indicates whether it is acceptable to encounter
   *                           the end of the input stream.  This should only
   *                           be {@code true} when the token is expected to be
   *                           the open parenthesis of the outermost JSON
   *                           object.
   *
   * @return  The token that was read, or {@code null} if the end of the input
   *          stream was reached.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the
   *                         token.
   */
  @Nullable()
  private Object readToken(final boolean allowEndOfStream)
          throws IOException, JSONException
  {
    skipWhitespace();

    final Byte byteRead = readByte(allowEndOfStream);
    if (byteRead == null)
    {
      return null;
    }

    switch (byteRead)
    {
      case '{':
        return '{';
      case '}':
        return '}';
      case '[':
        return '[';
      case ']':
        return ']';
      case ':':
        return ':';
      case ',':
        return ',';

      case '"':
        // This is the start of a JSON string.
        return readString();

      case 't':
      case 'f':
        // This is the start of a JSON true or false value.
        return readBoolean();

      case 'n':
        // This is the start of a JSON null value.
        return readNull();

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
        return readNumber();

      default:
        throw new JSONException(
             ERR_OBJECT_READER_ILLEGAL_FIRST_CHAR_FOR_JSON_TOKEN.get(
                  currentObjectBytes.length(), byteToCharString(byteRead)));
    }
  }



  /**
   * Skips over any valid JSON whitespace at the current position in the input
   * stream.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem is encountered while skipping
   *                         whitespace.
   */
  private void skipWhitespace()
          throws IOException, JSONException
  {
    while (true)
    {
      inputStream.mark(1);
      final Byte byteRead = readByte(true);
      if (byteRead == null)
      {
        // We've reached the end of the input stream.
        return;
      }

      switch (byteRead)
      {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
          // Spaces, tabs, newlines, and carriage returns are valid JSON
          // whitespace.
          break;

        // Technically, JSON does not provide support for comments.  But this
        // implementation will accept three types of comments:
        // - Comments that start with /* and end with */ (potentially spanning
        //   multiple lines).
        // - Comments that start with // and continue until the end of the line.
        // - Comments that start with # and continue until the end of the line.
        // All comments will be ignored by the parser.
        case '/':
          // This probably starts a comment.  If so, then the next byte must be
          // either another forward slash or an asterisk.
          final byte nextByte = readByte(false);
          if (nextByte == '/')
          {
            // Keep reading until we encounter a newline, a carriage return, or
            // the end of the input stream.
            while (true)
            {
              final Byte commentByte = readByte(true);
              if (commentByte == null)
              {
                return;
              }

              if ((commentByte == '\n') || (commentByte == '\r'))
              {
                break;
              }
            }
          }
          else if (nextByte == '*')
          {
            // Keep reading until we encounter an asterisk followed by a slash.
            // If we hit the end of the input stream before that, then that's an
            // error.
            while (true)
            {
              final Byte commentByte = readByte(false);
              if (commentByte == '*')
              {
                final Byte possibleSlashByte = readByte(false);
                if (possibleSlashByte == '/')
                {
                  break;
                }
              }
            }
          }
          else
          {
            throw new JSONException(
                 ERR_OBJECT_READER_ILLEGAL_SLASH_SKIPPING_WHITESPACE.get(
                      currentObjectBytes.length()));
          }
          break;

        case '#':
          // Keep reading until we encounter a newline, a carriage return, or
          // the end of the input stream.
          while (true)
          {
            final Byte commentByte = readByte(true);
            if (commentByte == null)
            {
              return;
            }

            if ((commentByte == '\n') || (commentByte == '\r'))
            {
              break;
            }
          }
          break;

        default:
          // We read a byte that isn't whitespace, so we'll need to reset the
          // stream so it will be read again, and we'll also need to remove the
          // that byte from the currentObjectBytes buffer.
          inputStream.reset();
          currentObjectBytes.setLength(currentObjectBytes.length() - 1);
          return;
      }
    }
  }



  /**
   * Reads the next byte from the input stream.
   *
   * @param  allowEndOfStream  Indicates whether it is acceptable to encounter
   *                           the end of the input stream.  This should only
   *                           be {@code true} when the token is expected to be
   *                           the open parenthesis of the outermost JSON
   *                           object.
   *
   * @return  The next byte read from the input stream, or {@code null} if the
   *          end of the input stream has been reached and that is acceptable.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If the end of the input stream is reached when that
   *                         is not acceptable.
   */
  @Nullable()
  private Byte readByte(final boolean allowEndOfStream)
          throws IOException, JSONException
  {
    final int byteRead = inputStream.read();
    if (byteRead < 0)
    {
      if (allowEndOfStream)
      {
        return null;
      }
      else
      {
        throw new JSONException(ERR_OBJECT_READER_UNEXPECTED_END_OF_STREAM.get(
             currentObjectBytes.length()));
      }
    }

    final byte b = (byte) (byteRead & 0xFF);
    currentObjectBytes.append(b);
    return b;
  }



  /**
   * Reads a string from the input stream.  The open quotation must have already
   * been read.
   *
   * @return  The JSON string that was read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         string.
   */
  @NotNull()
  private JSONString readString()
          throws IOException, JSONException
  {
    // Use a buffer to hold the string being decoded.  Also mark the current
    // position in the bytes that comprise the string representation so that
    // the JSON string representation (including the opening quote) will be
    // exactly as it was provided.
    stringBuffer.clear();
    final int jsonStringStartPos = currentObjectBytes.length() - 1;
    while (true)
    {
      final Byte byteRead = readByte(false);

      // See if it's a non-ASCII byte.  If so, then assume that it's UTF-8 and
      // read the appropriate number of remaining bytes.  We need to handle this
      // specially to avoid incorrectly detecting the end of the string because
      // a subsequent byte in a multi-byte character happens to be the same as
      // the ASCII quotation mark byte.
      if ((byteRead & 0x80) == 0x80)
      {
        final byte[] charBytes;
        if ((byteRead & 0xE0) == 0xC0)
        {
          // It's a two-byte character.
          charBytes = new byte[]
          {
            byteRead,
            readByte(false)
          };
        }
        else if ((byteRead & 0xF0) == 0xE0)
        {
          // It's a three-byte character.
          charBytes = new byte[]
          {
            byteRead,
            readByte(false),
            readByte(false)
          };
        }
        else if ((byteRead & 0xF8) == 0xF0)
        {
          // It's a four-byte character.
          charBytes = new byte[]
          {
            byteRead,
            readByte(false),
            readByte(false),
            readByte(false)
          };
        }
        else
        {
          // This isn't a valid UTF-8 sequence.
          throw new JSONException(
               ERR_OBJECT_READER_INVALID_UTF_8_BYTE_IN_STREAM.get(
                    currentObjectBytes.length(),
                    "0x" + StaticUtils.toHex(byteRead)));
        }

        stringBuffer.append(StaticUtils.toUTF8String(charBytes));
        continue;
      }


      // If the byte that we read was an escape, then we know that whatever
      // immediately follows it shouldn't be allowed to signal the end of the
      // string.
      if (byteRead == '\\')
      {
        final byte nextByte = readByte(false);
        switch (nextByte)
        {
          case '"':
          case '\\':
          case '/':
            stringBuffer.append(nextByte);
            break;
          case 'b':
            stringBuffer.append('\b');
            break;
          case 'f':
            stringBuffer.append('\f');
            break;
          case 'n':
            stringBuffer.append('\n');
            break;
          case 'r':
            stringBuffer.append('\r');
            break;
          case 't':
            stringBuffer.append('\t');
            break;
          case 'u':
            final char[] hexChars =
            {
              (char) (readByte(false) & 0xFF),
              (char) (readByte(false) & 0xFF),
              (char) (readByte(false) & 0xFF),
              (char) (readByte(false) & 0xFF)
            };

            try
            {
              stringBuffer.append(
                   (char) Integer.parseInt(new String(hexChars), 16));
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              throw new JSONException(
                   ERR_OBJECT_READER_INVALID_UNICODE_ESCAPE.get(
                        currentObjectBytes.length()),
                   e);
            }
            break;
          default:
            throw new JSONException(
                 ERR_OBJECT_READER_INVALID_ESCAPED_CHAR.get(
                      currentObjectBytes.length(), byteToCharString(nextByte)));
        }
        continue;
      }

      if (byteRead == '"')
      {
        // It's an unescaped quote, so it marks the end of the string.
        return new JSONString(stringBuffer.toString(),
             StaticUtils.toUTF8String(currentObjectBytes.getBackingArray(),
                  jsonStringStartPos,
                  (currentObjectBytes.length() - jsonStringStartPos)));
      }

      final int byteReadInt = (byteRead & 0xFF);
      if ((byteRead & 0xFF) <= 0x1F)
      {
        throw new JSONException(ERR_OBJECT_READER_UNESCAPED_CONTROL_CHAR.get(
             currentObjectBytes.length(), byteToCharString(byteRead)));
      }
      else
      {
        stringBuffer.append((char) byteReadInt);
      }
    }
  }



  /**
   * Reads a JSON Boolean from the input stream.  The first byte of either 't'
   * or 'f' will have already been read.
   *
   * @return  The JSON Boolean that was read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         Boolean.
   */
  @NotNull()
  private JSONBoolean readBoolean()
          throws IOException, JSONException
  {
    final byte firstByte =
         currentObjectBytes.getBackingArray()[currentObjectBytes.length() - 1];
    if (firstByte == 't')
    {
      if ((readByte(false) == 'r') &&
          (readByte(false) == 'u') &&
          (readByte(false) == 'e'))
      {
        return JSONBoolean.TRUE;
      }

      throw new JSONException(ERR_OBJECT_READER_INVALID_BOOLEAN_TRUE.get(
           currentObjectBytes.length()));
    }
    else
    {
      if ((readByte(false) == 'a') &&
          (readByte(false) == 'l') &&
          (readByte(false) == 's') &&
          (readByte(false) == 'e'))
      {
        return JSONBoolean.FALSE;
      }

      throw new JSONException(ERR_OBJECT_READER_INVALID_BOOLEAN_FALSE.get(
           currentObjectBytes.length()));
    }
  }



  /**
   * Reads a JSON Boolean from the input stream.  The first byte of 'n' will
   * have already been read.
   *
   * @return  The JSON null that was read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         null.
   */
  @NotNull()
  private JSONNull readNull()
          throws IOException, JSONException
  {
    if ((readByte(false) == 'u') &&
         (readByte(false) == 'l') &&
         (readByte(false) == 'l'))
    {
      return JSONNull.NULL;
    }

    throw new JSONException(ERR_OBJECT_READER_INVALID_NULL.get(
         currentObjectBytes.length()));
  }



  /**
   * Reads a JSON number from the input stream.  The first byte of the number
   * will have already been read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @return  The JSON number that was read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         number.
   */
  @NotNull()
  private JSONNumber readNumber()
          throws IOException, JSONException
  {
    // Use a buffer to hold the string representation of the number being
    // decoded.  Since the first byte of the number has already been read, we'll
    // need to add it into the buffer.
    stringBuffer.clear();
    stringBuffer.append(
         currentObjectBytes.getBackingArray()[currentObjectBytes.length() - 1]);


    // Read until we encounter whitespace, a comma, a closing square bracket, or
    // a closing curly brace.  Then try to parse what we read as a number.
    while (true)
    {
      // Mark the stream so that if we read a byte that isn't part of the
      // number, we'll be able to rewind the stream so that byte will be read
      // again by something else.
      inputStream.mark(1);

      final Byte b = readByte(false);
      switch (b)
      {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
        case ',':
        case ']':
        case '}':
          // This tell us we're at the end of the number.  Rewind the stream so
          // that we can read this last byte again whatever tries to get the
          // next token.  Also remove it from the end of currentObjectBytes
          // since it will be re-added when it's read again.
          inputStream.reset();
          currentObjectBytes.setLength(currentObjectBytes.length() - 1);
          return new JSONNumber(stringBuffer.toString());

        default:
          stringBuffer.append(b);
      }
    }
  }



  /**
   * Reads a JSON array from the input stream.  The opening square bracket will
   * have already been read.
   *
   * @return  The JSON array that was read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         array.
   */
  @NotNull()
  private JSONArray readArray()
          throws IOException, JSONException
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
      final Object token = readToken(false);
      if (token instanceof JSONValue)
      {
        values.add((JSONValue) token);
      }
      else if (token.equals('['))
      {
        values.add(readArray());
      }
      else if (token.equals('{'))
      {
        final LinkedHashMap<String,JSONValue> fieldMap =
             new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
        values.add(readObject(fieldMap));
      }
      else if (token.equals(']') && firstToken)
      {
        // It's an empty array.
        return JSONArray.EMPTY_ARRAY;
      }
      else
      {
        throw new JSONException(ERR_OBJECT_READER_INVALID_TOKEN_IN_ARRAY.get(
             currentObjectBytes.length(), String.valueOf(token)));
      }

      firstToken = false;


      // If we've gotten here, then we found a JSON value.  It must be followed
      // by either a comma (to indicate that there's at least one more value) or
      // a closing square bracket (to denote the end of the array).
      final Object nextToken = readToken(false);
      if (nextToken.equals(']'))
      {
        return new JSONArray(values);
      }
      else if (! nextToken.equals(','))
      {
        throw new JSONException(
             ERR_OBJECT_READER_INVALID_TOKEN_AFTER_ARRAY_VALUE.get(
                  currentObjectBytes.length(), String.valueOf(nextToken)));
      }
    }
  }



  /**
   * Reads a JSON object from the input stream.  The opening curly brace will
   * have already been read.
   *
   * @param  fields  The map into which to place the fields that are read.  The
   *                 returned object will include an unmodifiable view of this
   *                 map, but the caller may use the map directly if desired.
   *
   * @return  The JSON object that was read.
   *
   * @throws  IOException  If a problem is encountered while reading from the
   *                       input stream.
   *
   * @throws  JSONException  If a problem was encountered while reading the JSON
   *                         object.
   */
  @NotNull()
  private JSONObject readObject(@NotNull final Map<String,JSONValue> fields)
          throws IOException, JSONException
  {
    boolean firstField = true;
    while (true)
    {
      // Read the next token.  It must be a JSONString, unless we haven't read
      // any fields yet in which case it can be a closing curly brace to
      // indicate that it's an empty object.
      final String fieldName;
      final Object fieldNameToken = readToken(false);
      if (fieldNameToken instanceof JSONString)
      {
        fieldName = ((JSONString) fieldNameToken).stringValue();
        if (fields.containsKey(fieldName))
        {
          throw new JSONException(ERR_OBJECT_READER_DUPLICATE_FIELD.get(
               currentObjectBytes.length(), fieldName));
        }
      }
      else if (firstField && fieldNameToken.equals('}'))
      {
        return new JSONObject(fields);
      }
      else
      {
        throw new JSONException(ERR_OBJECT_READER_INVALID_TOKEN_IN_OBJECT.get(
             currentObjectBytes.length(), String.valueOf(fieldNameToken)));
      }
      firstField = false;

      // Read the next token.  It must be a colon.
      final Object colonToken = readToken(false);
      if (! colonToken.equals(':'))
      {
        throw new JSONException(ERR_OBJECT_READER_TOKEN_NOT_COLON.get(
             currentObjectBytes.length(), String.valueOf(colonToken),
             String.valueOf(fieldNameToken)));
      }

      // Read the next token.  It must be one of the following:
      // - A JSONValue
      // - An opening square bracket, designating the start of an array.
      // - An opening curly brace, designating the start of an object.
      final Object valueToken = readToken(false);
      if (valueToken instanceof JSONValue)
      {
        fields.put(fieldName, (JSONValue) valueToken);
      }
      else if (valueToken.equals('['))
      {
        final JSONArray a = readArray();
        fields.put(fieldName, a);
      }
      else if (valueToken.equals('{'))
      {
        final LinkedHashMap<String,JSONValue> m =
             new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
        final JSONObject o = readObject(m);
        fields.put(fieldName, o);
      }
      else
      {
        throw new JSONException(ERR_OBJECT_READER_TOKEN_NOT_VALUE.get(
             currentObjectBytes.length(), String.valueOf(valueToken),
             String.valueOf(fieldNameToken)));
      }

      // Read the next token.  It must be either a comma (to indicate that
      // there will be another field) or a closing curly brace (to indicate
      // that the end of the object has been reached).
      final Object separatorToken = readToken(false);
      if (separatorToken.equals('}'))
      {
        return new JSONObject(fields);
      }
      else if (! separatorToken.equals(','))
      {
        throw new JSONException(
             ERR_OBJECT_READER_INVALID_TOKEN_AFTER_OBJECT_VALUE.get(
                  currentObjectBytes.length(), String.valueOf(separatorToken),
                  String.valueOf(fieldNameToken)));
      }
    }
  }



  /**
   * Retrieves a string representation of the provided byte that is intended to
   * represent a character.  If the provided byte is a printable ASCII
   * character, then that character will be used.  Otherwise, the string
   * representation will be "0x" followed by the hexadecimal representation of
   * the byte.
   *
   * @param  b  The byte for which to obtain the string representation.
   *
   * @return  A string representation of the provided byte.
   */
  @NotNull()
  private static String byteToCharString(final byte b)
  {
    if ((b >= ' ') && (b <= '~'))
    {
      return String.valueOf((char) (b & 0xFF));
    }
    else
    {
      return "0x" + StaticUtils.toHex(b);
    }
  }
}
