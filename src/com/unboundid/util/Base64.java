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
package com.unboundid.util;



import java.io.IOException;
import java.text.ParseException;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides methods for encoding and decoding data in base64 as
 * defined in <A HREF="http://www.ietf.org/rfc/rfc4648.txt">RFC 4648</A>.  It
 * provides a relatively compact way of representing binary data using only
 * printable characters.  It uses a six-bit encoding mechanism in which every
 * three bytes of raw data is converted to four bytes of base64-encoded data,
 * which means that it only requires about a 33% increase in size (as compared
 * with a hexadecimal representation, which requires a 100% increase in size).
 * <BR><BR>
 * Base64 encoding is used in LDIF processing as per
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A> to represent data
 * that contains special characters or might otherwise be ambiguous.  It is also
 * used in a number of other areas (e.g., for the ASCII representation of
 * certificates) where it is desirable to deal with a string containing only
 * printable characters but the raw data may contain other characters outside of
 * that range.
 * <BR><BR>
 * This class also provides support for the URL-safe variant (called base64url)
 * as described in RFC 4648 section 5.  This is nearly the same as base64,
 * except that the '+' and '/' characters are replaced with '-' and '_',
 * respectively.  The padding may be omitted if the context makes the data size
 * clear, but if padding is to be used then the URL-encoded "%3d" will be used
 * instead of "=".
 * <BR><BR>
 * <H2>Example</H2>
 * The following examples demonstrate the process for base64-encoding raw data,
 * and for decoding a string containing base64-encoded data back to the raw
 * data used to create it:
 * <PRE>
 * // Base64-encode some raw data:
 * String base64String = Base64.encode(rawDataBytes);
 *
 * // Decode a base64 string back to raw data:
 * byte[] decodedRawDataBytes;
 * try
 * {
 *   decodedRawDataBytes = Base64.decode(base64String);
 * }
 * catch (ParseException pe)
 * {
 *   // The string did not represent a valid base64 encoding.
 *   decodedRawDataBytes = null;
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Base64
{
  /**
   * The set of characters in the base64 alphabet.
   */
  @NotNull private static final char[] BASE64_ALPHABET =
       ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
        "0123456789+/").toCharArray();



  /**
   * The set of characters in the base64url alphabet.
   */
  @NotNull private static final char[] BASE64URL_ALPHABET =
       ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
        "0123456789-_").toCharArray();



  /**
   * Prevent this class from being instantiated.
   */
  private Base64()
  {
    // No implementation is required.
  }



  /**
   * Encodes the UTF-8 representation of the provided string in base64 format.
   *
   * @param  data  The raw data to be encoded.  It must not be {@code null}.
   *
   * @return  The base64-encoded representation of the provided data.
   */
  @NotNull()
  public static String encode(@NotNull final String data)
  {
    Validator.ensureNotNull(data);

    return encode(StaticUtils.getBytes(data));
  }



  /**
   * Encodes the provided data in base64 format.
   *
   * @param  data  The raw data to be encoded.  It must not be {@code null}.
   *
   * @return  The base64-encoded representation of the provided data.
   */
  @NotNull()
  public static String encode(@NotNull final byte[] data)
  {
    Validator.ensureNotNull(data);

    final StringBuilder buffer = new StringBuilder(4*data.length/3+1);
    encode(BASE64_ALPHABET, data, 0, data.length, buffer, "=");
    return buffer.toString();
  }



  /**
   * Appends a base64-encoded version of the contents of the provided buffer
   * (using a UTF-8 representation) to the given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   */
  public static void encode(@NotNull final String data,
                            @NotNull final StringBuilder buffer)
  {
    Validator.ensureNotNull(data);

    encode(StaticUtils.getBytes(data), buffer);
  }



  /**
   * Appends a base64-encoded version of the contents of the provided buffer
   * (using a UTF-8 representation) to the given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   */
  public static void encode(@NotNull final String data,
                            @NotNull final ByteStringBuffer buffer)
  {
    Validator.ensureNotNull(data);

    encode(StaticUtils.getBytes(data), buffer);
  }



  /**
   * Appends a base64-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   */
  public static void encode(@NotNull final byte[] data,
                            @NotNull final StringBuilder buffer)
  {
    encode(BASE64_ALPHABET, data, 0, data.length, buffer, "=");
  }



  /**
   * Appends a base64-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The array containing the raw data to be encoded.  It must
   *                 not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   */
  public static void encode(@NotNull final byte[] data, final int off,
                            final int length,
                            @NotNull final StringBuilder buffer)
  {
    encode(BASE64_ALPHABET, data, off, length, buffer, "=");
  }



  /**
   * Appends a base64-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   */
  public static void encode(@NotNull final byte[] data,
                            @NotNull final ByteStringBuffer buffer)
  {
    encode(BASE64_ALPHABET, data, 0, data.length, buffer, "=");
  }



  /**
   * Appends a base64-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   */
  public static void encode(@NotNull final byte[] data, final int off,
                            final int length,
                            @NotNull final ByteStringBuffer buffer)
  {
    encode(BASE64_ALPHABET, data, off, length, buffer, "=");
  }



  /**
   * Retrieves a base64url-encoded representation of the provided data to the
   * given buffer.
   *
   * @param  data  The raw data to be encoded.  It must not be {@code null}.
   * @param  pad   Indicates whether to pad the URL if necessary.  Padding will
   *               use "%3d", as the URL-escaped representation of the equal
   *               sign.
   *
   * @return  A base64url-encoded representation of the provided data to the
   *          given buffer.
   */
  @NotNull()
  public static String urlEncode(@NotNull final String data, final boolean pad)
  {
    return urlEncode(StaticUtils.getBytes(data), pad);
  }



  /**
   * Retrieves a base64url-encoded representation of the provided data to the
   * given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   * @param  pad     Indicates whether to pad the URL if necessary.  Padding
   *                 will use "%3d", as the URL-escaped representation of the
   *                 equal sign.
   */
  public static void urlEncode(@NotNull final String data,
                               @NotNull final StringBuilder buffer,
                               final boolean pad)
  {
    final byte[] dataBytes = StaticUtils.getBytes(data);
    encode(BASE64_ALPHABET, dataBytes, 0, dataBytes.length, buffer,
         (pad ? "%3d" : null));
  }



  /**
   * Retrieves a base64url-encoded representation of the provided data to the
   * given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   * @param  pad     Indicates whether to pad the URL if necessary.  Padding
   *                 will use "%3d", as the URL-escaped representation of the
   *                 equal sign.
   */
  public static void urlEncode(@NotNull final String data,
                               @NotNull final ByteStringBuffer buffer,
                               final boolean pad)
  {
    final byte[] dataBytes = StaticUtils.getBytes(data);
    encode(BASE64_ALPHABET, dataBytes, 0, dataBytes.length, buffer,
         (pad ? "%3d" : null));
  }



  /**
   * Retrieves a base64url-encoded representation of the provided data to the
   * given buffer.
   *
   * @param  data  The raw data to be encoded.  It must not be {@code null}.
   * @param  pad   Indicates whether to pad the URL if necessary.  Padding will
   *               use "%3d", as the URL-escaped representation of the equal
   *               sign.
   *
   * @return  A base64url-encoded representation of the provided data to the
   *          given buffer.
   */
  @NotNull()
  public static String urlEncode(@NotNull final byte[] data, final boolean pad)
  {
    final StringBuilder buffer = new StringBuilder(4*data.length/3+6);
    encode(BASE64URL_ALPHABET, data, 0, data.length, buffer,
         (pad ? "%3d" : null));
    return buffer.toString();
  }



  /**
   * Appends a base64url-encoded representation of the provided data to the
   * given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   * @param  pad     Indicates whether to pad the URL if necessary.  Padding
   *                 will use "%3d", as the URL-escaped representation of the
   *                 equal sign.
   */
  public static void urlEncode(@NotNull final byte[] data, final int off,
                               final int length,
                               @NotNull final StringBuilder buffer,
                               final boolean pad)
  {
    encode(BASE64URL_ALPHABET, data, off, length, buffer, (pad ? "%3d" : null));
  }



  /**
   * Appends a base64url-encoded representation of the provided data to the
   * given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base64-encoded data is to be
   *                 written.
   * @param  pad     Indicates whether to pad the URL if necessary.  Padding
   *                 will use "%3d", as the URL-escaped representation of the
   *                 equal sign.
   */
  public static void urlEncode(@NotNull final byte[] data, final int off,
                               final int length,
                               @NotNull final ByteStringBuffer buffer,
                               final boolean pad)
  {
    encode(BASE64URL_ALPHABET, data, off, length, buffer, (pad ? "%3d" : null));
  }



  /**
   * Appends a base64-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  alphabet  The alphabet of base64 characters to use for the
   *                   encoding.
   * @param  data      The raw data to be encoded.  It must not be {@code null}.
   * @param  off       The offset in the array at which the data to encode
   *                   begins.
   * @param  length    The number of bytes to be encoded.
   * @param  buffer    The buffer to which the base64-encoded data is to be
   *                   written.
   * @param  padStr    The string to use for padding.  It may be {@code null} if
   *                   no padding should be applied.
   */
  private static void encode(@NotNull final char[] alphabet,
                             @NotNull final byte[] data,
                             final int off, final int length,
                             @NotNull final Appendable buffer,
                             @Nullable final String padStr)
  {
    Validator.ensureNotNull(data);
    Validator.ensureTrue(data.length >= off);
    Validator.ensureTrue(data.length >= (off+length));

    if (length == 0)
    {
      return;
    }

    try
    {
      int pos = off;
      for (int i=0; i < (length / 3); i++)
      {
        final int intValue = ((data[pos++] & 0xFF) << 16) |
             ((data[pos++] & 0xFF) << 8) |
             (data[pos++] & 0xFF);

        buffer.append(alphabet[(intValue >> 18) & 0x3F]);
        buffer.append(alphabet[(intValue >> 12) & 0x3F]);
        buffer.append(alphabet[(intValue >> 6) & 0x3F]);
        buffer.append(alphabet[intValue & 0x3F]);
      }

      switch ((off+length) - pos)
      {
        case 1:
          int intValue = (data[pos] & 0xFF) << 16;
          buffer.append(alphabet[(intValue >> 18) & 0x3F]);
          buffer.append(alphabet[(intValue >> 12) & 0x3F]);
          if (padStr != null)
          {
            buffer.append(padStr);
            buffer.append(padStr);
          }
          return;

        case 2:
          intValue = ((data[pos++] & 0xFF) << 16) | ((data[pos] & 0xFF) << 8);
          buffer.append(alphabet[(intValue >> 18) & 0x3F]);
          buffer.append(alphabet[(intValue >> 12) & 0x3F]);
          buffer.append(alphabet[(intValue >> 6) & 0x3F]);
          if (padStr != null)
          {
            buffer.append(padStr);
          }
          return;
      }
    }
    catch (final IOException ioe)
    {
      Debug.debugException(ioe);

      // This should never happen.
      throw new RuntimeException(ioe.getMessage(), ioe);
    }
  }



  /**
   * Decodes the contents of the provided base64-encoded string.
   *
   * @param  data  The base64-encoded string to decode.  It must not be
   *               {@code null}.
   *
   * @return  A byte array containing the decoded data.
   *
   * @throws  ParseException  If the contents of the provided string cannot be
   *                          parsed as base64-encoded data.
   */
  @NotNull()
  public static byte[] decode(@NotNull final String data)
         throws ParseException
  {
    Validator.ensureNotNull(data);

    final int length = data.length();
    if (length == 0)
    {
      return StaticUtils.NO_BYTES;
    }

    if ((length % 4) != 0)
    {
      throw new ParseException(ERR_BASE64_DECODE_INVALID_LENGTH.get(), length);
    }

    int numBytes = 3 * (length / 4);
    if (data.charAt(length-2) == '=')
    {
      numBytes -= 2;
    }
    else if (data.charAt(length-1) == '=')
    {
      numBytes--;
    }

    final byte[] b = new byte[numBytes];

    int stringPos = 0;
    int arrayPos  = 0;
    while (stringPos < length)
    {
      int intValue = 0x00;
      for (int i=0; i < 4; i++)
      {
        intValue <<= 6;
        switch (data.charAt(stringPos++))
        {
          case 'A':
            intValue |= 0x00;
            break;
          case 'B':
            intValue |= 0x01;
            break;
          case 'C':
            intValue |= 0x02;
            break;
          case 'D':
            intValue |= 0x03;
            break;
          case 'E':
            intValue |= 0x04;
            break;
          case 'F':
            intValue |= 0x05;
            break;
          case 'G':
            intValue |= 0x06;
            break;
          case 'H':
            intValue |= 0x07;
            break;
          case 'I':
            intValue |= 0x08;
            break;
          case 'J':
            intValue |= 0x09;
            break;
          case 'K':
            intValue |= 0x0A;
            break;
          case 'L':
            intValue |= 0x0B;
            break;
          case 'M':
            intValue |= 0x0C;
            break;
          case 'N':
            intValue |= 0x0D;
            break;
          case 'O':
            intValue |= 0x0E;
            break;
          case 'P':
            intValue |= 0x0F;
            break;
          case 'Q':
            intValue |= 0x10;
            break;
          case 'R':
            intValue |= 0x11;
            break;
          case 'S':
            intValue |= 0x12;
            break;
          case 'T':
            intValue |= 0x13;
            break;
          case 'U':
            intValue |= 0x14;
            break;
          case 'V':
            intValue |= 0x15;
            break;
          case 'W':
            intValue |= 0x16;
            break;
          case 'X':
            intValue |= 0x17;
            break;
          case 'Y':
            intValue |= 0x18;
            break;
          case 'Z':
            intValue |= 0x19;
            break;
          case 'a':
            intValue |= 0x1A;
            break;
          case 'b':
            intValue |= 0x1B;
            break;
          case 'c':
            intValue |= 0x1C;
            break;
          case 'd':
            intValue |= 0x1D;
            break;
          case 'e':
            intValue |= 0x1E;
            break;
          case 'f':
            intValue |= 0x1F;
            break;
          case 'g':
            intValue |= 0x20;
            break;
          case 'h':
            intValue |= 0x21;
            break;
          case 'i':
            intValue |= 0x22;
            break;
          case 'j':
            intValue |= 0x23;
            break;
          case 'k':
            intValue |= 0x24;
            break;
          case 'l':
            intValue |= 0x25;
            break;
          case 'm':
            intValue |= 0x26;
            break;
          case 'n':
            intValue |= 0x27;
            break;
          case 'o':
            intValue |= 0x28;
            break;
          case 'p':
            intValue |= 0x29;
            break;
          case 'q':
            intValue |= 0x2A;
            break;
          case 'r':
            intValue |= 0x2B;
            break;
          case 's':
            intValue |= 0x2C;
            break;
          case 't':
            intValue |= 0x2D;
            break;
          case 'u':
            intValue |= 0x2E;
            break;
          case 'v':
            intValue |= 0x2F;
            break;
          case 'w':
            intValue |= 0x30;
            break;
          case 'x':
            intValue |= 0x31;
            break;
          case 'y':
            intValue |= 0x32;
            break;
          case 'z':
            intValue |= 0x33;
            break;
          case '0':
            intValue |= 0x34;
            break;
          case '1':
            intValue |= 0x35;
            break;
          case '2':
            intValue |= 0x36;
            break;
          case '3':
            intValue |= 0x37;
            break;
          case '4':
            intValue |= 0x38;
            break;
          case '5':
            intValue |= 0x39;
            break;
          case '6':
            intValue |= 0x3A;
            break;
          case '7':
            intValue |= 0x3B;
            break;
          case '8':
            intValue |= 0x3C;
            break;
          case '9':
            intValue |= 0x3D;
            break;
          case '+':
            intValue |= 0x3E;
            break;
          case '/':
            intValue |= 0x3F;
            break;

          case '=':
            switch (length - stringPos)
            {
              case 0:
                // The string ended with a single equal sign, so there are only
                // two bytes left.  Shift the value eight bits to the right and
                // read those two bytes.
                intValue >>= 8;
                b[arrayPos++] = (byte) ((intValue >> 8) & 0xFF);
                b[arrayPos]   = (byte) (intValue & 0xFF);
                return b;

              case 1:
                // The string ended with two equal signs, so there is only one
                // byte left.  Shift the value ten bits to the right and read
                // that single byte.
                intValue >>= 10;
                b[arrayPos] = (byte) (intValue & 0xFF);
                return b;

              default:
                throw new ParseException(ERR_BASE64_DECODE_UNEXPECTED_EQUAL.get(
                                              (stringPos-1)),
                                         (stringPos-1));
            }

          default:
            throw new ParseException(ERR_BASE64_DECODE_UNEXPECTED_CHAR.get(
                                          data.charAt(stringPos-1)),
                                     (stringPos-1));
        }
      }

      b[arrayPos++] = (byte) ((intValue >> 16) & 0xFF);
      b[arrayPos++] = (byte) ((intValue >> 8) & 0xFF);
      b[arrayPos++] = (byte) (intValue & 0xFF);
    }

    return b;
  }



  /**
   * Decodes the contents of the provided base64-encoded string to a string
   * containing the raw data using the UTF-8 encoding.
   *
   * @param  data  The base64-encoded string to decode.  It must not be
   *               {@code null}.
   *
   * @return  A string containing the decoded data.
   *
   * @throws  ParseException  If the contents of the provided string cannot be
   *                          parsed as base64-encoded data using the UTF-8
   *                          encoding.
   */
  @NotNull()
  public static String decodeToString(@NotNull final String data)
         throws ParseException
  {
    Validator.ensureNotNull(data);

    final byte[] decodedBytes = decode(data);
    return StaticUtils.toUTF8String(decodedBytes);
  }



  /**
   * Decodes the contents of the provided base64url-encoded string.
   *
   * @param  data  The base64url-encoded string to decode.  It must not be
   *               {@code null}.
   *
   * @return  A byte array containing the decoded data.
   *
   * @throws  ParseException  If the contents of the provided string cannot be
   *                          parsed as base64url-encoded data.
   */
  @NotNull()
  public static byte[] urlDecode(@NotNull final String data)
         throws ParseException
  {
    Validator.ensureNotNull(data);

    final int length = data.length();
    if (length == 0)
    {
      return StaticUtils.NO_BYTES;
    }

    int stringPos = 0;
    final ByteStringBuffer buffer = new ByteStringBuffer(length);
decodeLoop:
    while (stringPos < length)
    {
      int intValue = 0x00;
      for (int i=0; i < 4; i++)
      {
        // Since the value may not be padded, then we need to handle the
        // possibility of missing characters.
        final char c;
        if (stringPos >= length)
        {
          c = '=';
          stringPos++;
        }
        else
        {
          c = data.charAt(stringPos++);
        }

        intValue <<= 6;
        switch (c)
        {
          case 'A':
            intValue |= 0x00;
            break;
          case 'B':
            intValue |= 0x01;
            break;
          case 'C':
            intValue |= 0x02;
            break;
          case 'D':
            intValue |= 0x03;
            break;
          case 'E':
            intValue |= 0x04;
            break;
          case 'F':
            intValue |= 0x05;
            break;
          case 'G':
            intValue |= 0x06;
            break;
          case 'H':
            intValue |= 0x07;
            break;
          case 'I':
            intValue |= 0x08;
            break;
          case 'J':
            intValue |= 0x09;
            break;
          case 'K':
            intValue |= 0x0A;
            break;
          case 'L':
            intValue |= 0x0B;
            break;
          case 'M':
            intValue |= 0x0C;
            break;
          case 'N':
            intValue |= 0x0D;
            break;
          case 'O':
            intValue |= 0x0E;
            break;
          case 'P':
            intValue |= 0x0F;
            break;
          case 'Q':
            intValue |= 0x10;
            break;
          case 'R':
            intValue |= 0x11;
            break;
          case 'S':
            intValue |= 0x12;
            break;
          case 'T':
            intValue |= 0x13;
            break;
          case 'U':
            intValue |= 0x14;
            break;
          case 'V':
            intValue |= 0x15;
            break;
          case 'W':
            intValue |= 0x16;
            break;
          case 'X':
            intValue |= 0x17;
            break;
          case 'Y':
            intValue |= 0x18;
            break;
          case 'Z':
            intValue |= 0x19;
            break;
          case 'a':
            intValue |= 0x1A;
            break;
          case 'b':
            intValue |= 0x1B;
            break;
          case 'c':
            intValue |= 0x1C;
            break;
          case 'd':
            intValue |= 0x1D;
            break;
          case 'e':
            intValue |= 0x1E;
            break;
          case 'f':
            intValue |= 0x1F;
            break;
          case 'g':
            intValue |= 0x20;
            break;
          case 'h':
            intValue |= 0x21;
            break;
          case 'i':
            intValue |= 0x22;
            break;
          case 'j':
            intValue |= 0x23;
            break;
          case 'k':
            intValue |= 0x24;
            break;
          case 'l':
            intValue |= 0x25;
            break;
          case 'm':
            intValue |= 0x26;
            break;
          case 'n':
            intValue |= 0x27;
            break;
          case 'o':
            intValue |= 0x28;
            break;
          case 'p':
            intValue |= 0x29;
            break;
          case 'q':
            intValue |= 0x2A;
            break;
          case 'r':
            intValue |= 0x2B;
            break;
          case 's':
            intValue |= 0x2C;
            break;
          case 't':
            intValue |= 0x2D;
            break;
          case 'u':
            intValue |= 0x2E;
            break;
          case 'v':
            intValue |= 0x2F;
            break;
          case 'w':
            intValue |= 0x30;
            break;
          case 'x':
            intValue |= 0x31;
            break;
          case 'y':
            intValue |= 0x32;
            break;
          case 'z':
            intValue |= 0x33;
            break;
          case '0':
            intValue |= 0x34;
            break;
          case '1':
            intValue |= 0x35;
            break;
          case '2':
            intValue |= 0x36;
            break;
          case '3':
            intValue |= 0x37;
            break;
          case '4':
            intValue |= 0x38;
            break;
          case '5':
            intValue |= 0x39;
            break;
          case '6':
            intValue |= 0x3A;
            break;
          case '7':
            intValue |= 0x3B;
            break;
          case '8':
            intValue |= 0x3C;
            break;
          case '9':
            intValue |= 0x3D;
            break;
          case '-':
            intValue |= 0x3E;
            break;
          case '_':
            intValue |= 0x3F;
            break;
          case '=':
          case '%':
            switch ((stringPos-1) % 4)
            {
              case 2:
                // The string should have two padding tokens, so only a single
                // byte of data remains.  Shift the value ten bits to the right
                // and read that single byte.
                intValue >>= 10;
                buffer.append((byte) (intValue & 0xFF));
                break decodeLoop;
              case 3:
                // The string should have a single padding token, so two bytes
                // of data remain.  Shift the value eight bits to the right and
                // read those two bytes.
                intValue >>= 8;
                buffer.append((byte) ((intValue >> 8) & 0xFF));
                buffer.append((byte) (intValue & 0xFF));
                break decodeLoop;
            }

            // If we've gotten here, then that must mean the string had padding
            // when none was needed, or it had an invalid length.  That's an
            // error.
            throw new ParseException(ERR_BASE64_URLDECODE_INVALID_LENGTH.get(),
                 (stringPos-1));

          default:
            throw new ParseException(
                 ERR_BASE64_DECODE_UNEXPECTED_CHAR.get(
                      data.charAt(stringPos-1)),
                 (stringPos-1));
        }
      }

      buffer.append((byte) ((intValue >> 16) & 0xFF));
      buffer.append((byte) ((intValue >> 8) & 0xFF));
      buffer.append((byte) (intValue & 0xFF));
    }

    return buffer.toByteArray();
  }



  /**
   * Decodes the contents of the provided base64-encoded string to a string
   * containing the raw data using the UTF-8 encoding.
   *
   * @param  data  The base64-encoded string to decode.  It must not be
   *               {@code null}.
   *
   * @return  A string containing the decoded data.
   *
   * @throws  ParseException  If the contents of the provided string cannot be
   *                          parsed as base64-encoded data using the UTF-8
   *                          encoding.
   */
  @NotNull()
  public static String urlDecodeToString(@NotNull final String data)
         throws ParseException
  {
    Validator.ensureNotNull(data);

    final byte[] decodedBytes = urlDecode(data);
    return StaticUtils.toUTF8String(decodedBytes);
  }
}
