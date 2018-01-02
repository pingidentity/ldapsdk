/*
 * Copyright 2012-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2018 Ping Identity Corporation
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
import static com.unboundid.util.Validator.*;



/**
 * This class provides methods for encoding and decoding data in base32 as
 * defined in <A HREF="http://www.ietf.org/rfc/rfc4648.txt">RFC 4648</A>.  It
 * provides a somewhat compact way of representing binary data using only
 * printable characters (a subset of ASCII letters and numeric digits selected
 * to avoid ambiguity, like confusion between the number 1 and the uppercase
 * letter I, and between the number 0 and the uppercase letter O).  It uses a
 * five-bit encoding mechanism in which every five bytes of raw data is
 * converted into eight bytes of base32-encoded data.
 * <BR><BR>
 * <H2>Example</H2>
 * The following examples demonstrate the process for base32-encoding raw data,
 * and for decoding a string containing base32-encoded data back to the raw
 * data used to create it:
 * <PRE>
 * // Base32-encode some raw data:
 * String base32String = Base32.encode(rawDataBytes);
 *
 * // Decode a base32 string back to raw data:
 * byte[] decodedRawDataBytes;
 * try
 * {
 *   decodedRawDataBytes = Base32.decode(base32String);
 * }
 * catch (ParseException pe)
 * {
 *   // The string did not represent a valid base32 encoding.
 *   decodedRawDataBytes = null;
 * }
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Base32
{
  /**
   * The set of characters in the base32 alphabet.
   */
  private static final char[] BASE32_ALPHABET =
       ("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").toCharArray();



  /**
   * Prevent this class from being instantiated.
   */
  private Base32()
  {
    // No implementation is required.
  }



  /**
   * Encodes the UTF-8 representation of the provided string in base32 format.
   *
   * @param  data  The raw data to be encoded.  It must not be {@code null}.
   *
   * @return  The base32-encoded representation of the provided data.
   */
  public static String encode(final String data)
  {
    ensureNotNull(data);

    return encode(StaticUtils.getBytes(data));
  }



  /**
   * Encodes the provided data in base32 format.
   *
   * @param  data  The raw data to be encoded.  It must not be {@code null}.
   *
   * @return  The base32-encoded representation of the provided data.
   */
  public static String encode(final byte[] data)
  {
    ensureNotNull(data);

    final StringBuilder buffer = new StringBuilder(4*data.length/3+1);
    encodeInternal(data, 0, data.length, buffer);
    return buffer.toString();
  }



  /**
   * Appends a base32-encoded version of the contents of the provided buffer
   * (using a UTF-8 representation) to the given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  public static void encode(final String data, final StringBuilder buffer)
  {
    ensureNotNull(data);

    encode(StaticUtils.getBytes(data), buffer);
  }



  /**
   * Appends a base32-encoded version of the contents of the provided buffer
   * (using a UTF-8 representation) to the given buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  public static void encode(final String data, final ByteStringBuffer buffer)
  {
    ensureNotNull(data);

    encode(StaticUtils.getBytes(data), buffer);
  }



  /**
   * Appends a base32-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  public static void encode(final byte[] data, final StringBuilder buffer)
  {
    encodeInternal(data, 0, data.length, buffer);
  }



  /**
   * Appends a base32-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The array containing the raw data to be encoded.  It must
   *                 not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  public static void encode(final byte[] data, final int off, final int length,
                            final StringBuilder buffer)
  {
    encodeInternal(data, off, length, buffer);
  }



  /**
   * Appends a base32-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  public static void encode(final byte[] data, final ByteStringBuffer buffer)
  {
    encodeInternal(data, 0, data.length, buffer);
  }



  /**
   * Appends a base32-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  public static void encode(final byte[] data, final int off, final int length,
                            final ByteStringBuffer buffer)
  {
    encodeInternal(data, off, length, buffer);
  }



  /**
   * Appends a base32-encoded representation of the provided data to the given
   * buffer.
   *
   * @param  data    The raw data to be encoded.  It must not be {@code null}.
   * @param  off     The offset in the array at which the data to encode begins.
   * @param  length  The number of bytes to be encoded.
   * @param  buffer  The buffer to which the base32-encoded data is to be
   *                 written.
   */
  private static void encodeInternal(final byte[] data, final int off,
                                     final int length, final Appendable buffer)
  {
    ensureNotNull(data);
    ensureTrue(data.length >= off);
    ensureTrue(data.length >= (off+length));

    if (length == 0)
    {
      return;
    }

    try
    {
      int pos = off;
      for (int i=0; i < (length / 5); i++)
      {
        final long longValue =
             (((data[pos++] & 0xFFL) << 32) |
              ((data[pos++] & 0xFFL) << 24) |
              ((data[pos++] & 0xFFL) << 16) |
              ((data[pos++] & 0xFFL) << 8) |
               (data[pos++] & 0xFFL));

        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 35) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 30) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 25) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 20) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 15) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 10) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) ((longValue >> 5) & 0x1FL)]);
        buffer.append(BASE32_ALPHABET[(int) (longValue & 0x1FL)]);
      }

      switch ((off+length) - pos)
      {
        case 1:
          long longValue = ((data[pos] & 0xFFL) << 32);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 35) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 30) & 0x1FL)]);
          buffer.append("======");
          return;

        case 2:
          longValue = (((data[pos++] & 0xFFL) << 32) |
                       ((data[pos] & 0xFFL) << 24));
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 35) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 30) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 25) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 20) & 0x1FL)]);
          buffer.append("====");
          return;

        case 3:
          longValue = (((data[pos++] & 0xFFL) << 32) |
                       ((data[pos++] & 0xFFL) << 24) |
                       ((data[pos] & 0xFFL) << 16));
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 35) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 30) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 25) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 20) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 15) & 0x1FL)]);
          buffer.append("===");
          return;

        case 4:
          longValue = (((data[pos++] & 0xFFL) << 32) |
                       ((data[pos++] & 0xFFL) << 24) |
                       ((data[pos++] & 0xFFL) << 16) |
                       ((data[pos] & 0xFFL) << 8));
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 35) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 30) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 25) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 20) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 15) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 10) & 0x1FL)]);
          buffer.append(BASE32_ALPHABET[(int) ((longValue >> 5) & 0x1FL)]);
          buffer.append("=");
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
   * Decodes the contents of the provided base32-encoded string.
   *
   * @param  data  The base32-encoded string to decode.  It must not be
   *               {@code null}.
   *
   * @return  A byte array containing the decoded data.
   *
   * @throws  ParseException  If the contents of the provided string cannot be
   *                          parsed as base32-encoded data.
   */
  public static byte[] decode(final String data)
         throws ParseException
  {
    ensureNotNull(data);

    final int length = data.length();
    if (length == 0)
    {
      return new byte[0];
    }

    if ((length % 8) != 0)
    {
      throw new ParseException(ERR_BASE32_DECODE_INVALID_LENGTH.get(), length);
    }

    final ByteStringBuffer buffer = new ByteStringBuffer(5 * (length / 8));

    int stringPos = 0;
    while (stringPos < length)
    {
      long longValue = 0x00;
      for (int i=0; i < 8; i++)
      {
        longValue <<= 5;
        switch (data.charAt(stringPos++))
        {
          case 'A':
          case 'a':
            longValue |= 0x00L;
            break;
          case 'B':
          case 'b':
            longValue |= 0x01L;
            break;
          case 'C':
          case 'c':
            longValue |= 0x02L;
            break;
          case 'D':
          case 'd':
            longValue |= 0x03L;
            break;
          case 'E':
          case 'e':
            longValue |= 0x04L;
            break;
          case 'F':
          case 'f':
            longValue |= 0x05L;
            break;
          case 'G':
          case 'g':
            longValue |= 0x06L;
            break;
          case 'H':
          case 'h':
            longValue |= 0x07L;
            break;
          case 'I':
          case 'i':
            longValue |= 0x08L;
            break;
          case 'J':
          case 'j':
            longValue |= 0x09L;
            break;
          case 'K':
          case 'k':
            longValue |= 0x0AL;
            break;
          case 'L':
          case 'l':
            longValue |= 0x0BL;
            break;
          case 'M':
          case 'm':
            longValue |= 0x0CL;
            break;
          case 'N':
          case 'n':
            longValue |= 0x0DL;
            break;
          case 'O':
          case 'o':
            longValue |= 0x0EL;
            break;
          case 'P':
          case 'p':
            longValue |= 0x0FL;
            break;
          case 'Q':
          case 'q':
            longValue |= 0x10L;
            break;
          case 'R':
          case 'r':
            longValue |= 0x11L;
            break;
          case 'S':
          case 's':
            longValue |= 0x12L;
            break;
          case 'T':
          case 't':
            longValue |= 0x13L;
            break;
          case 'U':
          case 'u':
            longValue |= 0x14L;
            break;
          case 'V':
          case 'v':
            longValue |= 0x15L;
            break;
          case 'W':
          case 'w':
            longValue |= 0x16L;
            break;
          case 'X':
          case 'x':
            longValue |= 0x17L;
            break;
          case 'Y':
          case 'y':
            longValue |= 0x18L;
            break;
          case 'Z':
          case 'z':
            longValue |= 0x19L;
            break;
          case '2':
            longValue |= 0x1AL;
            break;
          case '3':
            longValue |= 0x1BL;
            break;
          case '4':
            longValue |= 0x1CL;
            break;
          case '5':
            longValue |= 0x1DL;
            break;
          case '6':
            longValue |= 0x1EL;
            break;
          case '7':
            longValue |= 0x1FL;
            break;

          case '=':
            switch (length - stringPos)
            {
              case 0:
                // The string ended with a single equal sign, so there are
                // four bytes left.
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                buffer.append((byte) ((longValue >> 8) & 0xFFL));
                return buffer.toByteArray();

              case 2:
                // The string ended with three equal signs, so there are three
                // bytes left.
                longValue <<= 10;
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                buffer.append((byte) ((longValue >> 16) & 0xFFL));
                return buffer.toByteArray();

              case 3:
                // The string ended with four equal signs, so there are two
                // bytes left.
                longValue <<= 15;
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                buffer.append((byte) ((longValue >> 24) & 0xFFL));
                return buffer.toByteArray();

              case 5:
                // The string ended with six equal signs, so there is one byte
                // left.
                longValue <<= 25;
                buffer.append((byte) ((longValue >> 32) & 0xFFL));
                return buffer.toByteArray();

              default:
                throw new ParseException(
                     ERR_BASE32_DECODE_UNEXPECTED_EQUAL.get((stringPos-1)),
                     (stringPos-1));
            }

          default:
            throw new ParseException(
                 ERR_BASE32_DECODE_UNEXPECTED_CHAR.get(
                      data.charAt(stringPos-1)),
                 (stringPos-1));
        }
      }

      buffer.append((byte) ((longValue >> 32) & 0xFFL));
      buffer.append((byte) ((longValue >> 24) & 0xFFL));
      buffer.append((byte) ((longValue >> 16) & 0xFFL));
      buffer.append((byte) ((longValue >> 8) & 0xFFL));
      buffer.append((byte) (longValue & 0xFFL));
    }

    return buffer.toByteArray();
  }



  /**
   * Decodes the contents of the provided base32-encoded string to a string
   * containing the raw data using the UTF-8 encoding.
   *
   * @param  data  The base32-encoded string to decode.  It must not be
   *               {@code null}.
   *
   * @return  A string containing the decoded data.
   *
   * @throws  ParseException  If the contents of the provided string cannot be
   *                          parsed as base32-encoded data using the UTF-8
   *                          encoding.
   */
  public static String decodeToString(final String data)
         throws ParseException
  {
    ensureNotNull(data);

    final byte[] decodedBytes = decode(data);
    return StaticUtils.toUTF8String(decodedBytes);
  }
}
