/*
 * Copyright 2021-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2024 Ping Identity Corporation
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
 * Copyright (C) 2021-2024 Ping Identity Corporation
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

import com.unboundid.util.ByteString;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a set of properties that can be used to indicate which
 * types of optional escaping should be performed by the LDAP SDK when
 * constructing the string representation of DNs and RDNs.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DNEscapingStrategy
       implements Serializable
{
  /**
   * A DN escaping strategy that represents a default, user-friendly
   * configuration.  This includes:
   * <UL>
   *   <LI>
   *     ASCII control characters will be escaped.
   *   </LI>
   *   <LI>
   *     Displayable non-ASCII characters will not be escaped.
   *   </LI>
   *   <LI>
   *     Non-displayable non-ASCII characters will be escaped.
   *   </LI>
   *   <LI>
   *     In non-UTF-8 data, all bytes with the most significant bit set will be
   *     escaped.
   *   </LI>
   * </UL>
   */
  @NotNull public static final DNEscapingStrategy DEFAULT =
       new DNEscapingStrategy(true, false, true, true);



  /**
   * A DN escaping strategy that indicates that the LDAP SDK should only perform
   * required escaping and should not perform any optional escaping.
   */
  @NotNull public static final DNEscapingStrategy MINIMAL =
       new DNEscapingStrategy(false, false, false, false);



  /**
   * A base64-encoding strategy that indicates that the LDAP SDK should
   * perform the maximum amount of DN escaping that is considered reasonable.
   * All ASCII control characters, all non-ASCII characters and non-UTF-8 bytes
   * will be escaped.
   */
  @NotNull public static final DNEscapingStrategy MAXIMAL =
       new DNEscapingStrategy(true, true, true, true);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5438646712027992419L;



  // Indicates whether ASCII control characters should be escaped.
  private final boolean escapeASCIIControlCharacters;

  // Indicates whether displayable non-ASCII characters should be escaped.
  private final boolean escapeDisplayableNonASCIICharacters;

  // Indicates whether non-displayable non-ASCII characters should be escaped.
  private final boolean escapeNonDisplayableNonASCIICharacters;

  // Indicates whether bytes with the most significant bit set in non-UTF-8 data
  // should be escaped.
  private final boolean escapeNonUTF8Data;



  /**
   * Creates a new DN escaping strategy with the specified settings.
   *
   * @param  escapeASCIIControlCharacters
   *              Indicates whether ASCII control characters (characters whose
   *              Unicode code point is less than or equal to 0x1F, or is equal
   *              to 0x7F) should be escaped.  Note that the ASCII NULL control
   *              character (0x00) will always be escaped.
   * @param  escapeDisplayableNonASCIICharacters
   *              Indicates whether non-ASCII characters (characters whose
   *              Unicode code point is greater than 0x7F) that are believed to
   *              be displayable (as determined by the
   *              {@link StaticUtils#isLikelyDisplayableCharacter} method)
   *              should be escaped.
   * @param  escapeNonDisplayableNonASCIICharacters
   *              Indicates whether non-ASCII characters (characters whose
   *              Unicode code point is greater than 0x7F) that are not believed
   *              to be displayable (as determined by the
   *              {@link StaticUtils#isLikelyDisplayableCharacter} method)
   *              should be escaped.
   * @param  escapeNonUTF8Data
   *              Indicates whether bytes with the most significant bit set in
   *              non-UTF-8 data should be escaped.  Note that if a value does
   *              not represent a valid UTF-8 string, then the
   *              {@code escapeDisplayableNonASCIICharacters} and
   *              {@code escapeNonDisplayableNonASCIICharacters} arguments will
   *              not be used.
   */
  public DNEscapingStrategy(final boolean escapeASCIIControlCharacters,
              final boolean escapeDisplayableNonASCIICharacters,
              final boolean escapeNonDisplayableNonASCIICharacters,
              final boolean escapeNonUTF8Data)
  {
    this.escapeASCIIControlCharacters = escapeASCIIControlCharacters;
    this.escapeDisplayableNonASCIICharacters =
         escapeDisplayableNonASCIICharacters;
    this.escapeNonDisplayableNonASCIICharacters =
         escapeNonDisplayableNonASCIICharacters;
    this.escapeNonUTF8Data = escapeNonUTF8Data;
  }



  /**
   * Indicates whether ASCII control characters should be escaped.  Note that
   * the ASCII NULL control character (0x00) will always be escaped.
   *
   * @return  {@code true} if ASCII control characters should be escaped, or
   *          {@code false} if not.
   */
  public boolean escapeASCIIControlCharacters()
  {
    return escapeASCIIControlCharacters;
  }



  /**
   * Indicates whether displayable non-ASCII characters (as determined by the
   * {@link StaticUtils#isLikelyDisplayableCharacter} method) should be escaped.
   * Note that this only applies to values that represent valid UTF-8 strings.
   * Values that are not valid UTF-8 strings will use the setting represented
   * by the {@link #escapeNonUTF8Data} method.
   *
   * @return  {@code true} if displayable non-ASCII characters should be
   *          escaped, or {@code false} if not.
   */
  public boolean escapeDisplayableNonASCIICharacters()
  {
    return escapeDisplayableNonASCIICharacters;
  }



  /**
   * Indicates whether non-displayable non-ASCII characters (as determined by
   * the {@link StaticUtils#isLikelyDisplayableCharacter} method) should be
   * escaped.  Note that this only applies to values that represent valid UTF-8
   * strings.  Values that are not valid UTF-8 strings will use the setting
   * represented by the {@link #escapeNonUTF8Data} method.
   *
   * @return  {@code true} if non-displayable non-ASCII characters should be
   *          escaped, or {@code false} if not.
   */
  public boolean escapeNonDisplayableNonASCIICharacters()
  {
    return escapeNonDisplayableNonASCIICharacters;
  }



  /**
   * Indicates whether bytes with the most significant bit set in non-UTF-8 data
   * (as determined by the {@link StaticUtils#isValidUTF8} method) should be
   * escaped.
   *
   * @return  {@code true} if bytes with the most significant bit set in
   *          non-UTF-8 data should be escaped, or {@code false} if not.
   */
  public boolean escapeNonUTF8Data()
  {
    return escapeNonUTF8Data;
  }



  /**
   * Appends an appropriately escaped representation of the provided value to
   * the given buffer.
   *
   * @param  value   The value to be appended.  It must not be {@code null}.
   * @param  buffer  The buffer to which the escaped value should be appended.
   *                 It must not be {@code null}.
   */
  public void escape(@NotNull final byte[] value,
                     @NotNull final ByteStringBuffer buffer)
  {
    // If the value is empty, then we don't need to do anything.
    final int valueLength = value.length;
    if ((value == null) || (valueLength == 0))
    {
      return;
    }


    // Iterate through the value and examine each byte.
    Boolean isNonUTF8 = null;
    for (int i=0; i < valueLength; i++)
    {
      final byte b = value[i];
      switch (b)
      {
        // The following characters will always be escaped anywhere in a value.
        case '"':
        case '+':
        case ',':
        case ';':
        case '<':
        case '>':
        case '\\':
          buffer.append('\\');
          buffer.append(b);
          break;

        // The ASCII NULL character must also always be escaped, but it should
        // use a hex encoding.
        case '\u0000':
          buffer.append("\\00");
          break;

        // Spaces will only be escaped if they are the first or last character
        // of the value.
        case ' ':
          if ((i == 0) || (i == (valueLength - 1)))
          {
            buffer.append('\\');
          }
          buffer.append(b);
          break;

        // The octothorpe character will only be escaped if it is the first
        // character of a value.
        case '#':
          if (i == 0)
          {
            buffer.append('\\');
          }
          buffer.append(b);
          break;

        default:
          // If the byte is between 0x00 and 0x1F (inclusive), or if it's 0x7F,
          // then it's an ASCII control character.  Handle that appropriately.
          if (((b >= 0x00) && (b <= 0x1F)) || (b == 0x07F))
          {
            if (escapeASCIIControlCharacters)
            {
              buffer.append('\\');
              buffer.append(StaticUtils.toHex(b));
            }
            else
            {
              buffer.append(b);
            }
          }


          // Because Java represents bytes as signed values, if a byte is
          // greater than zero, then it's an ASCII byte and we won't escape it.
          else if (b > 0x00)
          {
            buffer.append(b);
          }


          // If we've gotten here, then the byte is negative, which means that
          // it's not ASCII.  If we know that it's non-UTF-8 data, then handle
          // that in accordance with the escapeNonUTF8Data flag.  Otherwise,
          // check to see whether it is valid UTF-8 and handle it as either a
          // string comprised of code points or as non-UTF-8 data.
          else
          {
            if (isNonUTF8 == null)
            {
              final byte[] remainingValueBytes = new byte[valueLength - i];
              System.arraycopy(value, i, remainingValueBytes, 0,
                   remainingValueBytes.length);
              if (StaticUtils.isValidUTF8(remainingValueBytes))
              {
                escape(StaticUtils.toUTF8String(remainingValueBytes), buffer,
                     (i == 0));
                return;
              }
              else
              {
                isNonUTF8 = Boolean.TRUE;
              }
            }

            // If we've gotten here, then we know that it's non-UTF-8 data
            // (because we would have gone to a different method if it was
            // valid UTF-8), so handle that in accordance with the
            // escapeNonUTF8Data flag.
            if (escapeNonUTF8Data)
            {
              buffer.append('\\');
              buffer.append(StaticUtils.toHex(b));
            }
            else
            {
              buffer.append(b);
            }
          }
          break;
      }
    }
  }



  /**
   * Appends an appropriately escaped representation of the provided value to
   * the given buffer.
   *
   * @param  value   The value to be appended.  It must not be {@code null}.
   * @param  buffer  The buffer to which the escaped value should be appended.
   *                 It must not be {@code null}.
   */
  public void escape(@NotNull final String value,
                     @NotNull final ByteStringBuffer buffer)
  {
    escape(value, buffer, true);
  }



  /**
   * Appends an appropriately escaped representation of the provided value to
   * the given buffer.
   *
   * @param  value   The value to be appended.  It must not be {@code null}.
   * @param  buffer  The buffer to which the escaped value should be appended.
   *                 It must not be {@code null}.
   */
  public void escape(@NotNull final ByteString value,
                     @NotNull final ByteStringBuffer buffer)
  {
    escape(value.getValue(), buffer);
  }



  /**
   * Appends an appropriately escaped representation of the provided value to
   * the given buffer.
   *
   * @param  value          The value to be appended.  It must not be
   *                        {@code null}.
   * @param  buffer         The buffer to which the escaped value should be
   *                        appended.  It must not be {@code null}.
   * @param  isWholeString  Indicates whether the provided string represents the
   *                        entire value being processed, or if a portion of the
   *                        value may have already been processed.
   */
  private void escape(@NotNull final String value,
                      @NotNull final ByteStringBuffer buffer,
                      final boolean isWholeString)
  {
    if ((value == null) || value.isEmpty())
    {
      return;
    }

    int pos = 0;
    while (pos < value.length())
    {
      final int codePoint = value.codePointAt(pos);
      switch (codePoint)
      {
        // The following characters will always be escaped anywhere in a value.
        case '"':
        case '+':
        case ',':
        case ';':
        case '<':
        case '>':
        case '\\':
          buffer.append('\\');
          buffer.append((byte) codePoint);
          break;

        // The ASCII NULL character must also always be escaped, but it should
        // use a hex encoding.
        case '\u0000':
          buffer.append("\\00");
          break;

        // Spaces will only be escaped if they are the first or last character
        // of the value.
        case ' ':
          if (((pos == 0) && isWholeString) ||
               (pos == (value.length() - 1)))
          {
            buffer.append('\\');
          }
          buffer.append(' ');
          break;

        // The octothorpe character will only be escaped if it is the first
        // character of a value.
        case '#':
          if ((pos == 0) && isWholeString)
          {
            buffer.append('\\');
          }
          buffer.append('#');
          break;

        default:
          // If the code point is between 0x00 and 0x1F (inclusive), or if it is
          // 0x7F, then it's an ASCII control character.  Handle that
          // appropriately.
          if (((codePoint >= 0x00) && (codePoint <= 0x1F)) ||
               (codePoint == 0x7F))
          {
            final byte codePointByte = (byte) codePoint;
            if (escapeASCIIControlCharacters)
            {
              buffer.append('\\');
              buffer.append(StaticUtils.toHex(codePointByte));
            }
            else
            {
              buffer.append(codePointByte);
            }
          }


          // If the code point is less than 0x7F, then it's an ASCII character
          // that we don't need to escape.
          else if (codePoint < 0x7F)
          {
            buffer.append((byte) codePoint);
          }


          // If we've gotten here, then the code point must represent a
          // non-ASCII character.  Determine whether it's displayable and handle
          // it appropriately.
          else
          {
            final String codePointString =
                 new String(new int[] { codePoint }, 0, 1);
            final byte[] codePointBytes = StaticUtils.getBytes(codePointString);
            if (StaticUtils.isLikelyDisplayableCharacter(codePoint))
            {
              if (escapeDisplayableNonASCIICharacters)
              {
                for (final byte b : codePointBytes)
                {
                  buffer.append('\\');
                  buffer.append(StaticUtils.toHex(b));
                }
              }
              else
              {
                buffer.append(codePointBytes);
              }
            }
            else
            {
              if (escapeNonDisplayableNonASCIICharacters)
              {
                for (final byte b : codePointBytes)
                {
                  buffer.append('\\');
                  buffer.append(StaticUtils.toHex(b));
                }
              }
              else
              {
                buffer.append(codePointBytes);
              }
            }
          }
          break;
      }

      final int charsPerCodePoint = Character.charCount(codePoint);
      pos += charsPerCodePoint;
    }
  }



  /**
   * Retrieves a string representation of this base64 encoding strategy.
   *
   * @return  A string representation of this base64 encoding strategy.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this base64 encoding strategy to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DNEscapingStrategy(escapeASCIIControlCharacters=");
    buffer.append(escapeASCIIControlCharacters);
    buffer.append(", escapeDisplayableNonASCIICharacters=");
    buffer.append(escapeDisplayableNonASCIICharacters);
    buffer.append(", escapeNonDisplayableNonASCIICharacters=");
    buffer.append(escapeNonDisplayableNonASCIICharacters);
    buffer.append(", escapeNonUTF8Data=");
    buffer.append(escapeNonUTF8Data);
    buffer.append(')');
  }
}
