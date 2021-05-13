/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.io.Serializable;

import com.unboundid.util.ByteString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a set of properties that can be used to indicate which
 * types of optional base64-encoding should be performed by the LDAP SDK.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Base64EncodingStrategy
       implements Serializable
{
  /**
   * A base64-encoding strategy that represents a default, user-friendly
   * configuration.  This includes:
   * <UL>
   *   <LI>
   *     The presence of ASCII control characters will cause a value to be
   *     base64-encoded.
   *   </LI>
   *   <LI>
   *     The presence of displayable non-ASCII characters will not cause a value
   *     to be base64-encoded.
   *   </LI>
   *   <LI>
   *     The presence of non-displayable non-ASCII characters will cause a value
   *     to be base64-encoded.
   *   </LI>
   *   <LI>
   *     The presence of non-UTF-8 data will cause a value to be base64-encoded.
   *   </LI>
   * </UL>
   */
  @NotNull public static final Base64EncodingStrategy DEFAULT =
       new Base64EncodingStrategy(true, false, true, true);



  /**
   * A base64-encoding strategy that indicates that the LDAP SDK should only
   * perform required base64 encoding and should not perform any optional
   * base64-encoding.
   */
  @NotNull public static final Base64EncodingStrategy MINIMAL =
       new Base64EncodingStrategy(false, false, false, false);



  /**
   * A base64-encoding strategy that indicates that the LDAP SDK should
   * perform the maximum amount of base64 encoding that is considered
   * reasonable.  Any value containing ASCII control characters, non-ASCII
   * characters of any kind, or non-UTF-8 data will be base64-encoded.
   */
  @NotNull public static final Base64EncodingStrategy MAXIMAL =
       new Base64EncodingStrategy(true, true, true, true);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2972495773823480376L;



  // Indicates whether the presence of one or more ASCII control characters
  // should cause a value to be base64-encoded.
  private final boolean encodeASCIIControlCharacters;

  // Indicates whether the presence of one or more displayable non-ASCII
  // characters should cause a value to be base64-encoded.
  private final boolean encodeDisplayableNonASCIICharacters;

  // Indicates whether the presence of one or more non-displayable non-ASCII
  // characters should cause a value to be base64-encoded.
  private final boolean encodeNonDisplayableNonASCIICharacters;

  // Indicates whether values that do not represent valid UTF-8 strings should
  // be base64-encoded.
  private final boolean encodeNonUTF8Data;



  /**
   * Creates a new base64 encoding strategy with the specified settings.
   *
   * @param  encodeASCIIControlCharacters
   *              Indicates whether the presence of one or more ASCII control
   *              characters (characters whose Unicode code point is less than
   *              or equal to 0x01F, or is equal to 0x7F) should cause a value
   *              to be base64-encoded.  Note that as per RFC 2849, the presence
   *              of the null (0x00), line feed (0x0A), and carriage return
   *              (0x0D) ASCII control characters will always cause a value to
   *              be base64-encoded.
   * @param  encodeDisplayableNonASCIICharacters
   *              Indicates whether the presence of one or more non-ASCII
   *              characters (characters whose Unicode code point is greater
   *              than 0x7F) that are believed to be displayable (as determined
   *              by the {@link StaticUtils#isLikelyDisplayableCharacter}
   *              method) should cause a value to be base64-encoded.
   * @param  encodeNonDisplayableNonASCIICharacters
   *              Indicates whether the presence of one or more non-ASCII
   *              characters (characters whose Unicode code point is greater
   *              than 0x7F) that are not believed to be displayable (as
   *              determined by the
   *              {@link StaticUtils#isLikelyDisplayableCharacter} method)
   *              should cause a value to be base64-encoded.
   * @param  encodeNonUTF8Data
   *              Indicates whether non-UTF-8-encoded data should be
   *              base64-encoded.  Note that if a value does not represent a
   *              valid UTF-8 string, then the
   *              {@code encodeDisplayableNonASCIICharacters} and
   *              {@code encodeNonDisplayableNonASCIICharacters} arguments will
   *              not be used.
   */
  public Base64EncodingStrategy(final boolean encodeASCIIControlCharacters,
              final boolean encodeDisplayableNonASCIICharacters,
              final boolean encodeNonDisplayableNonASCIICharacters,
              final boolean encodeNonUTF8Data)
  {
    this.encodeASCIIControlCharacters = encodeASCIIControlCharacters;
    this.encodeDisplayableNonASCIICharacters =
         encodeDisplayableNonASCIICharacters;
    this.encodeNonDisplayableNonASCIICharacters =
         encodeNonDisplayableNonASCIICharacters;
    this.encodeNonUTF8Data = encodeNonUTF8Data;
  }



  /**
   * Indicates whether the presence of one or more ASCII control characters
   * should cause a value to be base64-encoded.
   *
   * @return  {@code true} if the presence of one or more ASCII control
   *          characters should cause a value to be base64-encoded, or
   *          {@code false} if not.
   */
  public boolean encodeASCIIControlCharacters()
  {
    return encodeASCIIControlCharacters;
  }



  /**
   * Indicates whether the presence of one or more displayable non-ASCII
   * characters (as determined by the
   * {@link StaticUtils#isLikelyDisplayableCharacter} method) should cause a
   * value to be base64-encoded.  Note that this only applies to values that
   * represent valid UTF-8 strings.  Values that are not valid UTF-8 strings
   * will use the setting represented by the {@link #encodeNonUTF8Data} method.
   *
   * @return  {@code true} if the presence of one or more displayable
   *          non-ASCII characters should cause a value to be base64-encoded,
   *          or {@code false} if not.
   */
  public boolean encodeDisplayableNonASCIICharacters()
  {
    return encodeDisplayableNonASCIICharacters;
  }



  /**
   * Indicates whether the presence of one or more non-displayable non-ASCII
   * characters (as determined by the
   * {@link StaticUtils#isLikelyDisplayableCharacter} method) should cause a
   * value to be base64-encoded.  Note that this only applies to values that
   * represent valid UTF-8 strings.  Values that are not valid UTF-8 strings
   * will use the setting represented by the {@link #encodeNonUTF8Data} method.
   *
   * @return  {@code true} if the presence of one or more non-displayable
   *          non-ASCII characters should cause a value to be base64-encoded,
   *          or {@code false} if not.
   */
  public boolean encodeNonDisplayableNonASCIICharacters()
  {
    return encodeNonDisplayableNonASCIICharacters;
  }



  /**
   * Indicates whether values that do not represent valid UTF-8 strings (as
   * determined by the {@link StaticUtils#isValidUTF8} method) should be
   * base64-encoded.
   *
   * @return  {@code true} if values that do not represent valid UTF-8 strings
   *          should be base64-encoded, or {@code false} if not.
   */
  public boolean encodeNonUTF8Data()
  {
    return encodeNonUTF8Data;
  }



  /**
   * Indicates whether the provided value should be base64-encoded in accordance
   * with this strategy.
   *
   * @param  value  The value for which to make the determination.  It must not
   *                be {@code null}.
   *
   * @return  {@code true} if the provided value should be base64-encoded in
   *          accordance with this strategy, or {@code false} if not.
   */
  public boolean shouldBase64Encode(@NotNull final byte[] value)
  {
    // If the value is empty, then it does not need to be encoded.
    if ((value == null) || (value.length == 0))
    {
      return false;
    }


    // If the value starts with a space, colon, or less-than character, then it
    // must be base64-encoded.
    switch (value[0])
    {
      case ' ':
      case ':':
      case '<':
        return true;
    }


    // If the value ends with a space, then it must be base64-encoded.
    if (value[value.length - 1] == ' ')
    {
      return true;
    }


    // Examine all the bytes that make up the value.  If we encounter any
    // non-ASCII characters, then handle that specially.
    for (int i=0; i < value.length; i++)
    {
      // Bytes that are between 0x00 and 0x1F are ASCII control characters.  The
      // null (0x00), line feed (0x0A) and carriage return (0x0D) characters
      // must always base base64-encoded.  For other bytes, use the
      // encodeASCIIControlCharacters flag.
      final byte b = value[i];
      if ((b >= 0x00) && (b <= 0x1F))
      {
        switch (b)
        {
          case 0x00:
          case 0x0A:
          case 0x0D:
            return true;
          default:
            if (encodeASCIIControlCharacters)
            {
              return true;
            }
            break;
        }
      }

      // Byte 0x7F is the ASCII delete control character and should also be
      // controlled by the encodeASCIIControlCharacters flag.
      else if (b == 0x07F)
      {
        if (encodeASCIIControlCharacters)
        {
          return true;
        }
      }


      // All bytes between 0x20 and 0x7E (inclusive) should be fine.  All other
      // bytes will have the most significant bit set, and because Java bytes
      // are signed, they will be negative.  If we encounter any negative bytes,
      // then that means the value contains non-ASCII characters or doesn't
      // represent a UTF-8 string.  If it's not valid UTF-8, then we'll handle
      // it in accordance with the encodeNonUTF8Data flag.  Otherwise, we'll
      // convert the remainder of the byte to a string and iterate across the
      // code points for the rest of the determination.
      else if (b < 0x00)
      {
        final byte[] remainingBytes = new byte[value.length - i];
        System.arraycopy(value, i, remainingBytes, 0, remainingBytes.length);
        if (StaticUtils.isValidUTF8(remainingBytes))
        {
          final String valueString = StaticUtils.toUTF8String(remainingBytes);
          return shouldBase64EncodePreValidatedString(valueString);
        }
        else
        {
          return encodeNonUTF8Data;
        }
      }
    }


    // If we've gotten here, then the value does not need to be base64-encoded.
    return false;
  }



  /**
   * Indicates whether the provided value should be base64-encoded in accordance
   * with this strategy.
   *
   * @param  value  The value for which to make the determination.  It must not
   *                be {@code null}.
   *
   * @return  {@code true} if the provided value should be base64-encoded in
   *          accordance with this strategy, or {@code false} if not.
   */
  public boolean shouldBase64Encode(@NotNull final String value)
  {
    // If the value is empty, then it does not need to be encoded.
    if ((value == null) || (value.length() == 0))
    {
      return false;
    }


    // If the value starts with a space, colon, or less-than character, then it
    // must be base64-encoded.
    switch (value.charAt(0))
    {
      case ' ':
      case ':':
      case '<':
        return true;
    }


    // If the value ends with a space, then it must be base64-encoded.
    if (value.charAt(value.length() - 1) == ' ')
    {
      return true;
    }


    // Examine all of the characters in the string as code points so that we can
    // handle non-ASCII characters properly.
    return shouldBase64EncodePreValidatedString(value);
  }



  /**
   * Indicates whether the provided string should be base64-encoded in
   * accordance with this strategy.  Note that all of the appropriate first and
   * last character validation must have already been performed.
   *
   * @param  s  The string to validate.  It must not be {@code null}.
   *
   * @return  {@code true} if the value should be base64-encoded in accordance
   *          with this strategry, or {@code false} if not.
   */
  private boolean shouldBase64EncodePreValidatedString(@NotNull final String s)
  {
    int pos = 0;
    while (pos < s.length())
    {
      final int codePoint = s.codePointAt(pos);


      // Code points that are between 0x00 and 0x1F are ASCII control
      // characters.  The null (0x00), line feed (0x0A), and carriage return
      // (0x0D) characters must always be base64-encoded.  For other bytes, use
      // the encodeASCIIControlCharacters flag.
      //
      // Note that code points will never be negative, so we don't have to check
      // for a lower bound.
      if (codePoint <=0x1F)
      {
        switch (codePoint)
        {
          case 0x00:
          case 0x0A:
          case 0x0D:
            return true;
          default:
            if (encodeASCIIControlCharacters)
            {
              return true;
            }
            break;
        }
      }


      // Code point 0x7F is the ASCII delete control character and should also
      // be controlled by the encodeASCIIControlCharacters flag.
      else if (codePoint == 0x7F)
      {
        if (encodeASCIIControlCharacters)
        {
          return true;
        }
      }


      // If the code point is greater than 0x7F, then it's a non-ASCII character
      // and the behavior should be controlled by either the
      // encodeDisplayableNonASCIICharacters or
      // encodeNonDisplayableNonASCIICharacters flag, whichever is appropriate.
      else if (codePoint > 0x7F)
      {
        if (StaticUtils.isLikelyDisplayableCharacter(codePoint))
        {
          if (encodeDisplayableNonASCIICharacters)
          {
            return true;
          }
        }
        else
        {
          if (encodeNonDisplayableNonASCIICharacters)
          {
            return true;
          }
        }
      }


      // Increment the position index based on the number of characters in the
      // code point.  Some code points may require multiple characters to
      // represent.
      final int charsPerCodePoint = Character.charCount(codePoint);
      pos += charsPerCodePoint;
    }


    // If we've gotten here, then the value does not need to be base64-encoded.
    return false;
  }



  /**
   * Indicates whether the provided value should be base64-encoded in accordance
   * with this strategy.
   *
   * @param  value  The value for which to make the determination.  It must not
   *                be {@code null}.
   *
   * @return  {@code true} if the provided value should be base64-encoded in
   *          accordance with this strategy, or {@code false} if not.
   */
  public boolean shouldBase64Encode(@NotNull final ByteString value)
  {
    return shouldBase64Encode(value.getValue());
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
    buffer.append("Base64EncodingStrategy(encodeASCIIControlCharacters=");
    buffer.append(encodeASCIIControlCharacters);
    buffer.append(", encodeDisplayableNonASCIICharacters=");
    buffer.append(encodeDisplayableNonASCIICharacters);
    buffer.append(", encodeNonDisplayableNonASCIICharacters=");
    buffer.append(encodeNonDisplayableNonASCIICharacters);
    buffer.append(", encodeNonUTF8Data=");
    buffer.append(encodeNonUTF8Data);
    buffer.append(')');
  }
}
