/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.LogMessages.*;



/**
 * This class defines a log field syntax for values that are floating-point
 * numbers.  This syntax does not support redacting or tokenizing individual
 * components within the numbers.  Redacted floating-point values will have a
 * string representation of "-999999.999999".  Tokenized floating-point string
 * values will have a string representation of "-999999." followed by six digits
 * that correspond to a token value generated from the actual value.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FloatingPointLogFieldSyntax
       extends LogFieldSyntax<Double>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "floating-point";



  /**
   * The string representation that will be used for a floating-point value that
   * is completely redacted.
   */
  @NotNull private static final String REDACTED_FLOATING_POINT_STRING =
       "-999999.999999";



  /**
   * A singleton instance of this log field syntax.
   */
  @NotNull private static final FloatingPointLogFieldSyntax INSTANCE =
       new FloatingPointLogFieldSyntax();



  /**
   * Creates a new instance of this log field syntax implementation.
   */
  private FloatingPointLogFieldSyntax()
  {
    super(100);
  }



  /**
   * Retrieves a singleton instance of this log field syntax.
   *
   * @return  A singleton instance of this log field syntax.
   */
  @NotNull()
  public static FloatingPointLogFieldSyntax getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSyntaxName()
  {
    return SYNTAX_NAME;
  }



  /**
   * Appends a sanitized string representation of the provided float to the
   * given buffer.
   *
   * @param  value   The value to be appended.
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void valueToSanitizedString(final float value,
                            @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(String.valueOf(value));
  }



  /**
   * Appends a sanitized string representation of the provided double to the
   * given buffer.
   *
   * @param  value   The value to be appended.
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void valueToSanitizedString(final double value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(String.valueOf(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void valueToSanitizedString(@NotNull final Double value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(value.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Double parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    try
    {
      return Double.parseDouble(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (valueStringIncludesRedactedComponent(valueString))
      {
        throw new RedactedValueException(
             ERR_FP_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get(), e);
      }
      else if (valueStringIncludesTokenizedComponent(valueString))
      {
        throw new TokenizedValueException(
             ERR_FP_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get(), e);
      }
      else
      {
        throw new LogSyntaxException(
             ERR_FP_LOG_SYNTAX_CANNOT_PARSE.get(), e);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIsCompletelyRedacted(
                      @NotNull final String valueString)
  {
    return valueString.equals(REDACTED_STRING) ||
         valueString.equals(REDACTED_FLOATING_POINT_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean completelyRedactedValueConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void redactEntireValue(@NotNull final ByteStringBuffer buffer)
  {
    buffer.append(REDACTED_FLOATING_POINT_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsRedactedComponents()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIncludesRedactedComponent(
                      @NotNull final String valueString)
  {
    return valueStringIsCompletelyRedacted(valueString);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueWithRedactedComponentsConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIsCompletelyTokenized(
                      @NotNull final String valueString)
  {
    if (super.valueStringIsCompletelyTokenized(valueString))
    {
      return true;
    }

    return ((valueString.length() == 14) &&
         valueString.startsWith("-999999.") &&
         (! valueString.equals(REDACTED_FLOATING_POINT_STRING)));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean completelyTokenizedValueConformsToSyntax()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void tokenizeEntireValue(@NotNull final Double value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    // Get the bytes that comprise the bitwise encoding of the provided value.
    final long valueBitsLong = Double.doubleToLongBits(value);
    final byte[] valueBytes =
    {
      (byte) ((valueBitsLong >> 56) & 0xFFL),
      (byte) ((valueBitsLong >> 48) & 0xFFL),
      (byte) ((valueBitsLong >> 40) & 0xFFL),
      (byte) ((valueBitsLong >> 32) & 0xFFL),
      (byte) ((valueBitsLong >> 24) & 0xFFL),
      (byte) ((valueBitsLong >> 16) & 0xFFL),
      (byte) ((valueBitsLong >> 8) & 0xFFL),
      (byte) (valueBitsLong & 0xFFL)
    };


    // Concatenate the value bytes and the pepper and compute a SHA-256 digest
    // of the result.
    final byte[] tokenDigest;
    final ByteStringBuffer tempBuffer = getTemporaryBuffer();
    try
    {
      tempBuffer.append(valueBytes);
      tempBuffer.append(pepper);
      tokenDigest = sha256(tempBuffer);
    }
    finally
    {
      releaseTemporaryBuffer(tempBuffer);
    }


    // Use the first four bytes of the token digest to generate a positive
    // integer whose string representation is exactly ten digits long.  To do
    // this, AND the first byte with 0x7F (which will make it positive) and OR
    // the first byte with 0x40 (which will ensure that the value will be
    // greater than or equal to 1073741824, and we already know that int
    // values cannot exceed 2147483647, so that means it will be exactly ten
    // digits).
    final int fractionalDigitsInt =
         (((tokenDigest[0] & 0x7F) | 0x40) << 24) |
         ((tokenDigest[1] & 0xFF) << 16) |
         ((tokenDigest[2] & 0xFF) << 8) |
         (tokenDigest[3] & 0xFF);


    // Take the last six digits of the string representation of the generated
    // integer.
    String fractionalDigits = String.valueOf(fractionalDigitsInt).substring(4);


    // Make sure that the resulting six-digit string is not "999999", so that
    // the tokenized value won't be confused with a redacted value.
    if (fractionalDigits.equals("999999"))
    {
      fractionalDigits = "000000";
    }


    // Finally, generate the tokenized representation.  It will be "-999999."
    // followed by the fractional digits generated above.
    buffer.append("-999999.");
    buffer.append(fractionalDigits);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsTokenizedComponents()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueStringIncludesTokenizedComponent(
                      @NotNull final String valueString)
  {
    return valueStringIsCompletelyTokenized(valueString);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean valueWithTokenizedComponentsConformsToSyntax()
  {
    return true;
  }
}
