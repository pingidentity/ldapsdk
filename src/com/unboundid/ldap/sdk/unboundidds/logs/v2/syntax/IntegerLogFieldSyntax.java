/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
                   LogSyntaxMessages.*;



/**
 * This class defines a log field syntax for values that are integers.  This
 * syntax does not support redacting or tokenizing individual components within
 * the integers.  Redacted integer values will have a string representation of
 * "-999999999999999999".  Tokenized integer values will have a string
 * representation of "-999999999" followed by nine digits that correspond to a
 * token value generated from the actual value.
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
public final class IntegerLogFieldSyntax
       extends LogFieldSyntax<Long>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "integer";



  /**
   * The string representation that will be used for a floating-point value that
   * is completely redacted.
   */
  @NotNull private static final String REDACTED_INTEGER_STRING =
       "-999999999999999999";



  /**
   * A singleton instance of this log field syntax.
   */
  @NotNull private static final IntegerLogFieldSyntax INSTANCE =
       new IntegerLogFieldSyntax();



  /**
   * Creates a new instance of this log field syntax implementation.
   */
  private IntegerLogFieldSyntax()
  {
    super(100);
  }



  /**
   * Retrieves a singleton instance of this log field syntax.
   *
   * @return  A singleton instance of this log field syntax.
   */
  @NotNull()
  public static IntegerLogFieldSyntax getInstance()
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
   * Appends a sanitized string representation of the provided integer to the
   * given buffer.
   *
   * @param  value   The value to be appended.
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void valueToSanitizedString(final int value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(value);
  }



  /**
   * Appends a sanitized string representation of the provided long to the given
   * buffer.
   *
   * @param  value   The value to be appended.
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  public void valueToSanitizedString(final long value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void valueToSanitizedString(@NotNull final Long value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append('=');
    buffer.append(fieldValue.longValue());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(fieldName, fieldValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedValueToJSONFormattedLog(
              @NotNull final Long value,
              @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(value);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Long parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    try
    {
      return Long.parseLong(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (valueStringIncludesRedactedComponent(valueString))
      {
        throw new RedactedValueException(
             ERR_INTEGER_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get(), e);
      }
      else if (valueStringIncludesTokenizedComponent(valueString))
      {
        throw new TokenizedValueException(
             ERR_INTEGER_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get(), e);
      }
      else
      {
        throw new LogSyntaxException(
             ERR_INTEGER_LOG_SYNTAX_CANNOT_PARSE.get(), e);
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
         valueString.equals(REDACTED_INTEGER_STRING);
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
    buffer.append(REDACTED_INTEGER_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append('=');
    buffer.append(REDACTED_INTEGER_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(fieldName, REDACTED_INTEGER_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedValueToJSONFormattedLog(
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(REDACTED_INTEGER_STRING);
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
  public void logRedactedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    logCompletelyRedactedFieldToTextFormattedLog(fieldName, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyRedactedFieldToJSONFormattedLog(fieldName, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsValueToJSONFormattedLog(
                   @NotNull final Long value,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyRedactedValueToJSONFormattedLog(buffer);
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

    return ((valueString.length() == 19) &&
         valueString.startsWith("-999999999") &&
         (! valueString.equals(REDACTED_INTEGER_STRING)));
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
  public void tokenizeEntireValue(@NotNull final Long value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    // Get the bytes that comprise the bitwise encoding of the provided value.
    final long longValue = value;
    final byte[] valueBytes =
    {
      (byte) ((longValue >> 56) & 0xFFL),
      (byte) ((longValue >> 48) & 0xFFL),
      (byte) ((longValue >> 40) & 0xFFL),
      (byte) ((longValue >> 32) & 0xFFL),
      (byte) ((longValue >> 24) & 0xFFL),
      (byte) ((longValue >> 16) & 0xFFL),
      (byte) ((longValue >> 8) & 0xFFL),
      (byte) (longValue & 0xFFL)
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
    final int tokenValueInt =
         (((tokenDigest[0] & 0x7F) | 0x40) << 24) |
         ((tokenDigest[1] & 0xFF) << 16) |
         ((tokenDigest[2] & 0xFF) << 8) |
         (tokenDigest[3] & 0xFF);


    // Take the last nine digits of the string representation of the generated
    // integer.
    String tokenDigits = String.valueOf(tokenValueInt).substring(1);


    // Make sure that the resulting nine-digit string is not "999999999", so
    // that the tokenized value won't be confused with a redacted value.
    if (tokenDigits.equals("999999999"))
    {
      tokenDigits = "000000000";
    }


    // Finally, generate the tokenized representation.  It will be "-999999999"
    // followed by the token digits generated above.
    buffer.append("-999999999");
    buffer.append(tokenDigits);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append('=');
    tokenizeEntireValue(fieldValue, pepper, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(fieldName, tokenizeEntireValue(fieldValue, pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedValueToJSONFormattedLog(
                   @NotNull final Long value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(tokenizeEntireValue(value, pepper));
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



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    logCompletelyTokenizedFieldToTextFormattedLog(fieldName, fieldValue, pepper,
         buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Long fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyTokenizedFieldToJSONFormattedLog(fieldName, fieldValue, pepper,
         buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logTokenizedComponentsValueToJSONFormattedLog(
                   @NotNull final Long value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyTokenizedValueToJSONFormattedLog(value, pepper, buffer);
  }
}
