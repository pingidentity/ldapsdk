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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import java.util.Date;
import java.util.GregorianCalendar;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
                   LogSyntaxMessages.*;



/**
 * This class defines a log field syntax for values that are timestamps
 * represented in the generalized time format.  This syntax does not support
 * redacting or tokenizing individual components within the timestamps.
 * Redacted generalized time values will have a string representation of
 * "99990101000000.000Z", which corresponds to midnight UTC of January 1 in the
 * year 9999.  Tokenized values will have a year of 8888 (in the UTC time
 * zone).
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
public final class GeneralizedTimeLogFieldSyntax
       extends LogFieldSyntax<Date>
{
  /**
   * The name for this syntax.
   */
  @NotNull public static final String SYNTAX_NAME = "generalized-time";



  /**
   * The string that will be used for completely redacted generalized time
   * values.
   */
  @NotNull private static final String REDACTED_GENERALIZED_TIME_STRING =
       "99990101000000.000Z";



  /**
   * The year that will be used for dates that represent tokenized generalized
   * time values.
   */
  private static final int TOKENIZED_DATE_YEAR = 8888;



  /**
   * A singleton instance of this log field syntax.
   */
  @NotNull private static final GeneralizedTimeLogFieldSyntax INSTANCE =
       new GeneralizedTimeLogFieldSyntax();



  /**
   * Creates a new instance of this log field syntax implementation.
   */
  private GeneralizedTimeLogFieldSyntax()
  {
    super(100);
  }



  /**
   * Retrieves a singleton instance of this log field syntax.
   *
   * @return  A singleton instance of this log field syntax.
   */
  @NotNull()
  public static GeneralizedTimeLogFieldSyntax getInstance()
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
   * {@inheritDoc}
   */
  @Override()
  public void valueToSanitizedString(@NotNull final Date value,
                                     @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(StaticUtils.encodeGeneralizedTime(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Date fieldValue,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    valueToSanitizedString(fieldValue, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Date fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, valueToSanitizedString(fieldValue));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSanitizedValueToJSONFormattedLog(
              @NotNull final Date value,
              @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(valueToSanitizedString(value));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public Date parseValue(@NotNull final String valueString)
         throws RedactedValueException, TokenizedValueException,
                LogSyntaxException
  {
    try
    {
      return StaticUtils.decodeGeneralizedTime(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (valueStringIncludesRedactedComponent(valueString))
      {
        throw new RedactedValueException(
             ERR_GEN_TIME_LOG_SYNTAX_CANNOT_PARSE_REDACTED.get(), e);
      }
      else if (valueStringIncludesTokenizedComponent(valueString))
      {
        throw new TokenizedValueException(
             ERR_GEN_TIME_LOG_SYNTAX_CANNOT_PARSE_TOKENIZED.get(), e);
      }
      else
      {
        throw new LogSyntaxException(
             ERR_GEN_TIME_LOG_SYNTAX_CANNOT_PARSE.get(), e);
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
         valueString.equals(REDACTED_GENERALIZED_TIME_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void redactEntireValue(@NotNull final ByteStringBuffer buffer)
  {
    buffer.append(REDACTED_GENERALIZED_TIME_STRING);
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
  public void logCompletelyRedactedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    buffer.append(REDACTED_GENERALIZED_TIME_STRING);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, REDACTED_GENERALIZED_TIME_STRING);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyRedactedValueToJSONFormattedLog(
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(REDACTED_GENERALIZED_TIME_STRING);
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
                   @NotNull final Date fieldValue,
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
                   @NotNull final Date fieldValue,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyRedactedFieldToJSONFormattedLog(fieldName, buffer);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logRedactedComponentsValueToJSONFormattedLog(
                   @NotNull final Date value,
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

    return valueString.startsWith("8888");
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
  public void tokenizeEntireValue(@NotNull final Date value,
                                  @NotNull final byte[] pepper,
                                  @NotNull final ByteStringBuffer buffer)
  {
    // Concatenate the long value of the provided date and the pepper, and
    // generate a SHA-256 digest from the result.
    final byte[] tokenDigest;
    final ByteStringBuffer tempBuffer = getTemporaryBuffer();
    try
    {
      tempBuffer.append(value.getTime());
      tempBuffer.append(pepper);
      tokenDigest = sha256(tempBuffer);
    }
    finally
    {
      releaseTemporaryBuffer(tempBuffer);
    }


    // Generate a long value from the first eight digits of the digest.
    long tokenizedTime = 0L;
    for (int i=0; i < 8; i++)
    {
      tokenizedTime <<= 8;
      tokenizedTime |= (tokenDigest[i] & 0xFFL);
    }


    // Create a Gregorian calendar in the UTC time zone, seed it with the
    // tokenized time, and set the year to 8888.
    final GregorianCalendar tokenCalendar =
         new GregorianCalendar(StaticUtils.getUTCTimeZone());
    tokenCalendar.setTimeInMillis(tokenizedTime);
    tokenCalendar.set(GregorianCalendar.YEAR, TOKENIZED_DATE_YEAR);


    // Append a generalized time representation of the calendar value to the
    // provided buffer.
    buffer.append(StaticUtils.encodeGeneralizedTime(tokenCalendar.getTime()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToTextFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Date fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final ByteStringBuffer buffer)
  {
    buffer.append(' ');
    buffer.append(fieldName);
    buffer.append("=\"");
    tokenizeEntireValue(fieldValue, pepper, buffer);
    buffer.append('"');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedFieldToJSONFormattedLog(
                   @NotNull final String fieldName,
                   @NotNull final Date fieldValue,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(fieldName, tokenizeEntireValue(fieldValue, pepper));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompletelyTokenizedValueToJSONFormattedLog(
                   @NotNull final Date value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    buffer.appendString(tokenizeEntireValue(value, pepper));
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
                   @NotNull final Date fieldValue,
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
                   @NotNull final Date fieldValue,
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
                   @NotNull final Date value,
                   @NotNull final byte[] pepper,
                   @NotNull final JSONBuffer buffer)
  {
    logCompletelyTokenizedValueToJSONFormattedLog(value, pepper, buffer);
  }
}
