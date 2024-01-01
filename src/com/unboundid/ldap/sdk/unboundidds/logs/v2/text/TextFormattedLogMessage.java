/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogMessage;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.text.TextLogMessages.*;



/**
 * This class provides a data structure that holds information about a
 * text-formatted log message in the name=value format used by the Ping
 * Identity Directory Server and related server products.
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
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public class TextFormattedLogMessage
       implements LogMessage
{
  /**
   * A predefined string that will be used if a field exists in a log message
   * with just a value but no field name.
   */
  @NotNull protected static final String NO_FIELD_NAME = "";



  /**
   * The format string that will be used for log message timestamps
   * with seconds-level precision enabled.
   */
  @NotNull static final String TIMESTAMP_FORMAT_SECOND =
          "'['dd/MMM/yyyy:HH:mm:ss Z']'";



  /**
   * The format string that will be used for log message timestamps
   * with seconds-level precision enabled.
   */
  @NotNull static final String TIMESTAMP_FORMAT_MILLISECOND =
          "'['dd/MMM/yyyy:HH:mm:ss.SSS Z']'";



  /**
   * A set of thread-local date formatters that will be used for timestamp with
   * millisecond-level precision.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       MILLISECOND_DATE_FORMATTERS = new ThreadLocal<>();



  /**
   * A set of thread-local date formatters that will be used for timestamp with
   * second-level precision.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       SECOND_DATE_FORMATTERS = new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8953179308642786675L;



  // The timestamp value for this log message.
  private final long timestampValue;

  // A map of the fields in this log message.
  @NotNull private final Map<String,List<String>> logFields;

  // The string representation of this log message.
  @NotNull private final String logMessageString;



  /**
   * Creates a new text-formatted log message from the provided parsed message.
   *
   * @param  message  The message to use to create this log message.  It must
   *                  not be {@code null}.
   */
  protected TextFormattedLogMessage(
                 @NotNull final TextFormattedLogMessage message)
  {
    timestampValue = message.timestampValue;
    logFields = message.logFields;
    logMessageString = message.logMessageString;
  }



  /**
   * Creates a new text-formatted log message from the provided string.
   *
   * @param  logMessageString  The string representation of this log message.
   *                           It must not be {@code null}.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        text-formatted log message.
   */
  public TextFormattedLogMessage(@NotNull final String logMessageString)
         throws LogException
  {
    this.logMessageString = logMessageString;


    // The first element of the log message should be the timestamp, and it
    // should be enclosed in square brackets.
    final int closeBracketPos = logMessageString.indexOf(']');
    if ((closeBracketPos <= 0) || (! logMessageString.startsWith("[")))
    {
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_MISSING_TIMESTAMP.get(logMessageString));
    }

    final String timestampString =
         logMessageString.substring(0, (closeBracketPos+1));
    try
    {
      final SimpleDateFormat dateFormat =
           getDateFormat(timestampString.indexOf('.') > 0);
      final Date timestampDate = dateFormat.parse(timestampString);
      timestampValue = timestampDate.getTime();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_MISSING_TIMESTAMP.get(logMessageString),
           e);
    }


    // The remainder of the message should be the set of fields.
    logFields = parseFields(logMessageString, (closeBracketPos + 1));
  }



  /**
   * Retrieves a date formatter instance that should be used for parsing
   * timestamp values.
   *
   * @param  millisecondPrecision  Indicates whether to retrieve a formatter for
   *                               parsing timestamps with millisecond precision
   *                               (if {@code true}) or second precision (if
   *                               {@code false}).
   *
   * @return  The date formatter instance.
   */
  @NotNull()
  private static SimpleDateFormat getDateFormat(
               final boolean millisecondPrecision)
  {
    if (millisecondPrecision)
    {
      SimpleDateFormat dateFormat = MILLISECOND_DATE_FORMATTERS.get();
      if (dateFormat == null)
      {
        dateFormat = new SimpleDateFormat(TIMESTAMP_FORMAT_MILLISECOND);
        dateFormat.setLenient(false);
        MILLISECOND_DATE_FORMATTERS.set(dateFormat);
      }

      return dateFormat;
    }
    else
    {
      SimpleDateFormat dateFormat = SECOND_DATE_FORMATTERS.get();
      if (dateFormat == null)
      {
        dateFormat = new SimpleDateFormat(TIMESTAMP_FORMAT_SECOND);
        dateFormat.setLenient(false);
        SECOND_DATE_FORMATTERS.set(dateFormat);
      }

      return dateFormat;
    }
  }



  /**
   * Parses the set of log fields from the provided message string.
   *
   * @param  s         The complete message string being parsed.
   * @param  startPos  The position at which to start parsing.
   *
   * @return  The map containing the fields read from the message string.
   *
   * @throws  LogException  If a problem occurs while processing the message.
   */
  @NotNull()
  private static Map<String,List<String>> parseFields(@NotNull final String s,
                                                      final int startPos)
          throws LogException
  {
    final Map<String,List<String>> fieldMap = new LinkedHashMap<>();

    boolean inQuotes = false;
    final StringBuilder buffer = new StringBuilder();
    for (int p=startPos; p < s.length(); p++)
    {
      final char c = s.charAt(p);
      if ((c == ' ') && (! inQuotes))
      {
        if (buffer.length() > 0)
        {
          processField(s, buffer.toString(), fieldMap);
          buffer.setLength(0);
        }
      }
      else if (c == '"')
      {
        inQuotes = (! inQuotes);
      }
      else
      {
        buffer.append(c);
      }
    }

    if (buffer.length() > 0)
    {
      processField(s, buffer.toString(), fieldMap);
    }

    return Collections.unmodifiableMap(fieldMap);
  }



  /**
   * Processes the provided log field and adds it to the given map.
   *
   * @param  logMessageString  The complete log message string being parsed.
   * @param  fieldString       The string representation of the field being
   *                           parsed.
   * @param  fieldMap          The map into which the parsed field should be
   *                           added.
   *
   * @throws  LogException  If a problem occurs while processing the token.
   */
  private static void processField(@NotNull final String logMessageString,
               @NotNull final String fieldString,
               @NotNull final Map<String,List<String>> fieldMap)
          throws LogException
  {
    // The field name will be the portion of the string before the equal sign.
    // If there's no equal sign, then use the empty string as the field name.
    final String fieldName;
    final String fieldValue;
    final int equalPos = fieldString.indexOf('=');
    if (equalPos < 0)
    {
      fieldName = NO_FIELD_NAME;
      fieldValue = processValue(logMessageString, fieldString);
    }
    else
    {
      fieldName = fieldString.substring(0, equalPos);
      fieldValue =
           processValue(logMessageString, fieldString.substring(equalPos+1));
    }

    // We'll use an immutable list for the field values.  This shouldn't hurt
    // performance because fields with multiple values should be very rare.
    final List<String> values = fieldMap.get(fieldName);
    if (values == null)
    {
      fieldMap.put(fieldName, Collections.singletonList(fieldValue));
    }
    else
    {
      final List<String> updatedValues = new ArrayList<>(values.size() + 1);
      updatedValues.addAll(values);
      updatedValues.add(fieldValue);
      fieldMap.put(fieldName, Collections.unmodifiableList(updatedValues));
    }
  }



  /**
   * Performs any processing needed on the provided value to obtain the original
   * text.  This may include removing surrounding quotes and/or un-escaping any
   * special characters.
   *
   * @param  logMessageString  The complete log message string being parsed.
   * @param  valueString       The value being processed.
   *
   * @return  The processed version of the provided value.
   *
   * @throws  LogException  If a problem occurs while processing the value.
   */
  @NotNull()
  private static String processValue(@NotNull final String logMessageString,
                                     @NotNull final String valueString)
          throws LogException
  {
    final ByteStringBuffer b = new ByteStringBuffer();

    for (int i=0; i < valueString.length(); i++)
    {
      final char c = valueString.charAt(i);
      if (c == '"')
      {
        // This should only happen at the beginning or end of the string, in
        // which case it should be stripped out so we don't need to do anything.
      }
      else if (c == '#')
      {
        // Every octothorpe should be followed by exactly two hex digits, which
        // represent a byte of a UTF-8 character.
        if (i > (valueString.length() - 3))
        {
          throw new LogException(logMessageString,
               ERR_TEXT_LOG_MESSAGE_INVALID_ESCAPED_CHARACTER.get(valueString,
                    logMessageString));
        }

        byte rawByte = 0x00;
        for (int j=0; j < 2; j++)
        {
          rawByte <<= 4;
          switch (valueString.charAt(++i))
          {
            case '0':
              break;
            case '1':
              rawByte |= 0x01;
              break;
            case '2':
              rawByte |= 0x02;
              break;
            case '3':
              rawByte |= 0x03;
              break;
            case '4':
              rawByte |= 0x04;
              break;
            case '5':
              rawByte |= 0x05;
              break;
            case '6':
              rawByte |= 0x06;
              break;
            case '7':
              rawByte |= 0x07;
              break;
            case '8':
              rawByte |= 0x08;
              break;
            case '9':
              rawByte |= 0x09;
              break;
            case 'a':
            case 'A':
              rawByte |= 0x0A;
              break;
            case 'b':
            case 'B':
              rawByte |= 0x0B;
              break;
            case 'c':
            case 'C':
              rawByte |= 0x0C;
              break;
            case 'd':
            case 'D':
              rawByte |= 0x0D;
              break;
            case 'e':
            case 'E':
              rawByte |= 0x0E;
              break;
            case 'f':
            case 'F':
              rawByte |= 0x0F;
              break;
            default:
              throw new LogException(logMessageString,
                   ERR_TEXT_LOG_MESSAGE_INVALID_ESCAPED_CHARACTER.get(
                        valueString, logMessageString));
          }
        }

        b.append(rawByte);
      }
      else
      {
        b.append(c);
      }
    }

    return b.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Date getTimestamp()
  {
    return new Date(timestampValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final Map<String,List<String>> getFields()
  {
    return logFields;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Boolean getBoolean(@NotNull final LogField logField)
         throws LogException
  {
    final String valueString = getString(logField);
    if (valueString == null)
    {
      return null;
    }

    if (valueString.equalsIgnoreCase("true"))
    {
      return Boolean.TRUE;
    }
    else if (valueString.equalsIgnoreCase("false"))
    {
      return Boolean.FALSE;
    }
    else
    {
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_VALUE_NOT_BOOLEAN.get(logField.getFieldName(),
                logMessageString));
    }
  }



  /**
   * Retrieves the Boolean value of the specified field.
   *
   * @param  logField  The field for which to retrieve the Boolean value.
   *
   * @return  The Boolean value of the specified field, or {@code null} if the
   *          field does not exist in the log message or cannot be parsed as a
   *          Boolean.
   */
  @Nullable()
  final Boolean getBooleanNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getBoolean(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Date getGeneralizedTime(@NotNull final LogField logField)
         throws LogException
  {
    final String valueString = getString(logField);
    if (valueString == null)
    {
      return null;
    }

    try
    {
      return StaticUtils.decodeGeneralizedTime(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_VALUE_NOT_GENERALIZED_TIME.get(
                logField.getFieldName(), logMessageString),
           e);
    }
  }



  /**
   * Retrieves the generalized time value of the specified field.
   *
   * @param  logField  The field for which to retrieve the generalized time
   *                   value.
   *
   * @return  The generalized time value of the specified field, or {@code null}
   *          if the field does not exist in the log message or cannot be parsed
   *          as a timestamp in the generalized time format.
   */
  @Nullable()
  final Date getGeneralizedTimeNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getGeneralizedTime(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Double getDouble(@NotNull final LogField logField)
         throws LogException
  {
    final String valueString = getString(logField);
    if (valueString == null)
    {
      return null;
    }

    try
    {
      return Double.parseDouble(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_VALUE_NOT_FLOATING_POINT.get(
                logField.getFieldName(), logMessageString),
           e);
    }
  }



  /**
   * Retrieves the floating-point value of the specified field.
   *
   * @param  logField  The field for which to retrieve the floating-point value.
   *
   * @return  The floating-point value of the specified field, or {@code null}
   *          if the field does not exist in the log message or cannot be parsed
   *          as a Double.
   */
  @Nullable()
  final Double getDoubleNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getDouble(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Integer getInteger(@NotNull final LogField logField)
         throws LogException
  {
    final String valueString = getString(logField);
    if (valueString == null)
    {
      return null;
    }

    try
    {
      return Integer.parseInt(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                logField.getFieldName(), logMessageString),
           e);
    }
  }



  /**
   * Retrieves the integer value of the specified field.
   *
   * @param  logField  The field for which to retrieve the integer value.
   *
   * @return  The integer value of the specified field, or {@code null} if the
   *          field does not exist in the log message or cannot be parsed as an
   *          {@code Integer}.
   */
  @Nullable()
  final Integer getIntegerNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getInteger(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getLong(@NotNull final LogField logField)
         throws LogException
  {
    final String valueString = getString(logField);
    if (valueString == null)
    {
      return null;
    }

    try
    {
      return Long.parseLong(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_VALUE_NOT_INTEGER.get(
                logField.getFieldName(), logMessageString),
           e);
    }
  }



  /**
   * Retrieves the integer value of the specified field.
   *
   * @param  logField  The field for which to retrieve the integer value.
   *
   * @return  The integer value of the specified field, or {@code null} if the
   *          field does not exist in the log message or cannot be parsed as a
   *          {@code Long}.
   */
  @Nullable()
  final Long getLongNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getLong(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Date getRFC3339Timestamp(@NotNull final LogField logField)
         throws LogException
  {
    final String valueString = getString(logField);
    if (valueString == null)
    {
      return null;
    }

    try
    {
      return StaticUtils.decodeRFC3339Time(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(logMessageString,
           ERR_TEXT_LOG_MESSAGE_VALUE_NOT_RFC_3339_TIMESTAMP.get(
                logField.getFieldName(), logMessageString),
           e);
    }
  }



  /**
   * Retrieves the RFC 3339 timestamp value of the specified field.
   *
   * @param  logField  The field for which to retrieve the RFC 3339 timestamp
   *                   value.
   *
   * @return  The RFC 3339 timestamp value of the specified field, or
   *          {@code null} if the field does not exist in the log message or
   *          cannot be parsed as a timestamp in the RFC 3339 format.
   */
  @Nullable()
  final Date getRFC3339TimestampNoThrow(@NotNull final LogField logField)
  {
    try
    {
      return getRFC3339Timestamp(logField);
    }
    catch (final LogException e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getString(@NotNull final LogField logField)
  {
    final List<String> values = logFields.get(logField.getFieldName());
    if ((values == null) || values.isEmpty())
    {
      return null;
    }

    return values.get(0);
  }



  /**
   * Retrieves a list of the strings contained in a comma-delimited string held
   * in the specified field.
   *
   * @param  logField  The field containing the comma-delimited list of strings.
   *
   * @return  A list of the strings contained in the comma-delimited string
   *          field, or an empty list if the field was not present or the list
   *          was empty.
   */
  @NotNull()
  final List<String> getCommaDelimitedStringList(
             @NotNull final LogField logField)
  {
    final String stringValue = getString(logField);
    if ((stringValue == null) || stringValue.isEmpty())
    {
      return Collections.emptyList();
    }
    else
    {
      final List<String> valueList = new ArrayList<>();
      final StringTokenizer tokenizer = new StringTokenizer(stringValue, ",");
      while  (tokenizer.hasMoreTokens())
      {
        valueList.add(tokenizer.nextToken().trim());
      }

      return Collections.unmodifiableList(valueList);
    }
  }



  /**
   * Retrieves a set of the strings contained in a comma-delimited string held
   * in the specified field.
   *
   * @param  logField  The field containing the comma-delimited list of strings.
   *
   * @return  A set of the strings contained in the comma-delimited string
   *          field, or an empty set if the field was not present or the list
   *          was empty.
   */
  @NotNull()
  final Set<String> getCommaDelimitedStringSet(
             @NotNull final LogField logField)
  {
    final String stringValue = getString(logField);
    if ((stringValue == null) || stringValue.isEmpty())
    {
      return Collections.emptySet();
    }
    else
    {
      final Set<String> valueSet = new LinkedHashSet<>();
      final StringTokenizer tokenizer = new StringTokenizer(stringValue, ",");
      while  (tokenizer.hasMoreTokens())
      {
        valueSet.add(tokenizer.nextToken().trim());
      }

      return Collections.unmodifiableSet(valueSet);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    return logMessageString;
  }
}
