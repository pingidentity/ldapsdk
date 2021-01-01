/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Map;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.LogMessages.*;



/**
 * This class provides a data structure that holds information about a log
 * message contained in a Directory Server access or error log file.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LogMessage
       implements Serializable
{
  /**
   * The format string that will be used for log message timestamps
   * with seconds-level precision enabled.
   */
  @NotNull private static final String TIMESTAMP_SEC_FORMAT =
          "'['dd/MMM/yyyy:HH:mm:ss Z']'";



  /**
   * The format string that will be used for log message timestamps
   * with seconds-level precision enabled.
   */
  @NotNull private static final String TIMESTAMP_MS_FORMAT =
          "'['dd/MMM/yyyy:HH:mm:ss.SSS Z']'";



  /**
   * The thread-local date formatter.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat> dateSecFormat =
       new ThreadLocal<>();



  /**
   * The thread-local date formatter.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat> dateMsFormat =
       new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1210050773534504972L;



  // The timestamp for this log message.
  @NotNull private final Date timestamp;

  // The map of named fields contained in this log message.
  @NotNull private final Map<String,String> namedValues;

  // The set of unnamed values contained in this log message.
  @NotNull private final Set<String> unnamedValues;

  // The string representation of this log message.
  @NotNull private final String messageString;



  /**
   * Creates a log message from the provided log message.
   *
   * @param  m  The log message to use to create this log message.
   */
  protected LogMessage(@NotNull final LogMessage m)
  {
    timestamp     = m.timestamp;
    unnamedValues = m.unnamedValues;
    namedValues   = m.namedValues;
    messageString = m.messageString;
  }



  /**
   * Parses the provided string as a log message.
   *
   * @param  s  The string to be parsed as a log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  protected LogMessage(@NotNull final String s)
            throws LogException
  {
    messageString = s;


    // The first element should be the timestamp, which should end with a
    // closing bracket.
    final int bracketPos = s.indexOf(']');
    if (bracketPos < 0)
    {
      throw new LogException(s, ERR_LOG_MESSAGE_NO_TIMESTAMP.get());
    }

    final String timestampString = s.substring(0, bracketPos+1);

    SimpleDateFormat f;
    if (timestampIncludesMilliseconds(timestampString))
    {
      f = dateMsFormat.get();
      if (f == null)
      {
        f = new SimpleDateFormat(TIMESTAMP_MS_FORMAT);
        f.setLenient(false);
        dateMsFormat.set(f);
      }
    }
    else
    {
      f = dateSecFormat.get();
      if (f == null)
      {
        f = new SimpleDateFormat(TIMESTAMP_SEC_FORMAT);
        f.setLenient(false);
        dateSecFormat.set(f);
      }
    }

    try
    {
      timestamp = f.parse(timestampString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LogException(s,
           ERR_LOG_MESSAGE_INVALID_TIMESTAMP.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // The remainder of the message should consist of named and unnamed values.
    final LinkedHashMap<String,String> named =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    final LinkedHashSet<String> unnamed =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(10));
    parseTokens(s, bracketPos+1, named, unnamed);

    namedValues   = Collections.unmodifiableMap(named);
    unnamedValues = Collections.unmodifiableSet(unnamed);
  }



  /**
   * Parses the set of named and unnamed tokens from the provided message
   * string.
   *
   * @param  s         The complete message string being parsed.
   * @param  startPos  The position at which to start parsing.
   * @param  named     The map in which to place the named tokens.
   * @param  unnamed   The set in which to place the unnamed tokens.
   *
   * @throws  LogException  If a problem occurs while processing the tokens.
   */
  private static void parseTokens(@NotNull final String s, final int startPos,
                                  @NotNull final Map<String,String> named,
                                  @NotNull final Set<String> unnamed)
          throws LogException
  {
    boolean inQuotes = false;
    final StringBuilder buffer = new StringBuilder();
    for (int p=startPos; p < s.length(); p++)
    {
      final char c = s.charAt(p);
      if ((c == ' ') && (! inQuotes))
      {
        if (buffer.length() > 0)
        {
          processToken(s, buffer.toString(), named, unnamed);
          buffer.delete(0, buffer.length());
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
      processToken(s, buffer.toString(), named, unnamed);
    }
  }



  /**
   * Processes the provided token and adds it to the appropriate collection.
   *
   * @param  s         The complete message string being parsed.
   * @param  token     The token to be processed.
   * @param  named     The map in which to place named tokens.
   * @param  unnamed   The set in which to place unnamed tokens.
   *
   * @throws  LogException  If a problem occurs while processing the token.
   */
  private static void processToken(@NotNull final String s,
                                   @NotNull final String token,
                                   @NotNull final Map<String,String> named,
                                   @NotNull final Set<String> unnamed)
          throws LogException
  {
    // If the token contains an equal sign, then it's a named token.  Otherwise,
    // it's unnamed.
    final int equalPos = token.indexOf('=');
    if (equalPos < 0)
    {
      // Unnamed tokens should never need any additional processing.
      unnamed.add(token);
    }
    else
    {
      // The name of named tokens should never need any additional processing.
      // The value may need to be processed to remove surrounding quotes and/or
      // to un-escape any special characters.
      final String name  = token.substring(0, equalPos);
      final String value = processValue(s, token.substring(equalPos+1));
      named.put(name, value);
    }
  }



  /**
   * Performs any processing needed on the provided value to obtain the original
   * text.  This may include removing surrounding quotes and/or un-escaping any
   * special characters.
   *
   * @param  s  The complete message string being parsed.
   * @param  v  The value to be processed.
   *
   * @return  The processed version of the provided string.
   *
   * @throws  LogException  If a problem occurs while processing the value.
   */
  @NotNull()
  private static String processValue(@NotNull final String s,
                                     @NotNull final String v)
          throws LogException
  {
    final ByteStringBuffer b = new ByteStringBuffer();

    for (int i=0; i < v.length(); i++)
    {
      final char c = v.charAt(i);
      if (c == '"')
      {
        // This should only happen at the beginning or end of the string, in
        // which case it should be stripped out so we don't need to do anything.
      }
      else if (c == '#')
      {
        // Every octothorpe should be followed by exactly two hex digits, which
        // represent a byte of a UTF-8 character.
        if (i > (v.length() - 3))
        {
          throw new LogException(s,
               ERR_LOG_MESSAGE_INVALID_ESCAPED_CHARACTER.get(v));
        }

        byte rawByte = 0x00;
        for (int j=0; j < 2; j++)
        {
          rawByte <<= 4;
          switch (v.charAt(++i))
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
              throw new LogException(s,
                   ERR_LOG_MESSAGE_INVALID_ESCAPED_CHARACTER.get(v));
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
   * Determines whether a string that represents a timestamp includes a
   * millisecond component.
   *
   * @param  timestamp   The timestamp string to examine.
   *
   * @return  {@code true} if the given string includes a millisecond component,
   *          or {@code false} if not.
   */
  private static boolean timestampIncludesMilliseconds(
                              @NotNull final String timestamp)
  {
    // The sec and ms format strings differ at the 22nd character.
    return ((timestamp.length() > 21) && (timestamp.charAt(21) == '.'));
  }



  /**
   * Retrieves the timestamp for this log message.
   *
   * @return  The timestamp for this log message.
   */
  @NotNull()
  public final Date getTimestamp()
  {
    return timestamp;
  }



  /**
   * Retrieves the set of named tokens for this log message, mapped from the
   * name to the corresponding value.
   *
   * @return  The set of named tokens for this log message.
   */
  @NotNull()
  public final Map<String,String> getNamedValues()
  {
    return namedValues;
  }



  /**
   * Retrieves the value of the token with the specified name.
   *
   * @param  name  The name of the token to retrieve.
   *
   * @return  The value of the token with the specified name, or {@code null} if
   *          there is no value with the specified name.
   */
  @Nullable()
  public final String getNamedValue(@NotNull final String name)
  {
    return namedValues.get(name);
  }



  /**
   * Retrieves the value of the token with the specified name as a
   * {@code Boolean}.
   *
   * @param  name  The name of the token to retrieve.
   *
   * @return  The value of the token with the specified name as a
   *          {@code Boolean}, or {@code null} if there is no value with the
   *          specified name or the value cannot be parsed as a {@code Boolean}.
   */
  @Nullable()
  public final Boolean getNamedValueAsBoolean(@NotNull final String name)
  {
    final String s = namedValues.get(name);
    if (s == null)
    {
      return null;
    }

    final String lowerValue = StaticUtils.toLowerCase(s);
    if (lowerValue.equals("true") || lowerValue.equals("t") ||
        lowerValue.equals("yes") || lowerValue.equals("y") ||
        lowerValue.equals("on") || lowerValue.equals("1"))
    {
      return Boolean.TRUE;
    }
    else if (lowerValue.equals("false") || lowerValue.equals("f") ||
             lowerValue.equals("no") || lowerValue.equals("n") ||
             lowerValue.equals("off") || lowerValue.equals("0"))
    {
      return Boolean.FALSE;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the value of the token with the specified name as a
   * {@code Double}.
   *
   * @param  name  The name of the token to retrieve.
   *
   * @return  The value of the token with the specified name as a
   *          {@code Double}, or {@code null} if there is no value with the
   *          specified name or the value cannot be parsed as a {@code Double}.
   */
  @Nullable()
  public final Double getNamedValueAsDouble(@NotNull final String name)
  {
    final String s = namedValues.get(name);
    if (s == null)
    {
      return null;
    }

    try
    {
      return Double.valueOf(s);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value of the token with the specified name as an
   * {@code Integer}.
   *
   * @param  name  The name of the token to retrieve.
   *
   * @return  The value of the token with the specified name as an
   *          {@code Integer}, or {@code null} if there is no value with the
   *          specified name or the value cannot be parsed as an
   *          {@code Integer}.
   */
  @Nullable()
  public final Integer getNamedValueAsInteger(@NotNull final String name)
  {
    final String s = namedValues.get(name);
    if (s == null)
    {
      return null;
    }

    try
    {
      return Integer.valueOf(s);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the value of the token with the specified name as a {@code Long}.
   *
   * @param  name  The name of the token to retrieve.
   *
   * @return  The value of the token with the specified name as a {@code Long},
   *          or {@code null} if there is no value with the specified name or
   *          the value cannot be parsed as a {@code Long}.
   */
  @Nullable()
  public final Long getNamedValueAsLong(@NotNull final String name)
  {
    final String s = namedValues.get(name);
    if (s == null)
    {
      return null;
    }

    try
    {
      return Long.valueOf(s);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the set of unnamed tokens for this log message.
   *
   * @return  The set of unnamed tokens for this log message.
   */
  @NotNull()
  public final Set<String> getUnnamedValues()
  {
    return unnamedValues;
  }



  /**
   * Indicates whether this log message has the specified unnamed value.
   *
   * @param  value  The value for which to make the determination.
   *
   * @return  {@code true} if this log message has the specified unnamed value,
   *          or {@code false} if not.
   */
  public final boolean hasUnnamedValue(@NotNull final String value)
  {
    return unnamedValues.contains(value);
  }



  /**
   * Retrieves a string representation of this log message.
   *
   * @return  A string representation of this log message.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    return messageString;
  }
}
