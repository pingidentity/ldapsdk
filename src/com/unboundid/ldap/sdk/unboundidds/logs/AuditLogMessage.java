/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.persist.PersistUtils;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientRequestValue;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;

import static com.unboundid.ldap.sdk.unboundidds.logs.LogMessages.*;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server audit log.
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
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class AuditLogMessage
       implements Serializable
{
  /**
   * A regular expression that can be used to determine if a line looks like an
   * audit log message header.
   */
  @NotNull private static final Pattern STARTS_WITH_TIMESTAMP_PATTERN =
       Pattern.compile(
            "^# " +          // Starts with an octothorpe and a space.
            "\\d\\d" +      // Two digits for the day of the month.
            "\\/" +          // A slash to separate the day from the month.
            "\\w\\w\\w" +    // Three characters for the month.
            "\\/"       +    // A slash to separate the month from the year.
            "\\d\\d\\d\\d" + // Four digits for the year.
            ":" +            // A colon to separate the year from the hour.
            "\\d\\d" +       // Two digits for the hour.
            ":" +            // A colon to separate the hour from the minute.
            "\\d\\d" +       // Two digits for the minute.
            ":" +            // A colon to separate the minute from the second.
            "\\d\\d" +       // Two digits for the second.
            ".*$");           // The rest of the line.



  /**
   * The format string that will be used for log message timestamps
   * with second-level precision enabled.
   */
  @NotNull private static final String TIMESTAMP_SEC_FORMAT =
       "dd/MMM/yyyy:HH:mm:ss Z";



  /**
   * The format string that will be used for log message timestamps
   * with second-level precision enabled.
   */
  @NotNull private static final String TIMESTAMP_MS_FORMAT =
       "dd/MMM/yyyy:HH:mm:ss.SSS Z";



  /**
   * A set of thread-local date formatters that can be used to parse timestamps
   * with second-level precision.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       TIMESTAMP_SEC_FORMAT_PARSERS = new ThreadLocal<>();



  /**
   * A set of thread-local date formatters that can be used to parse timestamps
   * with millisecond-level precision.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       TIMESTAMP_MS_FORMAT_PARSERS = new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1817887018590767411L;



  // Indicates whether the associated operation was processed using a worker
  // thread from the administrative thread pool.
  @Nullable private final Boolean usingAdminSessionWorkerThread;

  // The timestamp for this audit log message.
  @NotNull private final Date timestamp;

  // The intermediate client request control for this audit log message.
  @Nullable private final IntermediateClientRequestControl
       intermediateClientRequestControl;

  // The lines that comprise the complete audit log message.
  @NotNull private final List<String> logMessageLines;

  // The request control OIDs for this audit log message.
  @Nullable private final List<String> requestControlOIDs;

  // The connection ID for this audit log message.
  @Nullable private final Long connectionID;

  // The operation ID for this audit log message.
  @Nullable private final Long operationID;

  // The thread ID for this audit log message.
  @Nullable private final Long threadID;

  // The connection ID for the operation that triggered this audit log message.
  @Nullable private final Long triggeredByConnectionID;

  // The operation ID for the operation that triggered this audit log message.
  @Nullable private final Long triggeredByOperationID;

  // The map of named fields contained in this audit log message.
  @NotNull private final Map<String, String> namedValues;

  // The operation purpose request control for this audit log message.
  @Nullable private final OperationPurposeRequestControl
       operationPurposeRequestControl;

  // The DN of the alternate authorization identity for this audit log message.
  @Nullable private final String alternateAuthorizationDN;

  // The line that comprises the header for this log message, including the
  // opening comment sequence.
  @NotNull private final String commentedHeaderLine;

  // The server instance name for this audit log message.
  @Nullable private final String instanceName;

  // The origin for this audit log message.
  @Nullable private final String origin;

  // The replication change ID for the audit log message.
  @Nullable private final String replicationChangeID;

  // The requester DN for this audit log message.
  @Nullable private final String requesterDN;

  // The requester IP address for this audit log message.
  @Nullable private final String requesterIP;

  // The product name for this audit log message.
  @Nullable private final String productName;

  // The startup ID for this audit log message.
  @Nullable private final String startupID;

  // The transaction ID for this audit log message.
  @Nullable private final String transactionID;

  // The line that comprises the header for this log message, without the
  // opening comment sequence.
  @NotNull private final String uncommentedHeaderLine;



  /**
   * Creates a new audit log message from the provided set of lines.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty, and it must not
   *                          contain any blank lines, although it may contain
   *                          comments.  In fact, it must contain at least one
   *                          comment line that appears before any non-comment
   *                          lines (but possibly after other comment lines)
   *                          that serves as the message header.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  protected AuditLogMessage(@NotNull final List<String> logMessageLines)
            throws AuditLogException
  {
    if (logMessageLines == null)
    {
      throw new AuditLogException(Collections.<String>emptyList(),
           ERR_AUDIT_LOG_MESSAGE_LIST_NULL.get());
    }

    if (logMessageLines.isEmpty())
    {
      throw new AuditLogException(Collections.<String>emptyList(),
           ERR_AUDIT_LOG_MESSAGE_LIST_EMPTY.get());
    }

    for (final String line : logMessageLines)
    {
      if ((line == null) || line.isEmpty())
      {
        throw new AuditLogException(logMessageLines,
             ERR_AUDIT_LOG_MESSAGE_LIST_CONTAINS_EMPTY_LINE.get());
      }
    }

    this.logMessageLines = Collections.unmodifiableList(
         new ArrayList<>(logMessageLines));


    // Iterate through the message lines until we find the commented header line
    // (which is good) or until we find a non-comment line (which is bad because
    // it means there is no header and we can't handle that).
    String headerLine = null;
    for (final String line : logMessageLines)
    {
      if (STARTS_WITH_TIMESTAMP_PATTERN.matcher(line).matches())
      {
        headerLine = line;
        break;
      }
    }

    if (headerLine == null)
    {
      throw new AuditLogException(logMessageLines,
           ERR_AUDIT_LOG_MESSAGE_LIST_DOES_NOT_START_WITH_COMMENT.get());
    }

    commentedHeaderLine = headerLine;
    uncommentedHeaderLine = commentedHeaderLine.substring(2);

    final LinkedHashMap<String,String> nameValuePairs =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    timestamp = parseHeaderLine(logMessageLines, uncommentedHeaderLine,
         nameValuePairs);
    namedValues = Collections.unmodifiableMap(nameValuePairs);

    connectionID = getNamedValueAsLong("conn", namedValues);
    operationID = getNamedValueAsLong("op", namedValues);
    threadID = getNamedValueAsLong("threadID", namedValues);
    triggeredByConnectionID =
         getNamedValueAsLong("triggeredByConn", namedValues);
    triggeredByOperationID = getNamedValueAsLong("triggeredByOp", namedValues);
    alternateAuthorizationDN = namedValues.get("authzDN");
    instanceName = namedValues.get("instanceName");
    origin = namedValues.get("origin");
    replicationChangeID = namedValues.get("replicationChangeID");
    requesterDN = namedValues.get("requesterDN");
    requesterIP = namedValues.get("clientIP");
    productName = namedValues.get("productName");
    startupID = namedValues.get("startupID");
    transactionID = namedValues.get("txnID");
    usingAdminSessionWorkerThread =
         getNamedValueAsBoolean("usingAdminSessionWorkerThread", namedValues);
    operationPurposeRequestControl =
         decodeOperationPurposeRequestControl(namedValues);
    intermediateClientRequestControl =
         decodeIntermediateClientRequestControl(namedValues);

    final String oidsString = namedValues.get("requestControlOIDs");
    if (oidsString == null)
    {
      requestControlOIDs = null;
    }
    else
    {
      final ArrayList<String> oidList = new ArrayList<>(10);
      final StringTokenizer tokenizer = new StringTokenizer(oidsString, ",");
      while (tokenizer.hasMoreTokens())
      {
        oidList.add(tokenizer.nextToken());
      }
      requestControlOIDs = Collections.unmodifiableList(oidList);
    }
  }



  /**
   * Parses the provided header line for this audit log message.
   *
   * @param  logMessageLines        The lines that comprise the log message.  It
   *                                must not be {@code null} or empty.
   * @param  uncommentedHeaderLine  The uncommented representation of the header
   *                                line.  It must not be {@code null}.
   * @param  nameValuePairs         A map into which the parsed name-value pairs
   *                                may be placed.  It must not be {@code null}
   *                                and must be updatable.
   *
   * @return  The date parsed from the header line.  The name-value pairs parsed
   *          from the header line will be added to the {@code nameValuePairs}
   *          map.
   *
   * @throws  AuditLogException  If the line cannot be parsed as a valid header.
   */
  @NotNull()
  private static Date parseHeaderLine(
               @NotNull final List<String> logMessageLines,
               @NotNull final String uncommentedHeaderLine,
               @NotNull final Map<String,String> nameValuePairs)
          throws AuditLogException
  {
    final byte[] uncommentedHeaderBytes =
         StaticUtils.getBytes(uncommentedHeaderLine);

    final ByteStringBuffer buffer =
         new ByteStringBuffer(uncommentedHeaderBytes.length);

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(uncommentedHeaderBytes);
    final Date timestamp = readTimestamp(logMessageLines, inputStream, buffer);
    while (true)
    {
      if (! readNameValuePair(logMessageLines, inputStream, nameValuePairs,
                 buffer))
      {
        break;
      }
    }

    return timestamp;
  }



  /**
   * Reads the timestamp from the provided input stream and parses it using one
   * of the expected formats.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty.
   * @param  inputStream      The input stream from which to read the timestamp.
   *                          It must not be {@code null}.
   * @param  buffer           A buffer that may be used to hold temporary data
   *                          for reading.  It must not be {@code null} and it
   *                          must be empty.
   *
   * @return  The parsed timestamp.
   *
   * @throws  AuditLogException  If the provided string cannot be parsed as a
   *                             timestamp.
   */
  @NotNull()
  private static Date readTimestamp(
               @NotNull final List<String> logMessageLines,
               @NotNull final ByteArrayInputStream inputStream,
               @NotNull final ByteStringBuffer buffer)
          throws AuditLogException
  {
    while (true)
    {
      final int intRead = inputStream.read();
      if ((intRead < 0) || (intRead == ';'))
      {
        break;
      }

      buffer.append((byte) (intRead & 0xFF));
    }

    SimpleDateFormat parser;
    final String timestampString = buffer.toString().trim();
    if (timestampString.length() == 30)
    {
      parser = TIMESTAMP_MS_FORMAT_PARSERS.get();
      if (parser == null)
      {
        parser = new SimpleDateFormat(TIMESTAMP_MS_FORMAT);
        parser.setLenient(false);
        TIMESTAMP_MS_FORMAT_PARSERS.set(parser);
      }
    }
    else if (timestampString.length() == 26)
    {
      parser = TIMESTAMP_SEC_FORMAT_PARSERS.get();
      if (parser == null)
      {
        parser = new SimpleDateFormat(TIMESTAMP_SEC_FORMAT);
        parser.setLenient(false);
        TIMESTAMP_SEC_FORMAT_PARSERS.set(parser);
      }
    }
    else
    {
      throw new AuditLogException(logMessageLines,
           ERR_AUDIT_LOG_MESSAGE_HEADER_MALFORMED_TIMESTAMP.get());
    }

    try
    {
      return parser.parse(timestampString);
    }
    catch (final ParseException e)
    {
      Debug.debugException(e);
      throw new AuditLogException(logMessageLines,
           ERR_AUDIT_LOG_MESSAGE_HEADER_MALFORMED_TIMESTAMP.get(), e);
    }
  }



  /**
   * Reads a name-value pair from the provided buffer.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty.
   * @param  inputStream      The input stream from which to read the name-value
   *                          pair.  It must not be {@code null}.
   * @param  nameValuePairs   A map to which the name-value pair should be
   *                          added.
   * @param  buffer           A buffer that may be used to hold temporary data
   *                          for reading.  It must not be {@code null}, but may
   *                          not be empty and should be cleared before use.
   *
   * @return  {@code true} if a name-value pair was read, or {@code false} if
   *          the end of the input stream was read without reading any more
   *          data.
   *
   * @throws  AuditLogException  If a problem is encountered while trying to
   *                             read the name-value pair.
   */
  private static boolean readNameValuePair(
               @NotNull final List<String> logMessageLines,
               @NotNull final ByteArrayInputStream inputStream,
               @NotNull final Map<String,String> nameValuePairs,
               @NotNull final ByteStringBuffer buffer)
          throws AuditLogException
  {
    // Read the property name.  It will be followed by an equal sign to separate
    // the name from the value.
    buffer.clear();
    while (true)
    {
      final int intRead = inputStream.read();
      if (intRead < 0)
      {
        // We've hit the end of the input stream.  This is okay if we haven't
        // yet read any data.
        if (buffer.isEmpty())
        {
          return false;
        }
        else
        {
          throw new AuditLogException(logMessageLines,
               ERR_AUDIT_LOG_MESSAGE_HEADER_ENDS_WITH_PROPERTY_NAME.get(
                    buffer.toString()));
        }
      }
      else if (intRead == '=')
      {
        break;
      }
      else if (intRead != ' ')
      {
        buffer.append((byte) (intRead & 0xFF));
      }
    }

    final String name = buffer.toString();
    if (name.isEmpty())
    {
      throw new AuditLogException(logMessageLines,
           ERR_AUDIT_LOG_MESSAGE_HEADER_EMPTY_PROPERTY_NAME.get());
    }


    // Read the property value.  Start by peeking at the next byte in the
    // input stream.  If it's a space, then skip it and loop back to the next
    // byte.  If it's an opening curly brace ({), then read the value as a JSON
    // object followed by a semicolon.  If it's a double quote ("), then read
    // the value as a quoted string followed by a semicolon.  If it's anything
    // else, then read the value as an unquoted string followed by a semicolon.
    final String valueString;
    while (true)
    {
      inputStream.mark(1);
      final int intRead = inputStream.read();
      if (intRead < 0)
      {
        // We hit the end of the input stream after the equal sign.  This is
        // fine.  We'll just use an empty value.
        valueString = "";
        break;
      }
      else if (intRead == ' ')
      {
        continue;
      }
      else if (intRead == '{')
      {
        inputStream.reset();
        final JSONObject jsonObject =
             readJSONObject(logMessageLines, name, inputStream);
        valueString = jsonObject.toString();
        break;
      }
      else if (intRead == '"')
      {
        valueString =
             readString(logMessageLines, name, true, inputStream, buffer);
        break;
      }
      else if (intRead == ';')
      {
        valueString = "";
        break;
      }
      else
      {
        inputStream.reset();
        valueString =
             readString(logMessageLines, name, false, inputStream, buffer);
        break;
      }
    }

    nameValuePairs.put(name, valueString);
    return true;
  }



  /**
   * Reads a JSON object from the provided input stream.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty.
   * @param  propertyName     The name of the property whose value is expected
   *                          to be a JSON object.  It must not be {@code null}.
   * @param  inputStream      The input stream from which to read the JSON
   *                          object.  It must not be {@code null}.
   *
   * @return  The JSON object that was read.
   *
   * @throws  AuditLogException  If a problem is encountered while trying to
   *                             read the JSON object.
   */
  @NotNull()
  private static JSONObject readJSONObject(
               @NotNull final List<String> logMessageLines,
               @NotNull final String propertyName,
               @NotNull final ByteArrayInputStream inputStream)
          throws AuditLogException
  {
    final JSONObject jsonObject;
    try
    {
      final JSONObjectReader reader = new JSONObjectReader(inputStream, false);
      jsonObject = reader.readObject();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new AuditLogException(logMessageLines,
           ERR_AUDIT_LOG_MESSAGE_ERROR_READING_JSON_OBJECT.get(propertyName,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    readSpacesAndSemicolon(logMessageLines, propertyName, inputStream);
    return jsonObject;
  }



  /**
   * Reads a string from the provided input stream.  It may optionally be
   * treated as a quoted string, in which everything read up to an unescaped
   * quote will be treated as part of the string, or an unquoted string, in
   * which the first space or semicolon encountered will signal the end of the
   * string.  Any character prefixed by a backslash will be added to the string
   * as-is (for example, a backslash followed by a quotation mark will cause the
   * quotation mark to be part of the string rather than signalling the end of
   * the quoted string).  Any octothorpe (#) character must be followed by two
   * hexadecimal digits that signify a single raw byte to add to the value.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty.
   * @param  propertyName     The name of the property with which the string
   *                          value is associated.  It must not be {@code null}.
   * @param  isQuoted         Indicates whether to read a quoted string or an
   *                          unquoted string.  In the case of a a quoted
   *                          string, the opening quote must have already been
   *                          read.
   * @param  inputStream      The input stream from which to read the string
   *                          value.  It must not be {@code null}.
   * @param  buffer           A buffer that may be used while reading the
   *                          string.  It must not be {@code null}, but may not
   *                          be empty and should be cleared before use.
   *
   * @return  The string that was read.
   *
   * @throws  AuditLogException  If a problem is encountered while trying to
   *                             read the string.
   */
  @NotNull()
  private static String readString(@NotNull final List<String> logMessageLines,
               @NotNull final String propertyName,
               final boolean isQuoted,
               @NotNull final ByteArrayInputStream inputStream,
               @NotNull final ByteStringBuffer buffer)
       throws AuditLogException
  {
    buffer.clear();

stringLoop:
    while (true)
    {
      inputStream.mark(1);
      final int intRead = inputStream.read();
      if (intRead < 0)
      {
        if (isQuoted)
        {
          throw new AuditLogException(logMessageLines,
               ERR_AUDIT_LOG_MESSAGE_END_BEFORE_CLOSING_QUOTE.get(
                    propertyName));
        }
        else
        {
          return buffer.toString();
        }
      }

      switch (intRead)
      {
        case '\\':
          final int literalCharacter = inputStream.read();
          if (literalCharacter < 0)
          {
            throw new AuditLogException(logMessageLines,
                 ERR_AUDIT_LOG_MESSAGE_END_BEFORE_ESCAPED.get(propertyName));
          }
          else
          {
            buffer.append((byte) (literalCharacter & 0xFF));
          }
          break;

        case '#':
          int hexByte =
               readHexDigit(logMessageLines, propertyName, inputStream);
          hexByte = (hexByte << 4) |
               readHexDigit(logMessageLines, propertyName, inputStream);
          buffer.append((byte) (hexByte & 0xFF));
          break;

        case '"':
          if (isQuoted)
          {
            break stringLoop;
          }

          buffer.append('"');
          break;

        case ' ':
          if (! isQuoted)
          {
            break stringLoop;
          }

          buffer.append(' ');
          break;

        case ';':
          if (! isQuoted)
          {
            inputStream.reset();
            break stringLoop;
          }

          buffer.append(';');
          break;

        default:
          buffer.append((byte) (intRead & 0xFF));
          break;
      }
    }

    readSpacesAndSemicolon(logMessageLines, propertyName, inputStream);
    return buffer.toString();
  }



  /**
   * Reads a single hexadecimal digit from the provided input stream and returns
   * its integer value.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty.
   * @param  propertyName     The name of the property with which the string
   *                          value is associated.  It must not be {@code null}.
   * @param  inputStream      The input stream from which to read the string
   *                          value.  It must not be {@code null}.
   *
   * @return  The integer value of the hexadecimal digit that was read.
   *
   * @throws  AuditLogException  If the end of the input stream was reached
   *                             before the byte could be read, or if the byte
   *                             that was read did not represent a hexadecimal
   *                             digit.
   */
  private static int readHexDigit(@NotNull final List<String> logMessageLines,
                          @NotNull final String propertyName,
                          @NotNull final ByteArrayInputStream inputStream)
          throws AuditLogException
  {
    final int byteRead = inputStream.read();
    if (byteRead < 0)
    {
      throw new AuditLogException(logMessageLines,
           ERR_AUDIT_LOG_MESSAGE_END_BEFORE_HEX.get(propertyName));
    }

    switch (byteRead)
    {
      case '0':
        return 0;
      case '1':
        return 1;
      case '2':
        return 2;
      case '3':
        return 3;
      case '4':
        return 4;
      case '5':
        return 5;
      case '6':
        return 6;
      case '7':
        return 7;
      case '8':
        return 8;
      case '9':
        return 9;
      case 'a':
      case 'A':
        return 10;
      case 'b':
      case 'B':
        return 11;
      case 'c':
      case 'C':
        return 12;
      case 'd':
      case 'D':
        return 13;
      case 'e':
      case 'E':
        return 14;
      case 'f':
      case 'F':
        return 15;
      default:
        throw new AuditLogException(logMessageLines,
             ERR_AUDIT_LOG_MESSAGE_INVALID_HEX_DIGIT.get(propertyName));
    }
  }



  /**
   * Reads zero or more spaces and the following semicolon from the provided
   * input stream.  It is also acceptable to encounter the end of the stream.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty.
   * @param  propertyName     The name of the property that was just read.  It
   *                          must not be {@code null}.
   * @param  inputStream      The input stream from which to read the spaces and
   *                          semicolon.  It must not be {@code null}.
   *
   * @throws  AuditLogException  If any byte is encountered that is not a space
   *                             or a semicolon.
   */
  private static void readSpacesAndSemicolon(
               @NotNull final List<String> logMessageLines,
               @NotNull final String propertyName,
               @NotNull final ByteArrayInputStream inputStream)
          throws AuditLogException
  {
    while (true)
    {
      final int intRead = inputStream.read();
      if ((intRead < 0) || (intRead == ';'))
      {
        return;
      }
      else if (intRead != ' ')
      {
        throw new AuditLogException(logMessageLines,
             ERR_AUDIT_LOG_MESSAGE_UNEXPECTED_CHAR_AFTER_PROPERTY.get(
                  String.valueOf((char) intRead), propertyName));
      }
    }
  }



  /**
   * Retrieves the value of the header property with the given name as a
   * {@code Boolean} object.
   *
   * @param  name            The name of the property to retrieve.  It must not
   *                         be {@code null}, and it will be treated in a
   *                         case-sensitive manner.
   * @param  nameValuePairs  The map containing the header properties as
   *                         name-value pairs.  It must not be {@code null}.
   *
   * @return  The value of the specified property as a {@code Boolean}, or
   *          {@code null} if the property is not defined or if it cannot be
   *          parsed as a {@code Boolean}.
   */
  @Nullable()
  protected static Boolean getNamedValueAsBoolean(@NotNull final String name,
                 @NotNull final Map<String,String> nameValuePairs)
  {
    final String valueString = nameValuePairs.get(name);
    if (valueString == null)
    {
      return null;
    }

    final String lowerValueString = StaticUtils.toLowerCase(valueString);
    if (lowerValueString.equals("true") ||
         lowerValueString.equals("t") ||
         lowerValueString.equals("yes") ||
         lowerValueString.equals("y") ||
         lowerValueString.equals("on") ||
         lowerValueString.equals("1"))
    {
      return Boolean.TRUE;
    }
    else if (lowerValueString.equals("false") ||
         lowerValueString.equals("f") ||
         lowerValueString.equals("no") ||
         lowerValueString.equals("n") ||
         lowerValueString.equals("off") ||
         lowerValueString.equals("0"))
    {
      return Boolean.FALSE;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the value of the header property with the given name as a
   * {@code Long} object.
   *
   * @param  name            The name of the property to retrieve.  It must not
   *                         be {@code null}, and it will be treated in a
   *                         case-sensitive manner.
   * @param  nameValuePairs  The map containing the header properties as
   *                         name-value pairs.  It must not be {@code null}.
   *
   * @return  The value of the specified property as a {@code Long}, or
   *          {@code null} if the property is not defined or if it cannot be
   *          parsed as a {@code Long}.
   */
  @Nullable()
  protected static Long getNamedValueAsLong(@NotNull final String name,
                 @NotNull final Map<String,String> nameValuePairs)
  {
    final String valueString = nameValuePairs.get(name);
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
      return null;
    }
  }



  /**
   * Decodes an entry (or list of attributes) from the commented header
   * contained in the log message lines.
   *
   * @param  header           The header line that appears before the encoded
   *                          entry.
   * @param  logMessageLines  The lines that comprise the audit log message.
   * @param  entryDN          The DN to use for the entry that is read.  It
   *                          should be {@code null} if the commented entry
   *                          includes a DN, and non-{@code null} if the
   *                          commented entry does not include a DN.
   *
   * @return  The entry that was decoded from the commented header, or
   *          {@code null} if it is not included in the header or if it cannot
   *          be decoded.  If the commented entry does not include a DN, then
   *          the DN of the entry returned will be the null DN.
   */
  @Nullable()
  protected static ReadOnlyEntry decodeCommentedEntry(
                 @NotNull final String header,
                 @NotNull final List<String> logMessageLines,
                 @Nullable final String entryDN)
  {
    List<String> ldifLines = null;
    StringBuilder invalidLDAPNameReason = null;
    for (final String line : logMessageLines)
    {
      final String uncommentedLine;
      if (line.startsWith("# "))
      {
        uncommentedLine = line.substring(2);
      }
      else
      {
        break;
      }

      if (ldifLines == null)
      {
        if (uncommentedLine.equalsIgnoreCase(header))
        {
          ldifLines = new ArrayList<>(logMessageLines.size());
          if (entryDN != null)
          {
            ldifLines.add("dn: " + entryDN);
          }
        }
      }
      else
      {
        final int colonPos = uncommentedLine.indexOf(':');
        if (colonPos <= 0)
        {
          break;
        }

        if (invalidLDAPNameReason == null)
        {
          invalidLDAPNameReason = new StringBuilder();
        }

        final String potentialAttributeName =
             uncommentedLine.substring(0, colonPos);
        if (PersistUtils.isValidLDAPName(potentialAttributeName,
             invalidLDAPNameReason))
        {
          ldifLines.add(uncommentedLine);
        }
        else
        {
          break;
        }
      }
    }

    if (ldifLines == null)
    {
      return null;
    }

    try
    {
      final String[] ldifLineArray = ldifLines.toArray(StaticUtils.NO_STRINGS);
      final Entry ldifEntry = LDIFReader.decodeEntry(ldifLineArray);
      return new ReadOnlyEntry(ldifEntry);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Decodes the operation purpose request control, if any, from the provided
   * set of name-value pairs.
   *
   * @param  nameValuePairs  The map containing the header properties as
   *                         name-value pairs.  It must not be {@code null}.
   *
   * @return  The operation purpose request control retrieved and decoded from
   *          the provided set of name-value pairs, or {@code null} if no
   *          valid operation purpose request control was included.
   */
  @Nullable()
  private static OperationPurposeRequestControl
                      decodeOperationPurposeRequestControl(
                           @NotNull final Map<String,String> nameValuePairs)
  {
    final String valueString = nameValuePairs.get("operationPurpose");
    if (valueString == null)
    {
      return null;
    }

    try
    {
      final JSONObject o = new JSONObject(valueString);

      final String applicationName = o.getFieldAsString("applicationName");
      final String applicationVersion =
           o.getFieldAsString("applicationVersion");
      final String codeLocation = o.getFieldAsString("codeLocation");
      final String requestPurpose = o.getFieldAsString("requestPurpose");

      return new OperationPurposeRequestControl(false, applicationName,
           applicationVersion, codeLocation, requestPurpose);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Decodes the intermediate client request control, if any, from the provided
   * set of name-value pairs.
   *
   * @param  nameValuePairs  The map containing the header properties as
   *                         name-value pairs.  It must not be {@code null}.
   *
   * @return  The intermediate client request control retrieved and decoded from
   *          the provided set of name-value pairs, or {@code null} if no
   *          valid operation purpose request control was included.
   */
  @Nullable()
  private static IntermediateClientRequestControl
                      decodeIntermediateClientRequestControl(
                           @NotNull final Map<String,String> nameValuePairs)
  {
    final String valueString =
         nameValuePairs.get("intermediateClientRequestControl");
    if (valueString == null)
    {
      return null;
    }

    try
    {
      final JSONObject o = new JSONObject(valueString);
      return new IntermediateClientRequestControl(
           decodeIntermediateClientRequestValue(o));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * decodes the provided JSON object as an intermediate client request control
   * value.
   *
   * @param  o  The JSON object to be decoded.  It must not be {@code null}.
   *
   * @return  The intermediate client request control value decoded from the
   *          provided JSON object.
   */
  @Nullable()
  private static IntermediateClientRequestValue
                      decodeIntermediateClientRequestValue(
                           @Nullable final JSONObject o)
  {
    if (o == null)
    {
      return null;
    }

    final String clientIdentity = o.getFieldAsString("clientIdentity");
    final String downstreamClientAddress =
         o.getFieldAsString("downstreamClientAddress");
    final Boolean downstreamClientSecure =
         o.getFieldAsBoolean("downstreamClientSecure");
    final String clientName = o.getFieldAsString("clientName");
    final String clientSessionID = o.getFieldAsString("clientSessionID");
    final String clientRequestID = o.getFieldAsString("clientRequestID");
    final IntermediateClientRequestValue downstreamRequest =
         decodeIntermediateClientRequestValue(
              o.getFieldAsObject("downstreamRequest"));

    return new IntermediateClientRequestValue(downstreamRequest,
         downstreamClientAddress, downstreamClientSecure, clientIdentity,
         clientName, clientSessionID, clientRequestID);
  }



  /**
   * Retrieves the lines that comprise the complete audit log message.
   *
   * @return  The lines that comprise the complete audit log message.
   */
  @NotNull()
  public final List<String> getLogMessageLines()
  {
    return logMessageLines;
  }



  /**
   * Retrieves the line that comprises the header for this log message,
   * including the leading octothorpe (#) and space that make it a comment.
   *
   * @return  The line that comprises the header for this log message, including
   *          the leading octothorpe (#) and space that make it a comment.
   */
  @NotNull()
  public final String getCommentedHeaderLine()
  {
    return commentedHeaderLine;
  }



  /**
   * Retrieves the line that comprises the header for this log message, without
   * the leading octothorpe (#) and space that make it a comment.
   *
   * @return  The line that comprises the header for this log message, without
   *          the leading octothorpe (#) and space that make it a comment.
   */
  @NotNull()
  public final String getUncommentedHeaderLine()
  {
    return uncommentedHeaderLine;
  }



  /**
   * Retrieves the timestamp for this audit log message.
   *
   * @return  The timestamp for this audit log message.
   */
  @NotNull()
  public final Date getTimestamp()
  {
    return timestamp;
  }



  /**
   * Retrieves a map of the name-value pairs contained in the header for this
   * log message.
   *
   * @return  A map of the name-value pairs contained in the header for this log
   *          message.
   */
  @NotNull()
  public final Map<String,String> getHeaderNamedValues()
  {
    return namedValues;
  }



  /**
   * Retrieves the server product name for this audit log message, if available.
   *
   * @return  The server product name for this audit log message, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final String getProductName()
  {
    return productName;
  }



  /**
   * Retrieves the server instance name for this audit log message, if
   * available.
   *
   * @return  The server instance name for this audit log message, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final String getInstanceName()
  {
    return instanceName;
  }



  /**
   * Retrieves the unique identifier generated when the server was started, if
   * available.
   *
   * @return  The unique identifier generated when the server was started, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final String getStartupID()
  {
    return startupID;
  }



  /**
   * Retrieves the identifier for the server thread that processed the change,
   * if available.
   *
   * @return  The identifier for the server thread that processed the change, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final Long getThreadID()
  {
    return threadID;
  }



  /**
   * Retrieves the DN of the user that requested the change, if available.
   *
   * @return  The DN of the user that requested the change, or {@code null} if
   *          it is not available.
   */
  @Nullable()
  public final String getRequesterDN()
  {
    return requesterDN;
  }



  /**
   * Retrieves the IP address of the client that requested the change, if
   * available.
   *
   * @return  The IP address of the client that requested the change, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final String getRequesterIPAddress()
  {
    return requesterIP;
  }



  /**
   * Retrieves the connection ID for the connection on which the change was
   * requested, if available.
   *
   * @return  The connection ID for the connection on which the change was
   *          requested, or {@code null} if it is not available.
   */
  @Nullable()
  public final Long getConnectionID()
  {
    return connectionID;
  }



  /**
   * Retrieves the connection ID for the connection on which the change was
   * requested, if available.
   *
   * @return  The connection ID for the connection on which the change was
   *          requested, or {@code null} if it is not available.
   */
  @Nullable()
  public final Long getOperationID()
  {
    return operationID;
  }



  /**
   * Retrieves the connection ID for the external operation that triggered the
   * internal operation with which this audit log message is associated, if
   * available.
   *
   * @return  The connection ID for the external operation that triggered the
   *          internal operation with which this audit log message is
   *          associated, or {@code null} if it is not available.
   */
  @Nullable()
  public final Long getTriggeredByConnectionID()
  {
    return triggeredByConnectionID;
  }



  /**
   * Retrieves the operation ID for the external operation that triggered the
   * internal operation with which this audit log message is associated, if
   * available.
   *
   * @return  The operation ID for the external operation that triggered the
   *          internal operation with which this audit log message is
   *          associated, or {@code null} if it is not available.
   */
  @Nullable()
  public final Long getTriggeredByOperationID()
  {
    return triggeredByOperationID;
  }



  /**
   * Retrieves the replication change ID for this audit log message, if
   * available.
   *
   * @return  The replication change ID for this audit log message, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final String getReplicationChangeID()
  {
    return replicationChangeID;
  }



  /**
   * Retrieves the alternate authorization DN for this audit log message, if
   * available.
   *
   * @return  The alternate authorization DN for this audit log message, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final String getAlternateAuthorizationDN()
  {
    return alternateAuthorizationDN;
  }



  /**
   * Retrieves the transaction ID for this audit log message, if available.
   *
   * @return  The transaction ID for this audit log message, or {@code null} if
   *          it is not available.
   */
  @Nullable()
  public final String getTransactionID()
  {
    return transactionID;
  }



  /**
   * Retrieves the origin for this audit log message, if available.
   *
   * @return  The origin for this audit log message, or {@code null} if it is
   *          not available.
   */
  @Nullable()
  public final String getOrigin()
  {
    return origin;
  }



  /**
   * Retrieves the value of the flag indicating whether the associated operation
   * was processed using an administrative session worker thread, if available.
   *
   * @return  {@code Boolean.TRUE} if it is known that the associated operation
   *          was processed using an administrative session worker thread,
   *          {@code Boolean.FALSE} if it is known that the associated operation
   *          was not processed using an administrative session worker thread,
   *          or {@code null} if it is not available.
   */
  @Nullable()
  public final Boolean getUsingAdminSessionWorkerThread()
  {
    return usingAdminSessionWorkerThread;
  }



  /**
   * Retrieves a list of the OIDs of the request controls included in the
   * operation request, if available.
   *
   * @return  A list of the OIDs of the request controls included in the
   *          operation, an empty list if it is known that there were no request
   *          controls, or {@code null} if it is not available.
   */
  @Nullable()
  public final List<String> getRequestControlOIDs()
  {
    return requestControlOIDs;
  }



  /**
   * Retrieves an operation purpose request control with information about the
   * purpose for the associated operation, if available.
   *
   * @return  An operation purpose request control with information about the
   *          purpose for the associated operation, or {@code null} if it is not
   *          available.
   */
  @Nullable()
  public final OperationPurposeRequestControl
                    getOperationPurposeRequestControl()
  {
    return operationPurposeRequestControl;
  }



  /**
   * Retrieves an intermediate client request control with information about the
   * downstream processing for the associated operation, if available.
   *
   * @return  An intermediate client request control with information about the
   *          downstream processing for the associated operation, or
   *          {@code null} if it is not available.
   */
  @Nullable()
  public final IntermediateClientRequestControl
                    getIntermediateClientRequestControl()
  {
    return intermediateClientRequestControl;
  }



  /**
   * Retrieves the DN of the entry targeted by the associated operation.
   *
   * @return  The DN of the entry targeted by the associated operation.
   */
  @NotNull()
  public abstract String getDN();



  /**
   * Retrieves the change type for this audit log message.
   *
   * @return  The change type for this audit log message.
   */
  @NotNull()
  public abstract ChangeType getChangeType();



  /**
   * Retrieves an LDIF change record that encapsulates the change represented by
   * this audit log message.
   *
   * @return  An LDIF change record that encapsulates the change represented by
   *          this audit log message.
   */
  @NotNull()
  public abstract LDIFChangeRecord getChangeRecord();



  /**
   * Indicates whether it is possible to use the
   * {@link #getRevertChangeRecords()} method to obtain a list of LDIF change
   * records that can be used to revert the changes described by this audit log
   * message.
   *
   * @return  {@code true} if it is possible to use the
   *          {@link #getRevertChangeRecords()} method to obtain a list of LDIF
   *          change records that can be used to revert the changes described
   *          by this audit log message, or {@code false} if not.
   */
  public abstract boolean isRevertible();



  /**
   * Retrieves a list of the change records that can be used to revert the
   * changes described by this audit log message.
   *
   * @return  A list of the change records that can be used to revert the
   *          changes described by this audit log message.
   *
   * @throws  AuditLogException  If this audit log message cannot be reverted.
   */
  @NotNull()
  public abstract List<LDIFChangeRecord> getRevertChangeRecords()
         throws AuditLogException;



  /**
   * Retrieves a single-line string representation of this audit log message.
   * It will start with the string returned by
   * {@link #getUncommentedHeaderLine()}, but will also contain additional
   * name-value pairs that are pertinent to the type of operation that the audit
   * log message represents.
   *
   * @return  A string representation of this audit log message.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of this audit log message to
   * the provided buffer.  The message will start with the string returned by
   * {@link #getUncommentedHeaderLine()}, but will also contain additional
   * name-value pairs that are pertinent to the type of operation that the audit
   * log message represents.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);



  /**
   * Retrieves a multi-line string representation of this audit log message.  It
   * will simply be a concatenation of all of the lines that comprise the
   * complete log message, with line breaks between them.
   *
   * @return  A multi-line string representation of this audit log message.
   */
  @NotNull()
  public final String toMultiLineString()
  {
    return StaticUtils.concatenateStrings(null, null, StaticUtils.EOL, null,
         null, logMessageLines);
  }
}
