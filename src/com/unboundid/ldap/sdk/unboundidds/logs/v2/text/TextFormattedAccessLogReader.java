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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.AccessLogReader;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.text.TextLogMessages.*;



/**
 * This class provides a mechanism for reading text-formatted access log
 * messages.
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
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TextFormattedAccessLogReader
       implements AccessLogReader
{
  // The buffered reader that will be used to read log messages.
  @NotNull private final BufferedReader logReader;



  /**
   * Creates a new text-formatted access log reader that will read log messages
   * from the specified file.
   *
   * @param  logFilePath  The path to the log file from which the access log
   *                      messages will be read.  It must not be {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the specified file
   *                       for reading.
   */
  public TextFormattedAccessLogReader(@NotNull final String logFilePath)
         throws IOException
  {
    this(new File(logFilePath));
  }



  /**
   * Creates a new text-formatted access log reader that will read log messages
   * messages from the specified file.
   *
   * @param  logFile  The log file from which the access log messages will be
   *                  read.  It must not be {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the specified file
   *                       for reading.
   */
  public TextFormattedAccessLogReader(@NotNull final File logFile)
         throws IOException
  {
    logReader = new BufferedReader(new FileReader(logFile));
  }



  /**
   * Creates a new text-formatted access log reader that will read log messages
   * from the provided input stream.
   *
   * @param  inputStream  The input stream from which the access log messages
   *                      will be read.  It must not be {@code null}.
   */
  public TextFormattedAccessLogReader(@NotNull final InputStream inputStream)
  {
    logReader = new BufferedReader(new InputStreamReader(inputStream));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public TextFormattedAccessLogMessage readMessage()
         throws IOException, LogException
  {
    // Read the next line from the log.  If this fails, then throw an
    // IOException to indicate that we can't continue reading.  If the line is
    // blank or starts with an octothorpe (indicating that it's a comment), then
    // skip it and read the next one.
    String messageString;
    while (true)
    {
      messageString = logReader.readLine();
      if (messageString == null)
      {
        return null;
      }

      if (messageString.isEmpty() || messageString.startsWith("#"))
      {
        continue;
      }

      break;
    }

    return parseMessage(messageString);
  }



  /**
   * Parses the contents of the provided string as a JSON-formatted access log
   * message.
   *
   * @param  messageString  The string to parse as an access log message.  It
   *                        must not be {@code null}.
   *
   * @return  The parsed access log message.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid access log message.
   */
  @NotNull()
  public static TextFormattedAccessLogMessage parseMessage(
              @NotNull final String messageString)
         throws LogException
  {
    // Parse the line as a generic log message, which will give us access to
    // all of its fields.
    final TextFormattedLogMessage m =
         new TextFormattedLogMessage(messageString);


    // Make sure that the message has at least one field without a name.
    final List<String> unnamedFields = m.getFields().get(
         TextFormattedLogMessage.NO_FIELD_NAME);
    if ((unnamedFields == null) || unnamedFields.isEmpty())
    {
      throw new LogException(messageString,
           ERR_TEXT_ACCESS_READER_CANNOT_DETERMINE_MESSAGE_TYPE.get(
                messageString));
    }


    // Look at the first unnamed field.  For messages that are not associated
    // with an operation, then it will be the message type.  For messages that
    // are associated with an operation, then the operation type will come
    // first, so it's okay if we can't parse the first unnamed field value as a
    // message type.
    final String messageOrOpType = unnamedFields.get(0);
    AccessLogMessageType messageType =
         AccessLogMessageType.forName(messageOrOpType);
    if (messageType != null)
    {
      switch (messageType)
      {
        case CONNECT:
          return new TextFormattedConnectAccessLogMessage(m);
        case DISCONNECT:
          return new TextFormattedDisconnectAccessLogMessage(m);
        case SECURITY_NEGOTIATION:
          return new TextFormattedSecurityNegotiationAccessLogMessage(m);
        case CLIENT_CERTIFICATE:
          return new TextFormattedClientCertificateAccessLogMessage(m);
        case ENTRY_REBALANCING_REQUEST:
          return new TextFormattedEntryRebalancingRequestAccessLogMessage(m);
        case ENTRY_REBALANCING_RESULT:
          return new TextFormattedEntryRebalancingResultAccessLogMessage(m);
        default:
          throw new LogException(messageString,
               ERR_TEXT_ACCESS_READER_CANNOT_DETERMINE_MESSAGE_TYPE.get(
                    messageString));
      }
    }


    // If we've gotten here, then we expect the first unnamed field to be the
    // operation type, and the second field will be the message type.
    final AccessLogOperationType opType =
         AccessLogOperationType.forName(messageOrOpType);
    if (opType == null)
    {
      throw new LogException(messageString,
           ERR_TEXT_ACCESS_READER_CANNOT_DETERMINE_MESSAGE_TYPE.get(
                messageOrOpType));
    }

    if (unnamedFields.size() < 2)
    {
      throw new LogException(messageString,
           ERR_TEXT_ACCESS_READER_CANNOT_DETERMINE_MESSAGE_TYPE.get(
                messageString));
    }

    messageType = AccessLogMessageType.forName(unnamedFields.get(1));
    if (messageType == null)
    {
      throw new LogException(messageString,
           ERR_TEXT_ACCESS_READER_CANNOT_DETERMINE_MESSAGE_TYPE.get(
                messageString));
    }

    switch (messageType)
    {
      case REQUEST:
        switch (opType)
        {
          case ABANDON:
            return new TextFormattedAbandonRequestAccessLogMessage(m);
          case ADD:
            return new TextFormattedAddRequestAccessLogMessage(m);
          case BIND:
            return new TextFormattedBindRequestAccessLogMessage(m);
          case COMPARE:
            return new TextFormattedCompareRequestAccessLogMessage(m);
          case DELETE:
            return new TextFormattedDeleteRequestAccessLogMessage(m);
          case EXTENDED:
            return new TextFormattedExtendedRequestAccessLogMessage(m);
          case MODIFY:
            return new TextFormattedModifyRequestAccessLogMessage(m);
          case MODDN:
            return new TextFormattedModifyDNRequestAccessLogMessage(m);
          case SEARCH:
            return new TextFormattedSearchRequestAccessLogMessage(m);
          case UNBIND:
            return new TextFormattedUnbindRequestAccessLogMessage(m);
          default:
            throw new LogException(messageString,
                 ERR_TEXT_ACCESS_READER_UNSUPPORTED_REQUEST_OP_TYPE.get(
                      messageString));
        }

      case FORWARD:
        switch (opType)
        {
          case ABANDON:
            return new TextFormattedAbandonForwardAccessLogMessage(m);
          case ADD:
            return new TextFormattedAddForwardAccessLogMessage(m);
          case BIND:
            return new TextFormattedBindForwardAccessLogMessage(m);
          case COMPARE:
            return new TextFormattedCompareForwardAccessLogMessage(m);
          case DELETE:
            return new TextFormattedDeleteForwardAccessLogMessage(m);
          case EXTENDED:
            return new TextFormattedExtendedForwardAccessLogMessage(m);
          case MODIFY:
            return new TextFormattedModifyForwardAccessLogMessage(m);
          case MODDN:
            return new TextFormattedModifyDNForwardAccessLogMessage(m);
          case SEARCH:
            return new TextFormattedSearchForwardAccessLogMessage(m);
          case UNBIND:
          default:
            throw new LogException(messageString,
                 ERR_TEXT_ACCESS_READER_UNSUPPORTED_FORWARD_OP_TYPE.get(
                      messageString));
        }

      case FORWARD_FAILED:
        switch (opType)
        {
          case ABANDON:
            return new TextFormattedAbandonForwardFailedAccessLogMessage(m);
          case ADD:
            return new TextFormattedAddForwardFailedAccessLogMessage(m);
          case BIND:
            return new TextFormattedBindForwardFailedAccessLogMessage(m);
          case COMPARE:
            return new TextFormattedCompareForwardFailedAccessLogMessage(m);
          case DELETE:
            return new TextFormattedDeleteForwardFailedAccessLogMessage(m);
          case EXTENDED:
            return new TextFormattedExtendedForwardFailedAccessLogMessage(m);
          case MODIFY:
            return new TextFormattedModifyForwardFailedAccessLogMessage(m);
          case MODDN:
            return new TextFormattedModifyDNForwardFailedAccessLogMessage(m);
          case SEARCH:
            return new TextFormattedSearchForwardFailedAccessLogMessage(m);
          case UNBIND:
          default:
            throw new LogException(messageString,
                 ERR_TEXT_ACCESS_READER_UNSUPPORTED_FORWARD_FAILED_OP_TYPE.get(
                      messageString));
        }

      case RESULT:
        switch (opType)
        {
          case ABANDON:
            return new TextFormattedAbandonResultAccessLogMessage(m);
          case ADD:
            return new TextFormattedAddResultAccessLogMessage(m);
          case BIND:
            return new TextFormattedBindResultAccessLogMessage(m);
          case COMPARE:
            return new TextFormattedCompareResultAccessLogMessage(m);
          case DELETE:
            return new TextFormattedDeleteResultAccessLogMessage(m);
          case EXTENDED:
            return new TextFormattedExtendedResultAccessLogMessage(m);
          case MODIFY:
            return new TextFormattedModifyResultAccessLogMessage(m);
          case MODDN:
            return new TextFormattedModifyDNResultAccessLogMessage(m);
          case SEARCH:
            return new TextFormattedSearchResultAccessLogMessage(m);
          case UNBIND:
          default:
            throw new LogException(messageString,
                 ERR_TEXT_ACCESS_READER_UNSUPPORTED_RESULT_OP_TYPE.get(
                      messageString));
        }

      case ASSURANCE_COMPLETE:
        switch (opType)
        {
          case ADD:
            return new TextFormattedAddAssuranceCompletedAccessLogMessage(m);
          case DELETE:
            return new TextFormattedDeleteAssuranceCompletedAccessLogMessage(m);
          case MODIFY:
            return new TextFormattedModifyAssuranceCompletedAccessLogMessage(m);
          case MODDN:
            return new TextFormattedModifyDNAssuranceCompletedAccessLogMessage(
                 m);
          case ABANDON:
          case BIND:
          case COMPARE:
          case EXTENDED:
          case SEARCH:
          case UNBIND:
          default:
            throw new LogException(messageString,
                 ERR_TEXT_ACCESS_READER_UNSUPPORTED_ASSURANCE_OP_TYPE.get(
                      messageString));
        }

      case ENTRY:
        return new TextFormattedSearchEntryAccessLogMessage(m);

      case REFERENCE:
        return new TextFormattedSearchReferenceAccessLogMessage(m);

      case INTERMEDIATE_RESPONSE:
        return new TextFormattedIntermediateResponseAccessLogMessage(m, opType);

      default:
        throw new LogException(messageString,
             ERR_TEXT_ACCESS_READER_CANNOT_DETERMINE_MESSAGE_TYPE.get(
                  messageString));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
         throws IOException
  {
    logReader.close();
  }
}
