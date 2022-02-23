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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogMessageType;
import com.unboundid.ldap.sdk.unboundidds.logs.AccessLogOperationType;
import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.AccessLogReader;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.JSONLogMessages.*;



/**
 * This class provides a mechanism for reading JSON-formatted access log
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
public final class JSONAccessLogReader
       implements AccessLogReader
{
  // The JSON object reader that will be used to read log messages.
  @NotNull private final JSONObjectReader jsonObjectReader;



  /**
   * Creates a new JSON access log reader that will read JSON-formatted access
   * log messages from the specified file.
   *
   * @param  logFilePath  The path to the log file from which the access log
   *                      messages will be read.  It must not be {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the specified file
   *                       for reading.
   */
  public JSONAccessLogReader(@NotNull final String logFilePath)
         throws IOException
  {
    this(new File(logFilePath));
  }



  /**
   * Creates a new JSON access log reader that will read JSON-formatted access
   * log messages from the specified file.
   *
   * @param  logFile  The log file from which the access log messages will be
   *                  read.  It must not be {@code null}.
   *
   * @throws  IOException  If a problem occurs while opening the specified file
   *                       for reading.
   */
  public JSONAccessLogReader(@NotNull final File logFile)
         throws IOException
  {
    this(new FileInputStream(logFile));
  }



  /**
   * Creates a new JSON access log reader that will read JSON-formatted access
   * log messages from the provided input stream.
   *
   * @param  inputStream  The input stream from which the access log messages
   *                      will be read.  It must not be {@code null}.
   */
  public JSONAccessLogReader(@NotNull final InputStream inputStream)
  {
    jsonObjectReader = new JSONObjectReader(inputStream);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public JSONAccessLogMessage readMessage()
         throws IOException, LogException
  {
    // Read the next JSON object from the log.  If this fails, then throw an
    // IOException to indicate that we can't continue reading.
    final JSONObject messageObject;
    try
    {
      messageObject = jsonObjectReader.readObject();
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new IOException(
           ERR_JSON_ACCESS_LOG_READER_NOT_VALID_JSON.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (messageObject == null)
    {
      return null;
    }

    return parseMessage(messageObject);
  }



  /**
   * Parses the contents of the provided JSON object as a JSON-formatted access
   * log message.
   *
   * @param  messageObject  The JSON object to parse as an access log message.
   *                        It must not be {@code null}.
   *
   * @return  The parsed access log message.
   *
   * @throws  LogException  If the provided JSON object cannot be parsed as a
   *                        valid access log message.
   */
  @NotNull()
  public static JSONAccessLogMessage parseMessage(
              @NotNull final JSONObject messageObject)
         throws LogException
  {
    // Determine the message type for the log message.
    final String messageTypeStr = messageObject.getFieldAsString(
         JSONFormattedAccessLogFields.MESSAGE_TYPE.getFieldName());
    if (messageTypeStr == null)
    {
      final String messageStr = messageObject.toSingleLineString();
      throw new LogException(messageStr,
           ERR_JSON_ACCESS_LOG_READER_MISSING_MESSAGE_TYPE.get(messageStr,
                JSONFormattedAccessLogFields.MESSAGE_TYPE.getFieldName()));
    }

    final AccessLogMessageType messageType =
         AccessLogMessageType.forName(messageTypeStr);
    if (messageType == null)
    {
      final String messageStr = messageObject.toSingleLineString();
      throw new LogException(messageStr,
           ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_MESSAGE_TYPE.get(messageStr,
                messageTypeStr));
    }

    switch (messageType)
    {
      case CONNECT:
        return new JSONConnectAccessLogMessage(messageObject);
      case DISCONNECT:
        return new JSONDisconnectAccessLogMessage(messageObject);
      case SECURITY_NEGOTIATION:
        return new JSONSecurityNegotiationAccessLogMessage(messageObject);
      case CLIENT_CERTIFICATE:
        return new JSONClientCertificateAccessLogMessage(messageObject);
      case ENTRY_REBALANCING_REQUEST:
        return new JSONEntryRebalancingRequestAccessLogMessage(messageObject);
      case ENTRY_REBALANCING_RESULT:
        return new JSONEntryRebalancingResultAccessLogMessage(messageObject);
      case ENTRY:
        return new JSONSearchEntryAccessLogMessage(messageObject);
      case REFERENCE:
        return new JSONSearchReferenceAccessLogMessage(messageObject);
      case INTERMEDIATE_RESPONSE:
        return new JSONIntermediateResponseAccessLogMessage(messageObject);
      case REQUEST:
        return createRequestMessage(messageObject);
      case RESULT:
        return createResultMessage(messageObject);
      case FORWARD:
        return createForwardMessage(messageObject);
      case FORWARD_FAILED:
        return createForwardFailedMessage(messageObject);
      case ASSURANCE_COMPLETE:
        return createAssuranceCompleteMessage(messageObject);
      default:
        final String messageStr = messageObject.toSingleLineString();
        throw new LogException(messageStr,
             ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_MESSAGE_TYPE.get(messageStr,
                  messageTypeStr));
    }
  }



  /**
   * Creates a new request access log message from the provided JSON object.
   *
   * @param  messageObject  The JSON object containing an encoded representation
   *                        of a request access log message.  It must not be
   *                        {@code null}.
   *
   * @return  The request access log message that was created.
   *
   * @throws  LogException  If the provided JSON object cannot be decoded as a
   *                        valid request access log message.
   */
  @NotNull()
  private static JSONAccessLogMessage createRequestMessage(
               @NotNull final JSONObject messageObject)
          throws LogException
  {
    final AccessLogOperationType operationType =
         getOperationType(messageObject);
    switch (operationType)
    {
      case ABANDON:
        return new JSONAbandonRequestAccessLogMessage(messageObject);
      case ADD:
        return new JSONAddRequestAccessLogMessage(messageObject);
      case BIND:
        return new JSONBindRequestAccessLogMessage(messageObject);
      case COMPARE:
        return new JSONCompareRequestAccessLogMessage(messageObject);
      case DELETE:
        return new JSONDeleteRequestAccessLogMessage(messageObject);
      case EXTENDED:
        return new JSONExtendedRequestAccessLogMessage(messageObject);
      case MODIFY:
        return new JSONModifyRequestAccessLogMessage(messageObject);
      case MODDN:
        return new JSONModifyDNRequestAccessLogMessage(messageObject);
      case SEARCH:
        return new JSONSearchRequestAccessLogMessage(messageObject);
      case UNBIND:
        return new JSONUnbindRequestAccessLogMessage(messageObject);
      default:
        final String messageStr = messageObject.toSingleLineString();
        throw new LogException(messageStr,
             ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_REQUEST_OP_TYPE.get(
                  messageStr, operationType.getLogIdentifier()));
    }
  }



  /**
   * Creates a new result access log message from the provided JSON object.
   *
   * @param  messageObject  The JSON object containing an encoded representation
   *                        of a result access log message.  It must not be
   *                        {@code null}.
   *
   * @return  The result access log message that was created.
   *
   * @throws  LogException  If the provided JSON object cannot be decoded as a
   *                        valid result access log message.
   */
  @NotNull()
  private static JSONAccessLogMessage createResultMessage(
               @NotNull final JSONObject messageObject)
          throws LogException
  {
    final AccessLogOperationType operationType =
         getOperationType(messageObject);
    switch (operationType)
    {
      case ABANDON:
        return new JSONAbandonResultAccessLogMessage(messageObject);
      case ADD:
        return new JSONAddResultAccessLogMessage(messageObject);
      case BIND:
        return new JSONBindResultAccessLogMessage(messageObject);
      case COMPARE:
        return new JSONCompareResultAccessLogMessage(messageObject);
      case DELETE:
        return new JSONDeleteResultAccessLogMessage(messageObject);
      case EXTENDED:
        return new JSONExtendedResultAccessLogMessage(messageObject);
      case MODIFY:
        return new JSONModifyResultAccessLogMessage(messageObject);
      case MODDN:
        return new JSONModifyDNResultAccessLogMessage(messageObject);
      case SEARCH:
        return new JSONSearchResultAccessLogMessage(messageObject);
      case UNBIND:
      default:
        final String messageStr = messageObject.toSingleLineString();
        throw new LogException(messageStr,
             ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_RESULT_OP_TYPE.get(
                  messageStr, operationType.getLogIdentifier()));
    }
  }



  /**
   * Creates a new forward access log message from the provided JSON object.
   *
   * @param  messageObject  The JSON object containing an encoded representation
   *                        of a forward access log message.  It must not be
   *                        {@code null}.
   *
   * @return  The forward access log message that was created.
   *
   * @throws  LogException  If the provided JSON object cannot be decoded as a
   *                        valid forward access log message.
   */
  @NotNull()
  private static JSONAccessLogMessage createForwardMessage(
               @NotNull final JSONObject messageObject)
          throws LogException
  {
    final AccessLogOperationType operationType =
         getOperationType(messageObject);
    switch (operationType)
    {
      case ABANDON:
        return new JSONAbandonForwardAccessLogMessage(messageObject);
      case ADD:
        return new JSONAddForwardAccessLogMessage(messageObject);
      case BIND:
        return new JSONBindForwardAccessLogMessage(messageObject);
      case COMPARE:
        return new JSONCompareForwardAccessLogMessage(messageObject);
      case DELETE:
        return new JSONDeleteForwardAccessLogMessage(messageObject);
      case EXTENDED:
        return new JSONExtendedForwardAccessLogMessage(messageObject);
      case MODIFY:
        return new JSONModifyForwardAccessLogMessage(messageObject);
      case MODDN:
        return new JSONModifyDNForwardAccessLogMessage(messageObject);
      case SEARCH:
        return new JSONSearchForwardAccessLogMessage(messageObject);
      case UNBIND:
      default:
        final String messageStr = messageObject.toSingleLineString();
        throw new LogException(messageStr,
             ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_FORWARD_OP_TYPE.get(
                  messageStr, operationType.getLogIdentifier()));
    }
  }



  /**
   * Creates a new forward failed access log message from the provided JSON
   * object.
   *
   * @param  messageObject  The JSON object containing an encoded representation
   *                        of a forward failed access log message.  It must not
   *                        be {@code null}.
   *
   * @return  The forward failed access log message that was created.
   *
   * @throws  LogException  If the provided JSON object cannot be decoded as a
   *                        valid forward failed access log message.
   */
  @NotNull()
  private static JSONAccessLogMessage createForwardFailedMessage(
               @NotNull final JSONObject messageObject)
          throws LogException
  {
    final AccessLogOperationType operationType =
         getOperationType(messageObject);
    switch (operationType)
    {
      case ABANDON:
        return new JSONAbandonForwardFailedAccessLogMessage(messageObject);
      case ADD:
        return new JSONAddForwardFailedAccessLogMessage(messageObject);
      case BIND:
        return new JSONBindForwardFailedAccessLogMessage(messageObject);
      case COMPARE:
        return new JSONCompareForwardFailedAccessLogMessage(messageObject);
      case DELETE:
        return new JSONDeleteForwardFailedAccessLogMessage(messageObject);
      case EXTENDED:
        return new JSONExtendedForwardFailedAccessLogMessage(messageObject);
      case MODIFY:
        return new JSONModifyForwardFailedAccessLogMessage(messageObject);
      case MODDN:
        return new JSONModifyDNForwardFailedAccessLogMessage(messageObject);
      case SEARCH:
        return new JSONSearchForwardFailedAccessLogMessage(messageObject);
      case UNBIND:
      default:
        final String messageStr = messageObject.toSingleLineString();
        throw new LogException(messageStr,
             ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_FORWARD_FAILED_OP_TYPE.get(
                  messageStr, operationType.getLogIdentifier()));
    }
  }



  /**
   * Creates a new assurance complete access log message from the provided JSON
   * object.
   *
   * @param  messageObject  The JSON object containing an encoded representation
   *                        of a assurance complete access log message.  It must
   *                        not be {@code null}.
   *
   * @return  The assurance complete access log message that was created.
   *
   * @throws  LogException  If the provided JSON object cannot be decoded as a
   *                        valid assurance complete access log message.
   */
  @NotNull()
  private static JSONAccessLogMessage createAssuranceCompleteMessage(
               @NotNull final JSONObject messageObject)
          throws LogException
  {
    final AccessLogOperationType operationType =
         getOperationType(messageObject);
    switch (operationType)
    {
      case ADD:
        return new JSONAddAssuranceCompletedAccessLogMessage(messageObject);
      case DELETE:
        return new JSONDeleteAssuranceCompletedAccessLogMessage(messageObject);
      case MODIFY:
        return new JSONModifyAssuranceCompletedAccessLogMessage(messageObject);
      case MODDN:
        return new JSONModifyDNAssuranceCompletedAccessLogMessage(
             messageObject);
      case ABANDON:
      case BIND:
      case COMPARE:
      case EXTENDED:
      case SEARCH:
      case UNBIND:
      default:
        final String messageStr = messageObject.toSingleLineString();
        throw new LogException(messageStr,
             ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_ASSURANCE_COMPLETED_OP_TYPE.
                  get(messageStr, operationType.getLogIdentifier()));
    }
  }



  /**
   * Determines the operation type for the JSON-formatted access log message
   * encoded in the provided JSON object.
   *
   * @param  messageObject  The JSON object containing an encoded representation
   *                        of an access log message.  It must not be
   *                        {@code null}.
   *
   * @return  The operation type extracted from the provided JSON object.
   *
   * @throws  LogException  If it is not possible to extract a valid operation
   *                        type from the provided JSON object.
   */
  @NotNull()
  private static AccessLogOperationType getOperationType(
               @NotNull final JSONObject messageObject)
          throws LogException
  {
    final String opTypeStr = messageObject.getFieldAsString(
         JSONFormattedAccessLogFields.OPERATION_TYPE.getFieldName());
    if (opTypeStr == null)
    {
      final String messageStr = messageObject.toSingleLineString();
      throw new LogException(messageStr,
           ERR_JSON_ACCESS_LOG_READER_MISSING_OPERATION_TYPE.get(messageStr,
                JSONFormattedAccessLogFields.OPERATION_TYPE.getFieldName()));
    }

    final AccessLogOperationType opType =
         AccessLogOperationType.forName(opTypeStr);
    if (opType == null)
    {
      final String messageStr = messageObject.toSingleLineString();
      throw new LogException(messageStr,
           ERR_JSON_ACCESS_LOG_READER_UNSUPPORTED_OPERATION_TYPE.get(messageStr,
                opTypeStr));
    }

    return opType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void close()
         throws IOException
  {
    jsonObjectReader.close();
  }
}
