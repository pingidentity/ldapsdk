/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides an implementation of an LDAP connection access logger
 * that records messages as JSON objects.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONLDAPConnectionLogger
       extends LDAPConnectionLogger
{
  /**
   * The bytes that comprise the value that will be used in place of redacted
   * attribute values.
   */
  @NotNull private static final String REDACTED_VALUE_STRING = "[REDACTED]";



  /**
   * The bytes that comprise the value that will be used in place of redacted
   * attribute values.
   */
  @NotNull private static final byte[] REDACTED_VALUE_BYTES =
       StaticUtils.getBytes(REDACTED_VALUE_STRING);



  // Indicates whether to flush the handler after logging information about each
  // successful for failed connection attempt.
  private final boolean flushAfterConnectMessages;

  // Indicates whether to flush the handler after logging information about each
  // disconnect.
  private final boolean flushAfterDisconnectMessages;

  // Indicates whether to flush the handler after logging information about each
  // request.
  private final boolean flushAfterRequestMessages;

  // Indicates whether to flush the handler after logging information about the
  // final result for each operation.
  private final boolean flushAfterFinalResultMessages;

  // Indicates whether to flush the handler after logging information about each
  // non-final result (including search result entries, search result
  // references, and intermediate response messages) for each operation.
  private final boolean flushAfterNonFinalResultMessages;

  // Indicates whether to include the names of attributes provided in add
  // requests.
  private final boolean includeAddAttributeNames;

  // Indicates whether to include the values of attributes provided in add
  // requests.
  private final boolean includeAddAttributeValues;

  // Indicates whether to include the names of attributes targeted by modify
  // requests.
  private final boolean includeModifyAttributeNames;

  // Indicates whether to include the values of attributes targeted by modify
  // requests.
  private final boolean includeModifyAttributeValues;

  // Indicates whether to include the OIDs of controls included in requests and
  // results.
  private final boolean includeControlOIDs;

  // Indicates whether to include the names of attributes provided in search
  // result entries.
  private final boolean includeSearchEntryAttributeNames;

  // Indicates whether to include the values of attributes provided in search
  // result entries.
  private final boolean includeSearchEntryAttributeValues;

  // Indicates whether to log successful and failed connection attempts.
  private final boolean logConnects;

  // Indicates whether to log disconnects.
  private final boolean logDisconnects;

  // Indicates whether to log intermediate response messages.
  private final boolean logIntermediateResponses;

  // Indicates whether to log operation requests for enabled operation types.
  private final boolean logRequests;

  // Indicates whether to log final operation results for enabled operation
  // types.
  private final boolean logFinalResults;

  // Indicates whether to log search result entries.
  private final boolean logSearchEntries;

  // Indicates whether to log search result references.
  private final boolean logSearchReferences;

  // The log handler that will be used to actually log the messages.
  @NotNull private final Handler logHandler;

  // The schema to use for identifying alternate attribute type names.
  @Nullable private final Schema schema;

  // The types of operations for which requests should be logged.
  @NotNull private final Set<OperationType> operationTypes;

  // The names or OIDs of the attributes whose values should be redacted.
  @NotNull private final Set<String> attributesToRedact;

  // The full set of the names and OIDs for attributes whose values should be
  // redacted.
  @NotNull private final Set<String> fullAttributesToRedact;

  // The set of thread-local JSON buffers that will be used for formatting log
  // messages.
  @NotNull private final ThreadLocal<JSONBuffer> jsonBuffers;

  // The set of thread-local date formatters that will be used for formatting
  // timestamps.
  @NotNull private final ThreadLocal<SimpleDateFormat> timestampFormatters;



  /**
   * Creates a new instance of this LDAP connection logger that will write
   * messages to the provided log handler using the given set of properties.
   *
   * @param  logHandler  The log handler that will be used to actually log the
   *                     messages.  All messages will be logged with a level of
   *                     {@code INFO}.
   * @param  properties  The properties to use for this logger.
   */
  public JSONLDAPConnectionLogger(@NotNull final Handler logHandler,
              @NotNull final JSONLDAPConnectionLoggerProperties properties)
  {
    this.logHandler = logHandler;

    flushAfterConnectMessages = properties.flushAfterConnectMessages();
    flushAfterDisconnectMessages = properties.flushAfterDisconnectMessages();
    flushAfterRequestMessages = properties.flushAfterRequestMessages();
    flushAfterFinalResultMessages =
         properties.flushAfterFinalResultMessages();
    flushAfterNonFinalResultMessages =
         properties.flushAfterNonFinalResultMessages();
    includeAddAttributeNames = properties.includeAddAttributeNames();
    includeAddAttributeValues = properties.includeAddAttributeValues();
    includeModifyAttributeNames = properties.includeModifyAttributeNames();
    includeModifyAttributeValues = properties.includeModifyAttributeValues();
    includeControlOIDs = properties.includeControlOIDs();
    includeSearchEntryAttributeNames =
         properties.includeSearchEntryAttributeNames();
    includeSearchEntryAttributeValues =
         properties.includeSearchEntryAttributeValues();
    logConnects = properties.logConnects();
    logDisconnects = properties.logDisconnects();
    logIntermediateResponses = properties.logIntermediateResponses();
    logRequests = properties.logRequests();
    logFinalResults = properties.logFinalResults();
    logSearchEntries = properties.logSearchEntries();
    logSearchReferences = properties.logSearchReferences();
    schema = properties.getSchema();

    attributesToRedact = Collections.unmodifiableSet(new LinkedHashSet<>(
         properties.getAttributesToRedact()));

    final EnumSet<OperationType> opTypes = EnumSet.noneOf(OperationType.class);
    opTypes.addAll(properties.getOperationTypes());
    operationTypes = Collections.unmodifiableSet(opTypes);

    jsonBuffers = new ThreadLocal<>();
    timestampFormatters = new ThreadLocal<>();

    final Set<String> fullAttrsToRedact = new HashSet<>();
    for (final String attr : attributesToRedact)
    {
      fullAttrsToRedact.add(StaticUtils.toLowerCase(attr));

      if (schema != null)
      {
        final AttributeTypeDefinition d = schema.getAttributeType(attr);
        if (d != null)
        {
          fullAttrsToRedact.add(StaticUtils.toLowerCase(d.getOID()));
          for (final String name : d.getNames())
          {
            fullAttrsToRedact.add(StaticUtils.toLowerCase(name));
          }
        }
      }
    }

    fullAttributesToRedact = Collections.unmodifiableSet(fullAttrsToRedact);
  }



  /**
   * Indicates whether to log successful and failed connection attempts.
   * Connection attempts will be logged by default.
   *
   * @return  {@code true} if connection attempts should be logged, or
   *          {@code false} if not.
   */
  public boolean logConnects()
  {
    return logConnects;
  }



  /**
   * Indicates whether to log disconnects.  Disconnects will be logged by
   * default.
   *
   * @return  {@code true} if disconnects should be logged, or {@code false} if
   *          not.
   */
  public boolean logDisconnects()
  {
    return logDisconnects;
  }



  /**
   * Indicates whether to log messages about requests for operations included
   * in the set of operation types returned by the {@link #getOperationTypes}
   * method.  Operation requests will be logged by default.
   *
   * @return  {@code true} if operation requests should be logged for
   *          appropriate operation types, or {@code false} if not.
   */
  public boolean logRequests()
  {
    return logRequests;
  }



  /**
   * Indicates whether to log messages about the final reults for operations
   * included in the set of operation types returned by the
   * {@link #getOperationTypes} method.  Final operation results will be
   * logged by default.
   *
   * @return  {@code true} if operation requests should be logged for
   *          appropriate operation types, or {@code false} if not.
   */
  public boolean logFinalResults()
  {
    return logFinalResults;
  }



  /**
   * Indicates whether to log messages about each search result entry returned
   * for search operations.  This property will only be used if the set returned
   * by the  {@link #getOperationTypes} method includes
   * {@link OperationType#SEARCH}.  Search result entries will not be logged by
   * default.
   *
   * @return  {@code true} if search result entries should be logged, or
   *          {@code false} if not.
   */
  public boolean logSearchEntries()
  {
    return logSearchEntries;
  }



  /**
   * Indicates whether to log messages about each search result reference
   * returned for search operations.  This property will only be used if the set
   * returned by the  {@link #getOperationTypes} method includes
   * {@link OperationType#SEARCH}.  Search result references will not be logged
   * by default.
   *
   * @return  {@code true} if search result references should be logged, or
   *          {@code false} if not.
   */
  public boolean logSearchReferences()
  {
    return logSearchReferences;
  }



  /**
   * Indicates whether to log messages about each intermediate response returned
   * in the course of processing an operation.  Intermediate response messages
   * will be logged by default.
   *
   * @return  {@code true} if intermediate response messages should be logged,
   *          or {@code false} if not.
   */
  public boolean logIntermediateResponses()
  {
    return logIntermediateResponses;
  }



  /**
   * Retrieves the set of operation types for which to log requests and
   * results.  All operation types will be logged by default.
   *
   * @return  The set of operation types for which to log requests and results.
   */
  @NotNull()
  public Set<OperationType> getOperationTypes()
  {
    return operationTypes;
  }



  /**
   * Indicates whether log messages about add requests should include the names
   * of the attributes provided in the request.  Add attribute names (but not
   * values) will be logged by default.
   *
   * @return  {@code true} if add attribute names should be logged, or
   *          {@code false} if not.
   */
  public boolean includeAddAttributeNames()
  {
    return includeAddAttributeNames;
  }



  /**
   * Indicates whether log messages about add requests should include the values
   * of the attributes provided in the request.  This property will only be used
   * if {@link #includeAddAttributeNames} returns {@code true}.  Values for
   * attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".  Add attribute names (but not values) will be
   * logged by default.
   *
   * @return  {@code true} if add attribute values should be logged, or
   *          {@code false} if not.
   */
  public boolean includeAddAttributeValues()
  {
    return includeAddAttributeValues;
  }



  /**
   * Indicates whether log messages about modify requests should include the
   * names of the attributes modified in the request.  Modified attribute names
   * (but not values) will be logged by default.
   *
   * @return  {@code true} if modify attribute names should be logged, or
   *          {@code false} if not.
   */
  public boolean includeModifyAttributeNames()
  {
    return includeModifyAttributeNames;
  }



  /**
   * Indicates whether log messages about modify requests should include the
   * values of the attributes modified in the request.  This property will only
   * be used if {@link #includeModifyAttributeNames} returns {@code true}.
   * Values for attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".  Modify attribute names (but not values) will be
   * logged by default.
   *
   * @return  {@code true} if modify attribute values should be logged, or
   *          {@code false} if not.
   */
  public boolean includeModifyAttributeValues()
  {
    return includeModifyAttributeValues;
  }



  /**
   * Indicates whether log messages about search result entries should include
   * the names of the attributes in the returned entry.  Entry attribute names
   * (but not values) will be logged by default.
   *
   * @return  {@code true} if search result entry attribute names should be
   *          logged, or {@code false} if not.
   */
  public boolean includeSearchEntryAttributeNames()
  {
    return includeSearchEntryAttributeNames;
  }



  /**
   * Indicates whether log messages about search result entries should include
   * the values of the attributes in the returned entry.  This property will
   * only be used if {@link #includeSearchEntryAttributeNames} returns
   * {@code true}.  Values for attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".  Entry attribute names (but not values) will be
   * logged by default.
   *
   * @return  {@code true} if search result entry attribute values should be
   *          logged, or {@code false} if not.
   */
  public boolean includeSearchEntryAttributeValues()
  {
    return includeSearchEntryAttributeValues;
  }



  /**
   * Retrieves a set containing the names or OIDs of the attributes whose values
   * should be redacted from log messages.  Values of the userPassword,
   * authPassword, and unicodePWD attributes will be redacted by default.
   *
   * @return  A set containing the names or OIDs of the attributes whose values
   *          should be redacted from log messages, or an empty set if no
   *          attribute values should be redacted.
   */
  @NotNull()
  public Set<String> getAttributesToRedact()
  {
    return attributesToRedact;
  }



  /**
   * Indicates whether request and result log messages should include the OIDs
   * of any controls included in that request or result.  Control OIDs will
   * be logged by default.
   *
   * @return  {@code true} if request control OIDs should be logged, or
   *          {@code false} if not.
   */
  public boolean includeControlOIDs()
  {
    return includeControlOIDs;
  }



  /**
   * Indicates whether the log handler should be flushed after logging each
   * successful or failed connection attempt.  By default, the handler will be
   * flushed after logging each connection attempt.
   *
   * @return  {@code true} if the log handler should be flushed after logging
   *          each connection attempt, or {@code false} if not.
   */
  public boolean flushAfterConnectMessages()
  {
    return flushAfterConnectMessages;
  }



  /**
   * Indicates whether the log handler should be flushed after logging each
   * disconnect.  By default, the handler will be flushed after logging each
   * disconnect.
   *
   * @return  {@code true} if the log handler should be flushed after logging
   *          each disconnect, or {@code false} if not.
   */
  public boolean flushAfterDisconnectMessages()
  {
    return flushAfterDisconnectMessages;
  }



  /**
   * Indicates whether the log handler should be flushed after logging each
   * request.  By default, the handler will be flushed after logging each final
   * result, but not after logging requests or non-final results.
   *
   * @return  {@code true} if the log handler should be flushed after logging
   *          each request, or {@code false} if not.
   */
  public boolean flushAfterRequestMessages()
  {
    return flushAfterRequestMessages;
  }



  /**
   * Indicates whether the log handler should be flushed after logging each
   * non-final result (including search result entries, search result
   * references, and intermediate response messages).  By default, the handler
   * will be flushed after logging each final result, but not after logging
   * requests or non-final results.
   *
   * @return  {@code true} if the log handler should be flushed after logging
   *          each non-final result, or {@code false} if not.
   */
  public boolean flushAfterNonFinalResultMessages()
  {
    return flushAfterNonFinalResultMessages;
  }



  /**
   * Indicates whether the log handler should be flushed after logging the final
   * result for each operation.  By default, the handler will be flushed after
   * logging each final result, but not after logging requests or non-final
   * results.
   *
   * @return  {@code true} if the log handler should be flushed after logging
   *          each final result, or {@code false} if not.
   */
  public boolean flushAfterFinalResultMessages()
  {
    return flushAfterFinalResultMessages;
  }



  /**
   * Retrieves the schema that will be used to identify alternate names and OIDs
   * for attributes whose values should be redacted.  The LDAP SDK's default
   * standard schema will be used by default.
   *
   * @return  The schema that will be used to identify alternate names and OIDs
   *          for attributes whose values should be redacted, or {@code null}
   *          if no schema should be used.
   */
  @Nullable()
  public Schema getSchema()
  {
    return schema;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logConnect(@NotNull final LDAPConnectionInfo connectionInfo,
                         @NotNull final String host,
                         @NotNull final InetAddress inetAddress,
                         final int port)
  {
    if (logConnects)
    {
      final JSONBuffer buffer = startLogMessage("connect", null,
           connectionInfo, -1);

      buffer.appendString("hostname", host);
      buffer.appendString("ip-address", inetAddress.getHostAddress());
      buffer.appendNumber("port", port);

      logMessage(buffer, flushAfterConnectMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logConnectFailure(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   @NotNull final String host, final int port,
                   @NotNull final LDAPException connectException)
  {
    if (logConnects)
    {
      final JSONBuffer buffer = startLogMessage("connect-failure", null,
           connectionInfo, -1);

      buffer.appendString("hostname", host);
      buffer.appendNumber("port", port);

      if (connectException != null)
      {
        appendException(buffer, "connect-exception", connectException);
      }

      logMessage(buffer, flushAfterConnectMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logDisconnect(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   @NotNull final String host, final int port,
                   @NotNull final DisconnectType disconnectType,
                   @Nullable final String disconnectMessage,
                   @Nullable final Throwable disconnectCause)
  {
    if (logDisconnects)
    {
      final JSONBuffer buffer = startLogMessage("disconnect", null,
           connectionInfo, -1);

      buffer.appendString("hostname", host);
      buffer.appendNumber("port", port);
      buffer.appendString("disconnect-type", disconnectType.name());

      if (disconnectMessage != null)
      {
        buffer.appendString("disconnect-message", disconnectMessage);
      }

      if (disconnectCause != null)
      {
        appendException(buffer, "disconnect-cause", disconnectCause);
      }

      logMessage(buffer, flushAfterDisconnectMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logAbandonRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   final int messageIDToAbandon,
                   @NotNull final List<Control> requestControls)
  {
    if (logRequests && operationTypes.contains(OperationType.ABANDON))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.ABANDON, connectionInfo, messageID);

      buffer.appendNumber("message-id-to-abandon", messageIDToAbandon);
      appendControls(buffer, "control-oids", requestControls);

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logAddRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                            final int messageID,
                            @NotNull final ReadOnlyAddRequest addRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.ADD))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.ADD, connectionInfo, messageID);

      appendDN(buffer, "dn", addRequest.getDN());

      if (includeAddAttributeNames)
      {
        appendAttributes(buffer, "attributes", addRequest.getAttributes(),
             includeAddAttributeValues);
      }

      appendControls(buffer, "control-oids", addRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logAddResult(@NotNull final LDAPConnectionInfo connectionInfo,
                           final int requestMessageID,
                           @NotNull final LDAPResult addResult)
  {
    logLDAPResult(connectionInfo, OperationType.ADD, requestMessageID,
         addResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logBindRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                             final int messageID,
                             @NotNull final SimpleBindRequest bindRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.BIND))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.BIND, connectionInfo, messageID);

      buffer.appendString("authentication-type", "simple");
      appendDN(buffer, "dn", bindRequest.getBindDN());

      appendControls(buffer, "control-oids", bindRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logBindRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                             final int messageID,
                             @NotNull final SASLBindRequest bindRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.BIND))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.BIND, connectionInfo, messageID);

      buffer.appendString("authentication-type", "SASL");
      buffer.appendString("sasl-mechanism", bindRequest.getSASLMechanismName());

      appendControls(buffer, "control-oids", bindRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logBindResult(@NotNull final LDAPConnectionInfo connectionInfo,
                            final int requestMessageID,
                            @NotNull final BindResult bindResult)
  {
    logLDAPResult(connectionInfo, OperationType.BIND, requestMessageID,
         bindResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompareRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyCompareRequest compareRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.COMPARE))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.COMPARE, connectionInfo, messageID);

      appendDN(buffer, "dn", compareRequest.getDN());
      appendDN(buffer, "attribute-type", compareRequest.getAttributeName());

      final String baseName = StaticUtils.toLowerCase(
           Attribute.getBaseName(compareRequest.getAttributeName()));
      if (fullAttributesToRedact.contains(baseName))
      {
        buffer.appendString("assertion-value", REDACTED_VALUE_STRING);
      }
      else
      {
        buffer.appendString("assertion-value",
             compareRequest.getAssertionValue());
      }

      appendControls(buffer, "control-oids", compareRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logCompareResult(@NotNull final LDAPConnectionInfo connectionInfo,
                               final int requestMessageID,
                               @NotNull final LDAPResult compareResult)
  {
    logLDAPResult(connectionInfo, OperationType.COMPARE, requestMessageID,
         compareResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logDeleteRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyDeleteRequest deleteRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.DELETE))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.DELETE, connectionInfo, messageID);

      appendDN(buffer, "dn", deleteRequest.getDN());
      appendControls(buffer, "control-oids", deleteRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logDeleteResult(@NotNull final LDAPConnectionInfo connectionInfo,
                              final int requestMessageID,
                              @NotNull final LDAPResult deleteResult)
  {
    logLDAPResult(connectionInfo, OperationType.DELETE, requestMessageID,
         deleteResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logExtendedRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ExtendedRequest extendedRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.EXTENDED))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.EXTENDED, connectionInfo, messageID);

      buffer.appendString("oid", extendedRequest.getOID());
      buffer.appendBoolean("has-value",  (extendedRequest.getValue() != null));

      appendControls(buffer, "control-oids", extendedRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logExtendedResult(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final ExtendedResult extendedResult)
  {
    logLDAPResult(connectionInfo, OperationType.EXTENDED, requestMessageID,
         extendedResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyModifyRequest modifyRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.MODIFY))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.MODIFY, connectionInfo, messageID);

      appendDN(buffer, "dn", modifyRequest.getDN());

      if (includeModifyAttributeNames)
      {
        final List<Modification> mods = modifyRequest.getModifications();

        if (includeModifyAttributeValues)
        {
          buffer.beginArray("modifications");
          for (final Modification m : mods)
          {
            buffer.beginObject();

            final String name = m.getAttributeName();
            buffer.appendString("attribute-name", name);
            buffer.appendString("modification-type",
                 m.getModificationType().getName());

            buffer.beginArray("attribute-values");
            final String baseName =
                 StaticUtils.toLowerCase(Attribute.getBaseName(name));
            if (fullAttributesToRedact.contains(baseName))
            {
              for (final String value : m.getValues())
              {
                buffer.appendString(REDACTED_VALUE_STRING);
              }
            }
            else
            {
              for (final String value : m.getValues())
              {
                buffer.appendString(value);
              }
            }

            buffer.endArray();
            buffer.endObject();
          }

          buffer.endArray();
        }
        else
        {
          final Map<String,String> modifiedAttributes = new LinkedHashMap<>(
               StaticUtils.computeMapCapacity(mods.size()));
          for (final Modification m : modifyRequest.getModifications())
          {
            final String name = m.getAttributeName();
            final String lowerName =  StaticUtils.toLowerCase(name);
            if (! modifiedAttributes.containsKey(lowerName))
            {
              modifiedAttributes.put(lowerName, name);
            }
          }

          buffer.beginArray("modified-attributes");
          for (final String attributeName : modifiedAttributes.values())
          {
            buffer.appendString(attributeName);
          }

          buffer.endArray();
        }
      }

      appendControls(buffer, "control-oids", modifyRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyResult(@NotNull final LDAPConnectionInfo connectionInfo,
                              final int requestMessageID,
                              @NotNull final LDAPResult modifyResult)
  {
    logLDAPResult(connectionInfo, OperationType.MODIFY, requestMessageID,
         modifyResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyDNRequest(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlyModifyDNRequest modifyDNRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.MODIFY_DN))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.MODIFY_DN, connectionInfo, messageID);

      appendDN(buffer, "dn", modifyDNRequest.getDN());
      appendDN(buffer, "new-rdn", modifyDNRequest.getNewRDN());
      buffer.appendBoolean("delete-old-rdn", modifyDNRequest.deleteOldRDN());

      final String newSuperiorDN = modifyDNRequest.getNewSuperiorDN();
      if (newSuperiorDN != null)
      {
        appendDN(buffer, "new-superior-dn", newSuperiorDN);
      }

      appendControls(buffer, "control-oids", modifyDNRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logModifyDNResult(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final LDAPResult modifyDNResult)
  {
    logLDAPResult(connectionInfo, OperationType.MODIFY_DN, requestMessageID,
         modifyDNResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final ReadOnlySearchRequest searchRequest)
  {
    if (logRequests && operationTypes.contains(OperationType.SEARCH))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.SEARCH, connectionInfo, messageID);

      appendDN(buffer, "base-dn", searchRequest.getBaseDN());

      buffer.appendString("scope", searchRequest.getScope().getName());
      buffer.appendString("dereference-policy",
           searchRequest.getDereferencePolicy().getName());
      buffer.appendNumber("size-limit", searchRequest.getSizeLimit());
      buffer.appendNumber("time-limit-seconds",
           searchRequest.getTimeLimitSeconds());
      buffer.appendBoolean("types-only", searchRequest.typesOnly());
      buffer.appendString("filter",
           redactFilter(searchRequest.getFilter()).toString());

      buffer.beginArray("requested-attributes");
      for (final String attributeName : searchRequest.getAttributeList())
      {
        buffer.appendString(attributeName);
      }
      buffer.endArray();

      appendControls(buffer, "control-oids", searchRequest.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchEntry(@NotNull final LDAPConnectionInfo connectionInfo,
                             final int requestMessageID,
                             @NotNull final SearchResultEntry searchEntry)
  {
    if (logSearchEntries && operationTypes.contains(OperationType.SEARCH))
    {
      final JSONBuffer buffer = startLogMessage("search-entry",
           OperationType.SEARCH, connectionInfo, requestMessageID);

      appendDN(buffer, "dn", searchEntry.getDN());

      if (includeSearchEntryAttributeNames)
      {
        appendAttributes(buffer, "attributes",
             new ArrayList<>(searchEntry.getAttributes()),
             includeSearchEntryAttributeValues);
      }

      appendControls(buffer, "control-oids", searchEntry.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchReference(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int requestMessageID,
                   @NotNull final SearchResultReference searchReference)
  {
    if (logSearchReferences && operationTypes.contains(OperationType.SEARCH))
    {
      final JSONBuffer buffer = startLogMessage("search-reference",
           OperationType.SEARCH, connectionInfo, requestMessageID);

      buffer.beginArray("referral-urls");
      for (final String url : searchReference.getReferralURLs())
      {
        buffer.appendString(url);
      }
      buffer.endArray();

      appendControls(buffer, "control-oids", searchReference.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logSearchResult(@NotNull final LDAPConnectionInfo connectionInfo,
                               final int requestMessageID,
                               @NotNull final SearchResult searchResult)
  {
    logLDAPResult(connectionInfo, OperationType.SEARCH, requestMessageID,
         searchResult);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logUnbindRequest(@NotNull final LDAPConnectionInfo connectionInfo,
                               final int messageID,
                               @NotNull final List<Control> requestControls)
  {
    if (logRequests && operationTypes.contains(OperationType.UNBIND))
    {
      final JSONBuffer buffer = startLogMessage("request",
           OperationType.UNBIND, connectionInfo, messageID);

      appendControls(buffer, "control-oids", requestControls);

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void logIntermediateResponse(
                   @NotNull final LDAPConnectionInfo connectionInfo,
                   final int messageID,
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    if (logIntermediateResponses)
    {
      final JSONBuffer buffer = startLogMessage("intermediate-response", null,
           connectionInfo, messageID);

      final String oid = intermediateResponse.getOID();
      if (oid != null)
      {
        buffer.appendString("oid", oid);
      }

      buffer.appendBoolean("has-value",
           (intermediateResponse.getValue() != null));

      appendControls(buffer, "control-oids",
           intermediateResponse.getControls());

      logMessage(buffer, flushAfterRequestMessages);
    }
  }



  /**
   * Starts generating a log message.
   *
   * @param  messageType     The message type for the log message.  It must not
   *                         be {@code null}.
   * @param  operationType   The operation type for the log message.  It may be
   *                         {@code null} if there is no associated operation
   *                         type.
   * @param  connectionInfo  Information about the connection with which the
   *                         message is associated.  It must not be
   *                         {@code null}.
   * @param  messageID       The LDAP message ID for the associated operation.
   *                         This will be ignored if the value is less than
   *                         zero.
   *
   * @return  A JSON buffer that may be used to construct the remainder of the
   *          log message.
   */
  @NotNull()
  private JSONBuffer startLogMessage(@NotNull final String messageType,
                          @Nullable final OperationType operationType,
                          @NotNull final LDAPConnectionInfo connectionInfo,
                          final int messageID)
  {
    JSONBuffer buffer = jsonBuffers.get();
    if (buffer == null)
    {
      buffer = new JSONBuffer();
      jsonBuffers.set(buffer);
    }
    else
    {
      buffer.clear();
    }

    buffer.beginObject();

    SimpleDateFormat timestampFormatter = timestampFormatters.get();
    if (timestampFormatter == null)
    {
      timestampFormatter =
           new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH':'mm':'ss.SSS'Z'");
      timestampFormatter.setTimeZone(StaticUtils.getUTCTimeZone());
      timestampFormatters.set(timestampFormatter);
    }

    buffer.appendString("timestamp", timestampFormatter.format(new Date()));
    buffer.appendString("message-type", messageType);

    if (operationType != null)
    {
      switch (operationType)
      {
        case ABANDON:
          buffer.appendString("operation-type", "abandon");
          break;
        case ADD:
          buffer.appendString("operation-type", "add");
          break;
        case BIND:
          buffer.appendString("operation-type", "bind");
          break;
        case COMPARE:
          buffer.appendString("operation-type", "compare");
          break;
        case DELETE:
          buffer.appendString("operation-type", "delete");
          break;
        case EXTENDED:
          buffer.appendString("operation-type", "extended");
          break;
        case MODIFY:
          buffer.appendString("operation-type", "modify");
          break;
        case MODIFY_DN:
          buffer.appendString("operation-type", "modify-dn");
          break;
        case SEARCH:
          buffer.appendString("operation-type", "search");
          break;
        case UNBIND:
          buffer.appendString("operation-type", "unbind");
          break;
      }
    }

    buffer.appendNumber("connection-id", connectionInfo.getConnectionID());

    final String connectionName = connectionInfo.getConnectionName();
    if (connectionName != null)
    {
      buffer.appendString("connection-name", connectionName);
    }

    final String connectionPoolName = connectionInfo.getConnectionPoolName();
    if (connectionPoolName != null)
    {
      buffer.appendString("connection-pool-name", connectionPoolName);
    }

    if (messageID >= 0)
    {
      buffer.appendNumber("ldap-message-id", messageID);
    }

    return buffer;
  }



  /**
   * Appends information about an exception to the provided buffer.
   *
   * @param  buffer     The buffer to which the exception should be appended.
   *                    It must not be {@code null}.
   * @param  fieldName  The name of the field to use for the exception
   *                    object that is appended to the buffer.  It must not be
   *                    {@code null}.
   * @param  exception  The exception to be appended.  It must not be
   *                    {@code null}.
   */
  private void appendException(@NotNull final JSONBuffer buffer,
                               @NotNull final String fieldName,
                               @NotNull final Throwable exception)
  {
    buffer.beginObject(fieldName);

    buffer.appendString("exception-class", exception.getClass().getName());

    final String message = exception.getMessage();
    if (message != null)
    {
      buffer.appendString("message", message);
    }

    buffer.beginArray("stack-trace-frames");
    for (final StackTraceElement frame : exception.getStackTrace())
    {
      buffer.beginObject();

      buffer.appendString("class", frame.getClassName());
      buffer.appendString("method", frame.getMethodName());

      final String fileName = frame.getFileName();
      if (fileName != null)
      {
        buffer.appendString("file", fileName);
      }

      if (frame.isNativeMethod())
      {
        buffer.appendBoolean("is-native-method", true);
      }
      else
      {
        final int lineNumber = frame.getLineNumber();
        if (lineNumber > 0)
        {
          buffer.appendNumber("line-number", lineNumber);
        }
      }

      buffer.endObject();
    }
    buffer.endArray();

    final Throwable cause = exception.getCause();
    if (cause != null)
    {
      appendException(buffer, "caused-by", cause);
    }

    buffer.endObject();
  }



  /**
   * Appends information about the given set of controls to the provided buffer,
   * if control OIDs should be included in log messages.
   *
   * @param  buffer     The buffer to which the information should be appended.
   *                    It must not be {@code null}.
   * @param  fieldName  The name to use for the JSON field.  It must not be
   *                    {@code null}.
   * @param  controls   The controls to be appended.  It must not be
   *                    {@code null} but may be empty.
   */
  private void appendControls(@NotNull final JSONBuffer buffer,
                              @NotNull final String fieldName,
                              @NotNull final Control... controls)
  {
    if (includeControlOIDs && (controls.length > 0))
    {
      buffer.beginArray(fieldName);
      for (final Control c : controls)
      {
        buffer.appendString(c.getOID());
      }
      buffer.endArray();
    }
  }



  /**
   * Appends information about the given set of controls to the provided buffer,
   * if control OIDs should be included in log messages.
   *
   * @param  buffer     The buffer to which the information should be appended.
   *                    It must not be {@code null}.
   * @param  fieldName  The name to use for the JSON field.  It must not be
   *                    {@code null}.
   * @param  controls   The controls to be appended.  It must not be
   *                    {@code null} but may be empty.
   */
  private void appendControls(@NotNull final JSONBuffer buffer,
                              @NotNull final String fieldName,
                              @NotNull final List<Control> controls)
  {
    if (includeControlOIDs && (! controls.isEmpty()))
    {
      buffer.beginArray(fieldName);
      for (final Control c : controls)
      {
        buffer.appendString(c.getOID());
      }
      buffer.endArray();
    }
  }



  /**
   * Appends a DN to the provided buffer, redacting any attribute values as
   * appropriate.
   *
   * @param  buffer     The buffer to which the information should be appended.
   *                    It must not be {@code null}.
   * @param  fieldName  The name to use for the JSON field.  It must not be
   *                    {@code null}.
   * @param  dn         The DN to be appended.  It must not be {@code null} but
   *                    may be empty.
   */
  private void appendDN(@NotNull final JSONBuffer buffer,
                        @NotNull final String fieldName,
                        @NotNull final String dn)
  {
    if (fullAttributesToRedact.isEmpty())
    {
      buffer.appendString(fieldName, dn);
      return;
    }

    final DN parsedDN;
    try
    {
      parsedDN = new DN(dn);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      buffer.appendString(fieldName, dn);
      return;
    }

    boolean redactionNeeded = false;
    final RDN[] originalRDNs = parsedDN.getRDNs();
    for (final RDN rdn : originalRDNs)
    {
      for (final String attributeName : rdn.getAttributeNames())
      {
        if (fullAttributesToRedact.contains(
             StaticUtils.toLowerCase(attributeName)))
        {
          redactionNeeded = true;
          break;
        }
      }
    }

    if (redactionNeeded)
    {
      final RDN[] newRDNs = new RDN[originalRDNs.length];
      for (int i=0; i < originalRDNs.length; i++)
      {
        final RDN rdn = originalRDNs[i];
        final String[] names = rdn.getAttributeNames();
        final byte[][] values = new byte[names.length][];
        for (int j=0; j < names.length; j++)
        {
          final String lowerName = StaticUtils.toLowerCase(names[j]);
          if (fullAttributesToRedact.contains(lowerName))
          {
            values[j] = REDACTED_VALUE_BYTES;
          }
          else
          {
            values[j] = rdn.getByteArrayAttributeValues()[j];
          }
        }

        newRDNs[i] = new RDN(names, values, rdn.getSchema());
      }

      buffer.appendString(fieldName, new DN(newRDNs).toString());
    }
    else
    {
      buffer.appendString(fieldName, dn);
    }
  }



  /**
   * Appends the given list of attributes to the provided buffer, redacting any
   * values as appropriate.
   *
   * @param  buffer         The buffer to which the information should be
   *                        appended.  It must not be {@code null}.
   * @param  fieldName      The name of the field to use for the attribute
   *                        array.  It must not be {@code null}.
   * @param  attributes     The attributes to be appended.  It must not be
   *                        {@code null}, but may be empty.
   * @param  includeValues  Indicates whether to include the values of the
   *                        attributes.
   */
  private void appendAttributes(@NotNull final JSONBuffer buffer,
                                @NotNull final String fieldName,
                                @NotNull final List<Attribute> attributes,
                                final boolean includeValues)
  {
    buffer.beginArray(fieldName);

    for (final Attribute attribute : attributes)
    {
      if (includeValues)
      {
        buffer.beginObject();
        buffer.appendString("name", attribute.getName());
        buffer.beginArray("values");

        final String baseName =
             StaticUtils.toLowerCase(attribute.getBaseName());
        if (fullAttributesToRedact.contains(baseName))
        {
          for (final String value : attribute.getValues())
          {
            buffer.appendString(REDACTED_VALUE_STRING);
          }
        }
        else
        {
          for (final String value : attribute.getValues())
          {
            buffer.appendString(value);
          }
        }

        buffer.endArray();
        buffer.endObject();
      }
      else
      {
        buffer.appendString(attribute.getName());
      }
    }

    buffer.endArray();
  }



  /**
   * Redacts the provided filter, if necessary.
   *
   * @param  filter  The filter to be redacted.  It must not be {@code null}.
   *
   * @return  The redacted filter.
   */
  @NotNull()
  private Filter redactFilter(@NotNull final Filter filter)
  {
    switch (filter.getFilterType())
    {
      case Filter.FILTER_TYPE_AND:
        final Filter[] currentANDComps = filter.getComponents();
        final Filter[] newANDComps = new Filter[currentANDComps.length];
        for (int i=0; i < currentANDComps.length; i++)
        {
          newANDComps[i] = redactFilter(currentANDComps[i]);
        }
        return Filter.createANDFilter(newANDComps);

      case Filter.FILTER_TYPE_OR:
        final Filter[] currentORComps = filter.getComponents();
        final Filter[] newORComps = new Filter[currentORComps.length];
        for (int i=0; i < currentORComps.length; i++)
        {
          newORComps[i] = redactFilter(currentORComps[i]);
        }
        return Filter.createORFilter(newORComps);

      case Filter.FILTER_TYPE_NOT:
        return Filter.createNOTFilter(redactFilter(filter.getNOTComponent()));

      case Filter.FILTER_TYPE_EQUALITY:
        return Filter.createEqualityFilter(filter.getAttributeName(),
             redactAssertionValue(filter));

      case Filter.FILTER_TYPE_GREATER_OR_EQUAL:
        return Filter.createGreaterOrEqualFilter(filter.getAttributeName(),
             redactAssertionValue(filter));

      case Filter.FILTER_TYPE_LESS_OR_EQUAL:
        return Filter.createLessOrEqualFilter(filter.getAttributeName(),
             redactAssertionValue(filter));

      case Filter.FILTER_TYPE_APPROXIMATE_MATCH:
        return Filter.createApproximateMatchFilter(filter.getAttributeName(),
             redactAssertionValue(filter));

      case Filter.FILTER_TYPE_EXTENSIBLE_MATCH:
        return Filter.createExtensibleMatchFilter(filter.getAttributeName(),
             filter.getMatchingRuleID(), filter.getDNAttributes(),
             redactAssertionValue(filter));

      case Filter.FILTER_TYPE_SUBSTRING:
        final String baseName = StaticUtils.toLowerCase(Attribute.getBaseName(
             filter.getAttributeName()));
        if (fullAttributesToRedact.contains(baseName))
        {
          final String[] redactedSubAnyStrings =
               new String[filter.getSubAnyStrings().length];
          Arrays.fill(redactedSubAnyStrings, REDACTED_VALUE_STRING);

          return Filter.createSubstringFilter(filter.getAttributeName(),
               filter.getSubInitialString() == null
                    ? null
                    : REDACTED_VALUE_STRING,
               redactedSubAnyStrings,
               filter.getSubFinalString() == null
                    ? null
                    : REDACTED_VALUE_STRING);
        }
        else
        {
          return Filter.createSubstringFilter(filter.getAttributeName(),
               filter.getSubInitialString(), filter.getSubAnyStrings(),
               filter.getSubFinalString());
        }

      case Filter.FILTER_TYPE_PRESENCE:
      default:
        return filter;
    }
  }



  /**
   * Retrieves an assertion value to use for a redacted filter.
   *
   * @param  filter  The filter for which to obtain the assertion value.
   *
   * @return  The assertion value to use for a redacted filter.
   */
  @NotNull()
  private String redactAssertionValue(@NotNull final Filter filter)
  {
    final String attributeName = filter.getAttributeName();
    if (attributeName == null)
    {
      return filter.getAssertionValue();
    }

    final String baseName =
         StaticUtils.toLowerCase(Attribute.getBaseName(attributeName));
    if (fullAttributesToRedact.contains(baseName))
    {
      return REDACTED_VALUE_STRING;
    }
    else
    {
      return filter.getAssertionValue();
    }
  }



  /**
   * Logs a final result message for the provided result.  If the result is a
   * {@code BindResult}, an {@code ExtendedResult}, or a {@code SearchResult},
   * then additional information about that type of result may also be included.
   *
   * @param  connectionInfo  Information about the connection with which the
   *                         result is associated.  It must not be
   *                         {@code null}.
   * @param  operationType   The operation type for the log message.  It must
   *                         not be {@code null}.
   * @param  messageID       The LDAP message ID for the associated operation.
   * @param  result          The result to be logged.
   */
  private void logLDAPResult(@NotNull final LDAPConnectionInfo connectionInfo,
                             @NotNull final OperationType operationType,
                             final int messageID,
                             @NotNull final LDAPResult result)
  {
    if (logFinalResults && operationTypes.contains(operationType))
    {
      final JSONBuffer buffer = startLogMessage("result", operationType,
           connectionInfo, messageID);

      buffer.appendNumber("result-code-value",
           result.getResultCode().intValue());
      buffer.appendString("result-code-name", result.getResultCode().getName());

      final String diagnosticMessage = result.getDiagnosticMessage();
      if (diagnosticMessage != null)
      {
        buffer.appendString("diagnostic-message", diagnosticMessage);
      }

      final String matchedDN = result.getMatchedDN();
      if (matchedDN != null)
      {
        buffer.appendString("matched-dn", matchedDN);
      }

      final String[] referralURLs = result.getReferralURLs();
      if ((referralURLs != null) && (referralURLs.length > 0))
      {
        buffer.beginArray("referral-urls");
        for (final String url : referralURLs)
        {
          buffer.appendString(url);
        }
        buffer.endArray();
      }

      if (result instanceof BindResult)
      {
        final BindResult bindResult = (BindResult) result;
        if (bindResult.getServerSASLCredentials() != null)
        {
          buffer.appendBoolean("has-server-sasl-credentials", true);
        }
      }
      else if (result instanceof ExtendedResult)
      {
        final ExtendedResult extendedResult = (ExtendedResult) result;
        final String oid = extendedResult.getOID();
        if (oid != null)
        {
          buffer.appendString("oid", oid);
        }

        buffer.appendBoolean("has-value", (extendedResult.getValue() != null));
      }

      appendControls(buffer, "control-oids", result.getResponseControls());

      logMessage(buffer, flushAfterFinalResultMessages);
    }
  }



  /**
   * Finalizes the message and writes it to the log handler, optionally flushing
   * the handler after the message has been written.
   *
   * @param  buffer        The buffer containing the message to be written.
   * @param  flushHandler  Indicates whether to flush the handler after the
   *                       message has been written.
   */
  private void logMessage(@NotNull final JSONBuffer buffer,
                          final boolean flushHandler)
  {
    buffer.endObject();

    logHandler.publish(new LogRecord(Level.INFO, buffer.toString()));

    if (flushHandler)
    {
      logHandler.flush();
    }
  }
}
