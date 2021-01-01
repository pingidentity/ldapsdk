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



import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that can be used to define the
 * properties to use when creating a {@link JSONLDAPConnectionLogger}.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class JSONLDAPConnectionLoggerProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 709385948984934296L;



  // Indicates whether to flush the handler after logging information about each
  // successful for failed connection attempt.
  private boolean flushAfterConnectMessages;

  // Indicates whether to flush the handler after logging information about each
  // disconnect.
  private boolean flushAfterDisconnectMessages;

  // Indicates whether to flush the handler after logging information about each
  // request.
  private boolean flushAfterRequestMessages;

  // Indicates whether to flush the handler after logging information about the
  // final result for each operation.
  private boolean flushAfterFinalResultMessages;

  // Indicates whether to flush the handler after logging information about each
  // non-final results (including search result entries, search result
  // references, and intermediate response messages) for each operation.
  private boolean flushAfterNonFinalResultMessages;

  // Indicates whether to include the names of attributes provided in add
  // requests.
  private boolean includeAddAttributeNames;

  // Indicates whether to include the values of attributes provided in add
  // requests.
  private boolean includeAddAttributeValues;

  // Indicates whether to include the names of attributes targeted by modify
  // requests.
  private boolean includeModifyAttributeNames;

  // Indicates whether to include the values of attributes targeted by modify
  // requests.
  private boolean includeModifyAttributeValues;

  // Indicates whether to include the OIDs of controls included in requests and
  // results.
  private boolean includeControlOIDs;

  // Indicates whether to include the names of attributes provided in search
  // result entries.
  private boolean includeSearchEntryAttributeNames;

  // Indicates whether to include the values of attributes provided in search
  // result entries.
  private boolean includeSearchEntryAttributeValues;

  // Indicates whether to log successful and failed connection attempts.
  private boolean logConnects;

  // Indicates whether to log disconnects.
  private boolean logDisconnects;

  // Indicates whether to log intermediate response messages.
  private boolean logIntermediateResponses;

  // Indicates whether to log operation requests for enabled operation types.
  private boolean logRequests;

  // Indicates whether to log final operation results for enabled operation
  // types.
  private boolean logFinalResults;

  // Indicates whether to log search result entries.
  private boolean logSearchEntries;

  // Indicates whether to log search result references.
  private boolean logSearchReferences;

  // The schema to use for identifying alternate attribute type names.
  @Nullable private Schema schema;

  // The types of operations for which requests should be logged.
  @NotNull private final Set<OperationType> operationTypes;

  // The names or OIDs of the attributes whose values should be redacted.
  @NotNull private final Set<String> attributesToRedact;



  /**
   * Creates a new set of JSON LDAP connection logger properties with the
   * default settings.
   */
  public JSONLDAPConnectionLoggerProperties()
  {
    flushAfterConnectMessages = true;
    flushAfterDisconnectMessages = true;
    flushAfterRequestMessages = false;
    flushAfterFinalResultMessages = true;
    flushAfterNonFinalResultMessages = false;
    includeAddAttributeNames = true;
    includeAddAttributeValues = false;
    includeModifyAttributeNames = true;
    includeModifyAttributeValues = false;
    includeControlOIDs = true;
    includeSearchEntryAttributeNames = true;
    includeSearchEntryAttributeValues = false;
    logConnects = true;
    logDisconnects = true;
    logIntermediateResponses = true;
    logRequests = true;
    logFinalResults = true;
    logSearchEntries = false;
    logSearchReferences = false;
    operationTypes = EnumSet.allOf(OperationType.class);

    try
    {
      schema = Schema.getDefaultStandardSchema();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      schema = null;
    }

    attributesToRedact =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(10));
    attributesToRedact.add("userPassword");
    attributesToRedact.add("authPassword");
    attributesToRedact.add("unicodePwd");
  }



  /**
   * Creates a new set of JSON LDAP connection logger properties that is a clone
   * of the provided set of properties.
   *
   * @param  properties  The set of properties to copy.  It must not be
   *                     {@code null}.
   */
  public JSONLDAPConnectionLoggerProperties(
              @NotNull final JSONLDAPConnectionLoggerProperties properties)
  {
    flushAfterConnectMessages = properties.flushAfterConnectMessages;
    flushAfterDisconnectMessages = properties.flushAfterDisconnectMessages;
    flushAfterRequestMessages = properties.flushAfterRequestMessages;
    flushAfterFinalResultMessages =
         properties.flushAfterFinalResultMessages;
    flushAfterNonFinalResultMessages =
         properties.flushAfterNonFinalResultMessages;
    includeAddAttributeNames = properties.includeAddAttributeNames;
    includeAddAttributeValues = properties.includeAddAttributeValues;
    includeModifyAttributeNames = properties.includeModifyAttributeNames;
    includeModifyAttributeValues = properties.includeModifyAttributeValues;
    includeControlOIDs = properties.includeControlOIDs;
    includeSearchEntryAttributeNames =
         properties.includeSearchEntryAttributeNames;
    includeSearchEntryAttributeValues =
         properties.includeSearchEntryAttributeValues;
    logConnects = properties.logConnects;
    logDisconnects = properties.logDisconnects;
    logIntermediateResponses = properties.logIntermediateResponses;
    logRequests = properties.logRequests;
    logFinalResults = properties.logFinalResults;
    logSearchEntries = properties.logSearchEntries;
    logSearchReferences = properties.logSearchReferences;
    schema = properties.schema;
    attributesToRedact = new LinkedHashSet<>(properties.attributesToRedact);

    operationTypes = EnumSet.noneOf(OperationType.class);
    operationTypes.addAll(properties.operationTypes);
  }



  /**
   * Creates a new set of JSON LDAP connection logger properties using the
   * configuration for the provided logger.
   *
   * @param  logger  The JSON LDAP connection logger whose configuration should
   *                 be used to create the set of properties.
   */
  public JSONLDAPConnectionLoggerProperties(
              @NotNull final JSONLDAPConnectionLogger logger)
  {
    flushAfterConnectMessages = logger.flushAfterConnectMessages();
    flushAfterDisconnectMessages = logger.flushAfterDisconnectMessages();
    flushAfterRequestMessages = logger.flushAfterRequestMessages();
    flushAfterFinalResultMessages = logger.flushAfterFinalResultMessages();
    flushAfterNonFinalResultMessages =
         logger.flushAfterNonFinalResultMessages();
    includeAddAttributeNames = logger.includeAddAttributeNames();
    includeAddAttributeValues = logger.includeAddAttributeValues();
    includeModifyAttributeNames = logger.includeModifyAttributeNames();
    includeModifyAttributeValues = logger.includeModifyAttributeValues();
    includeControlOIDs = logger.includeControlOIDs();
    includeSearchEntryAttributeNames =
         logger.includeSearchEntryAttributeNames();
    includeSearchEntryAttributeValues =
         logger.includeSearchEntryAttributeValues();
    logConnects = logger.logConnects();
    logDisconnects = logger.logDisconnects();
    logIntermediateResponses = logger.logIntermediateResponses();
    logRequests = logger.logRequests();
    logFinalResults = logger.logFinalResults();
    logSearchEntries = logger.logSearchEntries();
    logSearchReferences = logger.logSearchReferences();
    schema = logger.getSchema();
    attributesToRedact = new LinkedHashSet<>(logger.getAttributesToRedact());

    operationTypes = EnumSet.noneOf(OperationType.class);
    operationTypes.addAll(logger.getOperationTypes());
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
   * Specifies whether to log successful and failed connection attempts.
   *
   * @param  logConnects  Indicates whether to log successful and failed
   *                      connection attempts.
   */
  public void setLogConnects(final boolean logConnects)
  {
    this.logConnects = logConnects;
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
   * Specifies whether to log disconnects.  Disconnects will be logged by
   * default.
   *
   * @param  logDisconnects  Indicates whether to log disconnects.
   */
  public void setLogDisconnects(final boolean logDisconnects)
  {
    this.logDisconnects = logDisconnects;
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
   * Specifies whether to log messages about requests for operations included
   * in the set of operation types returned by the {@link #getOperationTypes}
   * method.
   *
   * @param  logRequests  Indicates whether to log messages about operation
   *                      requests.
   */
  public void setLogRequests(final boolean logRequests)
  {
    this.logRequests = logRequests;
  }



  /**
   * Indicates whether to log messages about the final results for operations
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
   * Specifies whether to log messages about the final results for operations
   * included in the set of operation types returned by the
   * {@link #getOperationTypes} method.
   *
   * @param  logFinalResults  Indicates whether to log messages about final
   *                          operation results.
   */
  public void setLogFinalResults(final boolean logFinalResults)
  {
    this.logFinalResults = logFinalResults;
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
   * Specifies whether to log messages about each search result entry returned
   * for search operations.  This property will only be used if the set returned
   * by the  {@link #getOperationTypes} method includes
   * {@link OperationType#SEARCH}.
   *
   * @param  logSearchEntries  Indicates whether to log search result entry
   *                           messages.
   */
  public void setLogSearchEntries(final boolean logSearchEntries)
  {
    this.logSearchEntries = logSearchEntries;
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
   * Specifies whether to log messages about each search result reference
   * returned for search operations.  This property will only be used if the set
   * returned by the  {@link #getOperationTypes} method includes
   * {@link OperationType#SEARCH}.
   *
   * @param  logSearchReferences  Indicates whether to log search result
   *                              reference messages.
   */
  public void setLogSearchReferences(final boolean logSearchReferences)
  {
    this.logSearchReferences = logSearchReferences;
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
   * Specifies whether to log messages about each intermediate response returned
   * in the course of processing an operation.
   *
   * @param  logIntermediateResponses  Indicates whether to log intermediate
   *                                   response messages.
   */
  public void setLogIntermediateResponses(
                   final boolean logIntermediateResponses)
  {
    this.logIntermediateResponses = logIntermediateResponses;
  }



  /**
   * Retrieves the set of operation types for which to log requests and results.
   * All operation types will be logged by default.
   *
   * @return  The set of operation types for which to log requests and results.
   */
  @NotNull()
  public Set<OperationType> getOperationTypes()
  {
    return operationTypes;
  }



  /**
   * Specifies the set of operation types for which to log requests and results.
   *
   * @param  operationTypes  The set of operation types for which to log
   *                         requests and results.  It may be {@code null} or
   *                         empty if no operation types should be logged.
   */
  public void setOperationTypes(@Nullable final OperationType... operationTypes)
  {
    this.operationTypes.clear();
    if (operationTypes != null)
    {
      this.operationTypes.addAll(Arrays.asList(operationTypes));
    }
  }



  /**
   * Specifies the set of operation types for which to log requests and results.
   *
   * @param  operationTypes  The set of operation types for which to log
   *                         requests and results.  It may be {@code null} or
   *                         empty if no operation types should be logged.
   */
  public void setOperationTypes(
                   @Nullable final Collection<OperationType> operationTypes)
  {
    this.operationTypes.clear();
    if (operationTypes != null)
    {
      this.operationTypes.addAll(operationTypes);
    }
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
   * Specifies whether log messages about add requests should include the names
   * of the attributes provided in the request.
   *
   * @param  includeAddAttributeNames  Indicates whether to include attribute
   *                                   names in add request log messages.
   */
  public void setIncludeAddAttributeNames(
                   final boolean includeAddAttributeNames)
  {
    this.includeAddAttributeNames = includeAddAttributeNames;
  }



  /**
   * Indicates whether log messages about add requests should include the values
   * of the attributes provided in the request.  This property will only be used
   * if {@link #includeAddAttributeNames} returns {@code true}.  Values for
   * attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".  Add attribute names (but not values) will be logged by
   * default.
   *
   * @return  {@code true} if add attribute values should be logged, or
   *          {@code false} if not.
   */
  public boolean includeAddAttributeValues()
  {
    return includeAddAttributeValues;
  }



  /**
   * Specifies whether log messages about add requests should include the values
   * of the attributes provided in the request.  This property will only be used
   * if {@link #includeAddAttributeNames} returns {@code true}.  Values for
   * attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".
   *
   * @param  includeAddAttributeValues  Indicates whether to include attribute
   *                                    values in add request log messages.
   */
  public void setIncludeAddAttributeValues(
                   final boolean includeAddAttributeValues)
  {
    this.includeAddAttributeValues = includeAddAttributeValues;
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
   * Specifies whether log messages about modify requests should include the
   * names of the attributes modified in the request.
   *
   * @param  includeModifyAttributeNames  Indicates whether to include attribute
   *                                      names in modify request log messages.
   */
  public void setIncludeModifyAttributeNames(
                   final boolean includeModifyAttributeNames)
  {
    this.includeModifyAttributeNames = includeModifyAttributeNames;
  }



  /**
   * Indicates whether log messages about modify requests should include the
   * values of the attributes modified in the request.  This property will only
   * be used if {@link #includeModifyAttributeNames} returns {@code true}.
   * Values for attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".  Modify attribute names (but not values) will be logged by
   * default.
   *
   * @return  {@code true} if modify attribute values should be logged, or
   *          {@code false} if not.
   */
  public boolean includeModifyAttributeValues()
  {
    return includeModifyAttributeValues;
  }



  /**
   * Specifies whether log messages about modify requests should include the
   * values of the attributes modified in the request.  This property will only
   * be used if {@link #includeModifyAttributeNames} returns {@code true}.
   * Values for attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".
   *
   * @param  includeModifyAttributeValues  Indicates whether to include
   *                                       attribute values in modify request
   *                                       log messages.
   */
  public void setIncludeModifyAttributeValues(
                   final boolean includeModifyAttributeValues)
  {
    this.includeModifyAttributeValues = includeModifyAttributeValues;
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
   * Specifies whether log messages about search result entries should include
   * the names of the attributes in the returned entry.
   *
   * @param  includeSearchEntryAttributeNames  Indicates whether to include
   *                                           attribute names in search result
   *                                           entry log messages.
   */
  public void setIncludeSearchEntryAttributeNames(
                   final boolean includeSearchEntryAttributeNames)
  {
    this.includeSearchEntryAttributeNames = includeSearchEntryAttributeNames;
  }



  /**
   * Indicates whether log messages about search result entries should include
   * the values of the attributes in the returned entry.  This property will
   * only be used if {@link #includeSearchEntryAttributeNames} returns
   * {@code true}.  Values for attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".  Entry attribute names (but not values) will be logged by
   * default.
   *
   * @return  {@code true} if search result entry attribute values should be
   *          logged, or {@code false} if not.
   */
  public boolean includeSearchEntryAttributeValues()
  {
    return includeSearchEntryAttributeValues;
  }



  /**
   * Specifies whether log messages about search result entries should include
   * the values of the attributes in the returned entry.  This property will
   * only be used if {@link #includeSearchEntryAttributeNames} returns
   * {@code true}.  Values for attributes named in the set returned by the
   * {@link #getAttributesToRedact} method will be replaced with a value of
   * "[REDACTED]".
   *
   * @param  includeSearchEntryAttributeValues  Indicates whether to include
   *                                            attribute values in search
   *                                            result entry log messages.
   */
  public void setIncludeSearchEntryAttributeValues(
                   final boolean includeSearchEntryAttributeValues)
  {
    this.includeSearchEntryAttributeValues = includeSearchEntryAttributeValues;
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
   * Specifies the names or OIDs of the attributes whose values should be
   * redacted from log messages.
   *
   * @param  attributesToRedact  The names or OIDs of the attributes whose
   *                             values should be redacted.  It may be
   *                             {@code null} or empty if no attribute values
   *                             should be redacted.
   */
  public void setAttributesToRedact(
                   @Nullable final String... attributesToRedact)
  {
    this.attributesToRedact.clear();
    if (attributesToRedact != null)
    {
      this.attributesToRedact.addAll(Arrays.asList(attributesToRedact));
    }
  }



  /**
   * Specifies the names or OIDs of the attributes whose values should be
   * redacted from log messages.
   *
   * @param  attributesToRedact  The names or OIDs of the attributes whose
   *                             values should be redacted.  It may be
   *                             {@code null} or empty if no attribute values
   *                             should be redacted.
   */
  public void setAttributesToRedact(
                   @Nullable final Collection<String> attributesToRedact)
  {
    this.attributesToRedact.clear();
    if (attributesToRedact != null)
    {
      this.attributesToRedact.addAll(attributesToRedact);
    }
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
   * Specifies whether request and result log messages should include the OIDs
   * of any controls included in that request or result.
   *
   * @param  includeControlOIDs  Indicates whether to include control OIDs in
   *                             request and result log messages.
   */
  public void setIncludeControlOIDs(final boolean includeControlOIDs)
  {
    this.includeControlOIDs = includeControlOIDs;
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
   * Specifies whether the log handler should be flushed after logging each
   * successful or failed connection attempt.
   *
   * @param  flushAfterConnectMessages  Indicates whether the log handler should
   *                                    be flushed after logging each connection
   *                                    attempt.
   */
  public void setFlushAfterConnectMessages(
                   final boolean flushAfterConnectMessages)
  {
    this.flushAfterConnectMessages = flushAfterConnectMessages;
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
   * Specifies whether the log handler should be flushed after logging each
   * disconnect.
   *
   * @param  flushAfterDisconnectMessages  Indicates whether the log handler
   *                                       should be flushed after logging each
   *                                       disconnect.
   */
  public void setFlushAfterDisconnectMessages(
                   final boolean flushAfterDisconnectMessages)
  {
    this.flushAfterDisconnectMessages = flushAfterDisconnectMessages;
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
   * Specifies whether the log handler should be flushed after logging each
   * request.
   *
   * @param  flushAfterRequestMessages  Indicates whether the log handler should
   *                                    be flushed after logging each request.
   */
  public void setFlushAfterRequestMessages(
                   final boolean flushAfterRequestMessages)
  {
    this.flushAfterRequestMessages = flushAfterRequestMessages;
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
   * Specifies whether the log handler should be flushed after logging each
   * non-final result (including search result entries, search result
   * references, and intermediate result messages).
   *
   * @param  flushAfterNonFinalResultMessages  Indicates whether the log
   *                                           handler should be flushed after
   *                                           logging each non-final result.
   */
  public void setFlushAfterNonFinalResultMessages(
                   final boolean flushAfterNonFinalResultMessages)
  {
    this.flushAfterNonFinalResultMessages =
         flushAfterNonFinalResultMessages;
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
   * Specifies whether the log handler should be flushed after logging the final
   * result for each operation.
   *
   * @param  flushAfterFinalResultMessages  Indicates whether the log handler
   *                                        should be flushed after logging
   *                                        each final result.
   */
  public void setFlushAfterFinalResultMessages(
                   final boolean flushAfterFinalResultMessages)
  {
    this.flushAfterFinalResultMessages = flushAfterFinalResultMessages;
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
   * Specifies the schema that will be used to identify alternate names and OIDs
   * for attributes whose values should be redacted.
   *
   * @param  schema  The schema that will be used to identify alternate names
   *                 and OIDs for attributes whose values should be redacted.
   *                 It may be {@code null} if no schema should be used.
   */
  public void setSchema(@Nullable final Schema schema)
  {
    this.schema = schema;
  }



  /**
   * Retrieves a string representation of this
   * {@code JSONLDAPConnectionLoggerProperties} object.
   *
   * @return  A string representation of this
   *          {@code JSONLDAPConnectionLoggerProperties} object.
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
   * Appends a string representation of this
   * {@code JSONLDAPConnectionLoggerProperties} object to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("JSONLDAPConnectionLoggerProperties(logConnects=");
    buffer.append(logConnects);
    buffer.append(", logDisconnects=");
    buffer.append(logDisconnects);
    buffer.append(", logRequests=");
    buffer.append(logRequests);
    buffer.append(", logFinalResults=");
    buffer.append(logFinalResults);
    buffer.append(", logSearchEntries=");
    buffer.append(logSearchEntries);
    buffer.append(", logSearchReferences=");
    buffer.append(logSearchReferences);
    buffer.append(", logIntermediateResponses=");
    buffer.append(logIntermediateResponses);
    buffer.append(", operationTypes={");

    final Iterator<OperationType> operationTypeIterator =
         operationTypes.iterator();
    while (operationTypeIterator.hasNext())
    {
      buffer.append(operationTypeIterator.next().toString());

      if (operationTypeIterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append(", includeAddAttributeNames=");
    buffer.append(includeAddAttributeNames);
    buffer.append(", includeAddAttributeValues=");
    buffer.append(includeAddAttributeValues);
    buffer.append(", includeModifyAttributeNames=");
    buffer.append(includeModifyAttributeNames);
    buffer.append(", includeModifyAttributeValues=");
    buffer.append(includeModifyAttributeValues);
    buffer.append(", includeSearchEntryAttributeNames=");
    buffer.append(includeSearchEntryAttributeNames);
    buffer.append(", includeSearchEntryAttributeValues=");
    buffer.append(includeSearchEntryAttributeValues);
    buffer.append(", attributesToRedact={");

    final Iterator<String> redactAttributeIterator =
         attributesToRedact.iterator();
    while (redactAttributeIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(redactAttributeIterator.next());
      buffer.append('\'');

      if (redactAttributeIterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append("}, includeControlOIDs=");
    buffer.append(includeControlOIDs);
    buffer.append(", flushAfterConnectMessages");
    buffer.append(flushAfterConnectMessages);
    buffer.append(", flushAfterDisconnectMessages");
    buffer.append(flushAfterDisconnectMessages);
    buffer.append(", flushAfterRequestMessages");
    buffer.append(flushAfterRequestMessages);
    buffer.append(", flushAfterFinalResultMessages");
    buffer.append(flushAfterFinalResultMessages);
    buffer.append(", flushAfterNonFinalResultMessages");
    buffer.append(flushAfterNonFinalResultMessages);
    buffer.append(')');
  }
}
