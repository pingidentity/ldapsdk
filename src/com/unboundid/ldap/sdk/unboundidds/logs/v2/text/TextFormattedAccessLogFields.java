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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.BooleanLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
            CommaDelimitedStringListLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.DNLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.FilterLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.
            FloatingPointLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.IntegerLogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.LogFieldSyntax;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax.StringLogFieldSyntax;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines a number of constants that represent fields that may
 * appear in text-formatted access log messages.
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
 *
 * @see  LogField
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TextFormattedAccessLogFields
{
  /**
   * The default value to use for the maximum number of characters per string.
   */
  private static final int DEFAULT_MAX_CHARACTERS_PER_STRING = 2_000;



  /**
   * A map containing all of the defined fields in this class.
   */
  @NotNull() private static final Map<String,LogField> DEFINED_FIELDS =
       new ConcurrentHashMap<>();



  /**
   * A map containing all of the defined fields in this class.
   */
  @NotNull() private static final AtomicReference<Map<String,LogField>>
       READ_ONLY_DEFINED_FIELDS_REF = new AtomicReference<>();



  /**
   * The default syntax instance that will be used for fields with Boolean
   * values.
   */
  @NotNull private static final BooleanLogFieldSyntax BOOLEAN_SYNTAX =
       BooleanLogFieldSyntax.getInstance();



  /**
   * The default syntax instance that will be used for fields whose values are
   * a comma-delimited list of strings.
   */
  @NotNull private static final CommaDelimitedStringListLogFieldSyntax
       COMMA_DELIMITED_STRING_LIST_SYNTAX =
            new CommaDelimitedStringListLogFieldSyntax(
                 DEFAULT_MAX_CHARACTERS_PER_STRING);



  /**
   * The default syntax instance that will be used for fields whose values are
   * expected to be DNs.  This instance does not specify any included or
   * excluded sensitive attributes, so all attribute values will be redacted
   * or tokenized when calling methods that redact or tokenize components.  It
   * will also use a default escaping strategy for determining which special
   * characters should be escaped.
   */
  @NotNull private static final DNLogFieldSyntax DN_SYNTAX =
       new DNLogFieldSyntax(DEFAULT_MAX_CHARACTERS_PER_STRING, null, null,
            null);



  /**
   * The default syntax instance that will be used for fields whose values are
   * expected to be search filters.  This instance does not specify any included
   * or excluded sensitive attributes, so all attribute values will be redacted
   * or tokenized when calling methods that redact or tokenize components.
   */
  @NotNull private static final FilterLogFieldSyntax FILTER_SYNTAX =
       new FilterLogFieldSyntax(DEFAULT_MAX_CHARACTERS_PER_STRING, null,
            null, null);



  /**
   * The default syntax instance that will be used for fields whose values are
   * floating-point numbers.
   */
  @NotNull private static final FloatingPointLogFieldSyntax
       FLOATING_POINT_SYNTAX = FloatingPointLogFieldSyntax.getInstance();



  /**
   * The default syntax instance that will be used for fields whose values are
   * integers.
   */
  @NotNull private static final IntegerLogFieldSyntax INTEGER_SYNTAX =
       IntegerLogFieldSyntax.getInstance();



  /**
   * The default syntax instance that will be used for fields whose values are
   * strings.
   */
  @NotNull private static final StringLogFieldSyntax STRING_SYNTAX =
       new StringLogFieldSyntax(DEFAULT_MAX_CHARACTERS_PER_STRING);



  /**
   * A field that holds the message ID for an operation to be abandoned.  This
   * field may appear in access log messages for abandon operations.
   */
  @NotNull public static final LogField ABANDON_MESSAGE_ID =
       createField("ABANDON_MESSAGE_ID", "idToAbandon", INTEGER_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of the attributes to
   * be added.  This field may appear in access log messages for add operations.
   */
  @NotNull public static final LogField ADD_ATTRIBUTES = createField(
       "ADD_ATTRIBUTES", "attrs", COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the DN of the entry to be added.  This field may appear
   * in access log messages for add operations.
   */
  @NotNull public static final LogField ADD_ENTRY_DN =
       createField("ADD_ENTRY_DN", "dn", DN_SYNTAX);



  /**
   * A field that holds the DN of the soft-deleted entry being undeleted.  This
   * field may appear in access log messages for add operations.
   */
  @NotNull public static final LogField ADD_UNDELETE_FROM_DN =
       createField("ADD_UNDELETE_FROM_DN", "undeleteFromDN", DN_SYNTAX);



  /**
   * A field that holds a message with additional information about the server's
   * processing for an operation.  This message will not be returned to the
   * client.  This field may appear in all types of operation result access log
   * messages.
   */
  @NotNull public static final LogField ADDITIONAL_INFO =
       createField("ADDITIONAL_INFO", "additionalInfo", STRING_SYNTAX);



  /**
   * A field that indicates that the associated operation includes an
   * administrative operation request control.  The value of the field is the
   * message (if any) contained in that control.  This field may appear in all
   * types of access log messages that are associated with an operation.
   */
  @NotNull public static final LogField ADMINISTRATIVE_OPERATION =
       createField("ADMINISTRATIVE_OPERATION", "administrativeOperation",
            STRING_SYNTAX);



  /**
   * A field that holds the requested replication assurance timeout, in
   * milliseconds.  This field may appear in all types of operation result
   * access log messages.
   */
  @NotNull public static final LogField ASSURANCE_TIMEOUT_MILLIS =
       createField("ASSURANCE_TIMEOUT_MILLIS", "assuranceTimeoutMillis",
            INTEGER_SYNTAX);



  /**
   * A field that holds the DN that was used as the alternative authorization
   * identity for the operation.  This field may appear in all types of
   * operation result access log messages.
   */
  @NotNull public static final LogField AUTHORIZATION_DN =
       createField("AUTHORIZATION_DN", "authzDN", DN_SYNTAX);



  /**
   * A field that holds the DN of the user that was automatically authenticated
   * to the server based on the certificate chain the client presented during
   * security negotiation.  This field may appear in SECURITY-NEGOTIATION
   * access log messages.
   */
  @NotNull public static final LogField AUTO_AUTHENTICATED_AS =
       createField("AUTO_AUTHENTICATED_AS", "autoAuthenticatedAs", DN_SYNTAX);



  /**
   * A field that holds the DN of the user that was authenticated in a bind
   * operation.  This field may appear in bind result access log messages.
   */
  @NotNull public static final LogField BIND_AUTHENTICATION_DN =
       createField("BIND_AUTHENTICATION_DN", "authDN", DN_SYNTAX);



  /**
   * A field that holds a numeric identifier that is associated with the
   * general reason for the authentication failure.  This field may appear in
   * bind result access log messages.
   */
  @NotNull public static final LogField BIND_AUTHENTICATION_FAILURE_ID =
       createField("BIND_AUTHENTICATION_FAILURE_ID", "authFailureID",
            INTEGER_SYNTAX);



  /**
   * A field that holds a numeric identifier that is associated with the
   * general reason for the authentication failure.  This field may appear in
   * bind result access log messages.
   */
  @NotNull public static final LogField BIND_AUTHENTICATION_FAILURE_NAME =
       createField("BIND_AUTHENTICATION_FAILURE_NAME", "authFailureName",
            STRING_SYNTAX);



  /**
   * A field that holds a message providing a reason for a failed authentication
   * attempt.  This field may appear in bind result access log messages.
   */
  @NotNull public static final LogField BIND_AUTHENTICATION_FAILURE_REASON =
       createField("BIND_AUTHENTICATION_FAILURE_REASON", "authFailureReason",
            STRING_SYNTAX);



  /**
   * A field that holds the authentication type for a bind request.  This field
   * may appear in access log messages for bind operations.
   */
  @NotNull public static final LogField BIND_AUTHENTICATION_TYPE =
       createField("BIND_AUTHENTICATION_TYPE", "authType", STRING_SYNTAX);



  /**
   * A field that holds the DN of the authorization identity resulting from a
   * bind operation.  This field may appear in bind result access log messages.
   */
  @NotNull public static final LogField BIND_AUTHORIZATION_DN =
       createField("BIND_AUTHORIZATION_DN", "authzDN", DN_SYNTAX);



  /**
   * A field that holds the bind DN for a bind request.  This field may appear
   * in access log messages for bind operations.
   */
  @NotNull public static final LogField BIND_DN =
       createField("BIND_DN", "dn", DN_SYNTAX);



  /**
   * A field that holds the protocol version for a bind request.  This field may
   * appear in access log messages for bind operations.
   */
  @NotNull public static final LogField BIND_PROTOCOL_VERSION =
       createField("BIND_PROTOCOL_VERSION", "version", STRING_SYNTAX);



  /**
   * A field that indicates whether a retired password was used in the course of
   * processing a bind operation.  This field may appear in bind result access
   * log messages.
   */
  @NotNull public static final LogField BIND_RETIRED_PASSWORD_USED =
       createField("BIND_RETIRED_PASSWORD_USED", "retiredPasswordUsed",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds the name of the SASL mechanism used for a bind request.
   * This field may appear in access log messages for bind operations.
   */
  @NotNull public static final LogField BIND_SASL_MECHANISM =
       createField("BIND_SASL_MECHANISM", "saslMechanism", STRING_SYNTAX);



  /**
   * A field that indicates whether the associated operation updated or removed
   * a soft-deleted entry.  This field may appear in access log messages for
   * modify and delete operations.
   */
  @NotNull public static final LogField CHANGE_TO_SOFT_DELETED_ENTRY =
       createField("CHANGE_TO_SOFT_DELETED_ENTRY", "changeToSoftDeletedEntry",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds the name of the cipher algorithm that was negotiated for
   * the client connection.  This field may appear in SECURITY-NEGOTIATION
   * access log messages.
   */
  @NotNull public static final LogField CIPHER =
       createField("CIPHER", "cipher", STRING_SYNTAX);



  /**
   * A field that holds the name of the client connection policy that has been
   * assigned to the associated connection.  This field may appear in CONNECT
   * access log messages, as well as in result access log messages for
   * operations that may cause a new client connection policy to be assigned
   * to the connection (including bind and StartTLS).
   */
  @NotNull public static final LogField CLIENT_CONNECTION_POLICY =
       createField("CLIENT_CONNECTION_POLICY", "clientConnectionPolicy",
            STRING_SYNTAX);



  /**
   * A field that holds the assertion value included in a compare operation.
   * This field may appear in access log messages for compare operations.
   */
  @NotNull public static final LogField COMPARE_ASSERTION_VALUE =
       createField("COMPARE_ASSERTION_VALUE", "assertionValue", STRING_SYNTAX);



  /**
   * A field that holds the name of the attribute targeted by a compare
   * operation.  This field may appear in access log messages for compare
   * operations.
   */
  @NotNull public static final LogField COMPARE_ATTRIBUTE_NAME =
       createField("COMPARE_ATTRIBUTE_NAME", "attr", STRING_SYNTAX);



  /**
   * A field that holds the DN of the entry targeted by a compare operation.
   * This field may appear in access log messages for compare operations.
   */
  @NotNull public static final LogField COMPARE_ENTRY_DN =
       createField("COMPARE_ENTRY_DN", "dn", DN_SYNTAX);



  /**
   * A field that holds the address of the client from which a connection has
   * been established.  This field may appear in CONNECT access log messages.
   */
  @NotNull public static final LogField CONNECT_FROM_ADDRESS =
       createField("CONNECT_FROM_ADDRESS", "from", STRING_SYNTAX);



  /**
   * A field that holds the remote port for a client connection that has been
   * established.  This field may appear in CONNECT access log messages.
   */
  @NotNull public static final LogField CONNECT_FROM_PORT =
       createField("CONNECT_FROM_PORT", "fromPort", INTEGER_SYNTAX);



  /**
   * A field that holds the server address to which a connection has been
   * established.  This field may appear in CONNECT access log messages.
   */
  @NotNull public static final LogField CONNECT_TO_ADDRESS =
       createField("CONNECT_TO_ADDRESS", "to", STRING_SYNTAX);



  /**
   * A field that holds the server port to which a connection has been
   * established.  This field may appear in CONNECT access log messages.
   */
  @NotNull public static final LogField CONNECT_TO_PORT =
       createField("CONNECT_TO_PORT", "toPort", INTEGER_SYNTAX);



  /**
   * A field that holds a numeric identifier for the associated client
   * connection.  All access log messages associated with a given connection
   * will share the same connection ID, so this field may be used to identify
   * messages associated with that connection.  Note, however, that the
   * connection ID counter is reset when the server is restarted, so the
   * {@link #STARTUP_ID} field may also be necessary to further distinguish
   * between connections across restarts.  Further, connection ID values may be
   * reused across instances, so the {@link #INSTANCE_NAME} field may also be
   * needed to distinguish between connections to different instances.  This
   * field may appear in all types of access log messages.
   */
  @NotNull public static final LogField CONNECTION_ID =
       createField("CONNECTION_ID", "conn", INTEGER_SYNTAX);



  /**
   * A field that holds the DN of the entry targeted by a delete operation.
   * This field may appear in access log messages for delete operations.
   */
  @NotNull public static final LogField DELETE_ENTRY_DN =
       createField("DELETE_ENTRY_DN", "dn", DN_SYNTAX);



  /**
   * A field that holds the DN of a soft-deleted entry resulting from a delete
   * operation.  This field may appear in access log messages for delete
   * operations.
   */
  @NotNull public static final LogField DELETE_SOFT_DELETED_ENTRY_DN =
       createField("DELETE_SOFT_DELETED_ENTRY_DN", "softDeleteEntryDN",
            DN_SYNTAX);



 /**
  * A field that holds the diagnostic message for an operation, which is a
  * message that is returned to the client.  This field may appear in all types
  * of operation result access log messages.
   */
  @NotNull public static final LogField DIAGNOSTIC_MESSAGE =
      createField("DIAGNOSTIC_MESSAGE", "message", STRING_SYNTAX);



 /**
  * A field that holds an additional message for a connection closure, which may
  * provide additional details about the disconnect.  This field may appear in
  * DISCONNECT access log messages.
   */
  @NotNull public static final LogField DISCONNECT_MESSAGE =
       createField("DISCONNECT_MESSAGE", "msg", STRING_SYNTAX);



  /**
   * A field that holds a reason for a connection closure.  This field may
   * appear in DISCONNECT access log messages.
   */
  @NotNull public static final LogField DISCONNECT_REASON =
       createField("DISCONNECT_REASON", "reason", STRING_SYNTAX);



  /**
   * A field that holds a message about any administrative action that may be
   * required after an entry rebalancing operation.  This field may appear in
   * entry rebalancing access log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_ADMIN_ACTION_MESSAGE =
       createField("ENTRY_REBALANCING_ADMIN_ACTION_MESSAGE",
            "adminActionRequired", STRING_SYNTAX);



  /**
   * A field that holds the base DN for an entry rebalancing operation.  This
   * field may appear in entry rebalancing access log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_BASE_DN =
       createField("ENTRY_REBALANCING_BASE_DN", "baseDN", DN_SYNTAX);



  /**
   * A field that holds the number of entries added to the target server in the
   * course of processing an entry rebalancing operation.  This field may appear
   * in entry rebalancing access log messages.
   */
  @NotNull public static final LogField
       ENTRY_REBALANCING_ENTRIES_ADDED_TO_TARGET = createField(
            "ENTRY_REBALANCING_ENTRIES_ADDED_TO_TARGET", "entriesAddedToTarget",
            INTEGER_SYNTAX);



  /**
   * A field that holds the number of entries deleted from the source server in
   * the course of processing an entry rebalancing operation.  This field may
   * appear in entry rebalancing access log messages.
   */
  @NotNull public static final LogField
       ENTRY_REBALANCING_ENTRIES_DELETED_FROM_SOURCE = createField(
            "ENTRY_REBALANCING_ENTRIES_DELETED_FROM_SOURCE",
            "entriesDeletedFromSource", INTEGER_SYNTAX);



  /**
   * A field that holds the number of entries read from the source server in the
   * course of processing an entry rebalancing operation.  This field may appear
   * in entry rebalancing access log messages.
   */
  @NotNull public static final LogField
       ENTRY_REBALANCING_ENTRIES_READ_FROM_SOURCE = createField(
            "ENTRY_REBALANCING_ENTRIES_READ_FROM_SOURCE",
            "entriesReadFromSource", INTEGER_SYNTAX);



  /**
   * A field that holds an error message for an entry rebalancing operation.
   * This field may appear in entry rebalancing access log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_ERROR_MESSAGE =
       createField("ENTRY_REBALANCING_ERROR_MESSAGE", "errorMessage",
            STRING_SYNTAX);



  /**
   * A field that holds the operation ID for an entry rebalancing operation.
   * This field may appear in entry rebalancing access log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_OPERATION_ID =
       createField("ENTRY_REBALANCING_OPERATION_ID", "rebalancingOp",
            INTEGER_SYNTAX);



  /**
   * A field that holds the size limit for an entry rebalancing operation.
   * This field may appear in entry rebalancing access log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_SIZE_LIMIT =
       createField("ENTRY_REBALANCING_SIZE_LIMIT", "sizeLimit", INTEGER_SYNTAX);



  /**
   * A field that holds the name of the source backend set for an entry
   * rebalancing operation.  This field may appear in entry rebalancing access
   * log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_SOURCE_BACKEND_SET =
       createField("ENTRY_REBALANCING_SOURCE_BACKEND_SET", "sourceBackendSet",
            STRING_SYNTAX);



  /**
   * A field that holds the address and port of the source server for an entry
   * rebalancing operation.  This field may appear in entry rebalancing access
   * log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_SOURCE_SERVER =
       createField("ENTRY_REBALANCING_SOURCE_SERVER", "sourceServer",
            STRING_SYNTAX);



  /**
   * A field that indicates whether the source server was altered in the course
   * of processing an entry rebalancing operation.  This field may appear in
   * entry rebalancing access log messages.
   */
  @NotNull public static final LogField
       ENTRY_REBALANCING_SOURCE_SERVER_ALTERED = createField(
            "ENTRY_REBALANCING_SOURCE_SERVER_ALTERED", "sourceAltered",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds the name of the target backend set for an entry
   * rebalancing operation.  This field may appear in entry rebalancing access
   * log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_TARGET_BACKEND_SET =
       createField("ENTRY_REBALANCING_TARGET_BACKEND_SET", "targetBackendSet",
            STRING_SYNTAX);



  /**
   * A field that holds the address and port of the target server for an entry
   * rebalancing operation.  This field may appear in entry rebalancing access
   * log messages.
   */
  @NotNull public static final LogField ENTRY_REBALANCING_TARGET_SERVER =
       createField("ENTRY_REBALANCING_TARGET_SERVER", "targetServer",
            STRING_SYNTAX);



  /**
   * A field that indicates whether the target server was altered in the course
   * of processing an entry rebalancing operation.  This field may appear in
   * entry rebalancing access log messages.
   */
  @NotNull public static final LogField
       ENTRY_REBALANCING_TARGET_SERVER_ALTERED = createField(
            "ENTRY_REBALANCING_TARGET_SERVER_ALTERED", "targetAltered",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds the request OID for an extended operation.  This field
   * may appear in access log messages for extended operations.
   */
  @NotNull public static final LogField EXTENDED_REQUEST_OID =
       createField("EXTENDED_REQUEST_OID", "requestOID", STRING_SYNTAX);



  /**
   * A field that holds the name for an extended request.  This field may
   * appear in access log messages for extended operations.
   */
  @NotNull public static final LogField EXTENDED_REQUEST_TYPE =
       createField("EXTENDED_REQUEST_TYPE", "requestType", STRING_SYNTAX);



  /**
   * A field that holds the response OID for an extended operation.  This field
   * may appear in access log messages for extended operations.
   */
  @NotNull public static final LogField EXTENDED_RESPONSE_OID =
       createField("EXTENDED_RESPONSE_OID", "responseOID", STRING_SYNTAX);



  /**
   * A field that holds the name for an extended response.  This field may
   * appear in access log messages for extended operations.
   */
  @NotNull public static final LogField EXTENDED_RESPONSE_TYPE =
       createField("EXTENDED_RESPONSE_TYPE", "responseType", STRING_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of any indexes
   * accessed in the course of processing operation that had exceeded the index
   * entry limit.  This field may appear operation result access log messages.
   */
  @NotNull public static final LogField
       INDEXES_WITH_KEYS_ACCESSED_EXCEEDING_ENTRY_LIMIT = createField(
            "INDEXES_WITH_KEYS_ACCESSED_EXCEEDING_ENTRY_LIMIT",
            "indexesWithKeysAccessedExceedingEntryLimit",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of any indexes
   * accessed in the course of processing operation that were near the index
   * entry limit.  This field may appear operation result access log messages.
   */
  @NotNull public static final LogField
       INDEXES_WITH_KEYS_ACCESSED_NEAR_ENTRY_LIMIT = createField(
            "INDEXES_WITH_KEYS_ACCESSED_NEAR_ENTRY_LIMIT",
            "indexesWithKeysAccessedNearEntryLimit",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the name of the server instance that logged the message.
   * This field may appear in all types of access log messages.
   */
  @NotNull public static final LogField INSTANCE_NAME =
       createField("INSTANCE_NAME", "instanceName", STRING_SYNTAX);



  /**
   * A field that holds the name of the name of the component that generated an
   * inter-server request control.  This field amy appear in all types of
   * access log messages that are associated with operations.
   */
  @NotNull public static final LogField INTER_SERVER_COMPONENT =
       createField("INTER_SERVER_COMPONENT", "interServerComponent",
            STRING_SYNTAX);



  /**
   * A field that holds a string representation of the properties included in an
   * inter-server request control.  This field amy appear in all types of
   * access log messages that are associated with operations.
   */
  @NotNull public static final LogField INTER_SERVER_PROPERTIES =
       createField("INTER_SERVER_PROPERTIES", "interServerProperties",
            STRING_SYNTAX);



  /**
   * A field that holds the operation purpose string included in an
   * inter-server request control.  This field amy appear in all types of
   * access log messages that are associated with operations.
   */
  @NotNull public static final LogField INTER_SERVER_OPERATION_PURPOSE =
       createField("INTER_SERVER_OPERATION_PURPOSE",
            "interServerOperationPurpose", STRING_SYNTAX);



  /**
   * A field that holds a string representation of any intermediate client
   * request control included in the operation.  This field may appear in all
   * types of access log messages that are associated with operations.
   */
  @NotNull public static final LogField INTERMEDIATE_CLIENT_REQUEST =
       createField("INTERMEDIATE_CLIENT_REQUEST", "via", STRING_SYNTAX);



  /**
   * A field that holds a string representation of any intermediate client
   * response control returned to the client.  This field may appear in all
   * types of operation result access log messages.
   */
  @NotNull public static final LogField INTERMEDIATE_CLIENT_RESULT =
       createField("INTERMEDIATE_CLIENT_RESULT", "from", STRING_SYNTAX);



  /**
   * A field that holds the name for an intermediate response returned to the
   * client.  This field may appear in intermediate response access log
   * messages.
   */
  @NotNull public static final LogField INTERMEDIATE_RESPONSE_NAME =
       createField("INTERMEDIATE_RESPONSE_NAME", "name", STRING_SYNTAX);



  /**
   * A field that holds the OID for an intermediate response returned to the
   * client.  This field may appear in intermediate response access log
   * messages.
   */
  @NotNull public static final LogField INTERMEDIATE_RESPONSE_OID =
       createField("INTERMEDIATE_RESPONSE_OID", "oid", STRING_SYNTAX);



  /**
   * A field that holds a string representation of the value for an intermediate
   * response returned to the client.  This field may appear in intermediate
   * response access log messages.
   */
  @NotNull public static final LogField INTERMEDIATE_RESPONSE_VALUE =
       createField("INTERMEDIATE_RESPONSE_VALUE", "value", STRING_SYNTAX);



  /**
   * A field that holds the number of intermediate response messages returned to
   * the client in the course of processing the operation.  This field may
   * appear in all types of operation result access log messages.
   */
  @NotNull public static final LogField INTERMEDIATE_RESPONSES_RETURNED =
       createField("INTERMEDIATE_RESPONSES_RETURNED",
            "intermediateResponsesReturned", INTEGER_SYNTAX);



  /**
   * A field that holds the subject DN for an issuer certificate presented in
   * the client certificate chain during security negotiation.  This field may
   * appear in CLIENT-CERTIFICATE access log messages, and it may appear
   * multiple times if the presented certificate chain included three or more
   * certificates.
   */
  @NotNull public static final LogField ISSUER_CERTIFICATE_SUBJECT_DN =
       createField("ISSUER_CERTIFICATE_SUBJECT_DN", "issuerSubject", DN_SYNTAX);



  /**
   * A field that holds the name of the requested local replication assurance
   * level for the operation.  This field may appear in all types of operation
   * result access log messages.
   */
  @NotNull public static final LogField LOCAL_ASSURANCE_LEVEL =
       createField("LOCAL_ASSURANCE_LEVEL", "localAssuranceLevel",
            STRING_SYNTAX);



  /**
   * A field that indicates whether the requested local assurance level was
   * satisfied in the course of processing the operation.  This field may appear
   * in assurance completed access log messages.
   */
  @NotNull public static final LogField LOCAL_ASSURANCE_SATISFIED =
       createField("LOCAL_ASSURANCE_SATISFIED", "localAssuranceSatisfied",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds the matched DN for the operation, which is the DN for
   * the closest ancestor of an entry that does not exist.  This field may
   * appear in all types of operation result access log messages.
   */
  @NotNull public static final LogField MATCHED_DN =
       createField("MATCHED_DN", "matchedDN", DN_SYNTAX);



  /**
   * A field that holds the numeric message ID for the associated operation on
   * the client connection.  For LDAP operations, this is the message ID
   * included in the LDAP request and response messages for that operation.
   * This field may appear in all types of access log messages that are
   * associated with operations.
   */
  @NotNull public static final LogField MESSAGE_ID =
       createField("MESSAGE_ID", "msgID", INTEGER_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of any privileges
   * that were required for the processing the operation that the requester did
   * not have.  This field may appear in all types of operation result access
   * log messages.
   */
  @NotNull public static final LogField MISSING_PRIVILEGES =
       createField("MISSING_PRIVILEGES", "missingPrivileges",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that indicates whether old RDN attribute values should be removed
   * from the entry.  This field may appear in access log messages for modify DN
   * operations.
   */
  @NotNull public static final LogField MODDN_DELETE_OLD_RDN =
       createField("MODDN_DELETE_OLD_RDN", "deleteOldRDN", BOOLEAN_SYNTAX);



  /**
   * A field that holds the DN of the entry to be renamed.  This field may
   * appear in access log messages for modify DN operations.
   */
  @NotNull public static final LogField MODDN_ENTRY_DN =
       createField("MODDN_ENTRY_DN", "dn", DN_SYNTAX);



  /**
   * A field that holds the new RDN to use for the entry to be renamed.  This
   * field may appear in access log messages for modify DN operations.
   */
  @NotNull public static final LogField MODDN_NEW_RDN =
       createField("MODDN_NEW_RDN", "newRDN", DN_SYNTAX);



  /**
   * A field that holds the new superior entry DN to use for the entry to be
   * renamed.  This field may appear in access log messages for modify DN
   * operations.
   */
  @NotNull public static final LogField MODDN_NEW_SUPERIOR_DN =
       createField("MODDN_NEW_SUPERIOR_DN", "newSuperior", DN_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of the attributes to
   * be modified.  This field may appear in access log messages for modify
   * operations.
   */
  @NotNull public static final LogField MODIFY_ATTRIBUTES = createField(
       "MODIFY_ATTRIBUTES", "attrs", COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the DN of the entry to be modified.  This field may
   * appear in access log messages for modify operations.
   */
  @NotNull public static final LogField MODIFY_ENTRY_DN =
       createField("MODIFY_ENTRY_DN", "dn", DN_SYNTAX);



  /**
   * A field that holds a numeric identifier for the associated operation on the
   * client connection.  If there are multiple access log messages for a given
   * operation (for example, if both request and response messages should be
   * logged), then each of those log messages will have the same connection ID
   * and operation ID values, so those fields may be used to identify messages
   * for that operation.  Note, however, that the connection ID counter is reset
   * when the server is restarted, so the {@link #STARTUP_ID} field may also be
   * necessary to further distinguish between connections across restarts.
   * Further, connection ID values may be reused across instances, so the
   * {@link #INSTANCE_NAME} field may also be needed to distinguish between
   * connections to different instances.  This field may appear in all types of
   * access log messages that are associated with operations.
   */
  @NotNull public static final LogField OPERATION_ID =
       createField("OPERATION_ID", "op", INTEGER_SYNTAX);



  /**
   * A field that holds a string representation of an operation purpose request
   * control included in the operation.  This field may appear in all types of
   * access log messages that are associated with operations.
   */
  @NotNull public static final LogField OPERATION_PURPOSE =
       createField("OPERATION_PURPOSE", "opPurpose", STRING_SYNTAX);



  /**
   * A field that holds information about the origin of the associated
   * operation.  This is especially common for things like internal operations
   * or operations processed by the replication subsystem.  This field may
   * appear in all types of access log messages that are associated with
   * operations.
   */
  @NotNull public static final LogField ORIGIN =
       createField("ORIGIN", "origin", STRING_SYNTAX);



  /**
   * A field that holds the subject DN for the peer certificate presented in the
   * client certificate chain during security negotiation.  This field may
   * appear in CLIENT-CERTIFICATE access log messages.
   */
  @NotNull public static final LogField PEER_CERTIFICATE_SUBJECT_DN =
       createField("PEER_CERTIFICATE_SUBJECT_DN", "peerSubject", DN_SYNTAX);



  /**
   * A field whose value is a comma-delimited list of the names of any
   * privileges used prior to processing a control that applies an alternative
   * authorization identity to the operation.  This field may appear in all
   * types of operation result access log messages.
   */
  @NotNull public static final LogField PRE_AUTHORIZATION_USED_PRIVILEGES =
       createField("PRE_AUTHORIZATION_USED_PRIVILEGES",
            "preAuthZUsedPrivileges", COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the length of time (in milliseconds) that a worker
   * thread spent processing the operation.  This field may appear in all types
   * of operation result access log messages.
   */
  @NotNull public static final LogField PROCESSING_TIME_MILLIS =
       createField("PROCESSING_TIME_MILLIS", "etime", FLOATING_POINT_SYNTAX);



  /**
   * A field that holds the name of the product that logged the message.  This
   * field may appear in all types of access log messages.
   */
  @NotNull public static final LogField PRODUCT_NAME =
       createField("PRODUCT_NAME", "product", STRING_SYNTAX);



  /**
   * A field that holds the name of the protocol a client is using to
   * communicate with the server.  This field may appear in CONNECT and
   * SECURITY-NEGOTIATION access log messages.
   */
  @NotNull public static final LogField PROTOCOL =
       createField("PROTOCOL", "protocol", STRING_SYNTAX);



  /**
   * A field that holds a comma-delimited list of referral URLs for an
   * operation, which indicate that the requested operation should be attempted
   * elsewhere.  This field may appear in all types of operation result access
   * log messages.
   */
  @NotNull public static final LogField REFERRAL_URLS = createField(
       "REFERRAL_URLS", "referralURLs", COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the name of the requested remote replication assurance
   * level for the operation.  This field may appear in all types of operation
   * result access log messages.
   */
  @NotNull public static final LogField REMOTE_ASSURANCE_LEVEL =
       createField("REMOTE_ASSURANCE_LEVEL", "remoteAssuranceLevel",
            STRING_SYNTAX);



  /**
   * A field that indicates whether the requested remote assurance level was
   * satisfied in the course of processing the operation.  This field may appear
   * in assurance completed access log messages.
   */
  @NotNull public static final LogField REMOTE_ASSURANCE_SATISFIED =
       createField("REMOTE_ASSURANCE_SATISFIED", "remoteAssuranceSatisfied",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds the replication change ID for a replicated operation.
   * This field may appear in all types of operation result access log messages.
   */
  @NotNull public static final LogField REPLICATION_CHANGE_ID =
       createField("REPLICATION_CHANGE_ID", "replicationChangeID",
            STRING_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the OIDs of any controls
   * included in the request.  This field may appear in all types of access log
   * messages that are associated with operations.
   */
  @NotNull public static final LogField REQUEST_CONTROL_OIDS =
       createField("REQUEST_CONTROL_OIDS", "requestControls",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the DN of the user that requested the associated
   * operation.  This field may appear in all types of access log messages that
   * are associated with operations.
   */
  @NotNull public static final LogField REQUESTER_DN =
       createField("REQUESTER_DN", "requesterDN", DN_SYNTAX);



  /**
   * A field that holds the IP address of the client that requested the
   * associated operation.  This field may appear in all types of access log
   * messages that are associated with operations.
   */
  @NotNull public static final LogField REQUESTER_IP_ADDRESS =
       createField("REQUESTER_IP_ADDRESS", "requesterIP", STRING_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the OIDs of any controls
   * included in the response.  This field may appear in all types of operation
   * result access log messages.
   */
  @NotNull public static final LogField RESPONSE_CONTROL_OIDS =
       createField("RESPONSE_CONTROL_OIDS", "responseControls",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that indicates whether the response to the operation was delayed
   * by replication assurance processing.  This field may appear in all types
   * of operation result access log messages.
   */
  @NotNull public static final LogField RESPONSE_DELAYED_BY_ASSURANCE =
       createField("RESPONSE_DELAYED_BY_ASSURANCE",
            "responseDelayedByAssurance", BOOLEAN_SYNTAX);



  /**
   * A field that holds the name of the result code for the associated
   * operation.  This field may appear in all types of operation result access
   * log messages.
   */
  @NotNull public static final LogField RESULT_CODE_NAME =
       createField("RESULT_CODE_NAME", "resultCodeName", STRING_SYNTAX);



  /**
   * A field that holds the numeric value of the result code for the associated
   * operation.  This field may appear in all types of operation result access
   * log messages.
   */
  @NotNull public static final LogField RESULT_CODE_VALUE =
       createField("RESULT_CODE_VALUE", "resultCode", INTEGER_SYNTAX);



  /**
   * A field that holds the base DN for a search operation.  This field may
   * appear in access log messages for search operations.
   */
  @NotNull public static final LogField SEARCH_BASE_DN =
       createField("SEARCH_BASE_DN", "base", DN_SYNTAX);



  /**
   * A field that holds the name of the policy to use for dereferencing aliases
   * for a search operation.  This field may appear in access log messages for
   * search operations.
   */
  @NotNull public static final LogField SEARCH_DEREF_POLICY =
       createField("SEARCH_DEREF_POLICY", "deref", STRING_SYNTAX);



  /**
   * A field that holds the number of search result entries that were returned
   * to the client.  This field may appear in search result access log messages.
   */
  @NotNull public static final LogField SEARCH_ENTRIES_RETURNED =
       createField("SEARCH_ENTRIES_RETURNED", "entriesReturned",
            INTEGER_SYNTAX);



  /**
   * A field that holds a string representation of the filter for a search
   * operation.  This field may appear in access log messages for search
   * operations.
   */
  @NotNull public static final LogField SEARCH_FILTER =
       createField("SEARCH_FILTER", "filter", FILTER_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of the attributes
   * requested to be included in search result entries.  This field may appear
   * in access log messages for search operations.
   */
  @NotNull public static final LogField SEARCH_REQUESTED_ATTRIBUTES =
       createField("SEARCH_REQUESTED_ATTRIBUTES", "attrs",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the DN for a search result entry.  This field may appear
   * in access log messages for search result entries.
   */
  @NotNull public static final LogField SEARCH_RESULT_ENTRY_DN =
       createField("SEARCH_RESULT_ENTRY_DN", "dn", DN_SYNTAX);



  /**
   * A field whose value is a comma-delimited list of the names of the
   * attributes returned to the client in a search result entry.  This field may
   * appear in access log messages for search operations.
   */
  @NotNull public static final LogField SEARCH_RESULT_ENTRY_ATTRIBUTES =
       createField("SEARCH_RESULT_ENTRY_ATTRIBUTES", "attrsReturned",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds the numeric value of the scope for a search operation.
   * This field may appear in access log messages for search operations.
   */
  @NotNull public static final LogField SEARCH_SCOPE_VALUE =
       createField("SEARCH_SCOPE_VALUE", "scope", INTEGER_SYNTAX);



  /**
   * A field that holds the requested size limit for a search operation.  This
   * field may appear in access log messages for search operations.
   */
  @NotNull public static final LogField SEARCH_SIZE_LIMIT =
       createField("SEARCH_SIZE_LIMIT", "sizeLimit", INTEGER_SYNTAX);



  /**
   * A field that holds the requested time limit (in seconds) for a search
   * operation.  This field may appear in access log messages for search
   * operations.
   */
  @NotNull public static final LogField SEARCH_TIME_LIMIT_SECONDS =
       createField("SEARCH_TIME_LIMIT_SECONDS", "timeLimit", INTEGER_SYNTAX);



  /**
   * A field that indicates whether search result entries should only include
   * attribute types or both types and values.  This field may appear in access
   * log messages for search operations.
   */
  @NotNull public static final LogField SEARCH_TYPES_ONLY =
       createField("SEARCH_TYPES_ONLY", "typesOnly", BOOLEAN_SYNTAX);



  /**
   * A field that indicates whether the search operation was considered
   * unindexed.  This field may appear in search result access log messages.
   */
  @NotNull public static final LogField SEARCH_UNINDEXED =
       createField("SEARCH_UNINDEXED", "unindexed", BOOLEAN_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the assurance results from
   * each of the servers.  This field may appear in assurance completed access
   * log messages.
   */
  @NotNull public static final LogField SERVER_ASSURANCE_RESULTS =
       createField("SERVER_ASSURANCE_RESULTS", "serverAssuranceResults",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the external servers accessed
   * during the course of processing the operation.  Each server in the list
   * will consist of the name or IP address, a colon, and the port number.  This
   * field may appear in all types of operation result access log messages.
   */
  @NotNull public static final LogField SERVERS_ACCESSED =
       createField("SERVERS_ACCESSED", "serversAccessed",
            COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that holds a unique value generated when the server started.  This
   * can help differentiate messages with the same connection ID and
   * operation ID (if applicable) because those values are reset upon a server
   * restart.  This field may appear in all types of access log messages.
   */
  @NotNull public static final LogField STARTUP_ID =
       createField("STARTUP_ID", "startupID", STRING_SYNTAX);



  /**
   * A field that holds the address of a server to which the operation was
   * forwarded for processing.  This field may appear in access log messages for
   * operations that were forwarded to a remote system.
   */
  @NotNull public static final LogField TARGET_HOST =
       createField("TARGET_HOST", "targetHost", STRING_SYNTAX);



  /**
   * A field that holds the port of a server to which the operation was
   * forwarded for processing.  This field may appear in access log messages for
   * operations that were forwarded to a remote system.
   */
  @NotNull public static final LogField TARGET_PORT =
       createField("TARGET_PORT", "targetPort", INTEGER_SYNTAX);



  /**
   * A field that holds the protocol used to communicate with a remote server
   * for an operation that was forwarded for processing.  This field may appear
   * in access log messages for operations that were forwarded to a remote
   * system.
   */
  @NotNull public static final LogField TARGET_PROTOCOL =
       createField("TARGET_PROTOCOL", "targetProtocol", STRING_SYNTAX);



  /**
   * A field that holds a numeric identifier for the thread that generated the
   * log message, which is also likely the thread that performed the associated
   * processing for the connection or operation).  This field may appear in all
   * types of access log messages.
   */
  @NotNull public static final LogField THREAD_ID =
       createField("THREAD_ID", "threadID", INTEGER_SYNTAX);



  /**
   * A field that holds the connection ID for another operation that triggered
   * the associated operation.  This field may appear in all types of access log
   * messages that are associated with operations.
   */
  @NotNull public static final LogField TRIGGERED_BY_CONNECTION_ID =
       createField("TRIGGERED_BY_CONNECTION_ID", "triggeredByConn",
            INTEGER_SYNTAX);



  /**
   * A field that holds the operation ID for another operation that triggered
   * the associated operation.  This field may appear in all types of access log
   * messages that are associated with operations.
   */
  @NotNull public static final LogField TRIGGERED_BY_OPERATION_ID =
       createField("TRIGGERED_BY_OPERATION_ID", "triggeredByOp",
            INTEGER_SYNTAX);



  /**
   * A field that indicates whether the server accessed any uncached data in the
   * course of processing the operation.  This field may appear in all types of
   * operation result access log messages.
   */
  @NotNull public static final LogField UNCACHED_DATA_ACCESSED =
       createField("UNCACHED_DATA_ACCESSED", "uncachedDataAccessed",
            BOOLEAN_SYNTAX);



  /**
   * A field that holds a comma-delimited list of the names of any privileges
   * used in the course of processing the operation.  This field may appear in
   * all types of operation result access log messages.
   */
  @NotNull public static final LogField USED_PRIVILEGES = createField(
       "USED_PRIVILEGES", "usedPrivileges", COMMA_DELIMITED_STRING_LIST_SYNTAX);



  /**
   * A field that indicates whether the associated operation is being processed
   * using a worker thread from a thread pool dedicated to processing
   * administrative operations.  This field may appear in all types of
   * access log messages that are associated with operations.
   */
  @NotNull public static final LogField USING_ADMIN_SESSION_WORKER_THREAD =
       createField("USING_ADMIN_SESSION_WORKER_THREAD",
            "usingAdminSessionWorkerThread", BOOLEAN_SYNTAX);



  /**
   * A field that holds the length of time (in milliseconds) that the operation
   * had to wait in the work queue before being picked up for processing.  This
   * field may appear in all types of operation result access log messages.
   */
  @NotNull public static final LogField WORK_QUEUE_WAIT_TIME_MILLIS =
       createField("WORK_QUEUE_WAIT_TIME_MILLIS", "qtime", INTEGER_SYNTAX);



  /**
   * Prevents this utility class from being instantiated.
   */
  private TextFormattedAccessLogFields()
  {
    // No implementation is required.
  }



  /**
   * Creates a new log field with the provided name and syntax and registers it
   * in the {@link #DEFINED_FIELDS} map.
   *
   * @param  constantName  The name for the constant in which the field is
   *                       defined.  It must not be {@code null} or empty.
   * @param  fieldName     The name for the field as it appears in log messages.
   *                       It must not be {@code null} or empty.
   * @param  fieldSyntax   The expected syntax for the field.  It must not be
   *                       {@code null} or empty.
   *
   * @return  The log field that was created.
   */
  @NotNull()
  private static LogField createField(@NotNull final String constantName,
               @NotNull final String fieldName,
               @NotNull final LogFieldSyntax<?> fieldSyntax)
  {
    final LogField field = new LogField(fieldName, constantName, fieldSyntax);
    DEFINED_FIELDS.put(constantName, field);
    return field;
  }



  /**
   * Retrieves a map of all predefined fields, indexed by the name of the
   * constant in which the field is defined.
   *
   * @return  A map of all predefined fields.
   */
  @NotNull()
  public static Map<String,LogField> getDefinedFields()
  {
    Map<String,LogField> m = READ_ONLY_DEFINED_FIELDS_REF.get();
    if (m != null)
    {
      return m;
    }

    m = Collections.unmodifiableMap(new TreeMap<>(DEFINED_FIELDS));
    if (READ_ONLY_DEFINED_FIELDS_REF.compareAndSet(null, m))
    {
      return m;
    }
    else
    {
      return READ_ONLY_DEFINED_FIELDS_REF.get();
    }
  }



  /**
   * Retrieves the predefined log field instance that is defined in the
   * specified constants.
   *
   * @param  constantName  The name of the constant in which the desired field
   *                       is defined.  It must not be {@code null}.
   *
   * @return  The log field instance defined in the specified constant, or
   *          {@code null} if there is no such constant.
   */
  @Nullable()
  public static LogField getFieldForConstantName(
              @NotNull final String constantName)
  {
    final String convertedName =
         StaticUtils.toUpperCase(constantName).replace('-', '_');
    return DEFINED_FIELDS.get(convertedName);
  }
}
