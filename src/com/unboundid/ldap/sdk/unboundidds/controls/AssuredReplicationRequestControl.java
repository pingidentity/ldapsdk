/*
 * Copyright 2013-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2022 Ping Identity Corporation
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
 * Copyright (C) 2013-2022 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of an LDAP control that can be included
 * in add, bind, modify, modify DN, and certain extended requests to indicate
 * the level of replication assurance desired for the associated operation.
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
 * <BR>
 * The OID for this control is 1.3.6.1.4.1.30221.2.5.28, and it may have a
 * criticality of either TRUE or FALSE.  It must have a value with the following
 * encoding:
 * <PRE>
 *   AssuredReplicationRequest ::= SEQUENCE {
 *        minimumLocalLevel           [0] LocalLevel OPTIONAL,
 *        maximumLocalLevel           [1] LocalLevel OPTIONAL,
 *        minimumRemoteLevel          [2] RemoteLevel OPTIONAL,
 *        maximumRemoteLevel          [3] RemoteLevel OPTIONAL,
 *        timeoutMillis               [4] INTEGER (1 .. 2147483647) OPTIONAL,
 *        sendResponseImmediately     [5] BOOLEAN DEFAULT FALSE,
 *        ... }
 *
 *   LocalLevel ::= ENUMERATED {
 *        none                    (0),
 *        receivedAnyServer       (1),
 *        processedAllServers     (2),
 *        ... }
 *
 *   RemoteLevel ::= ENUMERATED {
 *        none                           (0),
 *        receivedAnyRemoteLocation      (1),
 *        receivedAllRemoteLocations     (2),
 *        processedAllRemoteServers      (3),
 *        ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the assured replication request
 * control in conjunction with a delete operation to request that the server not
 * return the delete result to the client until the delete has been applied to
 * all available servers in the local data center and has also been replicated
 * to at least one remote data center:
 * <PRE>
 * DeleteRequest deleteRequest = new DeleteRequest(
 *      "uid=test.user,ou=People,dc=example,dc=com");
 * deleteRequest.addControl(new AssuredReplicationRequestControl(
 *      AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
 *      AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
 *      5000L));
 *  LDAPResult deleteResult = connection.delete(deleteRequest);
 *
 * if (deleteResult.getResultCode() == ResultCode.SUCCESS)
 * {
 *   AssuredReplicationResponseControl assuredReplicationResponse =
 *        AssuredReplicationResponseControl.get(deleteResult);
 *   if (assuredReplicationResponse == null)
 *   {
 *     // The entry was deleted, but its replication could not be confirmed in
 *     // either the local or remote data centers.
 *   }
 *   else
 *   {
 *     if (assuredReplicationResponse.localAssuranceSatisfied())
 *     {
 *       if (assuredReplicationResponse.remoteAssuranceSatisfied())
 *       {
 *         // The entry was deleted.  The delete has been applied across all
 *         // available local servers, and has been replicated to at least one
 *         // remote data center.
 *       }
 *       else
 *       {
 *         // The entry was deleted.  The delete has been applied across all
 *         // available local servers, but cannot be confirmed to have yet
 *         // been replicated to any remote data centers.
 *       }
 *     }
 *     else if (assuredReplicationResponse.remoteAssuranceSatisfied())
 *     {
 *       // The entry was deleted.  The delete has been confirmed to have been
 *       // replicated to at least one remote data center, but cannot be
 *       // confirmed to have yet been applied to all available local servers.
 *     }
 *     else
 *     {
 *       // The entry was deleted, but its replication could not be confirmed
 *       // to either local servers or remote data centers.
 *     }
 *   }
 * }
 * else
 * {
 *   // The entry could not be deleted.
 * }
 * </PRE>
 *
 * @see  AssuredReplicationResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AssuredReplicationRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.28) for the assured replication request
   * control.
   */
  @NotNull public static final String ASSURED_REPLICATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.28";


  /**
   * The BER type for the minimum local assurance level.
   */
  private static final byte TYPE_MIN_LOCAL_LEVEL = (byte) 0x80;


  /**
   * The BER type for the maximum local assurance level.
   */
  private static final byte TYPE_MAX_LOCAL_LEVEL = (byte) 0x81;


  /**
   * The BER type for the minimum remote assurance level.
   */
  private static final byte TYPE_MIN_REMOTE_LEVEL = (byte) 0x82;


  /**
   * The BER type for the maximum remote assurance level.
   */
  private static final byte TYPE_MAX_REMOTE_LEVEL = (byte) 0x83;


  /**
   * The BER type for the maximum remote assurance level.
   */
  private static final byte TYPE_SEND_RESPONSE_IMMEDIATELY = (byte) 0x84;


  /**
   * The BER type for the timeout.
   */
  private static final byte TYPE_TIMEOUT = (byte) 0x85;



  /**
   * The name of the field used to specify the maximum replication assurance
   * level in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MAXIMUM_LOCAL_LEVEL =
       "maximum-local-level";



  /**
   * The name of the field used to specify the maximum remote assurance
   * level in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MAXIMUM_REMOTE_LEVEL =
       "maximum-remote-level";



  /**
   * The name of the field used to specify the minimum replication assurance
   * level in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MINIMUM_LOCAL_LEVEL =
       "minimum-local-level";



  /**
   * The name of the field used to specify the minimum remote assurance
   * level in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MINIMUM_REMOTE_LEVEL =
       "minimum-remote-level";



  /**
   * The name of the field used to indicate whether to send the operation
   * response immediately in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SEND_RESPONSE_IMMEDIATELY =
       "send-response-immediately";



  /**
   * The name of the field used to specify the assurance timeout in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_TIMEOUT_MILLIS =
       "timeout-millis";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2013933506118879241L;



  // The requested maximum local assurance level.
  @Nullable private final AssuredReplicationLocalLevel maximumLocalLevel;

  // The requested minimum local assurance level.
  @Nullable private final AssuredReplicationLocalLevel minimumLocalLevel;

  // The requested maximum remote assurance level.
  @Nullable private final AssuredReplicationRemoteLevel maximumRemoteLevel;

  // The requested minimum remote assurance level.
  @Nullable private final AssuredReplicationRemoteLevel minimumRemoteLevel;

  // Indicates whether the server should immediately send the operation response
  // without waiting for assurance processing.
  private final boolean sendResponseImmediately;

  // The maximum length of time in milliseconds that the server should wait for
  // the desired assurance level to be attained.
  @Nullable private final Long timeoutMillis;



  /**
   * Creates a new assured replication request control with the provided
   * information.  It will not be critical.
   *
   * @param  minimumLocalLevel   The minimum replication assurance level desired
   *                             for servers in the same location as the server
   *                             receiving the change.  This may be overridden
   *                             by the server if the associated operation
   *                             matches an assured replication criteria with a
   *                             higher local assurance level.  If this is
   *                             {@code null}, then the server will determine
   *                             minimum local assurance level for the
   *                             operation.
   * @param  minimumRemoteLevel  The minimum replication assurance level desired
   *                             for servers in different locations from the
   *                             server receiving the change.  This may be
   *                             overridden by the server if the associated
   *                             operation matches an assured replication
   *                             criteria with a higher remote assurance level.
   *                             If this is {@code null}, then the server will
   *                             determine the remote assurance level for the
   *                             operation.
   * @param  timeoutMillis       The maximum length of time in milliseconds to
   *                             wait for the desired assurance to be satisfied.
   *                             If this is {@code null}, then the server will
   *                             determine the timeout to use.
   */
  public AssuredReplicationRequestControl(
       @Nullable final AssuredReplicationLocalLevel minimumLocalLevel,
       @Nullable final AssuredReplicationRemoteLevel minimumRemoteLevel,
       @Nullable final Long timeoutMillis)
  {
    this(false, minimumLocalLevel, null, minimumRemoteLevel, null,
         timeoutMillis, false);
  }



  /**
   * Creates a new assured replication request control with the provided
   * information.
   *
   * @param  isCritical               Indicates whether the control should be
   *                                  marked critical.
   * @param  minimumLocalLevel        The minimum replication assurance level
   *                                  desired for servers in the same location
   *                                  as the server receiving the change.  This
   *                                  may be overridden by the server if the
   *                                  associated operation matches an assured
   *                                  replication criteria with a higher local
   *                                  assurance level.  If this is {@code null},
   *                                  then the server will determine the minimum
   *                                  local assurance level for the operation.
   * @param  maximumLocalLevel        The maximum replication assurance level
   *                                  desired for servers in the same location
   *                                  as the server receiving the change.  This
   *                                  may override the server configuration if
   *                                  the operation matches an assured
   *                                  replication criteria that would have
   *                                  otherwise used a higher local assurance
   *                                  level.  If this is {@code null}, then the
   *                                  server will determine the maximum local
   *                                  assurance level for the operation.
   * @param  minimumRemoteLevel       The minimum replication assurance level
   *                                  desired for servers in different locations
   *                                  from the server receiving the change.
   *                                  This may be overridden by the server if
   *                                  the associated operation matches an
   *                                  assured replication criteria with a higher
   *                                  remote assurance level.  If this is
   *                                  {@code null}, then the server will
   *                                  determine the minimum remote assurance
   *                                  level for the operation.
   * @param  maximumRemoteLevel       The maximum replication assurance level
   *                                  desired for servers in different locations
   *                                  from the server receiving the change.
   *                                  This may override the server configuration
   *                                  if the operation matches an assured
   *                                  replication criteria that would have
   *                                  otherwise used a higher remote assurance
   *                                  level.  If this is {@code null}, then the
   *                                  server will determine the maximum remote
   *                                  assurance level for the operation.
   * @param  timeoutMillis            The maximum length of time in milliseconds
   *                                  to wait for the desired assurance to be
   *                                  satisfied.  If this is {@code null}, then
   *                                  the server will determine the timeout to
   *                                  use.
   * @param  sendResponseImmediately  Indicates whether the server should
   *              send the response to the client immediately after the change
   *              has been applied to the server receiving the change, without
   *              waiting for the desired assurance to be satisfied.
   */
  public AssuredReplicationRequestControl(final boolean isCritical,
              @Nullable final AssuredReplicationLocalLevel minimumLocalLevel,
              @Nullable final AssuredReplicationLocalLevel maximumLocalLevel,
              @Nullable final AssuredReplicationRemoteLevel minimumRemoteLevel,
              @Nullable final AssuredReplicationRemoteLevel maximumRemoteLevel,
              @Nullable final Long timeoutMillis,
              final boolean sendResponseImmediately)
  {
    super(ASSURED_REPLICATION_REQUEST_OID, isCritical,
         encodeValue(minimumLocalLevel, maximumLocalLevel, minimumRemoteLevel,
              maximumRemoteLevel, sendResponseImmediately, timeoutMillis));

    this.minimumLocalLevel       = minimumLocalLevel;
    this.maximumLocalLevel       = maximumLocalLevel;
    this.minimumRemoteLevel      = minimumRemoteLevel;
    this.maximumRemoteLevel      = maximumRemoteLevel;
    this.sendResponseImmediately = sendResponseImmediately;
    this.timeoutMillis           = timeoutMillis;
  }



  /**
   * Creates a new assured replication request control from the provided generic
   * control.
   *
   * @param  c  The generic control to decode as an assured replication request
   *            control.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided generic control cannot be parsed as
   *                         an assured replication request control.
   */
  public AssuredReplicationRequestControl(@NotNull final Control c)
         throws LDAPException
  {
    super(c);

    final ASN1OctetString value = c.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_REQUEST_NO_VALUE.get());
    }

    AssuredReplicationLocalLevel  maxLocalLevel   = null;
    AssuredReplicationLocalLevel  minLocalLevel   = null;
    AssuredReplicationRemoteLevel maxRemoteLevel  = null;
    AssuredReplicationRemoteLevel minRemoteLevel  = null;
    boolean                       sendImmediately = false;
    Long                          timeout         = null;

    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_MIN_LOCAL_LEVEL:
            int intValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            minLocalLevel = AssuredReplicationLocalLevel.valueOf(intValue);
            if (minLocalLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_REQUEST_INVALID_MIN_LOCAL_LEVEL.get(
                        intValue));
            }
            break;

          case TYPE_MAX_LOCAL_LEVEL:
            intValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            maxLocalLevel = AssuredReplicationLocalLevel.valueOf(intValue);
            if (maxLocalLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_REQUEST_INVALID_MAX_LOCAL_LEVEL.get(
                        intValue));
            }
            break;

          case TYPE_MIN_REMOTE_LEVEL:
            intValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            minRemoteLevel = AssuredReplicationRemoteLevel.valueOf(intValue);
            if (minRemoteLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_REQUEST_INVALID_MIN_REMOTE_LEVEL.get(
                        intValue));
            }
            break;

          case TYPE_MAX_REMOTE_LEVEL:
            intValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            maxRemoteLevel = AssuredReplicationRemoteLevel.valueOf(intValue);
            if (maxRemoteLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_REQUEST_INVALID_MAX_REMOTE_LEVEL.get(
                        intValue));
            }
            break;

          case TYPE_SEND_RESPONSE_IMMEDIATELY:
            sendImmediately = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_TIMEOUT:
            timeout = ASN1Long.decodeAsLong(e).longValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ASSURED_REPLICATION_REQUEST_UNEXPECTED_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_REQUEST_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    minimumLocalLevel       = minLocalLevel;
    maximumLocalLevel       = maxLocalLevel;
    minimumRemoteLevel      = minRemoteLevel;
    maximumRemoteLevel      = maxRemoteLevel;
    sendResponseImmediately = sendImmediately;
    timeoutMillis           = timeout;
  }



  /**
   * Encodes the provided information as needed for use as the value of this
   * control.
   *
   * @param  minimumLocalLevel        The minimum replication assurance level
   *                                  desired for servers in the same location
   *                                  as the server receiving the change.  This
   *                                  may be overridden by the server if the
   *                                  associated operation matches an assured
   *                                  replication criteria with a higher local
   *                                  assurance level.  If this is {@code null},
   *                                  then the server will determine the minimum
   *                                  local assurance level for the operation.
   * @param  maximumLocalLevel        The maximum replication assurance level
   *                                  desired for servers in the same location
   *                                  as the server receiving the change.  This
   *                                  may override the server configuration if
   *                                  the operation matches an assured
   *                                  replication criteria that would have
   *                                  otherwise used a higher local assurance
   *                                  level.  If this is {@code null}, then the
   *                                  server will determine the maximum local
   *                                  assurance level for the operation.
   * @param  minimumRemoteLevel       The minimum replication assurance level
   *                                  desired for servers in different locations
   *                                  from the server receiving the change.
   *                                  This may be overridden by the server if
   *                                  the associated operation matches an
   *                                  assured replication criteria with a higher
   *                                  remote assurance level.  If this is
   *                                  {@code null}, then the server will
   *                                  determine the minimum remote assurance
   *                                  level for the operation.
   * @param  maximumRemoteLevel       The maximum replication assurance level
   *                                  desired for servers in different locations
   *                                  from the server receiving the change.
   *                                  This may override the server configuration
   *                                  if the operation matches an assured
   *                                  replication criteria that would have
   *                                  otherwise used a higher remote assurance
   *                                  level.  If this is {@code null}, then the
   *                                  server will determine the maximum remote
   *                                  assurance level for the operation.
   * @param  timeoutMillis            The maximum length of time in milliseconds
   *                                  to wait for the desired assurance to be
   *                                  satisfied.  If this is {@code null}, then
   *                                  the server will determine the timeout to
   *                                  use.
   * @param  sendResponseImmediately  Indicates whether the server should
   *              send the response to the client immediately after the change
   *              has been applied to the server receiving the change, without
   *              waiting for the desired assurance to be satisfied.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final AssuredReplicationLocalLevel minimumLocalLevel,
               @Nullable final AssuredReplicationLocalLevel maximumLocalLevel,
               @Nullable final AssuredReplicationRemoteLevel minimumRemoteLevel,
               @Nullable final AssuredReplicationRemoteLevel maximumRemoteLevel,
               final boolean sendResponseImmediately,
               @Nullable final Long timeoutMillis)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(6);

    if (minimumLocalLevel != null)
    {
      elements.add(new ASN1Enumerated(TYPE_MIN_LOCAL_LEVEL,
           minimumLocalLevel.intValue()));
    }

    if (maximumLocalLevel != null)
    {
      elements.add(new ASN1Enumerated(TYPE_MAX_LOCAL_LEVEL,
           maximumLocalLevel.intValue()));
    }

    if (minimumRemoteLevel != null)
    {
      elements.add(new ASN1Enumerated(TYPE_MIN_REMOTE_LEVEL,
           minimumRemoteLevel.intValue()));
    }

    if (maximumRemoteLevel != null)
    {
      elements.add(new ASN1Enumerated(TYPE_MAX_REMOTE_LEVEL,
           maximumRemoteLevel.intValue()));
    }

    if (sendResponseImmediately)
    {
      elements.add(new ASN1Boolean(TYPE_SEND_RESPONSE_IMMEDIATELY, true));
    }

    if (timeoutMillis != null)
    {
      elements.add(new ASN1Long(TYPE_TIMEOUT, timeoutMillis));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the minimum desired replication level of assurance for local
   * servers (i.e., servers in the same location as the server that originally
   * received the change), if defined.  This may be overridden by the server if
   * the associated operation matches an assured replication criteria with a
   * higher local assurance level.
   *
   * @return  The minimum desired replication level of assurance for local
   *          servers, or {@code null} if the server should determine the
   *          minimum local assurance level for the operation.
   */
  @Nullable()
  public AssuredReplicationLocalLevel getMinimumLocalLevel()
  {
    return minimumLocalLevel;
  }



  /**
   * Retrieves the maximum desired replication level of assurance for local
   * servers (i.e., servers in the same location as the server that originally
   * received the change), if defined.  This may override the server
   * configuration if the operation matches an assured replication criteria that
   * would have otherwise used a higher local assurance level.
   *
   * @return  The maximum desired replication level of assurance for local
   *          servers, or {@code null} if the server should determine the
   *          maximum local assurance level for the operation.
   */
  @Nullable()
  public AssuredReplicationLocalLevel getMaximumLocalLevel()
  {
    return maximumLocalLevel;
  }



  /**
   * Retrieves the minimum desired replication level of assurance for remote
   * servers (i.e., servers in locations different from the server that
   * originally received the change), if defined.  This may be overridden by the
   * server if the associated operation matches an assured replication
   * criteria with a higher remote assurance level.
   *
   * @return  The minimum desired replication level of assurance for remote
   *          servers, or {@code null} if the server should determine the
   *          minimum remote assurance level for the operation.
   */
  @Nullable()
  public AssuredReplicationRemoteLevel getMinimumRemoteLevel()
  {
    return minimumRemoteLevel;
  }



  /**
   * Retrieves the maximum desired replication level of assurance for remote
   * servers (i.e., servers in locations different from the server that
   * originally received the change), if defined.  This may override the server
   * configuration if the operation matches an assured replication criteria that
   * would have otherwise used a higher remote assurance level.
   *
   * @return  The maximum desired replication level of assurance for remote
   *          servers, or {@code null} if the server should determine the
   *          maximum remote assurance level for the operation.
   */
  @Nullable()
  public AssuredReplicationRemoteLevel getMaximumRemoteLevel()
  {
    return maximumRemoteLevel;
  }



  /**
   * Indicates whether the server that originally received the change should
   * return the operation result immediately, without waiting for the requested
   * assurance processing to complete.
   *
   * @return  {@code false} if the server should wait to return the operation
   *          result until the desired assurance has been attained or a timeout
   *          has occurred, or {@code true} if the server should return the
   *          result immediately.
   */
  public boolean sendResponseImmediately()
  {
    return sendResponseImmediately;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that the operation
   * response should be delayed while waiting for the desired level of
   * assurance to be attained.
   *
   * @return  The maximum length of time in milliseconds that the operation
   *          response should be delayed while waiting for the desired level of
   *          assurance to be attained.
   */
  @Nullable()
  public Long getTimeoutMillis()
  {
    return timeoutMillis;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ASSURED_REPLICATION_REQUEST.get();
  }



  /**
   * Retrieves a representation of this assured replication request control as a
   * JSON object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the assured replication request
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.28".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this assured
   *     replication request control.  Exactly one of the {@code value-base64}
   *     and {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this assured replication
   *     request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code minimum-local-level} -- An optional string field whose
   *         value is the name of the minimum assurance level desired for
   *         replicas in the same location as the target server.  The value may
   *         be one of "{@code none}", "{@code received-any-server}", or
   *         "{@code processed-all-servers}".
   *       </LI>
   *       <LI>
   *         {@code maximum-local-level} -- An optional string field whose
   *         value is the name of the maximum assurance level desired for
   *         replicas in the same location as the target server.  The value may
   *         be one of "{@code none}", "{@code received-any-server}", or
   *         "{@code processed-all-servers}".
   *       </LI>
   *       <LI>
   *         {@code minimum-remote-level} -- An optional string field whose
   *         value is the name of the minimum assurance level desired for
   *         replicas in a different location from the target server.  The value
   *         may be one of "{@code none}",
   *         "{@code received-any-remote-location}",
   *         "{@code received-all-remote-locations}", or
   *         "{@code processed-all-remote-servers}".
   *       </LI>
   *       <LI>
   *         {@code maximum-remote-level} -- An optional string field whose
   *         value is the name of the maximum assurance level desired for
   *         replicas in a different location from the target server.  The value
   *         may be one of "{@code none}",
   *         "{@code received-any-remote-location}",
   *         "{@code received-all-remote-locations}", or
   *         "{@code processed-all-remote-servers}".
   *       </LI>
   *       <LI>
   *         {@code timeout-millis} -- An optional integer field whose value is
   *         the maximum length of time in milliseconds that the server should
   *         wait for assurance to be satisfied.
   *       </LI>
   *       <LI>
   *         {@code send-response-immediately} -- A mandatory Boolean field that
   *         indicates whether the server should return the response to the
   *         client immediately after applying the change locally, even if it
   *         has not yet been replicated.
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> jsonValueFields = new LinkedHashMap<>();

    if (minimumLocalLevel != null)
    {
      jsonValueFields.put(JSON_FIELD_MINIMUM_LOCAL_LEVEL,
           new JSONString(minimumLocalLevel.getName()));
    }

    if (maximumLocalLevel != null)
    {
      jsonValueFields.put(JSON_FIELD_MAXIMUM_LOCAL_LEVEL,
           new JSONString(maximumLocalLevel.getName()));
    }

    if (minimumRemoteLevel != null)
    {
      jsonValueFields.put(JSON_FIELD_MINIMUM_REMOTE_LEVEL,
           new JSONString(minimumRemoteLevel.getName()));
    }

    if (maximumRemoteLevel != null)
    {
      jsonValueFields.put(JSON_FIELD_MAXIMUM_REMOTE_LEVEL,
           new JSONString(maximumRemoteLevel.getName()));
    }

    if (timeoutMillis != null)
    {
      jsonValueFields.put(JSON_FIELD_TIMEOUT_MILLIS,
           new JSONNumber(timeoutMillis));
    }

    jsonValueFields.put(JSON_FIELD_SEND_RESPONSE_IMMEDIATELY,
         new JSONBoolean(sendResponseImmediately));

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              ASSURED_REPLICATION_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_ASSURED_REPLICATION_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(jsonValueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * assured replication request control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The assured replication control that was decoded from the provided
   *          JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid assured replication request control.
   */
  @NotNull()
  public static AssuredReplicationRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new AssuredReplicationRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    AssuredReplicationLocalLevel minimumLocalLevel = null;
    AssuredReplicationLocalLevel maximumLocalLevel = null;
    AssuredReplicationRemoteLevel minimumRemoteLevel = null;
    AssuredReplicationRemoteLevel maximumRemoteLevel = null;
    Long timeoutMillis = null;
    Boolean sendImmediately = null;
    final JSONObject valueObject = jsonControl.getValueObject();

    final String minLocalLevelStr =
         valueObject.getFieldAsString(JSON_FIELD_MINIMUM_LOCAL_LEVEL);
    if (minLocalLevelStr != null)
    {
      minimumLocalLevel =
           AssuredReplicationLocalLevel.forName(minLocalLevelStr);
      if (minimumLocalLevel == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ASSURED_REPLICATION_REQUEST_JSON_INVALID_MIN_LOCAL_LEVEL.get(
                  controlObject.toSingleLineString(),
                  minLocalLevelStr));
      }
    }

    final String maxLocalLevelStr =
         valueObject.getFieldAsString(JSON_FIELD_MAXIMUM_LOCAL_LEVEL);
    if (maxLocalLevelStr != null)
    {
      maximumLocalLevel =
           AssuredReplicationLocalLevel.forName(maxLocalLevelStr);
      if (maximumLocalLevel == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ASSURED_REPLICATION_REQUEST_JSON_INVALID_MAX_LOCAL_LEVEL.get(
                  controlObject.toSingleLineString(),
                  maxLocalLevelStr));
      }
    }

    final String minRemoteLevelStr =
         valueObject.getFieldAsString(JSON_FIELD_MINIMUM_REMOTE_LEVEL);
    if (minRemoteLevelStr != null)
    {
      minimumRemoteLevel =
           AssuredReplicationRemoteLevel.forName(minRemoteLevelStr);
      if (minimumRemoteLevel == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ASSURED_REPLICATION_REQUEST_JSON_INVALID_MIN_REMOTE_LEVEL.get(
                  controlObject.toSingleLineString(),
                  minRemoteLevelStr));
      }
    }

    final String maxRemoteLevelStr =
         valueObject.getFieldAsString(JSON_FIELD_MAXIMUM_REMOTE_LEVEL);
    if (maxRemoteLevelStr != null)
    {
      maximumRemoteLevel =
           AssuredReplicationRemoteLevel.forName(maxRemoteLevelStr);
      if (maximumRemoteLevel == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ASSURED_REPLICATION_REQUEST_JSON_INVALID_MAX_REMOTE_LEVEL.get(
                  controlObject.toSingleLineString(),
                  maxRemoteLevelStr));
      }
    }

    timeoutMillis = valueObject.getFieldAsLong(JSON_FIELD_TIMEOUT_MILLIS);

    sendImmediately =
         valueObject.getFieldAsBoolean(JSON_FIELD_SEND_RESPONSE_IMMEDIATELY);
    if (sendImmediately == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_REQUEST_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(),
                JSON_FIELD_SEND_RESPONSE_IMMEDIATELY));
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_MINIMUM_LOCAL_LEVEL,
                JSON_FIELD_MAXIMUM_LOCAL_LEVEL, JSON_FIELD_MINIMUM_REMOTE_LEVEL,
                JSON_FIELD_MAXIMUM_REMOTE_LEVEL, JSON_FIELD_TIMEOUT_MILLIS,
                JSON_FIELD_SEND_RESPONSE_IMMEDIATELY);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ASSURED_REPLICATION_REQUEST_JSON_CONTROL_UNRECOGNIZED_FIELD
                  .get(controlObject.toSingleLineString(),
                       unrecognizedFields.get(0)));
      }
    }


    return new AssuredReplicationRequestControl(jsonControl.getCriticality(),
         minimumLocalLevel, maximumLocalLevel, minimumRemoteLevel,
         maximumRemoteLevel, timeoutMillis, sendImmediately);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AssuredReplicationRequestControl(isCritical=");
    buffer.append(isCritical());

    if (minimumLocalLevel != null)
    {
      buffer.append(", minimumLocalLevel=");
      buffer.append(minimumLocalLevel.name());
    }

    if (maximumLocalLevel != null)
    {
      buffer.append(", maximumLocalLevel=");
      buffer.append(maximumLocalLevel.name());
    }

    if (minimumRemoteLevel != null)
    {
      buffer.append(", minimumRemoteLevel=");
      buffer.append(minimumRemoteLevel.name());
    }

    if (maximumRemoteLevel != null)
    {
      buffer.append(", maximumRemoteLevel=");
      buffer.append(maximumRemoteLevel.name());
    }

    buffer.append(", sendResponseImmediately=");
    buffer.append(sendResponseImmediately);

    if (timeoutMillis != null)
    {
      buffer.append(", timeoutMillis=");
      buffer.append(timeoutMillis);
    }

    buffer.append(')');
  }
}
