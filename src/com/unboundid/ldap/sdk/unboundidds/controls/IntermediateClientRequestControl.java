/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines an intermediate client request control, which can be used
 * to provide a server with information about the client and any downstream
 * clients that it may have.  It can be used to help trace operations from the
 * client to the directory server, potentially through any intermediate hops
 * (like proxy servers) that may also support the intermediate client controls.
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
 * This control is not based on any public standard.  It was originally
 * developed for use with the Ping Identity, UnboundID, and Nokia/Alcatel-Lucent
 * 8661 Directory Server.  The value of this control uses the following
 * encoding:
 * <BR><BR>
 * <PRE>
 * IntermediateClientRequest ::= SEQUENCE {
 *      downstreamRequest        [0] IntermediateClientRequest OPTIONAL,
 *      downstreamClientAddress  [1] OCTET STRING OPTIONAL,
 *      downstreamClientSecure   [2] BOOLEAN DEFAULT FALSE,
 *      clientIdentity           [3] authzId OPTIONAL,
 *      clientName               [4] OCTET STRING OPTIONAL,
 *      clientSessionID          [5] OCTET STRING OPTIONAL,
 *      clientRequestID          [6] OCTET STRING OPTIONAL,
 *      ... }
 * </PRE>
 * <H2>Example</H2>
 * The following example demonstrates the use of the intermediate client
 * controls to perform a search operation in the directory server.  The request
 * will be from an application named "my client" with a session ID of
 * "session123" and a request ID of "request456":
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"));
 * searchRequest.addControl(new IntermediateClientRequestControl(null, null,
 *      null, null, "my client", "session123", "request456"));
 * SearchResult searchResult = connection.search(searchRequest);
 *
 * IntermediateClientResponseControl c =
 *      IntermediateClientResponseControl.get(searchResult);
 * if (c != null)
 * {
 *   // There was an intermediate client response control.
 *   IntermediateClientResponseValue responseValue = c.getResponseValue();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IntermediateClientRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.2) for the intermediate client request
   * control.
   */
  @NotNull public static final String INTERMEDIATE_CLIENT_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4883725840393001578L;



  // The value for this intermediate client request control.
  @NotNull private final IntermediateClientRequestValue value;



  /**
   * Creates a new intermediate client request control with the provided
   * information.  It will be marked critical.
   *
   * @param  downstreamRequest        A wrapped intermediate client request from
   *                                  a downstream client.  It may be
   *                                  {@code null} if there is no downstream
   *                                  request.
   * @param  downstreamClientAddress  The IP address or resolvable name of the
   *                                  downstream client system.  It may be
   *                                  {@code null} if there is no downstream
   *                                  client or its address is not available.
   * @param  downstreamClientSecure   Indicates whether communication with the
   *                                  downstream client is secure.  It may be
   *                                  {@code null} if there is no downstream
   *                                  client or it is not known whether the
   *                                  communication is secure.
   * @param  clientIdentity           The requested client authorization
   *                                  identity.  It may be {@code null} if there
   *                                  is no requested authorization identity.
   * @param  clientName               An identifier string that summarizes the
   *                                  client application that created this
   *                                  intermediate client request.  It may be
   *                                  {@code null} if that information is not
   *                                  available.
   * @param  clientSessionID          A string that may be used to identify the
   *                                  session in the client application.  It may
   *                                  be {@code null} if there is no available
   *                                  session identifier.
   * @param  clientRequestID          A string that may be used to identify the
   *                                  request in the client application.  It may
   *                                  be {@code null} if there is no available
   *                                  request identifier.
   */
  public IntermediateClientRequestControl(
              @Nullable final IntermediateClientRequestValue downstreamRequest,
              @Nullable final String downstreamClientAddress,
              @Nullable final Boolean downstreamClientSecure,
              @Nullable final String clientIdentity,
              @Nullable final String clientName,
              @Nullable final String clientSessionID,
              @Nullable final String clientRequestID)
  {
    this(true,
         new IntermediateClientRequestValue(downstreamRequest,
                  downstreamClientAddress, downstreamClientSecure,
                  clientIdentity, clientName, clientSessionID,
                  clientRequestID));
  }



  /**
   * Creates a new intermediate client request control with the provided value.
   * It will be marked critical.
   *
   * @param  value  The value to use for this intermediate client request
   *                control.  It must not be {@code null}.
   */
  public IntermediateClientRequestControl(
              @NotNull final IntermediateClientRequestValue value)
  {
    this(true, value);
  }



  /**
   * Creates a new intermediate client request control with the provided value.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The value to use for this intermediate client request
   *                     control.  It must not be {@code null}.
   */
  public IntermediateClientRequestControl(final boolean isCritical,
              @NotNull final IntermediateClientRequestValue value)
  {
    super(INTERMEDIATE_CLIENT_REQUEST_OID, isCritical,
          new ASN1OctetString(value.encode().encode()));

    this.value = value;
  }



  /**
   * Creates a new intermediate client request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an intermediate
   *                  client request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         intermediate client request control.
   */
  public IntermediateClientRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString controlValue = control.getValue();
    if (controlValue == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ICREQ_CONTROL_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(controlValue.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ICREQ_CONTROL_VALUE_NOT_SEQUENCE.get(e), e);
    }

    value = IntermediateClientRequestValue.decode(valueSequence);
  }



  /**
   * Retrieves the value for this intermediate client request.
   *
   * @return  The value for this intermediate client request.
   */
  @NotNull()
  public IntermediateClientRequestValue getRequestValue()
  {
    return value;
  }



  /**
   * Retrieves the wrapped request from a downstream client, if available.
   *
   * @return  The wrapped request from a downstream client, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public IntermediateClientRequestValue getDownstreamRequest()
  {
    return value.getDownstreamRequest();
  }



  /**
   * Retrieves the requested client authorization identity, if available.
   *
   * @return  The requested client authorization identity, or {@code null} if
   *          there is none.
   */
  @Nullable()
  public String getClientIdentity()
  {
    return value.getClientIdentity();
  }



  /**
   * Retrieves the IP address or resolvable name of the downstream client
   * system, if available.
   *
   * @return  The IP address or resolvable name of the downstream client system,
   *          or {@code null} if there is no downstream client or its address is
   *          not available.
   */
  @Nullable()
  public String getDownstreamClientAddress()
  {
    return value.getDownstreamClientAddress();
  }



  /**
   * Indicates whether the communication with the communication with the
   * downstream client is secure (i.e., whether communication between the
   * client application and the downstream client is safe from interpretation or
   * undetectable alteration by a third party observer or interceptor).
   *
   *
   * @return  {@code Boolean.TRUE} if communication with the downstream client
   *          is secure, {@code Boolean.FALSE} if it is not secure, or
   *          {@code null} if there is no downstream client or it is not known
   *          whether the communication is secure.
   */
  @Nullable()
  public Boolean downstreamClientSecure()
  {
    return value.downstreamClientSecure();
  }



  /**
   * Retrieves a string that identifies the client application that created this
   * intermediate client request value.
   *
   * @return  A string that may be used to identify the client application that
   *          created this intermediate client request value.
   */
  @Nullable()
  public String getClientName()
  {
    return value.getClientName();
  }



  /**
   * Retrieves a string that may be used to identify the session in the client
   * application.
   *
   * @return  A string that may be used to identify the session in the client
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getClientSessionID()
  {
    return value.getClientSessionID();
  }



  /**
   * Retrieves a string that may be used to identify the request in the client
   * application.
   *
   * @return  A string that may be used to identify the request in the client
   *          application, or {@code null} if there is none.
   */
  @Nullable()
  public String getClientRequestID()
  {
    return value.getClientRequestID();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_INTERMEDIATE_CLIENT_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("IntermediateClientRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", value=");
    value.toString(buffer);
    buffer.append(')');
  }
}
