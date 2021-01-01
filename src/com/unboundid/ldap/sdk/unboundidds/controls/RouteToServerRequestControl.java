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



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be used to request that the
 * associated request be routed to a specific server.  It is primarily intended
 * for use when the request will pass through a Directory Proxy Server to
 * indicate that which backend server should be used to process the request.
 * The server ID for the server to use may be obtained using the
 * {@link GetServerIDRequestControl}.
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
 * If the request is processed successfully, then the result should include a
 * {@link GetServerIDResponseControl} with the server ID of the server that was
 * used to process the request.  It may or may not be the same as the server ID
 * included in the request control, depending on whether an alternate server was
 * determined to be better suited to handle the request.
 * <BR><BR>
 * The criticality for this control may be either {@code true} or {@code false}.
 * It must have a value with the following encoding:
 * <PRE>
 *   RouteToServerRequest ::= SEQUENCE {
 *        serverID                    [0] OCTET STRING,
 *        allowAlternateServer        [1] BOOLEAN,
 *        preferLocalServer           [2] BOOLEAN DEFAULT TRUE,
 *        preferNonDegradedServer     [3] BOOLEAN DEFAULT TRUE,
 *        ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process of performing a search to
 * retrieve an entry using the get server ID request control and then sending a
 * modify request to that same server using the route to server request control.
 * <PRE>
 * // Perform a search to find an entry, and use the get server ID request
 * // control to figure out which server actually processed the request.
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.BASE, Filter.createPresenceFilter("objectClass"),
 *      "description");
 * searchRequest.addControl(new GetServerIDRequestControl());
 *
 * SearchResultEntry entry = connection.searchForEntry(searchRequest);
 * GetServerIDResponseControl serverIDControl =
 *      GetServerIDResponseControl.get(entry);
 * String serverID = serverIDControl.getServerID();
 *
 * // Send a modify request to update the target entry, and include the route
 * // to server request control to request that the change be processed on the
 * // same server that processed the request.
 * ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
 *      new Modification(ModificationType.REPLACE, "description",
 *           "new description value"));
 * modifyRequest.addControl(new RouteToServerRequestControl(false, serverID,
 *      true, true, true));
 * LDAPResult modifyResult = connection.modify(modifyRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RouteToServerRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.16) for the route to server request control.
   */
  @NotNull public static final String ROUTE_TO_SERVER_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.16";



  /**
   * The BER type for the server ID element.
   */
  private static final byte TYPE_SERVER_ID = (byte) 0x80;



  /**
   * The BER type for the allow alternate server element.
   */
  private static final byte TYPE_ALLOW_ALTERNATE_SERVER = (byte) 0x81;



  /**
   * The BER type for the prefer local server element.
   */
  private static final byte TYPE_PREFER_LOCAL_SERVER = (byte) 0x82;



  /**
   * The BER type for the prefer non-degraded server element.
   */
  private static final byte TYPE_PREFER_NON_DEGRADED_SERVER = (byte) 0x83;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2100638364623466061L;



  // Indicates whether the associated request may be processed by an alternate
  // server if the server specified by the given server ID is not suitable for
  // use.
  private final boolean allowAlternateServer;

  // Indicates whether the associated request should may be routed to an
  // alternate server if the target server is more remote than an alternate
  // server.
  private final boolean preferLocalServer;

  // Indicates whether the associated request should be routed to an alternate
  // server if the target server is in a degraded state and an alternate server
  // is not in a degraded state.
  private final boolean preferNonDegradedServer;

  // The server ID of the server to which the request should be sent.
  @NotNull private final String serverID;



  /**
   * Creates a new route to server request control with the provided
   * information.
   *
   * @param  isCritical               Indicates whether this control should be
   *                                  considered critical.
   * @param  serverID                 The server ID for the server to which the
   *                                  request should be sent.  It must not be
   *                                  {@code null}.
   * @param  allowAlternateServer     Indicates whether the request may be
   *                                  routed to an alternate server in the
   *                                  event that the target server is not known,
   *                                  is not available, or is otherwise unsuited
   *                                  for use.  If this has a value of
   *                                  {@code false} and the target server is
   *                                  unknown or unavailable, then the
   *                                  associated operation will be rejected.  If
   *                                  this has a value of {@code true}, then an
   *                                  intermediate Directory Proxy Server may be
   *                                  allowed to route the request to a
   *                                  different server if deemed desirable or
   *                                  necessary.
   * @param  preferLocalServer        Indicates whether the associated request
   *                                  may be routed to an alternate server if
   *                                  the target server is in a remote location
   *                                  and a suitable alternate server is
   *                                  available locally.  This will only be used
   *                                  if {@code allowAlternateServer} is
   *                                  {@code true}.
   * @param  preferNonDegradedServer  Indicates whether the associated request
   *                                  may be routed to an alternate server if
   *                                  the target server is in a degraded state
   *                                  and an alternate server is not in a
   *                                  degraded state.  This will only be used if
   *                                  {@code allowAlternateServer} is
   *                                  {@code true}.
   */
  public RouteToServerRequestControl(final boolean isCritical,
                                     @NotNull final String serverID,
                                     final boolean allowAlternateServer,
                                     final boolean preferLocalServer,
                                     final boolean preferNonDegradedServer)
  {
    super(ROUTE_TO_SERVER_REQUEST_OID, isCritical,
          encodeValue(serverID, allowAlternateServer, preferLocalServer,
               preferNonDegradedServer));

    this.serverID                = serverID;
    this.allowAlternateServer    = allowAlternateServer;
    this.preferLocalServer       = (allowAlternateServer && preferLocalServer);
    this.preferNonDegradedServer =
         (allowAlternateServer && preferNonDegradedServer);
  }



  /**
   * Creates a new route to server request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a route to server
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         route to server request control.
   */
  public RouteToServerRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ROUTE_TO_SERVER_REQUEST_MISSING_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      valueSequence = ASN1Sequence.decodeAsSequence(value.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ROUTE_TO_SERVER_REQUEST_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    try
    {
      final ASN1Element[] elements = valueSequence.elements();
      serverID = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      allowAlternateServer =
           ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();

      boolean preferLocal       = allowAlternateServer;
      boolean preferNonDegraded = allowAlternateServer;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_PREFER_LOCAL_SERVER:
            preferLocal = allowAlternateServer &&
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;
          case TYPE_PREFER_NON_DEGRADED_SERVER:
            preferNonDegraded = allowAlternateServer &&
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ROUTE_TO_SERVER_REQUEST_INVALID_VALUE_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      preferLocalServer       = preferLocal;
      preferNonDegradedServer = preferNonDegraded;
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
           ERR_ROUTE_TO_SERVER_REQUEST_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Encodes the provided information into a form suitable for use as the value
   * of this control.
   *
   * @param  serverID                 The server ID for the server to which the
   *                                  request should be sent.  It must not be
   *                                  {@code null}.
   * @param  allowAlternateServer     Indicates whether the request may be
   *                                  routed to an alternate server in the
   *                                  event that the target server is not known,
   *                                  is not available, or is otherwise unsuited
   *                                  for use.  If this has a value of
   *                                  {@code false} and the target server is
   *                                  unknown or unavailable, then the
   *                                  associated operation will be rejected.  If
   *                                  this has a value of {@code true}, then an
   *                                  intermediate Directory Proxy Server may be
   *                                  allowed to route the request to a
   *                                  different server if deemed desirable or
   *                                  necessary.
   * @param  preferLocalServer        Indicates whether the associated request
   *                                  may be routed to an alternate server if
   *                                  the target server is in a remote location
   *                                  and a suitable alternate server is
   *                                  available locally.  This will only be used
   *                                  if {@code allowAlternateServer} is
   *                                  {@code true}.
   * @param  preferNonDegradedServer  Indicates whether the associated request
   *                                  may be routed to an alternate server if
   *                                  the target server is in a degraded state
   *                                  and an alternate server is not in a
   *                                  degraded state.  This will only be used if
   *                                  {@code allowAlternateServer} is
   *                                  {@code true}.
   *
   * @return  The encoded value for this control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String serverID,
                                      final boolean allowAlternateServer,
                                      final boolean preferLocalServer,
                                      final boolean preferNonDegradedServer)
  {
    Validator.ensureNotNull(serverID);

    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    elements.add(new ASN1OctetString(TYPE_SERVER_ID, serverID));
    elements.add(
         new ASN1Boolean(TYPE_ALLOW_ALTERNATE_SERVER, allowAlternateServer));

    if (allowAlternateServer && (! preferLocalServer))
    {
      elements.add(new ASN1Boolean(TYPE_PREFER_LOCAL_SERVER, false));
    }

    if (allowAlternateServer && (! preferNonDegradedServer))
    {
      elements.add(new ASN1Boolean(TYPE_PREFER_NON_DEGRADED_SERVER, false));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the server ID for the server to which the request should be sent.
   *
   * @return  The server ID for the server to which the request should be sent.
   */
  @NotNull()
  public String getServerID()
  {
    return serverID;
  }



  /**
   * Indicates whether the request may be routed to an alternate server if the
   * target server is unknown, unavailable, or otherwise unsuited for use.
   *
   * @return  {@code true} if the request may be routed to an alternate server
   *          if the target server is not suitable for use, or {@code false} if
   *          the operation should be rejected if it cannot be routed to the
   *          target server.
   */
  public boolean allowAlternateServer()
  {
    return allowAlternateServer;
  }



  /**
   * Indicates whether the request may be routed to an alternate server if the
   * target server is nonlocal and a suitable server is available locally.  This
   * will only return {@code true} if {@link #allowAlternateServer} also returns
   * {@code true}.
   *
   * @return  {@code true} if the request may be routed to a suitable local
   *          server if the target server is nonlocal, or {@code false} if the
   *          nonlocal target server should still be used.
   */
  public boolean preferLocalServer()
  {
    return preferLocalServer;
  }



  /**
   * Indicates whether the request may be routed to an alternate server if the
   * target server is in a degraded state and a suitable non-degraded server is
   * available.  This will only return {@code true} if
   * {@link #allowAlternateServer} also returns {@code true}.
   *
   * @return  {@code true} if the request may be routed to a suitable
   *          non-degraded server if the target server is degraded, or
   *          {@code false} if the degraded target server should still be used.
   */
  public boolean preferNonDegradedServer()
  {
    return preferNonDegradedServer;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ROUTE_TO_SERVER_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RouteToServerRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", serverID='");
    buffer.append(serverID);
    buffer.append("', allowAlternateServer=");
    buffer.append(allowAlternateServer);
    buffer.append(", preferLocalServer=");
    buffer.append(preferLocalServer);
    buffer.append(", preferNonDegradedServer=");
    buffer.append(preferNonDegradedServer);
    buffer.append(')');
  }
}
