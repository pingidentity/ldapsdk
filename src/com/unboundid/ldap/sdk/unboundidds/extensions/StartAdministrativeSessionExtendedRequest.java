/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the start administrative session
 * extended request, which clients may use to indicate that they are going to
 * perform a set of administrative operations in the server.  It may be used
 * to identify the client to the server and to indicate whether subsequent
 * requests received on the connection should be processed using worker threads
 * in a dedicated thread pool (subject to server configuration restrictions).
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
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.13, and it must
 * have a value with the following encoding:
 * <PRE>
 *   StartAdminSessionValue ::= SEQUENCE {
 *        clientName                 [0] OCTET STRING OPTIONAL,
 *        useDedicatedThreadPool     [1] BOOLEAN DEFAULT FALSE,
 *        ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for creating an administrative
 * session and using that session to request monitor information using a
 * dedicated worker thread.
 * <PRE>
 * // Establish a connection to the server.
 * LDAPConnection connection = new LDAPConnection(host, port);
 *
 * // Use the start administrative session operation to begin an administrative
 * // session and request that operations in the session use the dedicated
 * // thread pool.
 * ExtendedResult extendedResult = connection.processExtendedOperation(
 *      new StartAdministrativeSessionExtendedRequest("Test Client", true));
 *
 * // Authenticate the connection.  It is strongly recommended that the
 * // administrative session be created before the connection is authenticated.
 * // Attempting to authenticate the connection before creating the
 * // administrative session may result in the bind using a "regular" worker
 * // thread rather than an administrative session worker thread, and if all
 * // normal worker threads are busy or stuck, then the bind request may be
 * // blocked.
 * BindResult bindResult = connection.bind(userDN, password);
 *
 * // Use the connection to perform operations that may benefit from using an
 * // administrative session (e.g., operations that troubleshoot and attempt to
 * // correct some problem with the server).  In this example, we'll just
 * // request all monitor entries from the server.
 * List&lt;MonitorEntry&gt; monitorEntries =
 *      MonitorManager.getMonitorEntries(connection);
 *
 * // Use the end administrative session operation to end the administrative
 * // session and resume using normal worker threads for subsequent operations.
 * // This isn't strictly needed if we just want to close the connection.
 * extendedResult = connection.processExtendedOperation(
 *      new EndAdministrativeSessionExtendedRequest());
 *
 * // Do other operations that don't need an administrative session.
 *
 * connection.close();
 * </PRE>
 *
 * @see  EndAdministrativeSessionExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StartAdministrativeSessionExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.13) for the start administrative session
   * extended request.
   */
  @NotNull public static final String START_ADMIN_SESSION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.13";



  /**
   * The BER type for the client name element of the extended request value.
   */
  private static final byte TYPE_CLIENT_NAME = (byte) 0x80;



  /**
   * The BER type for the use dedicated thread pool element of the extended
   * request value.
   */
  private static final byte TYPE_USE_DEDICATED_THREAD_POOL = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2684374559100906505L;



  // Indicates whether the client has requested that the server use a dedicated
  // thread pool for processing operations during the administrative session.
  private final boolean useDedicatedThreadPool;

  // The name of the client application issuing this request.
  @Nullable private final String clientName;



  /**
   * Creates a new start administrative session extended request with the
   * provided information.
   *
   * @param  clientName              The name of the client application issuing
   *                                 this request.  It may be {@code null} if no
   *                                 client name should be provided.
   * @param  useDedicatedThreadPool  Indicates whether the server should use a
   *                                 dedicated worker thread pool for requests
   *                                 processed by this client.  Note that the
   *                                 server may define restrictions around the
   *                                 use of a dedicated thread pool.
   * @param  controls                The set of controls to include in the
   *                                 request.
   */
  public StartAdministrativeSessionExtendedRequest(
              @Nullable final String clientName,
              final boolean useDedicatedThreadPool,
              @Nullable final Control... controls)
  {
    super(START_ADMIN_SESSION_REQUEST_OID,
         encodeValue(clientName, useDedicatedThreadPool),
         controls);

    this.clientName             = clientName;
    this.useDedicatedThreadPool = useDedicatedThreadPool;
  }



  /**
   * Creates a new start administrative session extended request from the
   * provided generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          start administrative session extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public StartAdministrativeSessionExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_START_ADMIN_SESSION_REQUEST_NO_VALUE.get());
    }


    String  appName       = null;
    boolean dedicatedPool = false;

    try
    {
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      for (final ASN1Element e : valueSequence.elements())
      {
        switch (e.getType())
        {
          case TYPE_CLIENT_NAME:
            appName = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_USE_DEDICATED_THREAD_POOL:
            dedicatedPool = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_START_ADMIN_SESSION_REQUEST_UNKNOWN_VALUE_ELEMENT_TYPE.get(
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
           ERR_START_ADMIN_SESSION_REQUEST_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    clientName             = appName;
    useDedicatedThreadPool = dedicatedPool;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  clientName              The name of the client application issuing
   *                                 this request.  It may be {@code null} if no
   *                                 client name should be provided.
   * @param  useDedicatedThreadPool  Indicates whether the server should use a
   *                                 dedicated worker thread pool for requests
   *                                 processed by this client.  Note that the
   *                                 server may define restrictions around the
   *                                 use of a dedicated thread pool.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final String clientName,
               final boolean useDedicatedThreadPool)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(2);

    if (clientName != null)
    {
      elements.add(new ASN1OctetString(TYPE_CLIENT_NAME, clientName));
    }

    if (useDedicatedThreadPool)
    {
      elements.add(new ASN1Boolean(TYPE_USE_DEDICATED_THREAD_POOL, true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the name of the client application issuing this request, if
   * available.
   *
   * @return  The name of the client application issuing this request, or
   *          {@code null} if it was not included in the request.
   */
  @Nullable()
  public String getClientName()
  {
    return clientName;
  }



  /**
   * Indicates whether the server should attempt to use a dedicated worker
   * thread pool for requests from this client.
   *
   * @return  {@code true} if the server should attempt to use a dedicated
   *          worker thread pool for requests from this client, or {@code false}
   *          if not.
   */
  public boolean useDedicatedThreadPool()
  {
    return useDedicatedThreadPool;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartAdministrativeSessionExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public StartAdministrativeSessionExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    return new StartAdministrativeSessionExtendedRequest(clientName,
         useDedicatedThreadPool, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_START_ADMIN_SESSION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StartAdministrativeSessionExtendedRequest(");

    if (clientName != null)
    {
      buffer.append("clientName='");
      buffer.append(clientName);
      buffer.append("', ");
    }

    buffer.append("useDedicatedThreadPool=");
    buffer.append(useDedicatedThreadPool);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
