/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1Integer;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that is used to represent an LDAP bind request.
 * It should be extended by subclasses that provide the logic for processing
 * specific types of bind operations (e.g., simple binds, and the various SASL
 * mechanisms).
 * <BR><BR>
 * It is strongly recommended that all bind request types which implement the
 * rebind capability be made immutable.  If this is not done, then changes made
 * to a bind request object may alter the authentication/authorization identity
 * and/or credentials associated with that request so that a rebind request
 * created from it will not match the original request used to authenticate on a
 * connection.  Note, however, that it is not threadsafe to use the same
 * {@code BindRequest} object to attempt to bind concurrently over multiple
 * connections.
 * <BR><BR>
 * Note that even though this class is marked with the @Extensible annotation
 * type, it should not be directly subclassed by third-party code.  Only the
 * {@link SASLBindRequest} subclass is actually intended to be extended by
 * third-party code.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class BindRequest
       extends LDAPRequest
{
  /**
   * The pre-encoded ASN.1 element used to represent the protocol version.
   */
  @NotNull protected static final ASN1Integer VERSION_ELEMENT =
       new ASN1Integer(3);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1509925217235385907L;



  /**
   * Creates a new bind request with the provided set of controls.
   *
   * @param  controls  The set of controls to include in this bind request.
   */
  protected BindRequest(@Nullable final Control[] controls)
  {
    super(controls);
  }



  /**
   * Sends this bind request to the target server over the provided connection
   * and returns the corresponding response.
   *
   * @param  connection  The connection to use to send this bind request to the
   *                     server and read the associated response.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  The bind response read from the server.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected abstract BindResult process(@NotNull LDAPConnection connection,
                                        int depth)
            throws LDAPException;



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public final OperationType getOperationType()
  {
    return OperationType.BIND;
  }



  /**
   * Retrieves a human-readable string that describes the type of bind request.
   *
   * @return  A human-readable string that describes the type of bind request.
   */
  @NotNull()
  public abstract String getBindType();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public abstract BindRequest duplicate();



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public abstract BindRequest duplicate(@Nullable Control[] controls);



  /**
   * Retrieves a bind request that may be used to re-bind using the same
   * credentials authentication type and credentials as previously used to
   * perform the initial bind.  This may be used in an attempt to automatically
   * re-establish a connection that is lost, or potentially when following a
   * referral to another directory instance.
   * <BR><BR>
   * It is recommended that all bind request types which implement this
   * capability be implemented so that the elements needed to create a new
   * request are immutable.  If this is not done, then changes made to a bind
   * request object may alter the authentication/authorization identity and/or
   * credentials associated with that request so that a rebind request created
   * from it will not match the original request used to authenticate on a
   * connection.
   *
   * @param  host  The address of the directory server to which the connection
   *               is established.
   * @param  port  The port of the directory server to which the connection is
   *               established.
   *
   * @return  A bind request that may be used to re-bind using the same
   *          authentication type and credentials as previously used to perform
   *          the initial bind, or {@code null} to indicate that automatic
   *          re-binding is not supported for this type of bind request.
   */
  @Nullable()
  public BindRequest getRebindRequest(@NotNull final String host,
                                      final int port)
  {
    return null;
  }
}
