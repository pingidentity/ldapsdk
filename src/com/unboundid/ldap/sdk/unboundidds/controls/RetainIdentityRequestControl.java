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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class defines a request control that may be used to indicate that the
 * server should process all aspects of the associated bind request (including
 * password policy processing) but should not actually change the identity for
 * the client connection, regardless of whether the authentication is
 * successful.
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
 * This control can be very useful for applications that perform binds to
 * authenticate users but also use connection pooling to re-use connections
 * for multiple operations.  Bind operations are normally not well-suited for
 * use on pooled connections because they change the identity of that
 * connection, but the retain identity request control solves that problem by
 * performing all bind processing but does not change the identity associated
 * with the client connection.
 * <BR><BR>
 * There is no corresponding response control.  If the bind is successful, then
 * the server should return a bind response with the {@code ResultCode#SUCCESS}
 * result code just as if the bind request had not included the retain identity
 * request control.
 * <BR><BR>
 * This control is not based on any public standard.  It was originally
 * developed for use with the Ping Identity, UnboundID, and Nokia/Alcatel-Lucent
 * 8661 Directory Server.  It does not have a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the retain identity request
 * control:
 * <PRE>
 * SimpleBindRequest bindRequest = new SimpleBindRequest(
 *      "uid=john.doe,ou=People,dc=example,dc=com", "password",
 *      new RetainIdentityRequestControl());
 *
 * BindResult bindResult;
 * try
 * {
 *   bindResult = connection.bind(bindRequest);
 *   // The bind was successful and the account is usable, but the identity
 *   // associated with the client connection hasn't changed.
 * }
 * catch (LDAPException le)
 * {
 *   bindResult = new BindResult(le.toLDAPResult());
 *   // The bind was unsuccessful, potentially because the credentials were
 *   // invalid or the account is unusable for some reason (e.g., disabled,
 *   // locked, expired password, etc.).  The identity associated with the
 *   // client connection hasn't changed.
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RetainIdentityRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.3) for the retain identity request control.
   */
  @NotNull public static final String RETAIN_IDENTITY_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.3";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9066549673766581236L;



  /**
   * Creates a new retain identity request control.  It will be marked critical.
   */
  public RetainIdentityRequestControl()
  {
    super(RETAIN_IDENTITY_REQUEST_OID, true, null);
  }



  /**
   * Creates a new retain identity request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a retain identity
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         retain identity request control.
   */
  public RetainIdentityRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_RETAIN_IDENTITY_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_RETAIN_IDENTITY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RetainIdentityRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
