/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
 * This class provides a request control that can be included in a modify
 * request or a password modify extended request in order to indicate that if
 * the operation results in changing the password for a user, the user's former
 * password should be marked as "retired", which may allow it to remain in use
 * for a brief period of time (as configured in the password policy governing
 * that user) to allow for applications which may have been configured with that
 * password can be updated to use the new password.
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
 * This control has an OID of "1.3.6.1.4.1.30221.2.5.31" and does not have a
 * value.  The criticality may be either true (in which case the operation will
 * succeed only if the user's password policy allows passwords to be retired by
 * a request control) or false (in which case if the password policy does not
 * allow the use of this control, the operation will be processed as if the
 * control had not been included in the request).
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the retire password request
 * control to request that a user's current password be retired in the course of
 * a password change.
 * <PRE>
 * Control[] requestControls =
 * {
 *   new RetirePasswordRequestControl(true)
 * };
 *
 * PasswordModifyExtendedRequest passwordModifyRequest =
 *      new PasswordModifyExtendedRequest(
 *           "uid=test.user,ou=People,dc=example,dc=com", // The user to update
 *           null, // The current password -- we don't know it.
 *           "newPassword", // The new password to assign to the user.
 *           requestControls); // The controls to include in the request.
 * PasswordModifyExtendedResult passwordModifyResult =
 *      (PasswordModifyExtendedResult)
 *      connection.processExtendedOperation(passwordModifyRequest);
 * </PRE>
 *
 * @see  PurgePasswordRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RetirePasswordRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.31) for the retire password request control.
   */
  @NotNull public static final String RETIRE_PASSWORD_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.31";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7261376468186883355L;



  /**
   * Creates a new retire password request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   */
  public RetirePasswordRequestControl(final boolean isCritical)
  {
    super(RETIRE_PASSWORD_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new retire password request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a retire password
   *                  request control.
   *
   * @throws LDAPException  If the provided control cannot be decoded as a
   *                         retire password request control.
   */
  public RetirePasswordRequestControl(@NotNull final Control control)
       throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RETIRE_PASSWORD_REQUEST_CONTROL_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_RETIRE_PASSWORD_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RetirePasswordRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
