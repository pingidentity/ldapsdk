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
 * This class provides an implementation of the password policy request control
 * as described in draft-behera-ldap-password-policy.  It may be used to request
 * information related to a user's password policy.  In the Ping Identity,
 * UnboundID, and Nokia/Alcatel-Lucent 8661 Directory Server, this control may
 * be included with add, bind, compare, modify, and password modify requests.
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
 * This request control has an OID of 1.3.6.1.4.1.42.2.27.8.5.1.  The
 * criticality may be either true or false.  It does not have a value.
 * <BR><BR>
 * The corresponding {@link PasswordPolicyResponseControl} may include at most
 * one warning from the set of {@link PasswordPolicyWarningType} values and at
 * most one error from the set of {@link PasswordPolicyErrorType} values.  See
 * the documentation for those classes for more information on the information
 * that may be included.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the password policy request
 * control in conjunction with a bind operation:
 * <PRE>
 * SimpleBindRequest bindRequest = new SimpleBindRequest(
 *      "uid=john.doe,ou=People,dc=example,dc=com", "password",
 *      new PasswordPolicyRequestControl());
 *
 * BindResult bindResult;
 * try
 * {
 *   bindResult = connection.bind(bindRequest);
 * }
 * catch (LDAPException le)
 * {
 *   // The bind failed.  There may be a password policy response control to
 *   // help tell us why.
 *   bindResult = new BindResult(le.toLDAPResult());
 * }
 *
 * PasswordPolicyResponseControl pwpResponse =
 *      PasswordPolicyResponseControl.get(bindResult);
 * if (pwpResponse != null)
 * {
 *   PasswordPolicyErrorType errorType = pwpResponse.getErrorType();
 *   if (errorType != null)
 *   {
 *     // There was a password policy-related error.
 *   }
 *
 *   PasswordPolicyWarningType warningType = pwpResponse.getWarningType();
 *   if (warningType != null)
 *   {
 *     // There was a password policy-related warning.
 *     int value = pwpResponse.getWarningValue();
 *     switch (warningType)
 *     {
 *       case TIME_BEFORE_EXPIRATION:
 *         // The warning value is the number of seconds until the user's
 *         // password expires.
 *         break;
 *       case GRACE_LOGINS_REMAINING:
 *         // The warning value is the number of grace logins remaining for
 *         // the user.
 *     }
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordPolicyRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.8.5.1) for the password policy request
   * control.
   */
  @NotNull public static final String PASSWORD_POLICY_REQUEST_OID =
       "1.3.6.1.4.1.42.2.27.8.5.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6495056761590890150L;



  /**
   * Creates a new password policy request control.  The control will not be
   * marked critical.
   */
  public PasswordPolicyRequestControl()
  {
    super(PASSWORD_POLICY_REQUEST_OID, false, null);
  }



  /**
   * Creates a new password policy request control.
   *
   * @param  isCritical  Indicates whether the control should be marked
   * critical.
   */
  public PasswordPolicyRequestControl(final boolean isCritical)
  {
    super(PASSWORD_POLICY_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new password policy request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a password policy
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         password policy request control.
   */
  public PasswordPolicyRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_POLICY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordPolicyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
