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
package com.unboundid.ldap.sdk.controls;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the password expired control as
 * described in draft-vchu-ldap-pwd-policy.  It may be included in the response
 * for an unsuccessful bind operation to indicate that the reason for the
 * failure is that the target user's password has expired and must be reset
 * before the user will be allowed to authenticate.  Some servers may also
 * include this control in a successful bind response to indicate that the
 * authenticated user must change his or her password before being allowed to
 * perform any other operation.
 * <BR><BR>
 * No request control is required to trigger the server to send the password
 * expired response control.  If the server supports the use of this control and
 * the corresponding bind operation meets the criteria for this control to be
 * included in the response, then it will be returned to the client.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates a process that may be used to perform a
 * simple bind to authenticate against the server and handle any password
 * expired or password expiring control that may be included in the response:
 * <PRE>
 * // Send a simple bind request to the directory server.
 * BindRequest bindRequest =
 *      new SimpleBindRequest("uid=test.user,ou=People,dc=example,dc=com",
 *           "password");
 * BindResult bindResult;
 * boolean bindSuccessful;
 * boolean passwordExpired;
 * boolean passwordAboutToExpire;
 * try
 * {
 *   bindResult = connection.bind(bindRequest);
 *
 *   // If we got here, the bind was successful and we know the password was
 *   // not expired.  However, we shouldn't ignore the result because the
 *   // password might be about to expire.  To determine whether that is the
 *   // case, we should see if the bind result included a password expiring
 *   // control.
 *   bindSuccessful = true;
 *   passwordExpired = false;
 *
 *   PasswordExpiringControl expiringControl =
 *        PasswordExpiringControl.get(bindResult);
 *   if (expiringControl != null)
 *   {
 *     passwordAboutToExpire = true;
 *     int secondsToExpiration = expiringControl.getSecondsUntilExpiration();
 *   }
 *   else
 *   {
 *     passwordAboutToExpire = false;
 *   }
 * }
 * catch (LDAPException le)
 * {
 *   // If we got here, then the bind failed.  The failure may or may not have
 *   // been due to an expired password.  To determine that, we should see if
 *   // the bind result included a password expired control.
 *   bindSuccessful = false;
 *   passwordAboutToExpire = false;
 *   bindResult = new BindResult(le.toLDAPResult());
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 *
 *   PasswordExpiredControl expiredControl =
 *        PasswordExpiredControl.get(le);
 *   if (expiredControl != null)
 *   {
 *     passwordExpired = true;
 *   }
 *   else
 *   {
 *     passwordExpired = false;
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordExpiredControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (2.16.840.1.113730.3.4.4) for the password expired response
   * control.
   */
  @NotNull public static final String PASSWORD_EXPIRED_OID =
       "2.16.840.1.113730.3.4.4";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2731704592689892224L;



  /**
   * Creates a new password expired control.
   */
  public PasswordExpiredControl()
  {
    super(PASSWORD_EXPIRED_OID, false, new ASN1OctetString("0"));
  }



  /**
   * Creates a new password expired control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         password expired response control.
   */
  public PasswordExpiredControl(@NotNull final String oid,
                                final boolean isCritical,
                                @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRED_NO_VALUE.get());
    }

    try
    {
      Integer.parseInt(value.stringValue());
    }
    catch (final NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PW_EXPIRED_VALUE_NOT_INTEGER.get(), nfe);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PasswordExpiredControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new PasswordExpiredControl(oid, isCritical, value);
  }



  /**
   * Extracts a password expired control from the provided result.
   *
   * @param  result  The result from which to retrieve the password expired
   *                 control.
   *
   * @return  The password expired control contained in the provided result, or
   *          {@code null} if the result did not contain a password expired
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password expired control contained in
   *                         the provided result.
   */
  @Nullable()
  public static PasswordExpiredControl get(@NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_EXPIRED_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof PasswordExpiredControl)
    {
      return (PasswordExpiredControl) c;
    }
    else
    {
      return new PasswordExpiredControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts a password expired control from the provided exception.
   *
   * @param  exception  The exception from which to retrieve the password
   *                    expired control.
   *
   * @return  The password expired control contained in the provided exception,
   *          or {@code null} if the exception did not contain a password
   *          expired control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password expired control contained in
   *                         the provided exception.
   */
  @Nullable()
  public static PasswordExpiredControl get(
                     @NotNull final LDAPException exception)
         throws LDAPException
  {
    return get(exception.toLDAPResult());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_EXPIRED.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordExpiredControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
