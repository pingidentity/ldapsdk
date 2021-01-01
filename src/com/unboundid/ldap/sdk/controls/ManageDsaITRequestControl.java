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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the ManageDsaIT control as described
 * in <A HREF="http://www.ietf.org/rfc/rfc3296.txt">RFC 3296</A>.  This control
 * may be used to request that the directory server treat all entries as if they
 * were regular entries.
 * <BR><BR>
 * One of the most common uses of the ManageDsaIT control is to request that the
 * directory server to treat an entry containing the "{@code referral}" object
 * class as a regular entry rather than a smart referral.  Normally, when the
 * server encounters an entry with the {@code referral} object class, it sends
 * a referral with the URLs contained in the {@code ref} attribute of that
 * entry.  However, if the ManageDsaIT control is included then the operation
 * will attempt to operate on the referral definition itself rather than sending
 * that referral to the client.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the ManageDsaIT control to
 * delete an entry that may or may not be a referral:
 * <PRE>
 * // Establish a connection to the directory server.  Even though it's the
 * // default behavior, we'll explicitly configure the connection to not follow
 * // referrals.
 * LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
 * connectionOptions.setFollowReferrals(false);
 * LDAPConnection connection = new LDAPConnection(connectionOptions,
 *      serverAddress, serverPort, bindDN, bindPassword);
 *
 * // Try to delete an entry that will result in a referral.  Without the
 * // ManageDsaIT request control, we should get an exception.
 * DeleteRequest deleteRequest =
 *      new DeleteRequest("ou=referral entry,dc=example,dc=com");
 * LDAPResult deleteResult;
 * try
 * {
 *   deleteResult = connection.delete(deleteRequest);
 * }
 * catch (LDAPException le)
 * {
 *   // This exception is expected because we should get a referral, and
 *   // the connection is configured to not follow referrals.
 *   deleteResult = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 *   String[] referralURLs = le.getReferralURLs();
 * }
 * LDAPTestUtils.assertResultCodeEquals(deleteResult, ResultCode.REFERRAL);
 * LDAPTestUtils.assertHasReferral(deleteResult);
 *
 * // Update the delete request to include the ManageDsaIT request control,
 * // which will cause the server to try to delete the referral entry instead
 * // of returning a referral response.  We'll assume that the delete is
 * // successful.
 * deleteRequest.addControl(new ManageDsaITRequestControl());
 * try
 * {
 *   deleteResult = connection.delete(deleteRequest);
 * }
 * catch (LDAPException le)
 * {
 *   // The delete shouldn't trigger a referral, but it's possible that the
 *   // operation failed for some other reason (e.g., entry doesn't exist, the
 *   // user doesn't have permission to delete it, etc.).
 *   deleteResult = le.toLDAPResult();
 * }
 * LDAPTestUtils.assertResultCodeEquals(deleteResult, ResultCode.SUCCESS);
 * LDAPTestUtils.assertMissingReferral(deleteResult);
 *
 * connection.close();
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ManageDsaITRequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.2) for the ManageDsaIT request control.
   */
  @NotNull public static final String MANAGE_DSA_IT_REQUEST_OID =
       "2.16.840.1.113730.3.4.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4540943247829123783L;



  /**
   * Creates a new ManageDsaIT request control.  The control will not be marked
   * critical.
   */
  public ManageDsaITRequestControl()
  {
    super(MANAGE_DSA_IT_REQUEST_OID, false, null);
  }



  /**
   * Creates a new ManageDsaIT request control.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public ManageDsaITRequestControl(final boolean isCritical)
  {
    super(MANAGE_DSA_IT_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new ManageDsaIT request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a ManageDsaIT request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         ManageDsaIT request control.
   */
  public ManageDsaITRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_MANAGE_DSA_IT_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_MANAGE_DSAIT_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ManageDsaITRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
