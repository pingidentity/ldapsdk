/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
 * This class provides an implementation of a request control that can be
 * included in a bind request to indicate that the server should include a
 * control int eh bind response with information about recent login attempts
 * for the user.
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
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.61 and no value.  The
 * criticality may be either {@code true} or {@code false}.
 *
 * @see  GetRecentLoginHistoryRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetRecentLoginHistoryRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.61) for the get password policy state issues
   * request control.
   */
  @NotNull public static final  String GET_RECENT_LOGIN_HISTORY_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.61";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3060529240532292690L;



  /**
   * Creates a new instance of this control.  It will not be considered
   * critical.
   */
  public GetRecentLoginHistoryRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new instance of this control with the specified criticality.
   *
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   */
  public GetRecentLoginHistoryRequestControl(final boolean isCritical)
  {
    super(GET_RECENT_LOGIN_HISTORY_REQUEST_OID, isCritical);
  }



  /**
   * Creates a new instance of this control that is decoded from the provided
   * generic control.
   *
   * @param  control  The control to decode as a get recent login history
   *                  request control.
   *
   * @throws LDAPException  If a problem is encountered while attempting to
   *                         decode the provided control as a get recent login
   *                         history request control.
   */
  public GetRecentLoginHistoryRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_RECENT_LOGIN_HISTORY_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_RECENT_LOGIN_HISTORY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetRecentLoginHistoryRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
