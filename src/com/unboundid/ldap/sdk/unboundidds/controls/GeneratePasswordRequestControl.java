/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
 * This class provides a request control that can be included in an add request
 * to indicate that the server should generate a password for the new account.
 * If the add operation is processed successfully, then the generated password
 * will be included in the {@link GeneratePasswordResponseControl} in the add
 * result.
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
 * The OID for this control is 1.3.6.1.4.1.30221.2.5.58, the criticality may be
 * either {@code true} or {@code false}, and it does not have a value.
 *
 * @see  GeneratePasswordResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GeneratePasswordRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.58) for the generate password request
   * control.
   */
  @NotNull public static final  String GENERATE_PASSWORD_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.58";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5302210626500743525L;



  /**
   * Creates a new generate password request control.  It will be marked
   * critical.
   */
  public GeneratePasswordRequestControl()
  {
    this(true);
  }



  /**
   * Creates a new generate password request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public GeneratePasswordRequestControl(final boolean isCritical)
  {
    super(GENERATE_PASSWORD_REQUEST_OID, isCritical,  null);
  }



  /**
   * Creates a new generate password request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a generate password
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         generate password request control.
   */
  public GeneratePasswordRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GENERATE_PASSWORD_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GENERATE_PASSWORD_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GeneratePasswordRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
