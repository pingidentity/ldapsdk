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
 * This class provides a request control which may be included in a delete or
 * modify DN request to indicate that the server should skip any referential
 * integrity processing that would have otherwise been done for that operation.
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
 * The request control has an OID of "1.3.6.1.4.1.30221.2.5.30" and does not
 * have a value.  The criticality for this control may be either {@code TRUE}
 * or {@code FALSE}, which may impact whether a server will process the
 * associated modify DN or delete operation if the server does not support the
 * use of this control.  If a server receives a critical control that it does
 * not support for the associated operation, then it will return a failure
 * result without attempting to process that operation.  If a server receives
 * a non-critical control that it does not support for the associated operation,
 * then it will process the operation as if that control had not been provided.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SuppressReferentialIntegrityUpdatesRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.30) for the suppress referential integrity
   * updates request control.
   */
  @NotNull public static final String SUPPRESS_REFINT_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.30";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4761880447993567116L;



  /**
   * Creates a new suppress referential integrity updates request control.  It
   * will be critical.
   */
  public SuppressReferentialIntegrityUpdatesRequestControl()
  {
    this(true);
  }



  /**
   * Creates a new suppress referential integrity updates request control.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public SuppressReferentialIntegrityUpdatesRequestControl(
              final boolean isCritical)
  {
    super(SUPPRESS_REFINT_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new suppress referential integrity updates request control which
   * is decoded from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a suppress
   *                  referential integrity updates request control.
   *
   * @throws LDAPException  If the provided control cannot be decoded as a
   *                         suppress referential integrity updates request
   *                         control.
   */
  public SuppressReferentialIntegrityUpdatesRequestControl(
              @NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUPPRESS_REFINT_REQUEST_CONTROL_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SUPPRESS_REFINT_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SuppressReferentialIntegrityUpdatesRequestControl(" +
         "isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
