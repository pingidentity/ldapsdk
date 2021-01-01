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
 * This class provides an implementation of the LDAP don't use copy control as
 * defined in <A HREF="http://www.rfc-editor.org/rfc/rfc6171.txt">RFC 6171</A>.
 * This control may be used to request that only an authoritative directory
 * server be used to process the associated search or compare request, and that
 * the request should not be processed on a directory that may contain data
 * that is cached or potentially stale.  If the client includes this control in
 * a request sent to a non-authoritative server, then that server may send a
 * referral to the authoritative server, or it may simply reject the request.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DontUseCopyRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.1.22) for the don't use copy request control.
   */
  @NotNull public static final String DONT_USE_COPY_REQUEST_OID =
       "1.3.6.1.1.22";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5352797941017941217L;



  /**
   * Creates a new don't use copy request control.  The control will be marked
   * critical.
   */
  public DontUseCopyRequestControl()
  {
    super(DONT_USE_COPY_REQUEST_OID, true, null);
  }



  /**
   * Creates a new don't use copy request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a don't use copy
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         don't use copy request control.
   */
  public DontUseCopyRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DONT_USE_COPY_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_DONT_USE_COPY.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DontUseCopyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
