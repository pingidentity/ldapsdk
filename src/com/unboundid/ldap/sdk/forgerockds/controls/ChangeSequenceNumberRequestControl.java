/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.forgerockds.controls;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.forgerockds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that may be used to
 * request that the server return the replication change sequence number (CSN)
 * that it has assigned to the associated add, delete, modify, or modify DN
 * operation.
 * <BR>
 * This request control has an OID of 1.3.6.1.4.1.42.2.27.9.5.9, the criticality
 * may be either true or false, and it does not have a value.
 *
 * @see ChangeSequenceNumberResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ChangeSequenceNumberRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.9.5.9) for the change sequence number request
   * control.
   */
  @NotNull public static final String CHANGE_SEQUENCE_NUMBER_REQUEST_OID =
       "1.3.6.1.4.1.42.2.27.9.5.9";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3753511587752899510L;



  /**
   * Creates a new change sequence number  request control.  It will not be
   * marked critical.
   */
  public ChangeSequenceNumberRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new change sequence number request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public ChangeSequenceNumberRequestControl(final boolean isCritical)
  {
    super(CHANGE_SEQUENCE_NUMBER_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new change sequence number request control that is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a change sequence
   *                  number request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         change sequence number  request control.
   */
  public ChangeSequenceNumberRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSN_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_CSN_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ChangeSequenceNumberRequestControl()");
  }
}
