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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.forgerockds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that may be used to
 * provide the replication change sequence number (CSN) in the response to an
 * add, delete, modify, or modify DN request that included the change sequence
 * number request control.
 * <BR>
 * This response control has an OID of 1.3.6.1.4.1.42.2.27.9.5.9, and the value
 * is the string representation of the change sequence number.  As with all
 * response controls, the criticality should be false.
 *
 * @see  ChangeSequenceNumberRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ChangeSequenceNumberResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.9.5.9) for the change sequence number response
   * control.
   */
  @NotNull public static final String CHANGE_SEQUENCE_NUMBER_RESPONSE_OID =
       "1.3.6.1.4.1.42.2.27.9.5.9";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1107845623167919411L;



  // The change sequence number returned by the server.
  @NotNull private final String csn;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  ChangeSequenceNumberResponseControl()
  {
    csn = null;
  }



  /**
   * Creates a new change sequence number response control with the provided
   * CSN.
   *
   * @param  csn  The change sequence number returned by the server.  It must
   *              not be {@code null}.
   */
  public ChangeSequenceNumberResponseControl(@NotNull final String csn)
  {
    super(CHANGE_SEQUENCE_NUMBER_RESPONSE_OID, false,
          new ASN1OctetString(csn));

    Validator.ensureNotNull(csn);

    this.csn = csn;
  }



  /**
   * Creates a new change sequence number response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         change sequence number response control.
   */
  public ChangeSequenceNumberResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CSN_RESPONSE_NO_VALUE.get());
    }
    else
    {
      csn = value.stringValue();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ChangeSequenceNumberResponseControl
              decodeControl(@NotNull final String oid, final boolean isCritical,
                            @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new ChangeSequenceNumberResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a change sequence number response control from the provided
   * result.
   *
   * @param  result  The result from which to retrieve the change sequence
   *                 number response control.
   *
   * @return  The change sequence number response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          change sequence number response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the change sequence number response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static ChangeSequenceNumberResponseControl get(
              @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(CHANGE_SEQUENCE_NUMBER_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ChangeSequenceNumberResponseControl)
    {
      return (ChangeSequenceNumberResponseControl) c;
    }
    else
    {
      return new ChangeSequenceNumberResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Retrieves the CSN returned by the server.
   *
   * @return  The CSN returned by the server.
   */
  @NotNull()
  public String getCSN()
  {
    return csn;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_CSN_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ChangeSequenceNumberResponseControl(csn='");
    buffer.append(csn);
    buffer.append("')");
  }
}
