/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.forgerockds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control that can be used to
 * establish an affinity for one or more operations through a ForgeRock
 * Directory Proxy Server.  The server will attempt to route operations with
 * the same affinity value to the same backend server.
 * <BR>
 * This request control has an OID of 1.3.6.1.4.1.36733.2.1.5.2, and its value
 * is the desired affinity value (which may be an arbitrary string or set of
 * bytes, and the LDAP SDK may automatically generate an affinity value if none
 * is provided).  The criticality may be either true or false.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AffinityRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.36733.2.1.5.2) for the affinity request control.
   */
  @NotNull public static final String AFFINITY_REQUEST_OID =
       "1.3.6.1.4.1.36733.2.1.5.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7792760251213801179L;



  // The affinity value to use for this control.
  @NotNull private final ASN1OctetString affinityValue;



  /**
   * Creates a new affinity request control with the specified criticality and
   * a randomly generated affinity value.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public AffinityRequestControl(final boolean isCritical)
  {
    this(isCritical, new ASN1OctetString(StaticUtils.randomBytes(5, true)));
  }



  /**
   * Creates a new affinity request control with the specified criticality and
   * the provided affinity value.
   *
   * @param  isCritical     Indicates whether the control should be marked
   *                        critical.
   * @param  affinityValue  The affinity value to use for the control.  It must
   *                        not be {@code null}.
   */
  public AffinityRequestControl(final boolean isCritical,
                                @NotNull final String affinityValue)
  {
    this(isCritical, new ASN1OctetString(affinityValue));
  }



  /**
   * Creates a new affinity request control with the specified criticality and
   * the provided affinity value.
   *
   * @param  isCritical     Indicates whether the control should be marked
   *                        critical.
   * @param  affinityValue  The affinity value to use for the control.  It must
   *                        not be {@code null}.
   */
  public AffinityRequestControl(final boolean isCritical,
                                @NotNull final byte[] affinityValue)
  {
    this(isCritical, new ASN1OctetString(affinityValue));
  }



  /**
   * Creates a new affinity request control with the specified criticality and
   * the provided affinity value.
   *
   * @param  isCritical     Indicates whether the control should be marked
   *                        critical.
   * @param  affinityValue  The affinity value to use for the control.  It must
   *                        not be {@code null}.
   */
  public AffinityRequestControl(final boolean isCritical,
                                @NotNull final ASN1OctetString affinityValue)
  {
    super(AFFINITY_REQUEST_OID, isCritical, affinityValue);

    this.affinityValue = affinityValue;
  }



  /**
   * Creates a new affinity request control that is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as an affinity request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         affinity request control.
   */
  public AffinityRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    affinityValue = control.getValue();
    if (affinityValue == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_AFFINITY_REQUEST_MISSING_VALUE.get());
    }
  }



  /**
   * Retrieves the affinity value for this control.
   *
   * @return  The affinity value for this control.
   */
  @NotNull()
  public ASN1OctetString getAffinityValue()
  {
    return affinityValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_AFFINITY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AffinityRequestControl(");

    final byte[] affinityValueBytes = affinityValue.getValue();
    if (StaticUtils.isLikelyDisplayableUTF8String(affinityValueBytes))
    {
      buffer.append("affinityValueString='");
      buffer.append(affinityValue.stringValue());
    }
    else
    {
      buffer.append("affinityValueBytes='");
      StaticUtils.toHex(affinityValueBytes, buffer);
    }

    buffer.append("')");
  }
}
