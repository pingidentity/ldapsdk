/*
 * Copyright 2009-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2025 Ping Identity Corporation
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
 * Copyright (C) 2009-2025 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of the unsolicited cancel response
 * control, which may be returned by the Directory Server if an operation is
 * canceled by the server without a cancel or abandon request from the client.
 * This control does not have a value.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UnsolicitedCancelResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.7) for the unsolicited cancel response
   * control.
   */
  @NotNull public static final String UNSOLICITED_CANCEL_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.7";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 36962888392922937L;



  /**
   * Creates a new unsolicited cancel response control.
   */
  public UnsolicitedCancelResponseControl()
  {
    super(UNSOLICITED_CANCEL_RESPONSE_OID, false, null);
  }



  /**
   * Creates a new account usable response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         account usable response control.
   */
  public UnsolicitedCancelResponseControl(@NotNull final String oid,
                                          final boolean isCritical,
                                          @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value != null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_UNSOLICITED_CANCEL_RESPONSE_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnsolicitedCancelResponseControl decodeControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new UnsolicitedCancelResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts an unsolicited cancel response control from the provided result.
   *
   * @param  result  The result from which to retrieve the unsolicited cancel
   *                 response control.
   *
   * @return  The unsolicited cancel response control contained in the provided
   *          result, or {@code null} if the result did not contain an
   *          unsolicited cancel response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the unsolicited cancel response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static UnsolicitedCancelResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(UNSOLICITED_CANCEL_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof UnsolicitedCancelResponseControl)
    {
      return (UnsolicitedCancelResponseControl) c;
    }
    else
    {
      return new UnsolicitedCancelResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_UNSOLICITED_CANCEL_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this unsolicited cancel response control as a
   * JSON object.  The JSON object uses the following fields (note that since
   * this control does not have a value, neither the {@code value-base64} nor
   * {@code value-json} fields may be present):
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the unsolicited cancel response
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.7".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              UNSOLICITED_CANCEL_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_UNSOLICITED_CANCEL_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of an
   * unsolicited cancel response control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The unsolicited cancel response control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid unsolicited cancel response control.
   */
  @NotNull()
  public static UnsolicitedCancelResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, false, false);

    return new UnsolicitedCancelResponseControl();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UnsolicitedCancelResponseControl()");
  }
}
