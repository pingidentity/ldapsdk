/*
 * Copyright 2008-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2025 Ping Identity Corporation
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
 * Copyright (C) 2008-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP no-op control as defined in
 * draft-zeilenga-ldap-noop.  This control may be included in an add, delete,
 * modify, or modify DN request to indicate that the server should validate the
 * request but not actually make any changes to the data.  It allows the client
 * to verify that the operation would likely succeed (including schema
 * validation, access control checks, and other processing) without making any
 * changes to the server data.
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
 * Note that an operation which includes the no-op control will never have a
 * {@link ResultCode#SUCCESS} result.  Instead, if the operation would likely
 * have completed successfully if the no-op control had not been included, then
 * the server will include a response with the {@link ResultCode#NO_OPERATION}
 * result.  If the operation would not have been successful, then the result
 * code in the response will be the appropriate result code for that failure.
 * Note that if the response from the server includes the
 * {@link ResultCode#NO_OPERATION} result, then the LDAP SDK will not throw an
 * exception but will instead return the response in an
 * {@link com.unboundid.ldap.sdk.LDAPResult} object.  There is no corresponding
 * response control.
 * <BR><BR>
 * Note that at the time this control was written, the latest version of the
 * specification may be found in draft-zeilenga-ldap-noop-11.  This version of
 * the document does not explicitly specify either the OID that should be used
 * for the control, or the result code that should be used for the associated
 * operation if all other processing is completed successfully but no changes
 * are made as a result of this control.  Until such time as these are defined,
 * this implementation uses the OID temporarily assigned for its use by the
 * OpenLDAP Foundation, which is used by at least the OpenLDAP, OpenDS, and the
 * Ping Identity, UnboundID, and Nokia/Alcatel-Lucent 8661 Directory Server
 * implementations.
 * <BR><BR>
 * This control has an OID of 1.3.6.1.4.1.4203.1.10.2 and a criticality of true.
 * It does not have a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for attempting to perform a
 * modify operation including the LDAP no-op control so that the change is not
 * actually applied:
 * <PRE>
 * ModifyRequest modifyRequest = new ModifyRequest("dc=example,dc=com",
 *      new Modification(ModificationType.REPLACE, "description",
 *           "new value"));
 * modifyRequest.addControl(new NoOpRequestControl());
 *
 * try
 * {
 *   LDAPResult result = connection.modify(modifyRequest);
 *   if (result.getResultCode() == ResultCode.NO_OPERATION)
 *   {
 *     // The modify would likely have succeeded.
 *   }
 *   else
 *   {
 *     // The modify would likely have failed.
 *   }
 * }
 * catch (LDAPException le)
 * {
 *   // The modify attempt failed even with the no-op control.
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NoOpRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.4203.1.10.2) for the LDAP no-op request control.
   */
  @NotNull public static final String NO_OP_REQUEST_OID =
       "1.3.6.1.4.1.4203.1.10.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7435407787971958294L;



  /**
   * Creates a new no-op request control.  It will be marked critical, as
   * required by the control specification.
   */
  public NoOpRequestControl()
  {
    super(NO_OP_REQUEST_OID, true, null);
  }



  /**
   * Creates a new no-op request control which is decoded from the provided
   * generic control.
   *
   * @param  control  The generic control to be decoded as a no-op request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         no-op request control.
   */
  public NoOpRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_NOOP_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_NOOP_REQUEST.get();
  }



  /**
   * Retrieves a representation of this no-op request control as a JSON object.
   * The JSON object uses the following fields (note that since this control
   * does not have a value, neither the {@code value-base64} nor
   * {@code value-json} fields may be present):
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the no-op request control, the OID is
   *     "1.3.6.1.4.1.4203.1.10.2".
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
              NO_OP_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_NOOP_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a no-op
   * request control.
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
   * @return  The no-op request control that was decoded from the provided JSON
   *          object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid no-op request control.
   */
  @NotNull()
  public static NoOpRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, false, false);

    return new NoOpRequestControl();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("NoOpRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
