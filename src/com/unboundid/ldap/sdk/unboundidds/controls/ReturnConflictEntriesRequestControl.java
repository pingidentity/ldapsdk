/*
 * Copyright 2012-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2023 Ping Identity Corporation
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
 * Copyright (C) 2012-2023 Ping Identity Corporation
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
 * This class defines a request control that may be included in a search request
 * to indicate that the server should include replication conflict entries in
 * the set of search result entries.
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
 * This control is not based on any public standard.  It was originally
 * developed for use with the Ping Identity, UnboundID, and Nokia/Alcatel-Lucent
 * 8661 Directory Server.  It does not have a value.
 * <BR><BR>
 * There is no corresponding response control.  Replication conflict entries may
 * be identified by the object class "ds-sync-conflict-entry".
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReturnConflictEntriesRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.13) for the return conflict entries request
   * control.
   */
  @NotNull public static final String RETURN_CONFLICT_ENTRIES_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.13";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7688556660280234650L;



  /**
   * Creates a new return conflict entries request control.  It will be marked
   * critical.
   */
  public ReturnConflictEntriesRequestControl()
  {
    this(true);
  }



  /**
   * Creates a new return conflict entries request control.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public ReturnConflictEntriesRequestControl(final boolean isCritical)
  {
    super(RETURN_CONFLICT_ENTRIES_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new return conflict entries request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a return conflict
   *                  entries request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         return conflict entries request control.
   */
  public ReturnConflictEntriesRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RETURN_CONFLICT_ENTRIES_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_RETURN_CONFLICT_ENTRIES_REQUEST.get();
  }



  /**
   * Retrieves a representation of this return conflict entries request control
   * as a JSON object.  The JSON object uses the following fields (note that
   * since this control does not have a value, neither the {@code value-base64}
   * nor {@code value-json} fields may be present):
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the return conflict entries request
   *     control, the OID is "1.3.6.1.4.1.30221.2.5.13".
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
              RETURN_CONFLICT_ENTRIES_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_RETURN_CONFLICT_ENTRIES_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * return conflict entries request control.
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
   * @return  The return conflict entries request control that was decoded from
   *          the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid return conflict entrie request control.
   */
  @NotNull()
  public static ReturnConflictEntriesRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, false, false);

    return new ReturnConflictEntriesRequestControl(
         jsonControl.getCriticality());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReturnConflictEntriesRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
