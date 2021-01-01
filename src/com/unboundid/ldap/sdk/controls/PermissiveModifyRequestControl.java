/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
 * This class provides an implementation of the permissive modify request
 * control, which is supported by a number of servers and may be included in a
 * modify request to indicate that the server should not reject a modify
 * request which attempts to add an attribute value which already exists or
 * remove an attribute value which does not exist.  Normally, such modification
 * attempts would be rejected.
 * <BR><BR>
 * The OID for this control is "1.2.840.113556.1.4.1413".  It does not have a
 * value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the permissive modify request
 * control to process a modification that attempts to add an attribute value
 * to an entry that already contains that value.
 * <PRE>
 * // Ensure that we start with a known description value in the test entry
 * // by using a replace to overwrite any existing value(s).
 * ModifyRequest replaceRequest = new ModifyRequest(
 *      "uid=test.user,ou=People,dc=example,dc=com",
 *      new Modification(ModificationType.REPLACE, "description", "value"));
 * LDAPResult replaceResult = connection.modify(replaceRequest);
 *
 * // Create a modify request that will attempt to add the value that already
 * // exists.  If we attempt to do this without the permissive modify control,
 * // the attempt should fail.
 * ModifyRequest addExistingValueRequest = new ModifyRequest(
 *      "uid=test.user,ou=People,dc=example,dc=com",
 *      new Modification(ModificationType.ADD, "description", "value"));
 * LDAPResult addExistingValueResultWithoutControl;
 * try
 * {
 *   addExistingValueResultWithoutControl =
 *        connection.modify(addExistingValueRequest);
 *   // We shouldn't get here because the attempt to add the existing value
 *   // should fail.
 * }
 * catch (LDAPException le)
 * {
 *   // We expected this failure because the value we're trying to add already
 *   // exists in the entry.
 *   addExistingValueResultWithoutControl = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 *
 * // Update the modify request to include the permissive modify request
 * // control, and re-send the request.  The operation should now succeed.
 * addExistingValueRequest.addControl(new PermissiveModifyRequestControl());
 * LDAPResult addExistingValueResultWithControl;
 * try
 * {
 *   addExistingValueResultWithControl =
 *        connection.modify(addExistingValueRequest);
 *   // If we've gotten here, then the modification was successful.
 * }
 * catch (LDAPException le)
 * {
 *   // If we've gotten here, then the modification failed for some reason.
 *   addExistingValueResultWithControl = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PermissiveModifyRequestControl
       extends Control
{
  /**
   * The OID (1.2.840.113556.1.4.1413) for the permissive modify request
   * control.
   */
  @NotNull public static final String PERMISSIVE_MODIFY_REQUEST_OID =
       "1.2.840.113556.1.4.1413";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2599039772002106760L;



  /**
   * Creates a new permissive modify request control.  The control will not be
   * marked critical.
   */
  public PermissiveModifyRequestControl()
  {
    super(PERMISSIVE_MODIFY_REQUEST_OID, false, null);
  }



  /**
   * Creates a new permissive modify request control.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public PermissiveModifyRequestControl(final boolean isCritical)
  {
    super(PERMISSIVE_MODIFY_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new permissive modify request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a permissive modify
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         permissive modify request control.
   */
  public PermissiveModifyRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PERMISSIVE_MODIFY_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PERMISSIVE_MODIFY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PermissiveModifyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
