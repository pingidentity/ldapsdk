/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
 * This class provides an implementation of the subtree delete request control
 * as defined in draft-armijo-ldap-treedelete.  This can be used to delete an
 * entry and all subordinate entries in a single operation.
 * <BR><BR>
 * Normally, if an entry has one or more subordinates, a directory server will
 * refuse to delete it by rejecting the request with a
 * {@link ResultCode#NOT_ALLOWED_ON_NONLEAF} result.  In such cases, it is
 * necessary to first recursively remove all of its subordinates before the
 * target entry can be deleted.  However, this subtree delete request control
 * can be used to request that the server remove the entry and all subordinates
 * as a single operation.  For servers that support this control, it is
 * generally much more efficient and convenient than removing all of the
 * subordinate entries one at a time.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the subtree delete control:
 * <PRE>
 * // First, try to delete an entry that has children, but don't include the
 * // subtree delete control.  This delete attempt should fail, and the
 * // "NOT_ALLOWED_ON_NONLEAF" result is most appropriate if the failure reason
 * // is that the entry has subordinates.
 * DeleteRequest deleteRequest =
 *      new DeleteRequest("ou=entry with children,dc=example,dc=com");
 * LDAPResult resultWithoutControl;
 * try
 * {
 *   resultWithoutControl = connection.delete(deleteRequest);
 *   // We shouldn't get here because the delete should fail.
 * }
 * catch (LDAPException le)
 * {
 *   // This is expected because the entry has children.
 *   resultWithoutControl = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * LDAPTestUtils.assertResultCodeEquals(resultWithoutControl,
 *      ResultCode.NOT_ALLOWED_ON_NONLEAF);
 *
 * // Update the delete request to include the subtree delete request control
 * // and try again.
 * deleteRequest.addControl(new SubtreeDeleteRequestControl());
 * LDAPResult resultWithControl;
 * try
 * {
 *   resultWithControl = connection.delete(deleteRequest);
 *   // The delete should no longer be rejected just because the target entry
 *   // has children.
 * }
 * catch (LDAPException le)
 * {
 *   // The delete still failed for some other reason.
 *   resultWithControl = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * LDAPTestUtils.assertResultCodeEquals(resultWithControl, ResultCode.SUCCESS);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SubtreeDeleteRequestControl
       extends Control
{
  /**
   * The OID (1.2.840.113556.1.4.805) for the subtree delete request control.
   */
  @NotNull public static final String SUBTREE_DELETE_REQUEST_OID =
       "1.2.840.113556.1.4.805";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3748121547717081961L;



  /**
   * Creates a new subtree delete request control.  The control will not be
   * marked critical.
   */
  public SubtreeDeleteRequestControl()
  {
    super(SUBTREE_DELETE_REQUEST_OID, false, null);
  }



  /**
   * Creates a new subtree delete request control.
   *
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   */
  public SubtreeDeleteRequestControl(final boolean isCritical)
  {
    super(SUBTREE_DELETE_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new subtree delete request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a subtree delete
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         subtree delete request control.
   */
  public SubtreeDeleteRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_SUBTREE_DELETE_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SUBTREE_DELETE_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SubtreeDeleteRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
