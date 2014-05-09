/*
 * Copyright 2009-2013 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2013 UnboundID Corp.
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
 * control to remove a value of "test" from the description attribute, or to do
 * nothing if that value is not contained in the entry.
 * <PRE>
 *   Modification mod = new Modification(ModificationType.DELETE,
 *        "description", "test");
 *   ModifyRequest modifyRequest = new ModifyRequest(
 *        "uid=john.doe,ou=People,dc=example,dc=com", mod);
 *   modifyRequest.addControl(new PermissiveModifyRequestControl());
 *   LDAPResult modifyResult = connection.modify(modifyRequest);
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
  public static final String PERMISSIVE_MODIFY_REQUEST_OID =
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
  public PermissiveModifyRequestControl(final Control control)
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
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PERMISSIVE_MODIFY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PermissiveModifyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
