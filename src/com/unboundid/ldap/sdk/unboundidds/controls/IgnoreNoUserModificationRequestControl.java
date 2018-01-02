/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of an LDAP control that can be used to
 * request that the Directory Server ignore the NO-USER-MODIFICATION flag for
 * attribute types.  It may be included in an add request to allow the client to
 * include attributes which are not normally allowed to be externally specified
 * (e.g., entryUUID, creatorsName, modifiersName, etc.).  This control does not
 * have a value, and there is no corresponding response control.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for attempting to perform an
 * add operation including the ignore NO-USER-MODIFICATION control so that an
 * entry can be added which already includes the creatorsName and
 * createTimestamp attributes:
 * <PRE>
 * AddRequest addRequest = new AddRequest("dc=example,dc=com",
 *      new Attribute("objectClass", "top", "domain"),
 *      new Attribute("dc", "example"),
 *      new Attribute("creatorsName", "cn=Admin User DN"),
 *      new Attribute("createTimestamp", "20080101000000Z"));
 * addRequest.addControl(new IgnoreNoUserModificationRequestControl());
 *
 * try
 * {
 *   LDAPResult result = connection.add(addRequest);
 *   // The entry was added successfully.
 * }
 * catch (LDAPException le)
 * {
 *   // The attempt to add the entry failed.
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IgnoreNoUserModificationRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.5) for the ignore NO-USER-MODIFICATION
   * request control.
   */
  public static final String IGNORE_NO_USER_MODIFICATION_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.5";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2622432059171073555L;



  /**
   * Creates a new ignore NO-USER-MODIFICATION request control.  It will be
   * marked critical.
   */
  public IgnoreNoUserModificationRequestControl()
  {
    super(IGNORE_NO_USER_MODIFICATION_REQUEST_OID, true, null);
  }



  /**
   * Creates a new ignore NO-USER-MODIFICATION request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as an ignore
   *                  NO-USER-MODIFICATION request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         ignore NO-USER-MODIFICATION request control.
   */
  public IgnoreNoUserModificationRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_IGNORENUM_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_IGNORE_NO_USER_MODIFICATION_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("IgnoreNoUserModificationRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
