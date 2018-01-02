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
 * This class provides an implementation of the virtual attributes only request
 * control, which may be included in a search request to indicate that only
 * virtual attributes should be included in matching entries.
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
 * This control is not based on any public standard, but was first introduced in
 * the Netscape/iPlanet Directory Server.  It is also supported in the Sun Java
 * System Directory Server, OpenDS, and the Ping Identity, UnboundID, and
 * Alcatel-Lucent 8661 Directory Server.  It does not have a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the virtual attributes only
 * request control:
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"));
 *
 * searchRequest.addControl(new VirtualAttributesOnlyRequestControl());
 * SearchResult searchResult = connection.search(searchRequest);
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VirtualAttributesOnlyRequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.19) for the virtual attributes only request
   * control.
   */
  public static final String VIRTUAL_ATTRIBUTES_ONLY_REQUEST_OID =
       "2.16.840.1.113730.3.4.19";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1509094615426408618L;



  /**
   * Creates a new virtual attributes only request control.  It will not be
   * marked critical.
   */
  public VirtualAttributesOnlyRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new virtual attributes only request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public VirtualAttributesOnlyRequestControl(final boolean isCritical)
  {
    super(VIRTUAL_ATTRIBUTES_ONLY_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new virtual attributes only request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a virtual attributes
   *                  only request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         virtual attributes only request control.
   */
  public VirtualAttributesOnlyRequestControl(final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VIRTUAL_ATTRS_ONLY_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_VIRTUAL_ATTRS_ONLY_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("VirtualAttributesOnlyRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
