/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a control which can be used to
 * request that the Directory Server include extended information when returning
 * a subschema subentry.  In the Ping Identity, UnboundID, and
 * Nokia/Alcatel-Lucent 8661 Directory Server, this will cause the server to
 * include the X-SCHEMA-FILE extension (which contains the path to the file in
 * which that schema element is defined) and the X-READ-ONLY extension (which
 * indicates whether that schema element is read-only and cannot be altered by
 * external clients).
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
 * This control is not based on any public specification, and has been defined
 * by Ping Identity Corporation  It does not have a value, and may or may not be
 * critical.  It should only be included in search requests.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the procedure to use for requesting the
 * Directory Server schema with extended information.  Note that the
 * {@code LDAPInterface.getSchema} and {@code Schema.getSchema} convenience
 * methods cannot be used because they do not allow you to include controls in
 * the request.
 * <PRE>
 * String schemaDN = Schema.getSubschemaSubentryDN(connection, "");
 * SearchRequest searchRequest = new SearchRequest(schemaDN, SearchScope.BASE,
 *      Filter.createPresenceFilter("objectClass"), "*", "+");
 * searchRequest.addControl(new ExtendedSchemaInfoRequestControl());
 * SearchResult searchResult = connection.search(searchRequest);
 *
 * Schema schema = null;
 * if (searchResult.getEntryCount() == 1)
 * {
 *   schema = new Schema(searchResult.getSearchEntries().get(0));
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExtendedSchemaInfoRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.12) for the extended schema info request
   * control.
   */
  @NotNull public static final String EXTENDED_SCHEMA_INFO_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.12";


  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5668945270252160026L;



  /**
   * Creates a new extended schema info request control.  It will not be
   * marked critical.
   */
  public ExtendedSchemaInfoRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new extended schema info request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public ExtendedSchemaInfoRequestControl(final boolean isCritical)
  {
    super(EXTENDED_SCHEMA_INFO_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new extended schema info request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as an extended schema
   *                  info request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         extended schema info request control.
   */
  public ExtendedSchemaInfoRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_EXTENDED_SCHEMA_INFO_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_EXTENDED_SCHEMA_INFO.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ExtendedSchemaInfoRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
