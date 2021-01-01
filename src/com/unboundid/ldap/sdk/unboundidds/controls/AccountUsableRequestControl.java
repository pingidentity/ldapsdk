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
 * This class provides an implementation of the account usable request control.
 * It may be included in search requests, in which case each search result entry
 * matching that request should include the corresponding response control to
 * obtain information about the usability of the user account associated with
 * that entry.  In particular, it indicates whether a bind with valid
 * credentials would likely succeed and the resulting connection would be
 * usable, and if not the reason for the potential failure.  See the
 * {@link AccountUsableResponseControl} for information about the information
 * that is taken into account.
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
 * This control was designed by Sun Microsystems and is not based on any RFC or
 * Internet draft.  It does not include a value.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the account usable controls to
 * determine whether the account for user with uid "john.doe" is usable:
 * <PRE>
 * SearchRequest searchRequest =
 *      new SearchRequest("dc=example,dc=com", SearchScope.SUB,
 *           Filter.createEqualityFilter("uid", "john.doe"));
 * searchRequest.addControl(new AccountUsableRequestControl());
 * SearchResult searchResult = connection.search(searchRequest);
 *
 * boolean isUsable = false;
 * for (SearchResultEntry entry : searchResult.getSearchEntries())
 * {
 *   AccountUsableResponseControl c =
 *        AccountUsableResponseControl.get(entry);
 *   isUsable = c.isUsable();
 *   if (isUsable)
 *   {
 *     // The account is usable.
 *   }
 *   else
 *   {
 *     // The account is not usable.
 *     List&lt;String&gt; unusableReasons = c.getUnusableReasons();
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AccountUsableRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.9.5.8) for the account usable request control.
   */
  @NotNull public static final String ACCOUNT_USABLE_REQUEST_OID =
       "1.3.6.1.4.1.42.2.27.9.5.8";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2776055961624360982L;



  /**
   * Creates a new account usable request control.  It will not be marked
   * critical.
   */
  public AccountUsableRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new account usable request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public AccountUsableRequestControl(final boolean isCritical)
  {
    super(ACCOUNT_USABLE_REQUEST_OID, isCritical,  null);
  }



  /**
   * Creates a new account usable request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as an account usable
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         account usable request control.
   */
  public AccountUsableRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_ACCOUNT_USABLE_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ACCOUNT_USABLE_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AccountUsableRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
