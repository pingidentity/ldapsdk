/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a search result listener that will collect the DNs of
 * entries matching a set of search criteria.
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
@ThreadSafety(level= ThreadSafetyLevel.NOT_THREADSAFE)
final class LDAPDeleteSearchListener
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2185398520482379634L;



  // A reference to the return code that should be used for the tool.
  @NotNull private final AtomicReference<ResultCode> returnCode;

  // A reference to the associated LDAPDelete tool instance.
  @NotNull private final LDAPDelete ldapDelete;

  // A string representation of the search base DN.
  @NotNull private final String baseDN;

  // A string representation of the search filter.
  @NotNull private final String filter;

  // The that will be updated with the DNs of entries matching an associated
  // search.
  @NotNull private final TreeSet<DN> dnSet;



  /**
   * Creates a new search result listener with the provided information.
   *
   * @param  ldapDelete  A reference to the associated {@code LDAPDelete} tool
   *                     instance.  It must not be {@code null}.
   * @param  dnSet       A set that should be updated with the DNs of all
   *                     matching entries.  It must not be {@code null} and must
   *                     be updatable.
   * @param  returnCode  A reference that may be updated with the result code of
   *                     a failed operation if a problem occurs.  It must not be
   *                     {@code null} but may be unset.
   * @param  baseDN      The string representation base DN for the search being
   *                     processed.  It must not be {@code null}.
   * @param  filter      The string representation of the filter for the search
   *                     being processed.  It must not be {@code null}.
   */
  LDAPDeleteSearchListener(@NotNull final LDAPDelete ldapDelete,
       @NotNull final TreeSet<DN> dnSet,
       @NotNull final String baseDN,
       @NotNull final String filter,
       @NotNull final AtomicReference<ResultCode> returnCode)
  {
    this.ldapDelete = ldapDelete;
    this.baseDN = baseDN;
    this.filter = filter;
    this.dnSet = dnSet;
    this.returnCode = returnCode;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
     try
    {
      dnSet.add(searchEntry.getParsedDN());
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      ldapDelete.commentToErr(
           ERR_LDAPDELETE_SEARCH_LISTENER_CANNOT_PARSE_ENTRY_DN.get(
                baseDN, filter, searchEntry.getDN(),
                StaticUtils.getExceptionMessage(e)));
      returnCode.compareAndSet(null, e.getResultCode());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    returnCode.compareAndSet(null, ResultCode.REFERRAL);
    ldapDelete.commentToErr(ERR_LDAPDELETE_SEARCH_LISTENER_REFERENCE.get(
         baseDN, filter, String.valueOf(searchReference)));
  }
}
