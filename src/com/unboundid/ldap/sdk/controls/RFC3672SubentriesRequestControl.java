/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP subentries request control
 * as defined in RFC 3672.  It may be included in a search request to indicate
 * that entries with the {@code ldapSubEntry} object class should be included in
 * the search results.  The value of the control indicates whether entries
 * matching the filter but not containing that object class (but ) should also
 * be returned.
 * <BR><BR>
 * Entries containing the {@code ldapSubentry} object class are special in that
 * they are normally excluded from search results, unless the target entry is
 * requested with a base-level search.  They are used to store operational
 * information that controls how the server should behave rather than user data.
 * Because they do not hold user data, it is generally desirable to have them
 * excluded from search results, but for cases in which a client needs to
 * retrieve such an entry, then this subentries request control may be included
 * in the search request.  This control differs from the
 * {@link DraftLDUPSubentriesRequestControl} in that you can optionally also
 * return entries that do not contain the {@code ldapSubEntry} object class,
 * whereas the {@code DraftLDUPSubentriesRequestControl} will cause only
 * subentries to be returned.
 * <BR><BR>
 * There is no corresponding response control.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example illustrates the use of the subentries request control
 * to retrieve subentries that may not otherwise be returned.
 * <PRE>
 * // First, perform a search to retrieve an entry with a cn of "test subentry"
 * // but without including the subentries request control.  This should not
 * // return any matching entries.
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("cn", "test subentry"));
 * SearchResult resultWithoutControl = connection.search(searchRequest);
 * LDAPTestUtils.assertResultCodeEquals(resultWithoutControl,
 *      ResultCode.SUCCESS);
 * LDAPTestUtils.assertEntriesReturnedEquals(resultWithoutControl, 0);
 *
 * // Update the search request to add a subentries request control so that
 * // subentries should be included in search results.  This should cause the
 * // subentry to be returned.
 * searchRequest.addControl(new RFC3672SubentriesRequestControl(true));
 * SearchResult resultWithControl = connection.search(searchRequest);
 * LDAPTestUtils.assertResultCodeEquals(resultWithControl, ResultCode.SUCCESS);
 * LDAPTestUtils.assertEntriesReturnedEquals(resultWithControl, 1);
 * </PRE>
 *
 * @see  DraftLDUPSubentriesRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RFC3672SubentriesRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.4203.1.10.1) for the LDAP subentries request control.
   */
  @NotNull public static final String SUBENTRIES_REQUEST_OID =
       "1.3.6.1.4.1.4203.1.10.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3780729008801136950L;



  // Indicates whether to return only entries with the ldapSubEntry object
  // class.
  private final boolean returnOnlySubEntries;



  /**
   * Creates a new subentries request control.  it will not be marked critical.
   *
   * @param  returnOnlySubEntries  Indicates whether to return only matching
   *                               entries that contain the {@code ldapSubEntry}
   *                               object class.  If this is {@code true}, then
   *                               only subentries will be returned.  If this is
   *                               {@code false}, then both both regular entries
   *                               and subentries may be returned.
   */
  public RFC3672SubentriesRequestControl(final boolean returnOnlySubEntries)
  {
    this(returnOnlySubEntries, false);
  }



  /**
   * Creates a new subentries request control with the specified criticality.
   *
   * @param  returnOnlySubEntries  Indicates whether to return only matching
   *                               entries that contain the {@code ldapSubEntry}
   *                               object class.  If this is {@code true}, then
   *                               only subentries will be returned.  If this is
   *                               {@code false}, then both both regular entries
   *                               and subentries may be returned.
   * @param  isCritical            Indicates whether this control should be
   *                               marked critical.
   */
  public RFC3672SubentriesRequestControl(final boolean returnOnlySubEntries,
                                         final boolean isCritical)
  {
    super(SUBENTRIES_REQUEST_OID, isCritical,
         new ASN1OctetString(new ASN1Boolean(returnOnlySubEntries).encode()));

    this.returnOnlySubEntries = returnOnlySubEntries;
  }



  /**
   * Creates a new subentries request control which is decoded from the provided
   * generic control.
   *
   * @param  control  The generic control to be decoded as a subentries request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         subentries request control.
   */
  public RFC3672SubentriesRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    if (! control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUBENTRIES_MISSING_VALUE.get());
    }

    try
    {
      returnOnlySubEntries =  ASN1Boolean.decodeAsBoolean(
           control.getValue().getValue()).booleanValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SUBENTRIES_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Indicates whether the server should only return matching entries that have
   * the {@code ldapSubEntry} object class.
   *
   * @return  {@code true} if the server should only return matching entries
   *          that contain the {@code ldapSubEntry} object class, or
   *          {@code false} if the server may return both regular entries and
   *          subentries.
   */
  public boolean returnOnlySubEntries()
  {
    return returnOnlySubEntries;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_SUBENTRIES_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RFC3672SubentriesRequestControl(returnOnlySubEntries=");
    buffer.append(returnOnlySubEntries);
    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
