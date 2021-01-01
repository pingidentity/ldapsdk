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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.controls.ControlMessages.*;



/**
 * This class provides an implementation of the LDAP virtual list view (VLV)
 * request control as defined in draft-ietf-ldapext-ldapv3-vlv.  This control
 * may be used to retrieve arbitrary "pages" of entries from the complete set of
 * search results.  It is similar to the {@link SimplePagedResultsControl}, with
 * the exception that the simple paged results control requires scrolling
 * through the results in sequential order, while the VLV control allows
 * starting and resuming at any arbitrary point in the result set.  The starting
 * point may be specified using either a positional offset, or based on the
 * first entry with a value that is greater than or equal to a specified value.
 * <BR><BR>
 * When the start of the result set is to be specified using an offset, then the
 * virtual list view request control should include the following elements:
 * <UL>
 *   <LI>{@code targetOffset} -- The position in the result set of the entry to
 *       target for the next page of results to return.  Note that the offset is
 *       one-based (so the first entry has offset 1, the second entry has offset
 *       2, etc.).</LI>
 *   <LI>{@code beforeCount} -- The number of entries before the entry specified
 *       as the target offset that should be retrieved.</LI>
 *   <LI>{@code afterCount} -- The number of entries after the entry specified
 *       as the target offset that should be retrieved.</LI>
 *   <LI>{@code contentCount} -- The estimated total number of entries that
 *       are in the total result set.  This should be zero for the first request
 *       in a VLV search sequence, but should be the value returned by the
 *       server in the corresponding response control for subsequent searches as
 *       part of the VLV sequence.</LI>
 *   <LI>{@code contextID} -- This is an optional cookie that may be used to
 *       help the server resume processing on a VLV search.  It should be absent
 *       from the initial request, but for subsequent requests should be the
 *       value returned in the previous VLV response control.</LI>
 * </UL>
 * When the start of the result set is to be specified using a search string,
 * then the virtual list view request control should include the following
 * elements:
 * <UL>
 *   <LI>{@code assertionValue} -- The value that specifies the start of the
 *       page of results to retrieve.  The target entry will be the first entry
 *       in which the value for the primary sort attribute is greater than or
 *       equal to this assertion value.</LI>
 *   <LI>{@code beforeCount} -- The number of entries before the entry specified
 *        by the assertion value that should be retrieved.</LI>
 *   <LI>{@code afterCount} -- The number of entries after the entry specified
 *       by the assertion value that should be retrieved.</LI>
 *   <LI>{@code contentCount} -- The estimated total number of entries that
 *       are in the total result set.  This should be zero for the first request
 *       in a VLV search sequence, but should be the value returned by the
 *       server in the corresponding response control for subsequent searches as
 *       part of the VLV sequence.</LI>
 *   <LI>{@code contextID} -- This is an optional cookie that may be used to
 *       help the server resume processing on a VLV search.  It should be absent
 *       from the initial request, but for subsequent requests should be the
 *       value returned in the previous VLV response control.</LI>
 * </UL>
 * Note that the virtual list view request control may only be included in a
 * search request if that search request also includes the
 * {@link ServerSideSortRequestControl}.  This is necessary to ensure that a
 * consistent order is used for the resulting entries.
 * <BR><BR>
 * If the search is successful, then the search result done response may include
 * a {@link VirtualListViewResponseControl} to provide information about the
 * state of the virtual list view processing.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the virtual list view request
 * control to iterate through all users, retrieving up to 10 entries at a time:
 * <PRE>
 * // Perform a search to retrieve all users in the server, but only retrieving
 * // ten at a time.  Ensure that the users are sorted in ascending order by
 * // last name, then first name.
 * int numSearches = 0;
 * int totalEntriesReturned = 0;
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("objectClass", "person"));
 * int vlvOffset = 1;
 * int vlvContentCount = 0;
 * ASN1OctetString vlvContextID = null;
 * while (true)
 * {
 *   // Note that the VLV control always requires the server-side sort
 *   // control.
 *   searchRequest.setControls(
 *        new ServerSideSortRequestControl(new SortKey("sn"),
 *             new SortKey("givenName")),
 *        new VirtualListViewRequestControl(vlvOffset, 0, 9, vlvContentCount,
 *             vlvContextID));
 *   SearchResult searchResult = connection.search(searchRequest);
 *   numSearches++;
 *   totalEntriesReturned += searchResult.getEntryCount();
 *   for (SearchResultEntry e : searchResult.getSearchEntries())
 *   {
 *     // Do something with each entry...
 *   }
 *
 *   LDAPTestUtils.assertHasControl(searchResult,
 *        VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID);
 *   VirtualListViewResponseControl vlvResponseControl =
 *        VirtualListViewResponseControl.get(searchResult);
 *   vlvContentCount = vlvResponseControl.getContentCount();
 *   vlvOffset += 10;
 *   vlvContextID = vlvResponseControl.getContextID();
 *   if (vlvOffset &gt; vlvContentCount)
 *   {
 *     break;
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class VirtualListViewRequestControl
       extends Control
{
  /**
   * The OID (2.16.840.1.113730.3.4.9) for the virtual list view request
   * control.
   */
  @NotNull public static final String VIRTUAL_LIST_VIEW_REQUEST_OID =
       "2.16.840.1.113730.3.4.9";



  /**
   * The BER type that will be used for the target element when the target is
   * specified by offset.
   */
  private static final byte TARGET_TYPE_OFFSET = (byte) 0xA0;



  /**
   * The BER type that will be used for the target element when the target is
   * specified by an assertion value.
   */
  private static final byte TARGET_TYPE_GREATER_OR_EQUAL = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4348423177859960815L;



  // The assertion value that will be used to identify the start of the
  // requested page of results for a greater-or-equal target type.
  @Nullable private final ASN1OctetString assertionValue;

  // The context ID that may be used to help the server continue in the same
  // result set for subsequent searches.
  @Nullable private final ASN1OctetString contextID;

  // The maximum number of entries to return after the target entry.
  private final int afterCount;

  // The maximum number of entries to return before the target entry.
  private final int beforeCount;

  // The estimated number of entries in the complete result set.
  private final int contentCount;

  // The position of the entry at the start of the requested page of results for
  // an offset-based target type.
  private final int targetOffset;



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by a target offset.  It will be marked
   * critical.
   *
   * @param  targetOffset  The position of the entry that should be used as the
   *                       start of the result set.
   * @param  beforeCount   The maximum number of entries that should be returned
   *                       before the entry with the specified target offset.
   * @param  afterCount    The maximum number of entries that should be returned
   *                       after the entry with the specified target offset.
   * @param  contentCount  The estimated number of entries in the result set.
   *                       For the first request in a series of searches with
   *                       the VLV control, it should be zero.  For subsequent
   *                       searches in the VLV sequence, it should be the
   *                       content count included in the response control from
   *                       the previous search.
   * @param  contextID     The context ID that may be used to help the server
   *                       continue in the same result set for subsequent
   *                       searches.  For the first request in a series of
   *                       searches with the VLV control, it should be
   *                       {@code null}.  For subsequent searches in the VLV
   *                       sequence, it should be the (possibly {@code null})
   *                       context ID included in the response control from the
   *                       previous search.
   */
  public VirtualListViewRequestControl(final int targetOffset,
              final int beforeCount, final int afterCount,
              final int contentCount,
              @Nullable final ASN1OctetString contextID)
  {
    this(targetOffset, beforeCount, afterCount, contentCount, contextID, true);
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by an assertion value.  It will be marked
   * critical.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.  It must not be {@code null}.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   */
  public VirtualListViewRequestControl(@NotNull final String assertionValue,
              final int beforeCount, final int afterCount,
              @Nullable final ASN1OctetString contextID)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
         contextID, true);
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by an assertion value.  It will be marked
   * critical.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.  It must not be {@code null}.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   */
  public VirtualListViewRequestControl(@NotNull final byte[] assertionValue,
              final int beforeCount, final int afterCount,
              @Nullable final ASN1OctetString contextID)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
         contextID, true);
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by an assertion value.  It will be marked
   * critical.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.  It must not be {@code null}.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   */
  public VirtualListViewRequestControl(
              @NotNull final ASN1OctetString assertionValue,
              final int beforeCount, final int afterCount,
              @Nullable final ASN1OctetString contextID)
  {
    this(assertionValue, beforeCount, afterCount, contextID, true);
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by a target offset.
   *
   * @param  targetOffset  The position of the entry that should be used as the
   *                       start of the result set.
   * @param  beforeCount   The maximum number of entries that should be returned
   *                       before the entry with the specified target offset.
   * @param  afterCount    The maximum number of entries that should be returned
   *                       after the entry with the specified target offset.
   * @param  contentCount  The estimated number of entries in the result set.
   *                       For the first request in a series of searches with
   *                       the VLV control, it should be zero.  For subsequent
   *                       searches in the VLV sequence, it should be the
   *                       content count included in the response control from
   *                       the previous search.
   * @param  contextID     The context ID that may be used to help the server
   *                       continue in the same result set for subsequent
   *                       searches.  For the first request in a series of
   *                       searches with the VLV control, it should be
   *                       {@code null}.  For subsequent searches in the VLV
   *                       sequence, it should be the (possibly {@code null})
   *                       context ID included in the response control from the
   *                       previous search.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.
   */
  public VirtualListViewRequestControl(final int targetOffset,
              final int beforeCount, final int afterCount,
              final int contentCount,
              @Nullable final ASN1OctetString contextID,
              final boolean isCritical)
  {
    super(VIRTUAL_LIST_VIEW_REQUEST_OID, isCritical,
          encodeValue(targetOffset, beforeCount, afterCount, contentCount,
                      contextID));

    this.targetOffset = targetOffset;
    this.beforeCount  = beforeCount;
    this.afterCount   = afterCount;
    this.contentCount = contentCount;
    this.contextID    = contextID;

    assertionValue = null;
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by an assertion value.  It will be marked
   * critical.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.  It must not be {@code null}.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.
   */
  public VirtualListViewRequestControl(@NotNull final String assertionValue,
              final int beforeCount, final int afterCount,
              @Nullable final ASN1OctetString contextID,
              final boolean isCritical)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
                             contextID, isCritical);
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by an assertion value.  It will be marked
   * critical.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.  It must not be {@code null}.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.
   */
  public VirtualListViewRequestControl(@NotNull final byte[] assertionValue,
              final int beforeCount, final int afterCount,
              @Nullable final ASN1OctetString contextID,
              final boolean isCritical)
  {
    this(new ASN1OctetString(assertionValue), beforeCount, afterCount,
                             contextID, isCritical);
  }



  /**
   * Creates a new virtual list view request control that will identify the
   * beginning of the result set by an assertion value.  It will be marked
   * critical.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.  It must not be {@code null}.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.
   */
  public VirtualListViewRequestControl(
              @NotNull final ASN1OctetString assertionValue,
              final int beforeCount, final int afterCount,
              @Nullable final ASN1OctetString contextID,
              final boolean isCritical)
  {
    super(VIRTUAL_LIST_VIEW_REQUEST_OID, isCritical,
          encodeValue(assertionValue, beforeCount, afterCount, contextID));

    this.assertionValue = assertionValue;
    this.beforeCount    = beforeCount;
    this.afterCount     = afterCount;
    this.contextID      = contextID;

    targetOffset = -1;
    contentCount = -1;
  }



  /**
   * Creates a new virtual list view request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a virtual list view
   *                  request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         virtual list view request control.
   */
  public VirtualListViewRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_VLV_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();

      beforeCount = ASN1Integer.decodeAsInteger(elements[0]).intValue();
      afterCount  = ASN1Integer.decodeAsInteger(elements[1]).intValue();

      switch (elements[2].getType())
      {
        case TARGET_TYPE_OFFSET:
          assertionValue = null;
          final ASN1Element[] offsetElements =
               ASN1Sequence.decodeAsSequence(elements[2]).elements();
          targetOffset =
               ASN1Integer.decodeAsInteger(offsetElements[0]).intValue();
          contentCount =
               ASN1Integer.decodeAsInteger(offsetElements[1]).intValue();
          break;

        case TARGET_TYPE_GREATER_OR_EQUAL:
          assertionValue = ASN1OctetString.decodeAsOctetString(elements[2]);
          targetOffset   = -1;
          contentCount   = -1;
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_VLV_REQUEST_INVALID_ELEMENT_TYPE.get(
                    StaticUtils.toHex(elements[2].getType())));
      }

      if (elements.length == 4)
      {
        contextID = ASN1OctetString.decodeAsOctetString(elements[3]);
      }
      else
      {
        contextID = null;
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_VLV_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  targetOffset  The position of the entry that should be used as the
   *                       start of the result set.
   * @param  beforeCount   The maximum number of entries that should be returned
   *                       before the entry with the specified target offset.
   * @param  afterCount    The maximum number of entries that should be returned
   *                       after the entry with the specified target offset.
   * @param  contentCount  The estimated number of entries in the result set.
   *                       For the first request in a series of searches with
   *                       the VLV control, it should be zero.  For subsequent
   *                       searches in the VLV sequence, it should be the
   *                       content count included in the response control from
   *                       the previous search.
   * @param  contextID     The context ID that may be used to help the server
   *                       continue in the same result set for subsequent
   *                       searches.  For the first request in a series of
   *                       searches with the VLV control, it should be
   *                       {@code null}.  For subsequent searches in the VLV
   *                       sequence, it should be the (possibly {@code null})
   *                       context ID included in the response control from the
   *                       previous search.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int targetOffset,
                      final int beforeCount, final int afterCount,
                      final int contentCount,
                      @Nullable final ASN1OctetString contextID)
  {
    final ASN1Element[] targetElements =
    {
      new ASN1Integer(targetOffset),
      new ASN1Integer(contentCount)
    };

    final ASN1Element[] vlvElements;
    if (contextID == null)
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1Sequence(TARGET_TYPE_OFFSET, targetElements)
      };
    }
    else
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1Sequence(TARGET_TYPE_OFFSET, targetElements),
        contextID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(vlvElements).encode());
  }



  /**
   * Encodes the provided information into an octet string that can be used as
   * the value for this control.
   *
   * @param  assertionValue  The assertion value that will be used to identify
   *                         the start of the result set.  The target entry will
   *                         be the first entry with a value for the primary
   *                         sort attribute that is greater than or equal to
   *                         this assertion value.
   * @param  beforeCount     The maximum number of entries that should be
   *                         returned before the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  afterCount      The maximum number of entries that should be
   *                         returned after the first entry with a value
   *                         greater than or equal to the provided assertion
   *                         value.
   * @param  contextID       The context ID that may be used to help the server
   *                         continue in the same result set for subsequent
   *                         searches.  For the first request in a series of
   *                         searches with the VLV control, it should be
   *                         {@code null}.  For subsequent searches in the VLV
   *                         sequence, it should be the (possibly {@code null})
   *                         context ID included in the response control from
   *                         the previous search.
   *
   * @return  An ASN.1 octet string that can be used as the value for this
   *          control.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final ASN1OctetString assertionValue,
                      final int beforeCount,
                      final int afterCount,
                      @Nullable final ASN1OctetString contextID)
  {
    Validator.ensureNotNull(assertionValue);

    final ASN1Element[] vlvElements;
    if (contextID == null)
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1OctetString(TARGET_TYPE_GREATER_OR_EQUAL,
                            assertionValue.getValue())
      };
    }
    else
    {
      vlvElements = new ASN1Element[]
      {
        new ASN1Integer(beforeCount),
        new ASN1Integer(afterCount),
        new ASN1OctetString(TARGET_TYPE_GREATER_OR_EQUAL,
                            assertionValue.getValue()),
        contextID
      };
    }

    return new ASN1OctetString(new ASN1Sequence(vlvElements).encode());
  }



  /**
   * Retrieves the target offset position for this virtual list view request
   * control, if applicable.
   *
   * @return  The target offset position for this virtual list view request
   *          control, or -1 if the target is specified by an assertion value.
   */
  public int getTargetOffset()
  {
    return targetOffset;
  }



  /**
   * Retrieves the string representation of the assertion value for this virtual
   * list view request control, if applicable.
   *
   * @return  The string representation of the assertion value for this virtual
   *          list view request control, or {@code null} if the target is
   *          specified by offset.
   */
  @Nullable()
  public String getAssertionValueString()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.stringValue();
    }
  }



  /**
   * Retrieves the byte array representation of the assertion value for this
   * virtual list view request control, if applicable.
   *
   * @return  The byte array representation of the assertion value for this
   *          virtual list view request control, or {@code null} if the target
   *          is specified by offset.
   */
  @Nullable()
  public byte[] getAssertionValueBytes()
  {
    if (assertionValue == null)
    {
      return null;
    }
    else
    {
      return assertionValue.getValue();
    }
  }



  /**
   * Retrieves the assertion value for this virtual list view request control,
   * if applicable.
   *
   * @return  The assertion value for this virtual list view request control, or
   *          {@code null} if the target is specified by offset.
   */
  @Nullable()
  public ASN1OctetString getAssertionValue()
  {
    return assertionValue;
  }



  /**
   * Retrieves the number of entries that should be retrieved before the target
   * entry.
   *
   * @return  The number of entries that should be retrieved before the target
   *          entry.
   */
  public int getBeforeCount()
  {
    return beforeCount;
  }



  /**
   * Retrieves the number of entries that should be retrieved after the target
   * entry.
   *
   * @return  The number of entries that should be retrieved after the target
   *          entry.
   */
  public int getAfterCount()
  {
    return afterCount;
  }



  /**
   * Retrieves the estimated number of entries in the result set, if applicable.
   *
   * @return  The estimated number of entries in the result set, zero if it
   *          is not known (for the first search in a sequence where the
   *          target is specified by offset), or -1 if the target is specified
   *          by an assertion value.
   */
  public int getContentCount()
  {
    return contentCount;
  }



  /**
   * Retrieves the context ID for this virtual list view request control, if
   * available.
   *
   * @return  The context ID for this virtual list view request control, or
   *          {@code null} if there is none.
   */
  @Nullable()
  public ASN1OctetString getContextID()
  {
    return contextID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_VLV_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("VirtualListViewRequestControl(beforeCount=");
    buffer.append(beforeCount);
    buffer.append(", afterCount=");
    buffer.append(afterCount);

    if (assertionValue == null)
    {
      buffer.append(", targetOffset=");
      buffer.append(targetOffset);
      buffer.append(", contentCount=");
      buffer.append(contentCount);
    }
    else
    {
      buffer.append(", assertionValue='");
      buffer.append(assertionValue.stringValue());
      buffer.append('\'');
    }

    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
