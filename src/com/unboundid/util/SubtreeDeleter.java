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
package com.unboundid.util;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AbstractConnectionPool;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.HardDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PermitUnindexedSearchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReturnConflictEntriesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SoftDeletedEntryAccessRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            SetSubtreeAccessibilityExtendedRequest;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a utility that can delete all entries below a specified
 * base DN (including the base entry itself by default, although it can be
 * preserved if desired) in an LDAP directory server.  It accomplishes this
 * through a combination of search and delete operations.  Ideally, it will
 * first perform a search to find all entries below the target base DN, but in
 * some cases, it may be necessary to intertwine search and delete operations
 * if it is not possible to retrieve all entries in the target subtree in
 * advance.
 * <BR><BR>
 * The subtree deleter can optionally take advantage of a number of server
 * features to aid in processing, but does not require them.  Some of these
 * features include:
 * <UL>
 *   <LI>
 *     Set Subtree Accessibility Extended Operation -- A proprietary extended
 *     operation supported by the Ping Identity, UnboundID, and
 *     Nokia/Alcatel-Lucent 8661 Directory Server products.  This operation can
 *     restrict access to a specified subtree to all but a specified user.  If
 *     this is to be used, then the "Who Am I?" extended operation will first be
 *     used to identify the user that is authenticated on the provided
 *     connection, and then the set subtree accessibility extended operation
 *     will be used to make the target subtree hidden and read-only for all
 *     users except the user identified by the "Who Am I?" operation.  As far as
 *     all other clients are concerned, this will make the target subtree
 *     immediately disappear.  The subtree deleter will then be able to search
 *     for the entries to delete, and then delete those entries, without
 *     exposing other clients to its in-progress state.
 *     <BR><BR>
 *     The set subtree accessibility extended operation will not automatically
 *     be used.  If the
 *     {@link #setUseSetSubtreeAccessibilityOperationIfAvailable} method is
 *     called with a value of {@code true}, then this extended operation will be
 *     used if the server root DSE advertises support for both this operation
 *     and the LDAP "Who Am I?" extended operation.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     Simple Paged Results Request Control -- A standard request control that
 *     is supported by several types of directory servers.  This control allows
 *     a search to be broken up into pages to limit the number of entries that
 *     are returned in any single operation (which can help an authorized
 *     client circumvent search size limit restrictions).  It can also help
 *     ensure that if the server can return entries faster than the client can
 *     consume them, it will not result in a large backlog on the server.
 *     <BR><BR>
 *     The simple paged results request control will be used by default if the
 *     server root DSE advertises support for it, with a default page size of
 *     100 entries.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     Manage DSA IT Request Control -- A standard request control that is
 *     supported by several types of directory servers.  This control indicates
 *     that any referral entries (that is, entries that contain the "referral"
 *     object class and a "ref" attribute) should be treated as regular entries
 *     rather than triggering a referral result or a search result reference.
 *     The subtree deleter will not make any attempt to follow referrals, and
 *     if any referral or search result reference results are returned during
 *     processing, then it may not be possible to completely remove all entries
 *     in the target subtree.
 *     <BR><BR>
 *     The manage DSA IT request control will be used by default if the server
 *     root DSE advertises support for it.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     Permit Unindexed Search Request Control -- A proprietary request
 *     control supported by the Ping Identity, UnboundID, and
 *     Nokia/Alcatel-Lucent 8661 Directory Server products.  This control
 *     indicates that the client wishes to process the search even if it is
 *     unindexed.
 *     <BR><BR>
 *     The permit unindexed search request control will not automatically be
 *     used.  It may not needed if the requester has the unindexed-search
 *     privilege, and the permit unindexed search request control requires that
 *     the caller have either the unindexed-search or
 *     unindexed-search-with-control privilege.  If the
 *     {@link #setUsePermitUnindexedSearchControlIfAvailable} method is called
 *     with a value of {@code true}, then this control will be used if the
 *     server root DSE advertises support for it.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     LDAP Subentries Request Control -- A standard request control that is
 *     supported by several types of directory servers.  It allows the client
 *     to request a search that retrieves entries with the "ldapSubentry"
 *     object class, which are normally excluded from search results.  Note that
 *     because of the nature of this control, if it is to be used, then two
 *     separate sets of searches will be used:  one that retrieves only
 *     LDAP subentries, and a second that retrieves other types of entries.
 *     <BR><BR>
 *     The LDAP subentries request control will be used by default if the server
 *     root DSE advertises support for it.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     Return Conflict Entries Request Control -- A proprietary request control
 *     that is supported by the Ping Identity, UnboundID, and
 *     Nokia/Alcatel-Lucent 8661 Directory Server products.  This control
 *     indicates that the server should return replication conflict entries,
 *     which are normally excluded from search results.
 *     <BR><BR>
 *     The return conflict entries request control will be used by default if
 *     the server root DSE advertises support for it.
 *     <BR><BR>
 *   </LI>
 *   <LI>
 *     Soft-Deleted Entry Access Request Control -- A proprietary request
 *     control that is supported by the Ping Identity, UnboundID, and
 *     Nokia/Alcatel-Lucent 8661 Directory Server products.  This control
 *     indicates that the server should return soft-deleted entries, which are
 *     normally excluded from search results.
 *     <BR><BR>
 *     The soft-deleted entry access request control will be used by default if
 *     the server root DSE advertises support for it.
 *     <BR><BR>
 *   <LI>
 *     Hard Delete Request Control -- A proprietary request control that is
 *     supported by the Ping Identity, UnboundID, and Nokia/Alcatel-Lucent 8661
 *     Directory Server products.  This control indicates that the server
 *     should process a delete operation as a hard delete, even if a
 *     soft-delete policy would have otherwise converted it into a soft delete.
 *     A subtree cannot be deleted if it contains soft-deleted entries, so this
 *     should be used if the server is configured with such a soft-delete
 *     policy.
 *     <BR><BR>
 *     The hard delete request control will be used by default if the server
 *     root DSE advertises support for it.
 *     <BR><BR>
 *   </LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SubtreeDeleter
{
  // Indicates whether to delete the base entry itself, or only its
  // subordinates.
  private boolean deleteBaseEntry = true;

  // Indicates whether to include the hard delete request control in delete
  // requests, if the server root DSE advertises support for it.
  private boolean useHardDeleteControlIfAvailable = true;

  // Indicates whether to include the manage DSA IT request control in search
  // and delete requests, if the server root DSE advertises support for it.
  private boolean useManageDSAITControlIfAvailable = true;

  // Indicates whether to include the permit unindexed search request control in
  // search requests, if the server root DSE advertises support for it.
  private boolean usePermitUnindexedSearchControlIfAvailable = false;

  // Indicates whether to include the return conflict entries request control
  // in search requests, if the server root DSE advertises support for it.
  private boolean useReturnConflictEntriesRequestControlIfAvailable = true;

  // Indicates whether to use the simple paged results control in the course of
  // finding the entries to delete, if the server root DSE advertises support
  // for it.
  private boolean useSimplePagedResultsControlIfAvailable = true;

  // Indicates whether to include the soft-deleted entry access request control
  // in search requests, if the server root DSE advertises support for it.
  private boolean useSoftDeletedEntryAccessControlIfAvailable = true;

  // Indicates whether to use the subentries request control to search for LDAP
  // subentries if the server root DSE advertises support for it.
  private boolean useSubentriesControlIfAvailable = true;

  // Indicates whether to use the set subtree accessibility extended operation
  // to made the target subtree inaccessible, if the server root DSE advertises
  // support for it.
  private boolean useSetSubtreeAccessibilityOperationIfAvailable = false;

  // The maximum number of entries to return from any single search operation.
  private int searchRequestSizeLimit = 0;

  // The page size to use in conjunction with the simple paged results request
  // control.
  private int simplePagedResultsPageSize = 100;

  // The fixed-rate barrier that will be used to limit the rate at which delete
  // operations will be attempted.
  @Nullable private FixedRateBarrier deleteRateLimiter = null;

  // A list of additional controls that should be included in search requests
  // used to find the entries to delete.
  @NotNull private List<Control> additionalSearchControls =
       Collections.emptyList();

  // A list of additional controls that should be included in delete requests
  // used to
  @NotNull private List<Control> additionalDeleteControls =
       Collections.emptyList();



  /**
   * Creates a new instance of this subtree deleter with the default settings.
   */
  public SubtreeDeleter()
  {
    // No implementation is required.
  }



  /**
   * Indicates whether the base entry itself should be deleted along with all of
   * its subordinates.  This method returns {@code true} by default.
   *
   * @return  {@code true} if the base entry should be deleted in addition to
   *          its subordinates, or {@code false} if the base entry should not
   *          be deleted but all of its subordinates should be.
   */
  public boolean deleteBaseEntry()
  {
    return deleteBaseEntry;
  }



  /**
   * Specifies whether the base entry itself should be deleted along with all of
   * its subordinates.
   *
   * @param  deleteBaseEntry
   *              {@code true} to indicate that the base entry should be deleted
   *              in addition to its subordinates, or {@code false} if only the
   *              subordinates of the base entry should be removed.
   */
  public void setDeleteBaseEntry(final boolean deleteBaseEntry)
  {
    this.deleteBaseEntry = deleteBaseEntry;
  }



  /**
   * Indicates whether to use the {@link SetSubtreeAccessibilityExtendedRequest}
   * to make the target subtree hidden before starting to search for entries to
   * delete if the server root DSE advertises support for both that extended
   * request and the "Who Am I?" extended request.  In servers that support it,
   * this extended operation can make the target subtree hidden and read-only to
   * clients other than those authenticated as the user that issued the set
   * subtree accessibility request.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports both the set subtree
   * accessibility extended operation and the "Who Am I?" extended operation.
   *
   * @return  {@code true} if the set subtree accessibility extended operation
   *          should be used to make the target subtree hidden and read-only
   *          before attempting to search for entries to delete if the server
   *          root DSE advertises support for it, or {@code false} if the
   *          operation should not be used.
   */
  public boolean useSetSubtreeAccessibilityOperationIfAvailable()
  {
    return useSetSubtreeAccessibilityOperationIfAvailable;
  }



  /**
   * Specifies whether to use the {@link SetSubtreeAccessibilityExtendedRequest}
   * to make the target subtree hidden before starting to search for entries to
   * delete if the server root DSE advertises support for both that extended
   * request and the "Who Am I?" extended request.  In servers that support it,
   * this extended operation can make the target subtree hidden and read-only to
   * clients other than those authenticated as the user that issued the set
   * subtree accessibility request.
   *
   * @param  useSetSubtreeAccessibilityOperationIfAvailable
   *              {@code true} to indicate that the set subtree accessibility
   *              extended operation should be used to make the target subtree
   *              hidden and read-only before starting to search for entries
   *              to delete, or {@code false} if not.  This value will be
   *              ignored if the server root DSE does not advertise support for
   *              both the set subtree accessibility extended operation and the
   *              "Who Am I?" extended operation.
   */
  public void setUseSetSubtreeAccessibilityOperationIfAvailable(
                   final boolean useSetSubtreeAccessibilityOperationIfAvailable)
  {
    this.useSetSubtreeAccessibilityOperationIfAvailable =
         useSetSubtreeAccessibilityOperationIfAvailable;
  }



  /**
   * Indicates whether to use the {@link SimplePagedResultsControl} when
   * searching for entries to delete if the server advertises support for it.
   * Using this control can help avoid problems from running into the search
   * size limit, and can also prevent the server from trying to return entries
   * faster than the client can consume them.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the simple paged
   * results control.
   *
   * @return   {@code true} if the simple paged results control should be used
   *           when searching for entries to delete if the server root DSE
   *           advertises support for it, or {@code false} if the control should
   *           not be used.
   */
  public boolean useSimplePagedResultsControlIfAvailable()
  {
    return useSimplePagedResultsControlIfAvailable;
  }



  /**
   * Specifies whether to use the {@link SimplePagedResultsControl} when
   * searching for entries to delete if the server advertises support for it.
   * Using this control can help avoid problems from running into the search
   * size limit, and can also prevent the server from trying to return entries
   * faster than the client can consume them.
   *
   * @param  useSimplePagedResultsControlIfAvailable
   *              {@code true} to indicate that the simple paged results control
   *              should be used when searching for entries to delete, or
   *              {@code false} if not.  This value will be ignored if the
   *              server root DSE does not advertise support for the simple
   *              paged results control.
   */
  public void setUseSimplePagedResultsControlIfAvailable(
                   final boolean useSimplePagedResultsControlIfAvailable)
  {
    this.useSimplePagedResultsControlIfAvailable =
         useSimplePagedResultsControlIfAvailable;
  }



  /**
   * Retrieves the maximum number of entries that should be returned in each
   * page of results when using the simple paged results control.  This value
   * will only be used if {@link #useSimplePagedResultsControlIfAvailable()}
   * returns {@code true} and the server root DSE indicates that it supports the
   * simple paged results control.
   * <BR><BR>
   * This method returns {@code 100} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the simple paged
   * results control.
   *
   * @return  The maximum number of entries that should be returned in each page
   *          of results when using the simple paged results control.
   */
  public int getSimplePagedResultsPageSize()
  {
    return simplePagedResultsPageSize;
  }



  /**
   * Specifies the maximum number of entries that should be returned in each
   * page of results when using the simple paged results control. This value
   * will only be used if {@link #useSimplePagedResultsControlIfAvailable()}
   * returns {@code true} and the server root DSE indicates that it supports the
   * simple paged results control.
   *
   * @param  simplePagedResultsPageSize
   *              The maximum number of entries that should be returned in each
   *              page of results when using the simple paged results control.
   *              The value must be greater than or equal to one.
   */
  public void setSimplePagedResultsPageSize(
                   final int simplePagedResultsPageSize)
  {
    Validator.ensureTrue((simplePagedResultsPageSize >= 1),
         "SubtreeDeleter.simplePagedResultsPageSize must be greater than " +
              "or equal to 1.");
    this.simplePagedResultsPageSize = simplePagedResultsPageSize;
  }



  /**
   * Indicates whether to include the {@link ManageDsaITRequestControl} in
   * search and delete requests if the server root DSE advertises support for
   * it.  The manage DSA IT request control tells the server that it should
   * return referral entries as regular entries rather than returning them as
   * search result references when processing a search operation, or returning a
   * referral result when attempting a delete.  If any referrals are
   * encountered during processing and this control is not used, then it may
   * not be possible to completely delete the entire subtree.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the manage DSA IT
   * request control.
   *
   * @return  {@code true} if the manage DSA IT request control should be
   *          included in search and delete requests if the server root DSE
   *          advertises support for it, or {@code false} if not.
   */
  public boolean useManageDSAITControlIfAvailable()
  {
    return useManageDSAITControlIfAvailable;
  }



  /**
   * Specifies whether to include the {@link ManageDsaITRequestControl} in
   * search and delete requests if the server root DSE advertises support for
   * it.  The manage DSA IT request control tells the server that it should
   * return referral entries as regular entries rather than returning them as
   * search result references when processing a search operation, or returning a
   * referral result when attempting a delete.  If any referrals are
   * encountered during processing and this control is not used, then it may
   * not be possible to completely delete the entire subtree.
   *
   * @param  useManageDSAITControlIfAvailable
   *              {@code true} to indicate that the manage DSA IT request
   *              control should be included in search and delete requests,
   *              or {@code false} if not.  This value will be ignored if the
   *              server root DSE does not advertise support for the manage DSA
   *              IT request control.
   */
  public void setUseManageDSAITControlIfAvailable(
                   final boolean useManageDSAITControlIfAvailable)
  {
    this.useManageDSAITControlIfAvailable = useManageDSAITControlIfAvailable;
  }



  /**
   * Indicates whether to include the
   * {@link PermitUnindexedSearchRequestControl} in search requests used to
   * identify the entries to be deleted if the server root DSE advertises
   * support for it.  The permit unindexed search request control may allow
   * appropriately authorized clients to explicitly indicate that the server
   * should process an unindexed search that would normally be rejected.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the permit unindexed
   * search request control.
   *
   * @return  {@code true} if search requests should include the permit
   *          unindexed search request control if the server root DSE advertises
   *          support for it, or {@code false} if not.
   */
  public boolean usePermitUnindexedSearchControlIfAvailable()
  {
    return usePermitUnindexedSearchControlIfAvailable;
  }



  /**
   * Specifies whether to include the
   * {@link PermitUnindexedSearchRequestControl} in search request used to
   * identify the entries to be deleted if the server root DSE advertises
   * support for it.  The permit unindexed search request control may allow
   * appropriately authorized clients to explicitly indicate that the server
   * should process an unindexed search that would normally be rejected.
   *
   * @param  usePermitUnindexedSearchControlIfAvailable
   *              {@code true} to indicate that the permit unindexed search
   *              request control should be included in search requests, or
   *              {@code false} if not.  This value will be ignored if the
   *              server root DSE does not advertise support for the permit
   *              unindexed search request control.
   */
  public void setUsePermitUnindexedSearchControlIfAvailable(
                   final boolean usePermitUnindexedSearchControlIfAvailable)
  {
    this.usePermitUnindexedSearchControlIfAvailable =
         usePermitUnindexedSearchControlIfAvailable;
  }



  /**
   * Indicates whether to use the {@link DraftLDUPSubentriesRequestControl} when
   * searching for entries to delete if the server root DSE advertises support
   * for it.  The subentries request control allows LDAP subentries to be
   * included in search results.  These entries are normally excluded from
   * search results.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the subentries
   * request control.
   *
   * @return  {@code true} if the subentries request control should be used
   *          to retrieve LDAP subentries if the server root DSE advertises
   *          support for it, or {@code false} if not.
   */
  public boolean useSubentriesControlIfAvailable()
  {
    return useSubentriesControlIfAvailable;
  }



  /**
   * Specifies whether to use the {@link DraftLDUPSubentriesRequestControl} when
   * searching for entries to delete if the server root DSE advertises support
   * for it.  The subentries request control allows LDAP subentries to be
   * included in search results.  These entries are normally excluded from
   * search results.
   *
   * @param  useSubentriesControlIfAvailable
   *              [@code true} to indicate that the subentries request control
   *              should be used to retrieve LDAP subentries, or {@code false}
   *              if not.  This value will be ignored if the server root DSE
   *              does not advertise support for the subentries request
   *              control.
   */
  public void setUseSubentriesControlIfAvailable(
                   final boolean useSubentriesControlIfAvailable)
  {
    this.useSubentriesControlIfAvailable = useSubentriesControlIfAvailable;
  }



  /**
   * Indicates whether to use the {@link ReturnConflictEntriesRequestControl}
   * when searching for entries to delete if the server root DSE advertises
   * support for it.  The return conflict entries request control allows
   * replication conflict entries to be included in search results.  These
   * entries are normally excluded from search results.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the return
   * conflict entries request control.
   *
   * @return  {@code true} if the return conflict entries request control
   *          should be used to retrieve replication conflict entries if the
   *          server root DSE advertises support for it, or {@code false} if
   *          not.
   */
  public boolean useReturnConflictEntriesRequestControlIfAvailable()
  {
    return useReturnConflictEntriesRequestControlIfAvailable;
  }



  /**
   * Specifies whether to use the {@link ReturnConflictEntriesRequestControl}
   * when searching for entries to delete if the server root DSE advertises
   * support for it.  The return conflict entries request control allows
   * replication conflict entries to be included in search results.  These
   * entries are normally excluded from search results.
   *
   * @param  useReturnConflictEntriesRequestControlIfAvailable
   *              {@code true} to indicate that the return conflict entries
   *              request control should be used to retrieve replication
   *              conflict entries, or {@code false} if not.  This value will be
   *              ignored if the server root DSE does not advertise support for
   *              the return conflict entries request control.
   */
  public void setUseReturnConflictEntriesRequestControlIfAvailable(
       final boolean useReturnConflictEntriesRequestControlIfAvailable)
  {
    this.useReturnConflictEntriesRequestControlIfAvailable =
         useReturnConflictEntriesRequestControlIfAvailable;
  }



  /**
   * Indicates whether to use the {@link SoftDeletedEntryAccessRequestControl}
   * when searching for entries to delete if the server root DSE advertises
   * support for it.  The soft-deleted entry access request control allows
   * soft-deleted entries to be included in search results.  These entries are
   * normally excluded from search results.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the soft-deleted
   * entry access request control.
   *
   * @return  {@code true} if the soft-deleted entry access request control
   *          should be used to retrieve soft-deleted entries if the server
   *          root DSE advertises support for it, or {@code false} if not.
   */
  public boolean useSoftDeletedEntryAccessControlIfAvailable()
  {
    return useSoftDeletedEntryAccessControlIfAvailable;
  }



  /**
   * Specifies whether to use the {@link SoftDeletedEntryAccessRequestControl}
   * when searching for entries to delete if the server root DSE advertises
   * support for it.  The soft-deleted entry access request control allows
   * soft-deleted entries to be included in search results.  These entries are
   * normally excluded from search results.
   *
   * @param  useSoftDeletedEntryAccessControlIfAvailable
   *              {@code true} to indicate that the soft-deleted entry access
   *              request control should be used to retrieve soft-deleted
   *              entries, or {@code false} if not.  This value will be ignored
   *              if the server root DSE does not advertise support for the
   *              soft-deleted entry access request control.
   */
  public void setUseSoftDeletedEntryAccessControlIfAvailable(
                   final boolean useSoftDeletedEntryAccessControlIfAvailable)
  {
    this.useSoftDeletedEntryAccessControlIfAvailable =
         useSoftDeletedEntryAccessControlIfAvailable;
  }



  /**
   * Indicates whether to include the {@link HardDeleteRequestControl} in
   * delete requests if the server root DSE advertises support for it.  The
   * hard delete request control indicates that the server should treat a delete
   * operation as a hard delete even if it would have normally been processed as
   * a soft delete because it matches the criteria in a configured soft delete
   * policy.
   * <BR><BR>
   * This method returns {@code true} by default.  Its value will be ignored if
   * the server root DSE does not indicate that it supports the hard delete
   * request control.
   *
   * @return  {@code true} if the hard delete request control should be included
   *          in delete requests if the server root DSE advertises support for
   *          it, or {@code false} if not.
   */
  public boolean useHardDeleteControlIfAvailable()
  {
    return useHardDeleteControlIfAvailable;
  }



  /**
   * Specifies whether to include the {@link HardDeleteRequestControl} in
   * delete requests if the server root DSE advertises support for it.  The
   * hard delete request control indicates that the server should treat a delete
   * operation as a hard delete even if it would have normally been processed as
   * a soft delete because it matches the criteria in a configured soft delete
   * policy.
   *
   * @param  useHardDeleteControlIfAvailable
   *              {@code true} to indicate that the hard delete request control
   *              should be included in delete requests, or {@code false} if
   *              not.  This value will be ignored if the server root DSE does
   *              not advertise support for the hard delete request control.
   */
  public void setUseHardDeleteControlIfAvailable(
                   final boolean useHardDeleteControlIfAvailable)
  {
    this.useHardDeleteControlIfAvailable = useHardDeleteControlIfAvailable;
  }



  /**
   * Retrieves an unmodifiable list of additional controls that should be
   * included in search requests used to identify entries to delete.
   * <BR><BR>
   * This method returns an empty list by default.
   *
   * @return  An unmodifiable list of additional controls that should be
   *          included in search requests used to identify entries to delete.
   */
  @NotNull()
  public List<Control> getAdditionalSearchControls()
  {
    return additionalSearchControls;
  }



  /**
   * Specifies a list of additional controls that should be included in search
   * requests used to identify entries to delete.
   *
   * @param  additionalSearchControls
   *              A list of additional controls that should be included in
   *              search requests used to identify entries to delete.  This must
   *              not be {@code null} but may be empty.
   */
  public void setAdditionalSearchControls(
                   @NotNull final Control... additionalSearchControls)
  {
    setAdditionalSearchControls(Arrays.asList(additionalSearchControls));
  }



  /**
   * Specifies a list of additional controls that should be included in search
   * requests used to identify entries to delete.
   *
   * @param  additionalSearchControls
   *              A list of additional controls that should be included in
   *              search requests used to identify entries to delete.  This must
   *              not be {@code null} but may be empty.
   */
  public void setAdditionalSearchControls(
                   @NotNull final List<Control> additionalSearchControls)
  {
    this.additionalSearchControls = Collections.unmodifiableList(
         new ArrayList<>(additionalSearchControls));
  }



  /**
   * Retrieves an unmodifiable list of additional controls that should be
   * included in delete requests.
   * <BR><BR>
   * This method returns an empty list by default.
   *
   * @return  An unmodifiable list of additional controls that should be
   *          included in delete requests.
   */
  @NotNull()
  public List<Control> getAdditionalDeleteControls()
  {
    return additionalDeleteControls;
  }



  /**
   * Specifies a list of additional controls that should be included in delete
   * requests.
   *
   * @param  additionalDeleteControls
   *              A list of additional controls that should be included in
   *              delete requests.  This must not be {@code null} but may be
   *              empty.
   */
  public void setAdditionalDeleteControls(
                   @NotNull final Control... additionalDeleteControls)
  {
    setAdditionalDeleteControls(Arrays.asList(additionalDeleteControls));
  }



  /**
   * Specifies a list of additional controls that should be included in delete
   * requests.
   *
   * @param  additionalDeleteControls
   *              A list of additional controls that should be included in
   *              delete requests.  This must not be {@code null} but may be
   *              empty.
   */
  public void setAdditionalDeleteControls(
                   @NotNull final List<Control> additionalDeleteControls)
  {
    this.additionalDeleteControls = Collections.unmodifiableList(
         new ArrayList<>(additionalDeleteControls));
  }



  /**
   * Retrieves the size limit that should be used in each search request to
   * specify the maximum number of entries to return in response to that
   * request.  If a search request matches more than this number of entries,
   * then the server may return a subset of the results and a search result
   * done message with a result code of {@link ResultCode#SIZE_LIMIT_EXCEEDED}.
   * <BR><BR>
   * This method returns a value of zero by default, which indicates that the
   * client does not want to impose any limit on the number of entries that may
   * be returned in response to any single search operation (although the server
   * may still impose a limit).
   *
   * @return  The size limit that should be used in each search request to
   *          specify the maximum number of entries to return in response to
   *          that request, or zero to indicate that the client does not want to
   *          impose any size limit.
   */
  public int getSearchRequestSizeLimit()
  {
    return searchRequestSizeLimit;
  }



  /**
   * Specifies the size limit that should be used in each search request to
   * specify the maximum number of entries to return in response to that
   * request.  If a search request matches more than this number of entries,
   * then the server may return a subset of the results and a search result
   * done message with a result code of {@link ResultCode#SIZE_LIMIT_EXCEEDED}.
   * A value that is less than or equal to zero indicates that the client does
   * not want to impose any limit on the number of entries that may be returned
   * in response to any single search operation (although the server may still
   * impose a limit).
   *
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   */
  public void setSearchRequestSizeLimit(final int searchRequestSizeLimit)
  {
    if (searchRequestSizeLimit <= 0)
    {
      this.searchRequestSizeLimit = 0;
    }
    else
    {
      this.searchRequestSizeLimit = searchRequestSizeLimit;
    }
  }



  /**
   * Retrieves the fixed-rate barrier that may be used to impose a rate limit on
   * delete operations, if defined.
   * <BR><BR>
   * This method returns {@code null} by default, to indicate that no delete
   * rate limit will be imposed.
   *
   * @return  The fixed-rate barrier that may be used to impose a rate limit on
   *          delete operations, or {@code null} if no rate limit should be
   *          imposed.
   */
  @Nullable()
  public FixedRateBarrier getDeleteRateLimiter()
  {
    return deleteRateLimiter;
  }



  /**
   * Provides a fixed-rate barrier that may be used to impose a rate limit on
   * delete operations.
   *
   * @param  deleteRateLimiter
   *              A fixed-rate barrier that may be used to impose a rate limit
   *              on delete operations.  It may be {@code null} if no delete
   *              rate limit should be imposed.
   */
  public void setDeleteRateLimiter(
                  @Nullable final FixedRateBarrier deleteRateLimiter)
  {
    this.deleteRateLimiter = deleteRateLimiter;
  }



  /**
   * Attempts to delete the specified subtree using the current settings.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to delete.  It must not be
   *              {@code null}.
   *
   * @return  An object with information about the results of the subtree
   *          delete processing.
   *
   * @throws  LDAPException  If the provided base DN cannot be parsed as a valid
   *                         DN.
   */
  @NotNull()
  public SubtreeDeleterResult delete(@NotNull final LDAPInterface connection,
                                     @NotNull final String baseDN)
         throws LDAPException
  {
    return delete(connection, new DN(baseDN));
  }



  /**
   * Attempts to delete the specified subtree using the current settings.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to delete.  It must not be
   *              {@code null}.
   *
   * @return  An object with information about the results of the subtree
   *          delete processing.
   */
  @NotNull()
  public SubtreeDeleterResult delete(@NotNull final LDAPInterface connection,
                                     @NotNull final DN baseDN)
  {
    final AtomicReference<RootDSE> rootDSE = new AtomicReference<>();
    final boolean useSetSubtreeAccessibility =
         useSetSubtreeAccessibilityOperationIfAvailable &&
              supportsExtendedRequest(connection, rootDSE,
                   SetSubtreeAccessibilityExtendedRequest.
                        SET_SUBTREE_ACCESSIBILITY_REQUEST_OID) &&
              supportsExtendedRequest(connection, rootDSE,
                   WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID);

    final boolean usePagedResults = useSimplePagedResultsControlIfAvailable &&
         supportsControl(connection, rootDSE,
              SimplePagedResultsControl.PAGED_RESULTS_OID);

    final boolean useSubentries = useSubentriesControlIfAvailable &&
         supportsControl(connection, rootDSE,
              DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);

    final List<Control> searchControls = new ArrayList<>(10);
    searchControls.addAll(additionalSearchControls);

    final List<Control> deleteControls = new ArrayList<>(10);
    deleteControls.addAll(additionalDeleteControls);

    if (useHardDeleteControlIfAvailable &&
       supportsControl(connection, rootDSE,
            HardDeleteRequestControl.HARD_DELETE_REQUEST_OID))
    {
      deleteControls.add(new HardDeleteRequestControl(false));
    }

    if (useManageDSAITControlIfAvailable &&
       supportsControl(connection, rootDSE,
            ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID))
    {
      final ManageDsaITRequestControl c =
           new ManageDsaITRequestControl(false);
      searchControls.add(c);
      deleteControls.add(c);
    }

    if (usePermitUnindexedSearchControlIfAvailable &&
       supportsControl(connection, rootDSE,
            PermitUnindexedSearchRequestControl.
                 PERMIT_UNINDEXED_SEARCH_REQUEST_OID))
    {
      searchControls.add(new PermitUnindexedSearchRequestControl(false));
    }

    if (useReturnConflictEntriesRequestControlIfAvailable &&
       supportsControl(connection, rootDSE,
            ReturnConflictEntriesRequestControl.
                 RETURN_CONFLICT_ENTRIES_REQUEST_OID))
    {
      searchControls.add(new ReturnConflictEntriesRequestControl(false));
    }

    if (useSoftDeletedEntryAccessControlIfAvailable &&
       supportsControl(connection, rootDSE,
            SoftDeletedEntryAccessRequestControl.
                 SOFT_DELETED_ENTRY_ACCESS_REQUEST_OID))
    {
      searchControls.add(new SoftDeletedEntryAccessRequestControl(false,
           true, false));
    }

    return delete(connection, baseDN, deleteBaseEntry,
         useSetSubtreeAccessibility, usePagedResults, searchRequestSizeLimit,
         simplePagedResultsPageSize, useSubentries, searchControls,
         deleteControls, deleteRateLimiter);
  }



  /**
   * Attempts to delete the specified subtree using the current settings.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to delete.  It must not be
   *              {@code null}.
   * @param  deleteBaseEntry
   *              Indicates whether the base entry itself should be deleted
   *              along with its subordinates (if {@code true}), or if only the
   *              subordinates of the base entry should be deleted but the base
   *              entry itself should remain (if {@code false}).
   * @param  useSetSubtreeAccessibilityOperation
   *              Indicates whether to use the
   *              {@link SetSubtreeAccessibilityExtendedRequest} to make the
   *              target subtree hidden and read-only before beginning to search
   *              for entries to delete.
   * @param  useSimplePagedResultsControl
   *              Indicates whether to use the {@link SimplePagedResultsControl}
   *              when searching for entries to delete.
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  pageSize
   *              The page size for the simple paged results request control, if
   *              it is to be used.
   * @param  useSubentriesControl
   *              Indicates whether to look for LDAP subentries when searching
   *              for entries to delete.
   * @param  searchControls
   *              A list of controls that should be included in search requests
   *              used to find the entries to delete.  This must not be
   *              {@code null} but may be empty.
   * @param  deleteControls
   *              A list of controls that should be included in delete requests.
   *              This must not be {@code null} but may be empty.
   * @param  deleteRateLimiter
   *              A fixed-rate barrier used to impose a rate limit on delete
   *              operations.  This may be {@code null} if no rate limit should
   *              be imposed.
   *
   * @return  An object with information about the results of the subtree
   *          delete processing.
   */
  @NotNull()
  private static SubtreeDeleterResult delete(
               @NotNull final LDAPInterface connection,
               @NotNull final DN baseDN, final boolean deleteBaseEntry,
               final boolean useSetSubtreeAccessibilityOperation,
               final boolean useSimplePagedResultsControl,
               final int searchRequestSizeLimit, final int pageSize,
               final boolean useSubentriesControl,
               @NotNull final List<Control> searchControls,
               @NotNull final List<Control> deleteControls,
               @Nullable final FixedRateBarrier deleteRateLimiter)
  {
    if (useSetSubtreeAccessibilityOperation)
    {
      final ExtendedResult setInaccessibleResult =
           setInaccessible(connection, baseDN);
      if (setInaccessibleResult != null)
      {
        return new SubtreeDeleterResult(setInaccessibleResult, false, null,
             0L,  new TreeMap<DN,LDAPResult>());
      }
    }

    final SubtreeDeleterResult result;
    if (useSimplePagedResultsControl)
    {
      result = deleteEntriesWithSimplePagedResults(connection, baseDN,
           deleteBaseEntry, searchRequestSizeLimit, pageSize,
           useSubentriesControl, searchControls, deleteControls,
           deleteRateLimiter);
    }
    else
    {
      result = deleteEntriesWithoutSimplePagedResults(connection, baseDN,
           deleteBaseEntry, searchRequestSizeLimit, useSubentriesControl,
           searchControls, deleteControls, deleteRateLimiter);
    }

    if (result.completelySuccessful() && useSetSubtreeAccessibilityOperation)
    {
      final ExtendedResult removeAccessibilityRestrictionResult =
           removeAccessibilityRestriction(connection, baseDN);
      if (removeAccessibilityRestrictionResult.getResultCode() ==
           ResultCode.SUCCESS)
      {
        return new SubtreeDeleterResult(null, false, null,
             result.getEntriesDeleted(), result.getDeleteErrorsTreeMap());
      }
      else
      {
        return new SubtreeDeleterResult(removeAccessibilityRestrictionResult,
             true, null, result.getEntriesDeleted(),
             result.getDeleteErrorsTreeMap());
      }
    }
    else
    {
      return new SubtreeDeleterResult(null,
           useSetSubtreeAccessibilityOperation,
           result.getSearchError(), result.getEntriesDeleted(),
           result.getDeleteErrorsTreeMap());
    }
  }



  /**
   * Marks the specified subtree as inaccessible.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to make inaccessible.  It must not
   *              be {@code null}.
   *
   * @return  An {@code LDAPResult} with information about a failure that
   *          occurred while trying to make the subtree inaccessible, or
   *          {@code null} if the subtree was successfully made inaccessible.
   */
  @Nullable()
  private static ExtendedResult setInaccessible(
                                     @NotNull final LDAPInterface connection,
                                     @NotNull final DN baseDN)
  {
    // Use the "Who Am I?" extended operation to get the authorization identity
    // of the provided connection.
    final ExtendedResult genericWhoAmIResult = processExtendedOperation(
         connection, new WhoAmIExtendedRequest());
    if (genericWhoAmIResult.getResultCode() != ResultCode.SUCCESS)
    {
      return genericWhoAmIResult;
    }

    final WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult) genericWhoAmIResult;


    // Extract the user DN from the "Who Am I?" result's authorization ID.
    final String authzDN;
    final String authzID = whoAmIResult.getAuthorizationID();
    if (authzID.startsWith("dn:"))
    {
      authzDN = authzID.substring(3);
    }
    else
    {
      return new ExtendedResult(-1, ResultCode.LOCAL_ERROR,
           ERR_SUBTREE_DELETER_INTERFACE_WHO_AM_I_AUTHZ_ID_NOT_DN.get(
                authzID),
           null, StaticUtils.NO_STRINGS, null, null, StaticUtils.NO_CONTROLS);
    }


    // Use the set subtree accessibility extended operation to make the target
    // subtree hidden and read-only.
    final ExtendedResult setInaccessibleResult = processExtendedOperation(
         connection,
         SetSubtreeAccessibilityExtendedRequest.createSetHiddenRequest(
              baseDN.toString(), authzDN));

    if (setInaccessibleResult.getResultCode() == ResultCode.SUCCESS)
    {
      return null;
    }
    else
    {
      return setInaccessibleResult;
    }
  }




  /**
   * Deletes the specified subtree with the given settings.  The simple paged
   * results control will be used in the course of searching for entries to
   * delete.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to delete.  It must not be
   *              {@code null}.
   * @param  deleteBaseEntry
   *              Indicates whether the base entry itself should be deleted
   *              along with its subordinates (if {@code true}), or if only the
   *              subordinates of the base entry should be deleted but the base
   *              entry itself should remain (if {@code false}).
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  pageSize
   *              The page size for the simple paged results request control, if
   *              it is to be used.
   * @param  useSubentriesControl
   *              Indicates whether to look for LDAP subentries when searching
   *              for entries to delete.
   * @param  searchControls
   *              A list of controls that should be included in search requests
   *              used to find the entries to delete.  This must not be
   *              {@code null} but may be empty.
   * @param  deleteControls
   *              A list of controls that should be included in delete requests.
   *              This must not be {@code null} but may be empty.
   * @param  deleteRateLimiter
   *              A fixed-rate barrier used to impose a rate limit on delete
   *              operations.  This may be {@code null} if no rate limit should
   *              be imposed.
   *
   * @return  An object with information about the results of the subtree
   *          delete processing.
   */
  @NotNull()
  private static SubtreeDeleterResult deleteEntriesWithSimplePagedResults(
                      @NotNull final LDAPInterface connection,
                      @NotNull final DN baseDN,
                      final boolean deleteBaseEntry,
                      final int searchRequestSizeLimit,
                      final int pageSize,
                      final boolean useSubentriesControl,
                      @NotNull final List<Control> searchControls,
                      @NotNull final List<Control> deleteControls,
                      @Nullable final FixedRateBarrier deleteRateLimiter)
  {
    // If we should use the subentries control, then first search to find all
    // subentries in the subtree.
    final TreeSet<DN> dnsToDelete = new TreeSet<>();
    if (useSubentriesControl)
    {
      try
      {
        final SearchRequest searchRequest = createSubentriesSearchRequest(
             baseDN, 0, searchControls, dnsToDelete);
        doPagedResultsSearch(connection, searchRequest, pageSize);
      }
      catch (final LDAPSearchException e)
      {
        Debug.debugException(e);
        return new SubtreeDeleterResult(null, false, e.getSearchResult(), 0L,
             new TreeMap<DN,LDAPResult>());
      }
    }


    // Perform a paged search to find all all entries (except subentries) in the
    // target subtree.
    try
    {
      final SearchRequest searchRequest = createNonSubentriesSearchRequest(
           baseDN, 0, searchControls, dnsToDelete);
      doPagedResultsSearch(connection, searchRequest, pageSize);
    }
    catch (final LDAPSearchException e)
    {
      Debug.debugException(e);
      return new SubtreeDeleterResult(null, false, e.getSearchResult(), 0L,
           new TreeMap<DN,LDAPResult>());
    }


    // If we should not delete the base entry, then remove it from the set of
    // DNs to delete.
    if (! deleteBaseEntry)
    {
      dnsToDelete.remove(baseDN);
    }


    // Iterate through the DNs in reverse order and start deleting.  If we
    // encounter any entry that can't be deleted, then remove all of its
    // ancestors from the set of DNs to delete and create delete errors for
    // them.
    final AtomicReference<SearchResult> searchError = new AtomicReference<>();
    final AtomicLong entriesDeleted = new AtomicLong(0L);
    final TreeMap<DN,LDAPResult> deleteErrors = new TreeMap<>();
    final Iterator<DN> iterator = dnsToDelete.descendingIterator();
    while (iterator.hasNext())
    {
      final DN dn = iterator.next();
      if (! deleteErrors.containsKey(dn))
      {
        if (! deleteEntry(connection, dn, deleteControls, entriesDeleted,
             deleteErrors, deleteRateLimiter, searchRequestSizeLimit,
             searchControls, useSubentriesControl, searchError))
        {
          DN parentDN = dn.getParent();
          while ((parentDN != null) && parentDN.isDescendantOf(baseDN, true))
          {
            if (deleteErrors.containsKey(parentDN))
            {
              break;
            }

            deleteErrors.put(parentDN,
                 new LDAPResult(-1, ResultCode.NOT_ALLOWED_ON_NONLEAF,
                      ERR_SUBTREE_DELETER_SKIPPING_UNDELETABLE_ANCESTOR.get(
                           String.valueOf(parentDN), String.valueOf(dn)),
                      null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS));
            parentDN = parentDN.getParent();
          }
        }
      }
    }

    return new SubtreeDeleterResult(null, false, null, entriesDeleted.get(),
         deleteErrors);
  }



  /**
   * Creates a search request that can be used to find all LDAP subentries at
   * or below the specified base DN.
   *
   * @param  baseDN
   *              The base DN to use for the search request.  It must not be
   *              {@code null}.
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  controls
   *              The set of controls to use for the search request.  It must
   *              not be {@code null} but may be empty.
   * @param  dnSet
   *              The set of DNs that should be updated with the DNs of the
   *              matching entries.  It must not be {@code null} and must be
   *              updatable.
   *
   * @return  A search request that can be used to find all LDAP subentries at
   *          or below the specified base DN.
   */
  @NotNull()
  private static SearchRequest createSubentriesSearchRequest(
                                    @NotNull final DN baseDN,
                                    final int searchRequestSizeLimit,
                                    @NotNull final List<Control> controls,
                                    @NotNull final SortedSet<DN> dnSet)
  {
    final Filter filter =
         Filter.createEqualityFilter("objectClass", "ldapSubentry");

    final SubtreeDeleterSearchResultListener searchListener =
         new SubtreeDeleterSearchResultListener(baseDN, filter, dnSet);

    final SearchRequest searchRequest = new SearchRequest(searchListener,
         baseDN.toString(), SearchScope.SUB, DereferencePolicy.NEVER,
         searchRequestSizeLimit, 0, false, filter, "1.1");

    for (final Control c : controls)
    {
      searchRequest.addControl(c);
    }
    searchRequest.addControl(new DraftLDUPSubentriesRequestControl(false));

    return searchRequest;
  }



  /**
   * Creates a search request that can be used to find all entries at or below
   * the specified base DN that are not LDAP subentries.
   *
   * @param  baseDN
   *              The base DN to use for the search request.  It must not be
   *              {@code null}.
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  controls
   *              The set of controls to use for the search request.  It must
   *              not be {@code null} but may be empty.
   * @param  dnSet
   *              The set of DNs that should be updated with the DNs of the
   *              matching entries.  It must not be {@code null} and must be
   *              updatable.
   *
   * @return  A search request that can be used to find all entries at or below
   *          the specified base DN that are not LDAP subentries.
   */
  @NotNull()
  private static SearchRequest createNonSubentriesSearchRequest(
                                    @NotNull final DN baseDN,
                                    final int searchRequestSizeLimit,
                                    @NotNull final List<Control> controls,
                                    @NotNull final SortedSet<DN> dnSet)
  {
    final Filter filter = Filter.createPresenceFilter("objectClass");

    final SubtreeDeleterSearchResultListener searchListener =
         new SubtreeDeleterSearchResultListener(baseDN, filter, dnSet);

    final SearchRequest searchRequest = new SearchRequest(searchListener,
         baseDN.toString(), SearchScope.SUB, DereferencePolicy.NEVER,
         searchRequestSizeLimit, 0, false, filter, "1.1");

    for (final Control c : controls)
    {
      searchRequest.addControl(c);
    }

    return searchRequest;
  }



  /**
   * Uses the simple paged results control to iterate through all entries in
   * the server that match the criteria from the provided search request.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  searchRequest
   *              The search request to be processed using the simple paged
   *              results control.  The request must not already include the
   *              simple paged results request control, but must otherwise be
   *              the request that should be processed, including any other
   *              controls that are desired.  It must not be {@code null}.
   * @param  pageSize
   *              The maximum number of entries that should be included in any
   *              page of results.  It must be greater than or equal to one.
   *
   * @throws  LDAPSearchException  If a problem is encountered during search
   *                               processing that prevents it from successfully
   *                               identifying all of the entries.
   */
  private static void doPagedResultsSearch(
                           @NotNull final LDAPInterface connection,
                           @NotNull final SearchRequest searchRequest,
                           final int pageSize)
          throws LDAPSearchException
  {
    final SubtreeDeleterSearchResultListener searchListener =
         (SubtreeDeleterSearchResultListener)
         searchRequest.getSearchResultListener();

    ASN1OctetString pagedResultsCookie = null;
    while (true)
    {
      final SearchRequest pagedResultsSearchRequest = searchRequest.duplicate();
      pagedResultsSearchRequest.addControl(new SimplePagedResultsControl(
           pageSize, pagedResultsCookie, true));

      SearchResult searchResult;
      try
      {
        searchResult = connection.search(pagedResultsSearchRequest);
      }
      catch (final LDAPSearchException e)
      {
        Debug.debugException(e);
        searchResult = e.getSearchResult();
      }

      if (searchResult.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        // This means that the base entry doesn't exist.  This isn't an error.
        // It just means that there aren't any entries to delete.
        return;
      }
      else if (searchResult.getResultCode() != ResultCode.SUCCESS)
      {
        throw new LDAPSearchException(searchResult);
      }
      else if (searchListener.getFirstException() != null)
      {
        throw new LDAPSearchException(searchListener.getFirstException());
      }

      final SimplePagedResultsControl responseControl;
      try
      {
        responseControl = SimplePagedResultsControl.get(searchResult);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new LDAPSearchException(e);
      }

      if (responseControl == null)
      {
        throw new LDAPSearchException(ResultCode.CONTROL_NOT_FOUND,
             ERR_SUBTREE_DELETER_MISSING_PAGED_RESULTS_RESPONSE.get(
                  searchRequest.getBaseDN(), searchRequest.getFilter()));
      }

      if (responseControl.moreResultsToReturn())
      {
        pagedResultsCookie = responseControl.getCookie();
      }
      else
      {
        return;
      }
    }
  }



  /**
   * Attempts to delete an entry from the server.  If the delete attempt fails
   * with a {@link ResultCode#NOT_ALLOWED_ON_NONLEAF} result, then an attempt
   * will be made to search for all of the subordinates of the target entry so
   * that they can be deleted, and then a second attempt will be made to remove
   * the target entry.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  dn   The DN of the entry to delete.  It must not be {@code null}.
   * @param  deleteControls
   *              A list of the controls that should be included in the delete
   *              request.  It must not be {@code null}, but may be empty.
   * @param  entriesDeleted
   *              A counter that should be incremented for each entry that is
   *              successfully deleted.  It must not be {@code null}.
   * @param  deleteErrors
   *              A map that should be updated with the DN of the entry and the
   *              delete result, if the delete is unsuccessful.  It must not be
   *              {@code null} and must be updatable.
   * @param  deleteRateLimiter
   *              A fixed-rate barrier used to impose a rate limit on delete
   *              operations.  This may be {@code null} if no rate limit should
   *              be imposed.
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  searchControls
   *              A list of controls that should be included in search
   *              requests, if the initial delete attempt fails because the
   *              entry has subordinates.  It must not be {@code null}, but may
   *              be empty.
   * @param  useSubentriesControl
   *              Indicates whether to look for LDAP subentries when searching
   *              for entries to delete.
   * @param  searchError
   *              A reference that may be updated, if it is not already set,
   *              with information about an error that occurred during search
   *              processing.  It must not be {@code null}, but may be
   *              unassigned.
   *
   * @return  {@code true} if the entry was successfully deleted, or
   *          {@code false} if not.
   */
  private static boolean deleteEntry(@NotNull final LDAPInterface connection,
               @NotNull final DN dn,
               @NotNull final List<Control> deleteControls,
               @NotNull final AtomicLong entriesDeleted,
               @NotNull final SortedMap<DN,LDAPResult> deleteErrors,
               @Nullable final FixedRateBarrier deleteRateLimiter,
               final int searchRequestSizeLimit,
               @NotNull final List<Control> searchControls,
               final boolean useSubentriesControl,
               @NotNull final AtomicReference<SearchResult> searchError)
  {
    if (deleteRateLimiter != null)
    {
      deleteRateLimiter.await();
    }

    LDAPResult deleteResult;
    try
    {
      deleteResult = connection.delete(dn.toString());
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      deleteResult = e.toLDAPResult();
    }

    final ResultCode resultCode = deleteResult.getResultCode();
    if (resultCode == ResultCode.SUCCESS)
    {
      // The entry was successfully deleted.
      entriesDeleted.incrementAndGet();
      return true;
    }
    else if (resultCode == ResultCode.NO_SUCH_OBJECT)
    {
      // This is fine.  It must have been deleted between the time of the
      // search and the time we got around to deleting it.
      return true;
    }
    else if (resultCode == ResultCode.NOT_ALLOWED_ON_NONLEAF)
    {
      // The entry must have children.  Try to recursively delete it.
      return searchAndDelete(connection, dn, searchRequestSizeLimit,
           searchControls, useSubentriesControl, searchError, deleteControls,
           entriesDeleted, deleteErrors, deleteRateLimiter);
    }
    else
    {
      // This is just an error.
      deleteErrors.put(dn, deleteResult);
      return false;
    }
  }



  /**
   * Issues a subtree search (or a pair of subtree searches if the subentries
   * control should be used) to find any entries below the provided base DN,
   * and then attempts to delete all of those entries.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree in which to perform the search and
   *              delete operations.  It must not be {@code null}.
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  searchControls
   *              A list of controls that should be included in search
   *              requests, if the initial delete attempt fails because the
   *              entry has subordinates.  It must not be {@code null}, but may
   *              be empty.
   * @param  useSubentriesControl
   *              Indicates whether to look for LDAP subentries when searching
   *              for entries to delete.
   * @param  searchError
   *              A reference that may be updated, if it is not already set,
   *              with information about an error that occurred during search
   *              processing.  It must not be {@code null}, but may be
   *              unassigned.
   * @param  deleteControls
   *              A list of the controls that should be included in the delete
   *              request.  It must not be {@code null}, but may be empty.
   * @param  entriesDeleted
   *              A counter that should be incremented for each entry that is
   *              successfully deleted.  It must not be {@code null}.
   * @param  deleteErrors
   *              A map that should be updated with the DN of the entry and the
   *              delete result, if the delete is unsuccessful.  It must not be
   *              {@code null} and must be updatable.
   * @param  deleteRateLimiter
   *              A fixed-rate barrier used to impose a rate limit on delete
   *              operations.  This may be {@code null} if no rate limit should
   *              be imposed.
   *
   * @return  {@code true} if the subtree was successfully deleted, or
   *          {@code false} if any errors occurred that prevented one or more
   *          entries from being removed.
   */
  private static boolean searchAndDelete(
               @NotNull final LDAPInterface connection,
               @NotNull final DN baseDN,
               final int searchRequestSizeLimit,
               @NotNull final List<Control> searchControls,
               final boolean useSubentriesControl,
               @NotNull final AtomicReference<SearchResult> searchError,
               @NotNull final List<Control> deleteControls,
               @NotNull final AtomicLong entriesDeleted,
               @NotNull final SortedMap<DN,LDAPResult> deleteErrors,
               @Nullable final FixedRateBarrier deleteRateLimiter)
  {
    while (true)
    {
      // If appropriate, search for subentries.
      SearchResult subentriesSearchResult = null;
      final TreeSet<DN> dnsToDelete = new TreeSet<>();
      if (useSubentriesControl)
      {
        try
        {
          subentriesSearchResult = connection.search(
               createSubentriesSearchRequest(baseDN, searchRequestSizeLimit,
                    searchControls, dnsToDelete));
        }
        catch (final LDAPSearchException e)
        {
          Debug.debugException(e);
          subentriesSearchResult = e.getSearchResult();
        }
      }


      // Search for non-subentries.
      SearchResult nonSubentriesSearchResult;
      try
      {
        nonSubentriesSearchResult = connection.search(
             createNonSubentriesSearchRequest(baseDN, searchRequestSizeLimit,
                  searchControls, dnsToDelete));
      }
      catch (final LDAPSearchException e)
      {
        Debug.debugException(e);
        nonSubentriesSearchResult = e.getSearchResult();
      }


      // If we didn't find any entries, then there's nothing to do but
      // potentially update the search error.
      if (dnsToDelete.isEmpty())
      {
        if (subentriesSearchResult != null)
        {
          switch (subentriesSearchResult.getResultCode().intValue())
          {
            case ResultCode.SUCCESS_INT_VALUE:
            case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
              // These are both fine.
              break;

            default:
              searchError.compareAndSet(null, subentriesSearchResult);
              return false;
          }
        }

        switch (nonSubentriesSearchResult.getResultCode().intValue())
        {
          case ResultCode.SUCCESS_INT_VALUE:
          case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
            // These are both fine.
            break;

          default:
            searchError.compareAndSet(null, nonSubentriesSearchResult);
            return false;
        }

        // Even though we didn't delete anything, we can assume that the entries
        // don't exist, so we'll consider it successful.
        return true;
      }


      // Iterate through the entries that we found and delete the ones that we
      // can.
      boolean anySuccessful = false;
      boolean allSuccessful = true;
      final TreeSet<DN> ancestorsToSkip = new TreeSet<>();

      final DeleteRequest deleteRequest = new DeleteRequest("");
      deleteRequest.setControls(deleteControls);
      for (final DN dn : dnsToDelete.descendingSet())
      {
        if (deleteErrors.containsKey(dn))
        {
          // We've already encountered an error for this entry, so don't try to
          // delete it.
          allSuccessful = false;
          continue;
        }
        else if (ancestorsToSkip.contains(dn))
        {
          // We've already encountered an error while trying to delete one of
          // the descendants of this entry, so we'll skip it on this pass.  We
          // might get it on another pass.
          allSuccessful = false;
          continue;
        }

        // If there is a rate limiter, then wait on it.
        if (deleteRateLimiter != null)
        {
          deleteRateLimiter.await();
        }

        // Try to delete the target entry.
        LDAPResult deleteResult;
        try
        {
          deleteRequest.setDN(dn);
          deleteResult = connection.delete(deleteRequest);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          deleteResult = e.toLDAPResult();
        }

        switch (deleteResult.getResultCode().intValue())
        {
          case ResultCode.SUCCESS_INT_VALUE:
            // The entry was successfully deleted.
            anySuccessful = true;
            entriesDeleted.incrementAndGet();
            break;

          case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
            // The entry doesn't exist.  It may have been deleted between the
            // time we searched for it and the time we tried to delete it.
            // We'll treat this like a success, but won't increment the
            // counter.
            anySuccessful = true;
            break;

          case ResultCode.NOT_ALLOWED_ON_NONLEAF_INT_VALUE:
            // This suggests that the entry has children.  If it is the base
            // entry, then we may be able to loop back around and delete it on
            // another pass.  Otherwise, try to recursively delete it.
            if (dn.equals(baseDN))
            {
              allSuccessful = false;
            }
            else
            {
              if (searchAndDelete(connection, dn, searchRequestSizeLimit,
                   searchControls, useSubentriesControl, searchError,
                   deleteControls, entriesDeleted, deleteErrors,
                   deleteRateLimiter))
              {
                anySuccessful = true;
              }
              else
              {
                allSuccessful = false;

                DN parentDN = dn.getParent();
                while (parentDN != null)
                {
                  ancestorsToSkip.add(parentDN);
                  parentDN = parentDN.getParent();
                }
              }
            }
            break;

          default:
            // We definitely couldn't delete this entry, and we're not going to
            // make another attempt.  Put it in the set of delete errors, and
            // also include the DNs of all of its ancestors.
            deleteErrors.put(dn, deleteResult);

            DN parentDN = dn.getParent();
            while ((parentDN != null) && parentDN.isDescendantOf(baseDN, true))
            {
              deleteErrors.put(parentDN,
                   new LDAPResult(-1, ResultCode.NOT_ALLOWED_ON_NONLEAF,
                      ERR_SUBTREE_DELETER_SKIPPING_UNDELETABLE_ANCESTOR.get(
                           String.valueOf(parentDN), String.valueOf(dn)),
                      null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS));
              parentDN = parentDN.getParent();
            }

            allSuccessful = false;
            break;
        }
      }


      // Look at the search results and see if we need to update the search
      // error.  There's no error for a result code of SUCCESS or
      // NO_SUCH_OBJECT.  If the result code is SIZE_LIMIT_EXCEEDED, then that's
      // an error only if we couldn't delete any of the entries that we found.
      // If the result code is anything else, then that's an error.
      if (subentriesSearchResult != null)
      {
        switch (subentriesSearchResult.getResultCode().intValue())
        {
          case ResultCode.SUCCESS_INT_VALUE:
          case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
            break;

          case ResultCode.SIZE_LIMIT_EXCEEDED_INT_VALUE:
            if (! anySuccessful)
            {
              searchError.compareAndSet(null, subentriesSearchResult);
            }
            break;

          default:
            searchError.compareAndSet(null, subentriesSearchResult);
            break;
        }
      }

      switch (nonSubentriesSearchResult.getResultCode().intValue())
      {
        case ResultCode.SUCCESS_INT_VALUE:
        case ResultCode.NO_SUCH_OBJECT_INT_VALUE:
          break;

        case ResultCode.SIZE_LIMIT_EXCEEDED_INT_VALUE:
          if (! anySuccessful)
          {
            searchError.compareAndSet(null, nonSubentriesSearchResult);
          }
          break;

        default:
          searchError.compareAndSet(null, nonSubentriesSearchResult);
          break;
      }


      // Evaluate the success or failure of the processing that we performed.
      if (allSuccessful)
      {
        // We were able to successfully complete all of the deletes that we
        // attempted.  If the base entry was included in that set, then we were
        // successful and can return true.  Otherwise, we should loop back
        // around because that suggests there are more entries to delete.
        if (dnsToDelete.contains(baseDN))
        {
          return true;
        }
      }
      else if (! anySuccessful)
      {
        // We couldn't delete any of the entries that we tried.  This is
        // definitely an error.
        return false;
      }


      // If we've gotten here, then that means that we deleted at least some of
      // the entries, but we need to loop back around and make another attempt
    }
  }



  /**
   * Deletes the specified subtree with the given settings.  The simple paged
   * results control will not be used in the course of searching for entries to
   * delete.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to delete.  It must not be
   *              {@code null}.
   * @param  deleteBaseEntry
   *              Indicates whether the base entry itself should be deleted
   *              along with its subordinates (if {@code true}), or if only the
   *              subordinates of the base entry should be deleted but the base
   *              entry itself should remain (if {@code false}).
   * @param  searchRequestSizeLimit
   *              The size limit that should be used in each search request to
   *              specify the maximum number of entries to return in response
   *              to that request.  A value that is less than or equal to zero
   *              indicates that the client does not want to impose any size
   *              limit.
   * @param  useSubentriesControl
   *              Indicates whether to look for LDAP subentries when searching
   *              for entries to delete.
   * @param  searchControls
   *              A list of controls that should be included in search requests
   *              used to find the entries to delete.  This must not be
   *              {@code null} but may be empty.
   * @param  deleteControls
   *              A list of controls that should be included in delete requests.
   *              This must not be {@code null} but may be empty.
   * @param  deleteRateLimiter
   *              A fixed-rate barrier used to impose a rate limit on delete
   *              operations.  This may be {@code null} if no rate limit should
   *              be imposed.
   *
   * @return  An object with information about the results of the subtree
   *          delete processing.
   */
  @NotNull()
  private static SubtreeDeleterResult deleteEntriesWithoutSimplePagedResults(
                      @NotNull final LDAPInterface connection,
                      @NotNull final DN baseDN,
                      final boolean deleteBaseEntry,
                      final int searchRequestSizeLimit,
                      final boolean useSubentriesControl,
                      @NotNull final List<Control> searchControls,
                      @NotNull final List<Control> deleteControls,
                      @Nullable final FixedRateBarrier deleteRateLimiter)
  {
    // If we should use the subentries control, then first search to find all
    // subentries in the subentry, and delete them first.  Continue the
    // process until we run out of entries or until we can't delete any more.
    final TreeSet<DN> dnsToDelete = new TreeSet<>();
    final AtomicReference<SearchResult> searchError = new AtomicReference<>();
    final AtomicLong entriesDeleted = new AtomicLong(0L);
    final TreeMap<DN,LDAPResult> deleteErrors = new TreeMap<>();
    if (useSubentriesControl)
    {
      final SearchRequest searchRequest = createSubentriesSearchRequest(
           baseDN, searchRequestSizeLimit, searchControls, dnsToDelete);
      searchAndDelete(connection, baseDN, searchRequest, useSubentriesControl,
           searchControls, dnsToDelete, searchError, deleteBaseEntry,
           deleteControls, deleteRateLimiter,
           entriesDeleted, deleteErrors);
    }


    // Create a search request that doesn't use the subentries request
    // control,and use that to conduct the searches to identify the entries to
    // delete.
    final SearchRequest searchRequest = createNonSubentriesSearchRequest(baseDN,
         searchRequestSizeLimit, searchControls, dnsToDelete);
    searchAndDelete(connection, baseDN, searchRequest, useSubentriesControl,
         searchControls, dnsToDelete, searchError, deleteBaseEntry,
         deleteControls, deleteRateLimiter,
         entriesDeleted, deleteErrors);

    return new SubtreeDeleterResult(null, false, searchError.get(),
         entriesDeleted.get(), deleteErrors);
  }



  /**
   * Repeatedly processes the provided search request until there are no more
   * matching entries or until no more entries can be deleted.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to delete.  It must not be
   *              {@code null}.
   * @param  searchRequest
   *              The search request to use to identify the entries to delete.
   *              It must not be {@code null}, and must be repeatable exactly
   *              as-is.
   * @param  useSubentriesControl
   *              Indicates whether to look for LDAP subentries when searching
   *              for entries to delete.
   * @param  searchControls
   *              A list of controls that should be included in search requests
   *              used to find the entries to delete.  This must not be
   *              {@code null} but may be empty.
   * @param  dnsToDelete
   *              A sorted set that will be updated during search processing
   *              with the DNs of the entries that match the search criteria.
   *              It must not be {@code null}, and must be updatable.
   * @param  searchError
   *              A reference to an error that was encountered during search
   *              processing.  It must not be {@code null}, but may be
   *              unassigned.
   * @param  deleteBaseEntry
   *              Indicates whether the base entry itself should be deleted
   *              along with its subordinates (if {@code true}), or if only the
   *              subordinates of the base entry should be deleted but the base
   *              entry itself should remain (if {@code false}).
   * @param  deleteControls
   *              A list of controls that should be included in delete requests.
   *              This must not be {@code null} but may be empty.
   * @param  deleteRateLimiter
   *              A fixed-rate barrier used to impose a rate limit on delete
   *              operations.  This may be {@code null} if no rate limit should
   *              be imposed.
   * @param  entriesDeleted
   *              A counter used to keep track of the number of entries that
   *              have been deleted.  It must not be {@code null}.
   * @param  deleteErrors
   *              A sorted map that will be updated with information about
   *              unsuccessful attempts to delete entries.  It must not be
   *              {@code null}, and must be updatable.
   */
  private static void searchAndDelete(@NotNull final LDAPInterface connection,
               @NotNull final DN baseDN,
               @NotNull final SearchRequest searchRequest,
               final boolean useSubentriesControl,
               @NotNull final List<Control> searchControls,
               @NotNull final TreeSet<DN> dnsToDelete,
               @NotNull final AtomicReference<SearchResult> searchError,
               final boolean deleteBaseEntry,
               @NotNull final List<Control> deleteControls,
               @Nullable final FixedRateBarrier deleteRateLimiter,
               @NotNull final AtomicLong entriesDeleted,
               @NotNull final SortedMap<DN,LDAPResult> deleteErrors)
  {
    while (true)
    {
      // Get the number of entries that have been deleted thus far.  If this
      // hasn't gone up by the end of this loop, then we'll stop looping.
      final long beforeDeleteCount = entriesDeleted.get();


      // Issue a search to find all of the entries we can that match the
      // search criteria.
      SearchResult searchResult;
      try
      {
        searchResult = connection.search(searchRequest);
      }
      catch (final LDAPSearchException e)
      {
        Debug.debugException(e);
        searchResult = e.getSearchResult();
      }


      // See if we should update the search error result.
      if (searchError.get() == null)
      {
        final ResultCode searchResultCode = searchResult.getResultCode();
        if (searchResultCode == ResultCode.SUCCESS)
        {
          // This is obviously not an error.
        }
        else if (searchResultCode == ResultCode.NO_SUCH_OBJECT)
        {
          // This is also not an error.  It means that the base entry doesn't
          // exist, so there's no point in continuing on.
          return;
        }
        else if (searchResultCode == ResultCode.SIZE_LIMIT_EXCEEDED)
        {
          // This is probably not an error, but we may consider it one if we
          // can't delete anything during this pass.
        }
        else
        {
          // This is an error.
          searchError.compareAndSet(null, searchResult);
        }
      }


      // If we should not delete the base entry, then remove it from the set.
      if (! deleteBaseEntry)
      {
        dnsToDelete.remove(baseDN);
      }


      // Iterate through the DN set, which should have been populated by the
      // search.  If any of them are in the delete errors map, then we'll skip
      // them.  All others we'll try to delete.
      final Iterator<DN> dnIterator = dnsToDelete.descendingIterator();
      while (dnIterator.hasNext())
      {
        final DN dnToDelete = dnIterator.next();
        dnIterator.remove();

        // Don't try to delete the entry if we've already tried and failed.
        if (! deleteErrors.containsKey(dnToDelete))
        {
          if (! deleteEntry(connection, dnToDelete, deleteControls,
               entriesDeleted, deleteErrors, deleteRateLimiter,
               searchRequest.getSizeLimit(), searchControls,
               useSubentriesControl, searchError))
          {
            // We couldn't delete the entry.  That means we also won't be able
            // to delete its parents, so put them in the errors map so that we
            // won't even try to delete them.
            DN parentDN = dnToDelete.getParent();
            while ((parentDN != null) && parentDN.isDescendantOf(baseDN, true))
            {
              if (deleteErrors.containsKey(parentDN))
              {
                break;
              }

              deleteErrors.put(parentDN,
                   new LDAPResult(-1, ResultCode.NOT_ALLOWED_ON_NONLEAF,
                        ERR_SUBTREE_DELETER_SKIPPING_UNDELETABLE_ANCESTOR.get(
                             String.valueOf(parentDN),
                             String.valueOf(dnToDelete)),
                        null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS));
              parentDN = parentDN.getParent();
            }
          }
        }
      }

      final long afterDeleteCount = entriesDeleted.get();
      if (afterDeleteCount == beforeDeleteCount)
      {
        // We were unable to successfully delete any entries this time through
        // the loop.  That may mean that there aren't any more entries, or that
        // errors prevented deleting the entries we did find.  If we happened to
        // get a "size limit exceeded" search result, and if the search error
        // isn't set, then set it to the "size limit exceeded" result.
        if (searchResult.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED)
        {
          searchError.compareAndSet(null, searchResult);
        }

        return;
      }
    }
  }



  /**
   * Removes teh subtree accessibility restriction from the server.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  baseDN
   *              The base DN for the subtree to make accessible.  It must not
   *              be {@code null}.
   *
   * @return  The result of the attempt to remove the subtree accessibility
   *          restriction.
   */
  @NotNull()
  private static ExtendedResult removeAccessibilityRestriction(
                                     @NotNull final LDAPInterface connection,
                                     @NotNull final DN baseDN)
  {
    return processExtendedOperation(connection,
         SetSubtreeAccessibilityExtendedRequest.createSetAccessibleRequest(
              baseDN.toString()));
  }



  /**
   * Uses the provided connection to process the given extended request.
   *
   * @param  connection
   *              The {@link LDAPInterface} instance to use to communicate with
   *              the directory server.  While this may be an individual
   *              {@link LDAPConnection}, it may be better as a connection
   *              pool with automatic retry enabled so that it's more likely to
   *              succeed in the event that a connection becomes invalid or an
   *              operation experiences a transient failure.  It must not be
   *              {@code null}.
   * @param  request
   *              The extended request to be processed.  It must not be
   *              {@code null}.
   *
   * @return  The extended result obtained from processing the request.
   */
  @NotNull()
  private static ExtendedResult processExtendedOperation(
                                     @NotNull final LDAPInterface connection,
                                     @NotNull final ExtendedRequest request)
  {
    try
    {
      if (connection instanceof LDAPConnection)
      {
        return ((LDAPConnection) connection).processExtendedOperation(
             request);
      }
      else if (connection instanceof AbstractConnectionPool)
      {
        return ((AbstractConnectionPool) connection).processExtendedOperation(
             request);
      }
      else
      {
        return new ExtendedResult(-1, ResultCode.PARAM_ERROR,
             ERR_SUBTREE_DELETER_INTERFACE_EXTOP_NOT_SUPPORTED.get(
                  connection.getClass().getName()),
             null, StaticUtils.NO_STRINGS, null, null, StaticUtils.NO_CONTROLS);
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      return new ExtendedResult(e);
    }
  }



  /**
   * Attempts to determine whether the server advertises support for the
   * specified extended request.
   *
   * @param  connection
   *              The connection (or other {@link LDAPInterface} instance, like
   *              a connection pool) that should be used to communicate with the
   *              directory server.  It must not be {@code null}.
   * @param  rootDSE
   *              A reference to the server root DSE, if it has already been
   *              retrieved.  It must not be {@code null}, but may be
   *              unassigned.
   * @param  oid  The OID of the extended request for which to make the
   *              determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the server advertises support for the specified
   *          request control, or {@code false} if not.
   */
  private static boolean supportsExtendedRequest(
                              @NotNull final LDAPInterface connection,
                              @NotNull final AtomicReference<RootDSE> rootDSE,
                              @NotNull final String oid)
  {
    final RootDSE dse = getRootDSE(connection, rootDSE);
    if (dse == null)
    {
      return false;
    }
    else
    {
      return dse.supportsExtendedOperation(oid);
    }
  }



  /**
   * Attempts to determine whether the server advertises support for the
   * specified request control.
   *
   * @param  connection
   *              The connection (or other {@link LDAPInterface} instance, like
   *              a connection pool) that should be used to communicate with the
   *              directory server.  It must not be {@code null}.
   * @param  rootDSE
   *              A reference to the server root DSE, if it has already been
   *              retrieved.  It must not be {@code null}, but may be
   *              unassigned.
   * @param  oid  The OID of the request control for which to make the
   *              determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the server advertises support for the specified
   *          request control, or {@code false} if not.
   */
  private static boolean supportsControl(
                              @NotNull final LDAPInterface connection,
                              @NotNull final AtomicReference<RootDSE> rootDSE,
                              @NotNull final String oid)
  {
    final RootDSE dse = getRootDSE(connection, rootDSE);
    if (dse == null)
    {
      return false;
    }
    else
    {
      return dse.supportsControl(oid);
    }
  }



  /**
   * Retrieves the server's root DSE.  It will use the cached version if it's
   * already available, or will retrieve it from the server if not.
   *
   * @param  connection
   *              The connection (or other {@link LDAPInterface} instance, like
   *              a connection pool) that should be used to communicate with the
   *              directory server.  It must not be {@code null}.
   * @param  rootDSE
   *              A reference to the server root DSE, if it has already been
   *              retrieved.  It must not be {@code null}, but may be
   *              unassigned.
   *
   * @return  The server's root DSE, or {@code null} if it could not be
   *          retrieved.
   */
  @Nullable()
  private static RootDSE getRootDSE(@NotNull final LDAPInterface connection,
                              @NotNull final AtomicReference<RootDSE> rootDSE)
  {
    final RootDSE dse = rootDSE.get();
    if (dse != null)
    {
      return dse;
    }

    try
    {
      return connection.getRootDSE();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves a string representation of this subtree deleter.
   *
   * @return  A string representation of this subtree deleter.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this subtree deleter to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SubtreeDeleter(deleteBaseEntry=");
    buffer.append(deleteBaseEntry);
    buffer.append(", useSetSubtreeAccessibilityOperationIfAvailable=");
    buffer.append(useSetSubtreeAccessibilityOperationIfAvailable);

    if (useSimplePagedResultsControlIfAvailable)
    {
      buffer.append(
           ", useSimplePagedResultsControlIfAvailable=true, pageSize=");
      buffer.append(simplePagedResultsPageSize);
    }
    else
    {
      buffer.append(", useSimplePagedResultsControlIfAvailable=false");
    }

    buffer.append(", useManageDSAITControlIfAvailable=");
    buffer.append(useManageDSAITControlIfAvailable);
    buffer.append(", usePermitUnindexedSearchControlIfAvailable=");
    buffer.append(usePermitUnindexedSearchControlIfAvailable);
    buffer.append(", useSubentriesControlIfAvailable=");
    buffer.append(useSubentriesControlIfAvailable);
    buffer.append(", useReturnConflictEntriesRequestControlIfAvailable=");
    buffer.append(useReturnConflictEntriesRequestControlIfAvailable);
    buffer.append(", useSoftDeletedEntryAccessControlIfAvailable=");
    buffer.append(useSoftDeletedEntryAccessControlIfAvailable);
    buffer.append(", useHardDeleteControlIfAvailable=");
    buffer.append(useHardDeleteControlIfAvailable);

    buffer.append(", additionalSearchControls={ ");
    final Iterator<Control> searchControlIterator =
         additionalSearchControls.iterator();
    while (searchControlIterator.hasNext())
    {
      buffer.append(searchControlIterator.next());
      if (searchControlIterator.hasNext())
      {
        buffer.append(',');
      }
      buffer.append(' ');
    }

    buffer.append("}, additionalDeleteControls={");
    final Iterator<Control> deleteControlIterator =
         additionalSearchControls.iterator();
    while (deleteControlIterator.hasNext())
    {
      buffer.append(deleteControlIterator.next());
      if (deleteControlIterator.hasNext())
      {
        buffer.append(',');
      }
      buffer.append(' ');
    }

    buffer.append("}, searchRequestSizeLimit=");
    buffer.append(searchRequestSizeLimit);
    buffer.append(')');
  }
}
