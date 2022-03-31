/*
 * Copyright 2014-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2022 Ping Identity Corporation
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
 * Copyright (C) 2014-2022 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be included in a search
 * request to indicate that the server should provide the number of entries that
 * match the search criteria.  The count will be included in the search result
 * done message, and all search result entries will be suppressed.
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
 * Whenever possible, the server will use index information to quickly identify
 * entries matching the criteria of the associated search request.  However, if
 * the count is only determined using index information, then that count may
 * include entries that would not actually be returned to the client in the
 * course of processing that search (e.g., because the client doesn't have
 * permission to access the entry, or because it is a special "operational"
 * entry like an LDAP subentry, replication conflict entry, or soft-deleted
 * entry).  Indicating that the server should always examine candidate entries
 * will increase the length of time to obtain the matching entry count, but will
 * ensure that the count will not include entries that would not otherwise be
 * returned by that search.
 * <BR><BR>
 * Also note that this control is not compatible for use with other controls
 * that may cause only a subset of entries to be returned, including the simple
 * paged results control and the virtual list view control.  It is also not
 * compatible for use with other controls that may cause the server to return
 * more entries than those that match the search criteria, like the LDAP join
 * control.
 * <BR><BR>
 * The OID for a matching entry count request control is
 * "1.3.6.1.4.1.30221.2.5.36", and it may have a criticality of either
 * {@code true} or {@code false}.  It must include a value with the following
 * encoding:
 * <PRE>
 *   MatchingEntryCountRequest ::= SEQUENCE {
 *        maxCandidatesToExamine           [0] INTEGER (0 .. MAX) DEFAULT 0,
 *        alwaysExamineCandidates          [1] BOOLEAN DEFAULT FALSE,
 *        processSearchIfUnindexed         [2] BOOLEAN DEFAULT FALSE,
 *        includeDebugInfo                 [3] BOOLEAN DEFAULT FALSE,
 *        skipResolvingExplodedIndexes     [4] BOOLEAN DEFAULT FALSE,
 *        fastShortCircuitThreshold        [5] INTEGER (0 .. MAX) OPTIONAL,
 *        slowShortCircuitThreshold        [6] INTEGER (0 .. MAX) OPTIONAL,
 *        includeExtendedResponseData      [7] BOOLEAN DEFAULT FALSE,
 *        ... }
 * </PRE>
 *
 * @see  MatchingEntryCountResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MatchingEntryCountRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.36) for the matching entry count request
   * control.
   */
  @NotNull public static final String MATCHING_ENTRY_COUNT_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.36";



  /**
   * The OID (1.3.6.1.4.1.30221.2.12.7) for the supportedFeature value that a
   * server should advertise in its root DSE if it supports returning extended
   * information in the response control that older clients may not be able to
   * handle.  Clients that wish to use the {@code includeExtendedResponseData}
   * element of the request control should check the target server's root DSE
   * to determine whether it supports this feature before requesting it because
   * older versions of the server that do not support it may not accept a
   * control that requests it.
   */
  @NotNull public static final String EXTENDED_RESPONSE_DATA_FEATURE_OID =
       "1.3.6.1.4.1.30221.2.12.7";



  /**
   * The BER type for the element that specifies the maximum number of candidate
   * entries to examine.
   */
  private static final byte TYPE_MAX_CANDIDATES_TO_EXAMINE = (byte) 0x80;



  /**
   * The BER type for the element that indicates whether always examine
   * candidate entries to determine whether they would actually be returned to
   * the client.
   */
  private static final byte TYPE_ALWAYS_EXAMINE_CANDIDATES = (byte) 0x81;



  /**
   * The BER type for the element that indicates whether to process an unindexed
   * search to determine the number of matching entries.
   */
  private static final byte TYPE_PROCESS_SEARCH_IF_UNINDEXED = (byte) 0x82;



  /**
   * The BER type for the element that indicates whether to include debug
   * information in the response.
   */
  private static final byte TYPE_INCLUDE_DEBUG_INFO = (byte) 0x83;



  /**
   * The BER type for the element that indicates whether to skip resolving
   * exploded indexes if the number of matching entries is known.
   */
  private static final byte TYPE_SKIP_RESOLVING_EXPLODED_INDEXES = (byte) 0x84;



  /**
   * The BER type for the element that specifies the short-circuit threshold to
   * use when performing index processing that is expected to be very fast
   * (e.g., filter components that can be evaluated with a single index lookup,
   * like presence, equality, and approximate match components).
   */
  private static final byte TYPE_FAST_SHORT_CIRCUIT_THRESHOLD = (byte) 0x85;



  /**
   * The BER type for the element that specifies the short-circuit threshold to
   * use when evaluating filter components that are not covered by the fast
   * short-circuit threshold.
   */
  private static final byte TYPE_SLOW_SHORT_CIRCUIT_THRESHOLD = (byte) 0x86;



  /**
   * The BER type for the element that indicates whether the client wants the
   * server to return extended information in the response, including elements
   * that may indicate whether all of the identified candidate entries are
   * within the scope of the search and any portion of the filter that is
   * unindexed or unevaluated.
   */
  private static final byte TYPE_INCLUDE_EXTENDED_RESPONSE_DATA = (byte) 0x87;



  /**
   * The name of the field used to hold the always examine candidates flag in
   * the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ALWAYS_EXAMINE_CANDIDATES =
       "always-examine-candidates";



  /**
   * The name of the field used to hold the fast short-circuit threshold in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_FAST_SHORT_CIRCUIT_THRESHOLD =
       "fast-short-circuit-threshold";



  /**
   * The name of the field used to hold the include debug info flag in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_INCLUDE_DEBUG_INFO =
       "include-debug-info";



  /**
   * The name of the field used to hold the include extended response data flag
   * in the JSON representation of this control.
   */
  @NotNull private static final String
       JSON_FIELD_INCLUDE_EXTENDED_RESPONSE_DATA =
            "include-extended-response-data";



  /**
   * The name of the field used to hold the maximum candidates to examine in the
   * JSON representation of this control.
   */
  @NotNull private static final String
       JSON_FIELD_MAXIMUM_CANDIDATES_TO_EXAMINE =
            "maximum-candidates-to-examine";



  /**
   * The name of the field used to hold the process search if unindexed flag in
   * the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_PROCESS_SEARCH_IF_UNINDEXED =
       "process-search-if-unindexed";



  /**
   * The name of the field used to hold the skip resolving exploded indexes flag
   * in the JSON representation of this control.
   */
  @NotNull private static final String
       JSON_FIELD_SKIP_RESOLVING_EXPLODED_INDEXES =
            "skip-resolving-exploded-indexes";



  /**
   * The name of the field used to hold the slow short-circuit threshold in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_SLOW_SHORT_CIRCUIT_THRESHOLD =
       "slow-short-circuit-threshold";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8670611963939571953L;



  // Indicates whether the server should internally retrieve and examine
  // candidate entries to determine whether they would actually be returned to
  // the client.
  private final boolean alwaysExamineCandidates;

  // Indicates whether to include debug information in the response control.
  private final boolean includeDebugInfo;

  // Indicates whether to include extended information in the response.
  private final boolean includeExtendedResponseData;

  // Indicates whether the server should attempt to actually iterate through the
  // entries in the backend in order to obtain the count if the search criteria
  // is not indexed.
  private final boolean processSearchIfUnindexed;

  // Indicates whether the server should skip retrieving the entry ID set for
  // an exploded index key if the number of matching entries is known.
  private final boolean skipResolvingExplodedIndexes;

  // The maximum number of candidate entries that should be examined if it is
  // not possible to obtain an exact count using only information contained in
  // the server indexes.
  private final int maxCandidatesToExamine;

  // The short-circuit threshold that the server will use when evaluating filter
  // components that are not categorized as fast.
  @Nullable private final Long slowShortCircuitThreshold;

  // The short-circuit threshold that the server will for index processing that
  // should be very fast.
  @Nullable private final Long fastShortCircuitThreshold;



  /**
   * Creates a new matching entry count request control with the default
   * settings.  The control will be critical, no candidate entries will be
   * examined, and the search will not be processed if it is unindexed.
   */
  public MatchingEntryCountRequestControl()
  {
    this(true, 0, false, false, false);
  }



  /**
   * Creates a new matching entry count request control with the provided
   * information.
   *
   * @param  isCritical                Indicates whether this control should be
   *                                   critical.
   * @param  maxCandidatesToExamine    The maximum number of candidate entries
   *                                   that the server should retrieve and
   *                                   examine to determine whether they
   *                                   actually match the search criteria.  If
   *                                   the search is partially indexed and the
   *                                   total number of candidate entries is less
   *                                   than or equal to this value, then these
   *                                   candidate entries will be examined to
   *                                   determine which of them match the search
   *                                   criteria so that an accurate count can
   *                                   be determined.  If the search is fully
   *                                   indexed such that the all candidate
   *                                   entries are known to match the search
   *                                   criteria, then the server may still
   *                                   examine each of these entries if the
   *                                   number of candidates is less than
   *                                   {@code maxCandidatesToExamine} and
   *                                   {@code alwaysExamineCandidates} is true
   *                                   in order to allow the entry count that
   *                                   is returned to be restricted to only
   *                                   those entries that would actually be
   *                                   returned to the client.  This will be
   *                                   ignored for searches that are completely
   *                                   unindexed.
   *                                   <BR><BR>
   *                                   The value for this argument must be
   *                                   greater than or equal to zero.  If it
   *                                   is zero, then the server will not
   *                                   examine any entries, so a
   *                                   partially-indexed search will only be
   *                                   able to return a count that is an upper
   *                                   bound, and a fully-indexed search will
   *                                   only be able to return an unexamined
   *                                   exact count.  If there should be no bound
   *                                   on the number of entries to retrieve,
   *                                   then a value of {@code Integer.MAX_VALUE}
   *                                   may be specified.
   * @param  alwaysExamineCandidates   Indicates whether the server should
   *                                   always examine candidate entries to
   *                                   determine whether they would actually
   *                                   be returned to the client in a normal
   *                                   search.  This will only be used for
   *                                   fully-indexed searches in which the
   *                                   set of matching entries is known.  If the
   *                                   value is {@code true} and the number of
   *                                   candidates is smaller than
   *                                   {@code maxCandidatesToExamine}, then each
   *                                   matching entry will be internally
   *                                   retrieved and examined to determine
   *                                   whether it would be returned to the
   *                                   client based on the details of the search
   *                                   request (e.g., whether the requester has
   *                                   permission to access the entry, whether
   *                                   it's an LDAP subentry, replication
   *                                   conflict entry, soft-deleted entry, or
   *                                   other type of entry that is normally
   *                                   hidden) so that an exact count can be
   *                                   returned.  If this is {@code false} or
   *                                   the number of candidates exceeds
   *                                   {@code maxCandidatesToExamine}, then the
   *                                   server will only be able to return an
   *                                   unexamined count which may include
   *                                   entries that match the search criteria
   *                                   but that would not normally be returned
   *                                   to the requester.
   * @param  processSearchIfUnindexed  Indicates whether the server should
   *                                   attempt to determine the number of
   *                                   matching entries if the search criteria
   *                                   is completely unindexed.  If this is
   *                                   {@code true} and the requester has the
   *                                   unindexed-search privilege, then the
   *                                   server will iterate through all entries
   *                                   in the scope (which may take a very long
   *                                   time to complete) in order to to
   *                                   determine which of them match the search
   *                                   criteria so that it can return an
   *                                   accurate count.  If this is
   *                                   {@code false} or the requester does not
   *                                   have the unindexed-search privilege, then
   *                                   the server will not spend any time
   *                                   attempting to determine the number of
   *                                   matching entries and will instead return
   *                                   a matching entry count response control
   *                                   indicating that the entry count is
   *                                   unknown.
   * @param  includeDebugInfo          Indicates whether the server should
   *                                   include debug information in the response
   *                                   that may help better understand how it
   *                                   arrived at the result.  If any debug
   *                                   information is returned, it will be in
   *                                   the form of human-readable text that is
   *                                   not intended to be machine-parsable.
   */
  public MatchingEntryCountRequestControl(final boolean isCritical,
              final int maxCandidatesToExamine,
              final boolean alwaysExamineCandidates,
              final boolean processSearchIfUnindexed,
              final boolean includeDebugInfo)
  {
    this(isCritical, maxCandidatesToExamine, alwaysExamineCandidates,
         processSearchIfUnindexed, false, null, null, includeDebugInfo);
  }



  /**
   * Creates a new matching entry count request control with the provided
   * information.
   *
   * @param  isCritical                    Indicates whether this control should
   *                                       be critical.
   * @param  maxCandidatesToExamine        The maximum number of candidate
   *                                       entries that the server should
   *                                       retrieve and examine to determine
   *                                       whether they actually match the
   *                                       search criteria.  If the search is
   *                                       partially indexed and the total
   *                                       number of candidate entries is less
   *                                       than or equal to this value, then
   *                                       these candidate entries will be
   *                                       examined to determine which of them
   *                                       match the search criteria so that an
   *                                       accurate count can be determined.  If
   *                                       the search is fully indexed such that
   *                                       the all candidate entries are known
   *                                       to match the search criteria, then
   *                                       the server may still examine each of
   *                                       these entries if the number of
   *                                       candidates is less than
   *                                       {@code maxCandidatesToExamine} and
   *                                       {@code alwaysExamineCandidates} is
   *                                       {@code true} in order to allow the
   *                                       entry count that is returned to be
   *                                       restricted to only those entries that
   *                                       would actually be returned to the
   *                                       client.  This will be ignored for
   *                                       searches that are completely
   *                                       unindexed.
   *                                       <BR><BR>
   *                                       The value for this argument must be
   *                                       greater than or equal to zero.  If it
   *                                       is zero, then the server will not
   *                                       examine any entries, so a
   *                                       partially-indexed search will only be
   *                                       able to return a count that is an
   *                                       upper bound, and a fully-indexed
   *                                       search will only be able to return an
   *                                       unexamined exact count.  If there
   *                                       should be no bound on the number of
   *                                       entries to retrieve, then a value of
   *                                       {@code Integer.MAX_VALUE} may be
   *                                       specified.
   * @param  alwaysExamineCandidates       Indicates whether the server should
   *                                       always examine candidate entries to
   *                                       determine whether they would actually
   *                                       be returned to the client in a normal
   *                                       search.  This will only be used for
   *                                       fully-indexed searches in which the
   *                                       set of matching entries is known.  If
   *                                       the value is {@code true} and the
   *                                       number of candidates is smaller than
   *                                       {@code maxCandidatesToExamine}, then
   *                                       each matching entry will be
   *                                       internally retrieved and examined to
   *                                       determine whether it would be
   *                                       returned to the client based on the
   *                                       details of the search request (e.g.,
   *                                       whether the requester has permission
   *                                       to access the entry, whether it's an
   *                                       LDAP subentry, replication conflict
   *                                       entry, soft-deleted entry, or other
   *                                       type of entry that is normally
   *                                       hidden, etc.) so that an exact count
   *                                       can be returned.  If this is
   *                                       {@code false} or the number of
   *                                       candidates exceeds
   *                                       {@code maxCandidatesToExamine}, then
   *                                       the server will only be able to
   *                                       return an unexamined count which may
   *                                       include entries that match the search
   *                                       criteria but that would not normally
   *                                       be returned to the requester.
   * @param  processSearchIfUnindexed      Indicates whether the server should
   *                                       attempt to determine the number of
   *                                       matching entries if the search
   *                                       criteria is completely unindexed.  If
   *                                       this is {@code true} and the
   *                                       requester has the unindexed-search
   *                                       privilege, then the server will
   *                                       iterate through all entries in the
   *                                       scope (which may take a very long
   *                                       time to complete) in order to to
   *                                       determine which of them match the
   *                                       search criteria so that it can return
   *                                       an accurate count.  If this is
   *                                       {@code false} or the requester does
   *                                       not have the unindexed-search
   *                                       privilege, then the server will not
   *                                       spend any time attempting to
   *                                       determine the number of matching
   *                                       entries and will instead return a
   *                                       matching entry count response control
   *                                       indicating that the entry count is
   *                                       unknown.
   * @param  skipResolvingExplodedIndexes  Indicates whether the server should
   *                                       skip the effort of actually
   *                                       retrieving the candidate entry IDs
   *                                       for exploded index keys in which the
   *                                       number of matching entries is known.
   *                                       Skipping the process of retrieving
   *                                       the candidate entry IDs can allow the
   *                                       server to more quickly estimate the
   *                                       matching entry count, but the
   *                                       resulting estimate may be less
   *                                       accurate.
   * @param  fastShortCircuitThreshold     Specifies the short-circuit threshold
   *                                       that the server should use when
   *                                       determining whether to continue with
   *                                       index processing in an attempt to
   *                                       further pare down a candidate set
   *                                       that already has a defined superset
   *                                       of the entries that actually match
   *                                       the filter.  Short-circuiting may
   *                                       allow the server to skip
   *                                       potentially-costly index processing
   *                                       and allow it to obtain the matching
   *                                       entry count estimate faster, but the
   *                                       resulting estimate may be less
   *                                       accurate.  The fast short-circuit
   *                                       threshold will be used for index
   *                                       processing that is expected to be
   *                                       very fast (e.g., when performing
   *                                       index lookups for presence, equality,
   *                                       and approximate-match components,
   *                                       which should only require accessing a
   *                                       single index key).  A value that is
   *                                       less than or equal to zero indicates
   *                                       that the server should never short
   *                                       circuit when performing fast index
   *                                       processing.  A value of {@code null}
   *                                       indicates that the server should
   *                                       determine the appropriate fast
   *                                       short-circuit threshold to use.
   * @param  slowShortCircuitThreshold     Specifies the short-circuit threshold
   *                                       that the server should use when
   *                                       determining whether to continue with
   *                                       index processing for evaluation that
   *                                       may be more expensive than what falls
   *                                       into the "fast" category (e.g.,
   *                                       substring and range filter
   *                                       components).  A value that is less
   *                                       than or equal to zero indicates that
   *                                       the server should never short circuit
   *                                       when performing slow index
   *                                       processing.  A value of {@code null}
   *                                       indicates that the server should
   *                                       determine the appropriate slow
   *                                       short-circuit threshold to use.
   * @param  includeDebugInfo              Indicates whether the server should
   *                                       include debug information in the
   *                                       response that may help better
   *                                       understand how it arrived at the
   *                                       result.  If any debug information is
   *                                       returned, it will be in the form of
   *                                       human-readable text that is not
   *                                       intended to be machine-parsable.
   */
  public MatchingEntryCountRequestControl(final boolean isCritical,
              final int maxCandidatesToExamine,
              final boolean alwaysExamineCandidates,
              final boolean processSearchIfUnindexed,
              final boolean skipResolvingExplodedIndexes,
              @Nullable final Long fastShortCircuitThreshold,
              @Nullable final Long slowShortCircuitThreshold,
              final boolean includeDebugInfo)
  {
    super(MATCHING_ENTRY_COUNT_REQUEST_OID, isCritical,
         encodeValue(maxCandidatesToExamine, alwaysExamineCandidates,
              processSearchIfUnindexed, skipResolvingExplodedIndexes,
              fastShortCircuitThreshold, slowShortCircuitThreshold, false,
              includeDebugInfo));

    Validator.ensureTrue(maxCandidatesToExamine >= 0);

    this.maxCandidatesToExamine       = maxCandidatesToExamine;
    this.alwaysExamineCandidates      = alwaysExamineCandidates;
    this.processSearchIfUnindexed     = processSearchIfUnindexed;
    this.skipResolvingExplodedIndexes = skipResolvingExplodedIndexes;
    this.includeDebugInfo             = includeDebugInfo;

    if (fastShortCircuitThreshold == null)
    {
      this.fastShortCircuitThreshold = null;
    }
    else
    {
      this.fastShortCircuitThreshold = Math.max(0L, fastShortCircuitThreshold);
    }

    if (slowShortCircuitThreshold == null)
    {
      this.slowShortCircuitThreshold = null;
    }
    else
    {
      this.slowShortCircuitThreshold = Math.max(0L, slowShortCircuitThreshold);
    }

    includeExtendedResponseData = false;
  }



  /**
   * Creates a new matching entry count request control with the provided
   * properties.
   *
   * @param  isCritical  Indicates whether the control should be critical.
   * @param  properties  The properties that should be used to create this
   *                     matching entry count request control.  It must not be
   *                     {@code null}.
   */
  public MatchingEntryCountRequestControl(final boolean isCritical,
       @NotNull final MatchingEntryCountRequestControlProperties properties)
  {
    super(MATCHING_ENTRY_COUNT_REQUEST_OID, isCritical,
         encodeValue(properties.getMaxCandidatesToExamine(),
              properties.alwaysExamineCandidates(),
              properties.processSearchIfUnindexed(),
              properties.skipResolvingExplodedIndexes(),
              properties.getFastShortCircuitThreshold(),
              properties.getSlowShortCircuitThreshold(),
              properties.includeExtendedResponseData(),
              properties.includeDebugInfo()));

    maxCandidatesToExamine = properties.getMaxCandidatesToExamine();
    alwaysExamineCandidates = properties.alwaysExamineCandidates();
    processSearchIfUnindexed = properties.processSearchIfUnindexed();
    skipResolvingExplodedIndexes = properties.skipResolvingExplodedIndexes();
    fastShortCircuitThreshold = properties.getFastShortCircuitThreshold();
    slowShortCircuitThreshold = properties.getSlowShortCircuitThreshold();
    includeExtendedResponseData = properties.includeExtendedResponseData();
    includeDebugInfo = properties.includeDebugInfo();
  }



  /**
   * Creates a new matching entry count request control that is decoded from the
   * provided generic control.
   *
   * @param  control  The control to decode as a matching entry count request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         matching entry count request control.
   */
  public MatchingEntryCountRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MATCHING_ENTRY_COUNT_REQUEST_MISSING_VALUE.get());
    }

    try
    {
      boolean alwaysExamine    = false;
      boolean debug            = false;
      boolean includeExtended  = false;
      boolean processUnindexed = false;
      boolean skipExploded     = false;
      int     maxCandidates    = 0;
      Long    fastSCThreshold  = null;
      Long    slowSCThreshold  = null;
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_MAX_CANDIDATES_TO_EXAMINE:
            maxCandidates = ASN1Integer.decodeAsInteger(e).intValue();
            if (maxCandidates < 0)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_MATCHING_ENTRY_COUNT_REQUEST_INVALID_MAX.get());
            }
            break;

          case TYPE_ALWAYS_EXAMINE_CANDIDATES:
            alwaysExamine = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_PROCESS_SEARCH_IF_UNINDEXED:
            processUnindexed = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_INCLUDE_DEBUG_INFO:
            debug = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_SKIP_RESOLVING_EXPLODED_INDEXES:
            skipExploded = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_FAST_SHORT_CIRCUIT_THRESHOLD:
            fastSCThreshold =
                 Math.max(0L, ASN1Long.decodeAsLong(e).longValue());
            break;

          case TYPE_SLOW_SHORT_CIRCUIT_THRESHOLD:
            slowSCThreshold =
                 Math.max(0L, ASN1Long.decodeAsLong(e).longValue());
            break;

          case TYPE_INCLUDE_EXTENDED_RESPONSE_DATA:
            includeExtended = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
        }
      }

      maxCandidatesToExamine       = maxCandidates;
      alwaysExamineCandidates      = alwaysExamine;
      processSearchIfUnindexed     = processUnindexed;
      includeDebugInfo             = debug;
      includeExtendedResponseData  = includeExtended;
      skipResolvingExplodedIndexes = skipExploded;
      fastShortCircuitThreshold    = fastSCThreshold;
      slowShortCircuitThreshold    = slowSCThreshold;
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
           ERR_MATCHING_ENTRY_COUNT_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the control value.
   *
   * @param  maxCandidatesToExamine        The maximum number of candidate
   *                                       entries that the server should
   *                                       retrieve and examine to determine
   *                                       whether they actually match the
   *                                       search criteria.
   * @param  alwaysExamineCandidates       Indicates whether the server should
   *                                       always examine candidate entries to
   *                                       determine whether they would actually
   *                                       be returned to the client in a normal
   *                                       search with the same criteria.
   * @param  processSearchIfUnindexed      Indicates whether the server should
   *                                       attempt to determine the number of
   *                                       matching entries if the search
   *                                       criteria is completely unindexed.
   * @param  skipResolvingExplodedIndexes  Indicates whether the server should
   *                                       skip the effort of actually
   *                                       retrieving the candidate entry IDs
   *                                       for exploded index keys in which the
   *                                       number of matching entries is known.
   * @param  fastShortCircuitThreshold     Specifies the short-circuit threshold
   *                                       that the server should use when
   *                                       determining whether to continue with
   *                                       index processing for fast index
   *                                       processing.
   * @param  slowShortCircuitThreshold     Specifies the short-circuit threshold
   *                                       that the server should use when
   *                                       determining whether to continue with
   *                                       index processing for slow index
   *                                       processing.
   * @param  includeExtendedResponseData  Indicates whether the server may
   *                                      include extended response data in the
   *                                      corresponding response control.
   * @param  includeDebugInfo              Indicates whether the server should
   *                                       include debug information in the
   *                                       response that may help better
   *                                       understand how it arrived at the
   *                                       result.
   *
   * @return  The ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      final int maxCandidatesToExamine,
                      final boolean alwaysExamineCandidates,
                      final boolean processSearchIfUnindexed,
                      final boolean skipResolvingExplodedIndexes,
                      @Nullable final Long fastShortCircuitThreshold,
                      @Nullable final Long slowShortCircuitThreshold,
                      final boolean includeExtendedResponseData,
                      final boolean includeDebugInfo)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(4);

    if (maxCandidatesToExamine > 0)
    {
      elements.add(new ASN1Integer(TYPE_MAX_CANDIDATES_TO_EXAMINE,
           maxCandidatesToExamine));
    }

    if (alwaysExamineCandidates)
    {
      elements.add(new ASN1Boolean(TYPE_ALWAYS_EXAMINE_CANDIDATES, true));
    }

    if (processSearchIfUnindexed)
    {
      elements.add(new ASN1Boolean(TYPE_PROCESS_SEARCH_IF_UNINDEXED, true));
    }

    if (includeDebugInfo)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_DEBUG_INFO, true));
    }

    if (skipResolvingExplodedIndexes)
    {
      elements.add(new ASN1Boolean(TYPE_SKIP_RESOLVING_EXPLODED_INDEXES, true));
    }

    if (fastShortCircuitThreshold != null)
    {
      elements.add(new ASN1Long(TYPE_FAST_SHORT_CIRCUIT_THRESHOLD,
           Math.max(0L, fastShortCircuitThreshold)));
    }

    if (slowShortCircuitThreshold != null)
    {
      elements.add(new ASN1Long(TYPE_SLOW_SHORT_CIRCUIT_THRESHOLD,
           Math.max(0L, slowShortCircuitThreshold)));
    }

    if (includeExtendedResponseData)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_EXTENDED_RESPONSE_DATA, true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the maximum number of candidate entries that should be examined
   * in order to determine accurate count of the number of matching entries.
   * <BR><BR>
   * For a fully-indexed search, this property will only be used if
   * {@link #alwaysExamineCandidates} is true.  If the number of candidate
   * entries identified is less than the maximum number of candidates to
   * examine, then the server will return an {@code EXAMINED_COUNT} result that
   * indicates the number of entries matching the criteria that would actually
   * be returned in a normal search with the same criteria.  If the number of
   * candidate entries exceeds the maximum number of candidates to examine, then
   * the server will return an {@code UNEXAMINED_COUNT} result that indicates
   * the number of entries matching the search criteria but that may include
   * entries that would not actually be returned to the client.
   * <BR><BR>
   * For a partially-indexed search, if the upper bound on the number of
   * candidates is less than or equal to the maximum number of candidates to
   * examine, then the server will internally retrieve and examine each of those
   * candidates to determine which of them match the search criteria and would
   * actually be returned to the client, and will then return an
   * {@code EXAMINED_COUNT} result with that count.  If the upper bound on the
   * number of candidates is greater than the maximum number of candidates to
   * examine, then the server will return an {@code UPPER_BOUND} result to
   * indicate that the exact count is not known but an upper bound is available.
   *
   * @return  The maximum number of candidate entries to examine in order to
   *          determine an accurate count of the number of matching entries.
   */
  public int getMaxCandidatesToExamine()
  {
    return maxCandidatesToExamine;
  }



  /**
   * Indicates whether the server should always examine candidate entries in
   * fully-indexed searches to determine whether they would actually be returned
   * to the client in a normal search with the same criteria.
   *
   * @return  {@code true} if the server should attempt to internally retrieve
   *          and examine matching entries to determine whether they would
   *          normally be returned to the client (e.g., that the client has
   *          permission to access the entry and that it is not a
   *          normally-hidden entry like an LDAP subentry, a replication
   *          conflict entry, or a soft-deleted entry), or {@code false} if the
   *          server should return an unverified count.
   */
  public boolean alwaysExamineCandidates()
  {
    return alwaysExamineCandidates;
  }



  /**
   * Indicates whether the server should internally retrieve and examine all
   * entries within the search scope in order to obtain an exact matching entry
   * count for an unindexed search.  Note that this value will not be considered
   * for completely-indexed or partially-indexed searches, nor for searches in
   * which matching entries should be returned.
   *
   * @return  {@code true} if the server should internally retrieve and examine
   *          all entries within the search scope in order to obtain an exact
   *          matching entry count for an unindexed search, or {@code false} if
   *          not.
   */
  public boolean processSearchIfUnindexed()
  {
    return processSearchIfUnindexed;
  }



  /**
   * Indicates whether the server should skip the effort of actually retrieving
   * the candidate entry IDs for exploded index keys in which the number of
   * matching entries is known.  Skipping the process of accessing an exploded
   * index can allow the server to more quickly arrive at the matching entry
   * count estimate, but that estimate may be less accurate than if it had
   * actually retrieved those candidates.
   *
   * @return  {@code true} if the server should skip the effort of actually
   *          retrieving the candidate entry IDs for exploded index keys in
   *          which the number of matching entries is known, or {@code false} if
   *          it may retrieve candidates from an exploded index in the course of
   *          determining the matching entry count.
   */
  public boolean skipResolvingExplodedIndexes()
  {
    return skipResolvingExplodedIndexes;
  }



  /**
   * Retrieves the short-circuit threshold that the server should use when
   * determining whether to continue with index processing in an attempt to
   * further pare down a candidate set that already has a defined superset of
   * the entries that actually match the filter.  If the number of entries in
   * that candidate set is less than or equal to the short-circuit threshold,
   * then the server may simply use that candidate set in the course of
   * determining the matching entry count, even if there may be additional
   * processing that can be performed (e.g., further filter components to
   * evaluate) that may allow the server to pare down the results even further.
   * Short-circuiting may allow the server to obtain the matching entry count
   * estimate faster, but may also cause the resulting estimate to be less
   * accurate.
   * <BR><BR>
   * The value returned by this method will be used for cases in which the
   * server is performing the fastest types of index processing.  For example,
   * this may include evaluating presence, equality, or approximate match
   * components, which should only require retrieving a single index key to
   * obtain the candidate set.
   *
   * @return  The short-circuit threshold that should be used for fast index
   *          processing, zero if the server should not short-circuit at all
   *          during fast index processing, or {@code null} if the server should
   *          determine the appropriate fast short-circuit threshold to use.
   */
  @Nullable()
  public Long getFastShortCircuitThreshold()
  {
    return fastShortCircuitThreshold;
  }



  /**
   * Retrieves the short-circuit threshold that the server should use when
   * determining whether to continue with index processing in an attempt to
   * further pare down a candidate set that already has a defined superset of
   * the entries that actually match the filter.  If the number of entries in
   * that candidate set is less than or equal to the short-circuit threshold,
   * then the server may simply use that candidate set in the course of
   * determining the matching entry count, even if there may be additional
   * processing that can be performed (e.g., further filter components to
   * evaluate) that may allow the server to pare down the results even further.
   * Short-circuiting may allow the server to obtain the matching entry count
   * estimate faster, but may also cause the resulting estimate to be less
   * accurate.
   * <BR><BR>
   * The value returned by this method will be used for cases in which the
   * server is performing index processing that is not considered to be among
   * the fastest types of processing.  For example, this may include evaluating
   * substring and range components, as they may require retrieving many index
   * keys to obtain the full candidate set.
   *
   * @return  The short-circuit threshold that should be used for slow index
   *          processing, or zero if the server should not short-circuit at all
   *          during slow index processing, or {@code null} if the server should
   *          determine the appropriate slow short-circuit threshold to use.
   */
  @Nullable()
  public Long getSlowShortCircuitThreshold()
  {
    return slowShortCircuitThreshold;
  }



  /**
   * Indicates whether the server may include extended response data in the
   * corresponding response control, which may provide information like whether
   * all of the identified candidate entries are within the scope of the search
   * and any unindexed or unevaluated portion of the search filter.
   *
   * @return  {@code true} if the server may include extended response data
   *          in the corresponding response control, or {@code false} if not.
   */
  public boolean includeExtendedResponseData()
  {
    return includeExtendedResponseData;
  }



  /**
   * Attempts to determine whether the server to which the provided connection
   * is established supports including extended response data in the matching
   * entry count response control.
   *
   * @param  connection  The connection (or connection pool or other interface)
   *                     to use to communicate with the server.  It must not be
   *                     {@code null} and must be established.
   *
   * @return  {@code true} if the server reports that supports including
   *          extended response data in the matching entry count response
   *          control, or {@code false} if it does not indicate that it is
   *          supported.
   *
   * @throws  LDAPException  If a problem occurs while attempting to communicate
   *                         with the server.
   */
  public static boolean serverSupportsExtendedResponseData(
              @NotNull final LDAPInterface connection)
         throws LDAPException
  {
    final RootDSE rootDSE = connection.getRootDSE();
    return ((rootDSE != null) && serverSupportsExtendedResponseData(rootDSE));
  }



  /**
   * Determines whether the provided root DSE indicates that the associated
   * server supports including extended response data in the matching entry
   * count response control.
   *
   * @param  rootDSE  The root DSE retrieved from the server for which to make
   *                  the determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the root DSE indicates that supports including
   *          extended response data in the matching entry count response
   *          control, or {@code false} if not.
   */
  public static boolean serverSupportsExtendedResponseData(
              @NotNull final RootDSE rootDSE)
  {
    return rootDSE.supportsFeature(EXTENDED_RESPONSE_DATA_FEATURE_OID);
  }



  /**
   * Indicates whether the server should include debug information in the
   * response control that provides additional information about how the server
   * arrived at the result.  If debug information is to be provided, it will be
   * in a human-readable rather than machine-parsable form.
   *
   * @return  {@code true} if the server should include debug information in
   *          the response control, or {@code false} if not.
   */
  public boolean includeDebugInfo()
  {
    return includeDebugInfo;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_MATCHING_ENTRY_COUNT_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();

    if (maxCandidatesToExamine > 0)
    {
      valueFields.put(JSON_FIELD_MAXIMUM_CANDIDATES_TO_EXAMINE,
           new JSONNumber(maxCandidatesToExamine));
    }
    else
    {
      valueFields.put(JSON_FIELD_MAXIMUM_CANDIDATES_TO_EXAMINE,
           new JSONNumber(0));
    }

    valueFields.put(JSON_FIELD_ALWAYS_EXAMINE_CANDIDATES,
         new JSONBoolean(alwaysExamineCandidates));
    valueFields.put(JSON_FIELD_PROCESS_SEARCH_IF_UNINDEXED,
         new JSONBoolean(processSearchIfUnindexed));
    valueFields.put(JSON_FIELD_INCLUDE_DEBUG_INFO,
         new JSONBoolean(includeDebugInfo));
    valueFields.put(JSON_FIELD_SKIP_RESOLVING_EXPLODED_INDEXES,
         new JSONBoolean(skipResolvingExplodedIndexes));

    if (fastShortCircuitThreshold != null)
    {
      valueFields.put(JSON_FIELD_FAST_SHORT_CIRCUIT_THRESHOLD,
           new JSONNumber(fastShortCircuitThreshold));
    }

    if (slowShortCircuitThreshold != null)
    {
      valueFields.put(JSON_FIELD_SLOW_SHORT_CIRCUIT_THRESHOLD,
           new JSONNumber(slowShortCircuitThreshold));
    }

    valueFields.put(JSON_FIELD_INCLUDE_EXTENDED_RESPONSE_DATA,
         new JSONBoolean(includeExtendedResponseData));

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              MATCHING_ENTRY_COUNT_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_MATCHING_ENTRY_COUNT_REQUEST.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * matching entry count request control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The matching entry count request control that was decoded from the
   *          provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid matching entry count request control.
   */
  @NotNull()
  public static MatchingEntryCountRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new MatchingEntryCountRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final Integer maximumCandidatesToExamine = valueObject.getFieldAsInteger(
         JSON_FIELD_MAXIMUM_CANDIDATES_TO_EXAMINE);
    if (maximumCandidatesToExamine == null)
    {
      properties.setMaxCandidatesToExamine(0);
    }
    else
    {
      properties.setMaxCandidatesToExamine(maximumCandidatesToExamine);
    }


    final Boolean alwaysExamineCandidates =
         valueObject.getFieldAsBoolean(JSON_FIELD_ALWAYS_EXAMINE_CANDIDATES);
    if (alwaysExamineCandidates == null)
    {
      properties.setAlwaysExamineCandidates(false);
    }
    else
    {
      properties.setAlwaysExamineCandidates(alwaysExamineCandidates);
    }


    final Boolean processSearchIfUnindexed =
         valueObject.getFieldAsBoolean(JSON_FIELD_PROCESS_SEARCH_IF_UNINDEXED);
    if (processSearchIfUnindexed == null)
    {
      properties.setProcessSearchIfUnindexed(false);
    }
    else
    {
      properties.setProcessSearchIfUnindexed(processSearchIfUnindexed);
    }


    final Boolean includeDebugInfo =
         valueObject.getFieldAsBoolean(JSON_FIELD_INCLUDE_DEBUG_INFO);
    if (includeDebugInfo == null)
    {
      properties.setIncludeDebugInfo(false);
    }
    else
    {
      properties.setIncludeDebugInfo(includeDebugInfo);
    }


    final Boolean skipResolvingExplodedIndexes =
         valueObject.getFieldAsBoolean(
              JSON_FIELD_SKIP_RESOLVING_EXPLODED_INDEXES);
    if (skipResolvingExplodedIndexes == null)
    {
      properties.setSkipResolvingExplodedIndexes(false);
    }
    else
    {
      properties.setSkipResolvingExplodedIndexes(skipResolvingExplodedIndexes);
    }


    final Long fastShortCircuitThreshold =
         valueObject.getFieldAsLong(JSON_FIELD_FAST_SHORT_CIRCUIT_THRESHOLD);
    if (fastShortCircuitThreshold != null)
    {
      properties.setFastShortCircuitThreshold(fastShortCircuitThreshold);
    }


    final Long slowShortCircuitThreshold =
         valueObject.getFieldAsLong(JSON_FIELD_SLOW_SHORT_CIRCUIT_THRESHOLD);
    if (slowShortCircuitThreshold != null)
    {
      properties.setSlowShortCircuitThreshold(slowShortCircuitThreshold);
    }


    final Boolean includeExtendedResponseData = valueObject.getFieldAsBoolean(
         JSON_FIELD_INCLUDE_EXTENDED_RESPONSE_DATA);
    if (includeExtendedResponseData == null)
    {
      properties.setIncludeExtendedResponseData(false);
    }
    else
    {
      properties.setIncludeExtendedResponseData(includeExtendedResponseData);
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_MAXIMUM_CANDIDATES_TO_EXAMINE,
                JSON_FIELD_ALWAYS_EXAMINE_CANDIDATES,
                JSON_FIELD_PROCESS_SEARCH_IF_UNINDEXED,
                JSON_FIELD_INCLUDE_DEBUG_INFO,
                JSON_FIELD_SKIP_RESOLVING_EXPLODED_INDEXES,
                JSON_FIELD_FAST_SHORT_CIRCUIT_THRESHOLD,
                JSON_FIELD_SLOW_SHORT_CIRCUIT_THRESHOLD,
                JSON_FIELD_INCLUDE_EXTENDED_RESPONSE_DATA);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MATCHING_ENTRY_COUNT_RESPONSE_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new MatchingEntryCountRequestControl(jsonControl.getCriticality(),
         properties);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MatchingEntryCountRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", maxCandidatesToExamine=");
    buffer.append(maxCandidatesToExamine);
    buffer.append(", alwaysExamineCandidates=");
    buffer.append(alwaysExamineCandidates);
    buffer.append(", processSearchIfUnindexed=");
    buffer.append(processSearchIfUnindexed);
    buffer.append(", skipResolvingExplodedIndexes=");
    buffer.append(skipResolvingExplodedIndexes);
    buffer.append(", fastShortCircuitThreshold=");
    buffer.append(fastShortCircuitThreshold);
    buffer.append(", slowShortCircuitThreshold=");
    buffer.append(slowShortCircuitThreshold);
    buffer.append(", includeExtendedResponseData=");
    buffer.append(includeExtendedResponseData);
    buffer.append(", includeDebugInfo=");
    buffer.append(includeDebugInfo);
    buffer.append(')');
  }
}
