/*
 * Copyright 2021-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2024 Ping Identity Corporation
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
 * Copyright (C) 2021-2024 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a set of properties that can be used in conjunction with
 * the {@link MatchingEntryCountRequestControl}.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class MatchingEntryCountRequestControlProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7231704969312951204L;



  // Indicates whether the server should internally retrieve and examine
  // candidate entries to determine whether they would actually be returned to
  // the client.
  private boolean alwaysExamineCandidates;

  // Indicates whether to include debug information in the response control.
  private boolean includeDebugInfo;

  // Indicates whether to include extended information in the response.
  private boolean includeExtendedResponseData;

  // Indicates whether the server should attempt to actually iterate through the
  // entries in the backend in order to obtain the count if the search criteria
  // is not indexed.
  private boolean processSearchIfUnindexed;

  // Indicates whether the server should skip retrieving the entry ID set for
  // an exploded index key if the number of matching entries is known.
  private boolean skipResolvingExplodedIndexes;

  // The maximum number of candidate entries that should be examined if it is
  // not possible to obtain an exact count using only information contained in
  // the server indexes.
  private int maxCandidatesToExamine;

  // The short-circuit threshold that the server will use when evaluating filter
  // components that are not categorized as fast.
  @Nullable private Long slowShortCircuitThreshold;

  // The short-circuit threshold that the server will for index processing that
  // should be very fast.
  @Nullable private Long fastShortCircuitThreshold;



  /**
   * Creates a new matching entry count request control properties object with
   * the default settings.
   */
  public MatchingEntryCountRequestControlProperties()
  {
    maxCandidatesToExamine = 0;
    alwaysExamineCandidates = false;
    processSearchIfUnindexed = false;
    skipResolvingExplodedIndexes = false;
    fastShortCircuitThreshold = null;
    slowShortCircuitThreshold = null;
    includeExtendedResponseData = false;
    includeDebugInfo = false;
  }



  /**
   * Creates a new matching entry count request control properties object that
   * is a copy of the provided properties.
   *
   * @param  properties  The properties to use to create the new set of
   *                     properties.
   */
  public MatchingEntryCountRequestControlProperties(
       @NotNull final MatchingEntryCountRequestControlProperties properties)
  {
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
   * Creates a new matching entry count request control properties object with
   * the settings used for the provided control.
   *
   * @param  control  The matching entry count request control to use to
   *                  initialize this set of properties.
   */
  public MatchingEntryCountRequestControlProperties(
              @NotNull final MatchingEntryCountRequestControl control)
  {
    maxCandidatesToExamine = control.getMaxCandidatesToExamine();
    alwaysExamineCandidates = control.alwaysExamineCandidates();
    processSearchIfUnindexed = control.processSearchIfUnindexed();
    skipResolvingExplodedIndexes = control.skipResolvingExplodedIndexes();
    fastShortCircuitThreshold = control.getFastShortCircuitThreshold();
    slowShortCircuitThreshold = control.getSlowShortCircuitThreshold();
    includeExtendedResponseData = control.includeExtendedResponseData();
    includeDebugInfo = control.includeDebugInfo();
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
   * Specifies the maximum number of candidate entries that should be examined
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
   * @param  maxCandidatesToExamine  The maximum number of candidate entries
   *                                 that the server should retrieve and examine
   *                                 to determine whether they actually match
   *                                 the search criteria.  If the search is
   *                                 partially indexed and the total number of
   *                                 candidate entries is less than or equal to
   *                                 this value, then these candidate entries
   *                                 will be examined to determine which of them
   *                                 match the search criteria so that an
   *                                 accurate count can be determined.  If the
   *                                 search is fully indexed such that the all
   *                                 candidate entries are known to match the
   *                                 search criteria, then the server may still
   *                                 examine each of these entries if the number
   *                                 of candidates is less than
   *                                 {@code maxCandidatesToExamine} and
   *                                 {@code alwaysExamineCandidates} is
   *                                 {@code true} in order to allow the entry
   *                                 count that is returned to be restricted to
   *                                 only those entries that would actually be
   *                                 returned to the client.  This will be
   *                                 ignored for searches that are completely
   *                                 unindexed.
   *                                 <BR><BR>
   *                                 The value for this argument must be greater
   *                                 than or equal to zero.  If it is zero, then
   *                                 the server will not examine any entries, so
   *                                 a partially-indexed search will only be
   *                                 able to return a count that is an upper
   *                                 bound, and a fully-indexed search will only
   *                                 be able to return an unexamined exact
   *                                 count.  If there should be no bound on the
   *                                 number of entries to retrieve, then a value
   *                                 of {@code Integer.MAX_VALUE} may be
   *                                 specified.
   */
  public void setMaxCandidatesToExamine(final int maxCandidatesToExamine)
  {
    Validator.ensureTrue((maxCandidatesToExamine >= 0),
         "MatchingEntryCountRequestControlProperties.maxCandidatesToExamine " +
              "must be greater than or equal to zero.");

    this.maxCandidatesToExamine = maxCandidatesToExamine;
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
   *Specifies whether the server should always examine candidate entries in
   * fully-indexed searches to determine whether they would actually be returned
   * to the client in a normal search with the same criteria.
   *
   * @param  alwaysExamineCandidates Indicates whether the server should always
   *                                 examine candidate entries to determine
   *                                 whether they would actually be returned to
   *                                 the client in a normal search.  This will
   *                                 only be used for fully-indexed searches in
   *                                 which the set of matching entries is known.
   *                                 If the value is {@code true} and the number
   *                                 of candidates is smaller than
   *                                 {@code maxCandidatesToExamine}, then each
   *                                 matching entry will be internally retrieved
   *                                 and examined to determine whether it would
   *                                 be returned to the client based on the
   *                                 details of the search request (e.g.,
   *                                 whether the requester has permission to
   *                                 access the entry, whether it's an LDAP
   *                                 subentry, replication conflict entry,
   *                                 soft-deleted entry, or other type of entry
   *                                 that is normally hidden, etc.) so that an
   *                                 exact count can be returned.  If this is
   *                                 {@code false} or the number of candidates
   *                                 exceeds {@code maxCandidatesToExamine},
   *                                 then the server will only be able to return
   *                                 an unexamined count which may include
   *                                 entries that match the search criteria but
   *                                 that would not normally be returned to the
   *                                 requester.
   */
  public void setAlwaysExamineCandidates(final boolean alwaysExamineCandidates)
  {
    this.alwaysExamineCandidates = alwaysExamineCandidates;
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
   * Specifies whether the server should internally retrieve and examine all
   * entries within the search scope in order to obtain an exact matching entry
   * count for an unindexed search.  Note that this value will not be considered
   * for completely-indexed or partially-indexed searches, nor for searches in
   * which matching entries should be returned.
   *
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
   */
  public void setProcessSearchIfUnindexed(
                   final boolean processSearchIfUnindexed)
  {
    this.processSearchIfUnindexed = processSearchIfUnindexed;
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
   * Specifies whether the server should skip the effort of actually retrieving
   * the candidate entry IDs for exploded index keys in which the number of
   * matching entries is known.  Skipping the process of accessing an exploded
   * index can allow the server to more quickly arrive at the matching entry
   * count estimate, but that estimate may be less accurate than if it had
   * actually retrieved those candidates.
   *
   * @param  skipResolvingExplodedIndexes  Indicates whether the server should
   *                                       skip the effort of actually
   *                                       retrieving the candidate entry IDs
   *                                       for exploded index keys in which the
   *                                       number of matching entries is known.
   */
  public void setSkipResolvingExplodedIndexes(
                   final boolean skipResolvingExplodedIndexes)
  {
    this.skipResolvingExplodedIndexes = skipResolvingExplodedIndexes;
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
   * Specifies the short-circuit threshold that the server should use when
   * determining whether to continue with index processing in an attempt to
   * further pare down a candidate set that already has a defined superset of
   * entries that actually match the filter.  Short-circuiting may allow the
   * server to skip potentially-costly index processing and allow it to obtain
   * the matching entry count estimate faster, but the resulting estimate may be
   * less accurate.  The fast short-circuit threshold will be used for index
   * processing that is expected to be very fast (e.g., when performing index
   * lookups for presence, equality, and approximate-match components, which
   * should only require accessing a single index key).
   *
   * @param  fastShortCircuitThreshold  The short-circuit threshold that the
   *                                    server should use when determining
   *                                    whether to continue with index
   *                                    processing in an attempt to further pare
   *                                    down a candidate set that already has a
   *                                    defined superset of the entries that
   *                                    actually match the filter.  A value that
   *                                    is less than or equal to zero indicates
   *                                    that the server should never short
   *                                    circuit when performing fast index
   *                                    processing.  A value of {@code null}
   *                                    indicates that the server should
   *                                    determine the appropriate fast
   *                                    short-circuit threshold to use.
   */
  public void setFastShortCircuitThreshold(
                   @Nullable final Long fastShortCircuitThreshold)
  {
    if ((fastShortCircuitThreshold == null) || (fastShortCircuitThreshold >= 0))
    {
      this.fastShortCircuitThreshold = fastShortCircuitThreshold;
    }
    else
    {
      this.fastShortCircuitThreshold = 0L;
    }
  }



  /**
   * Retrieves the short-circuit threshold that the server should use when
   * determining whether to continue with index processing for evaluation that
   * may be more expensive than what falls into the "fast" category (e.g.,
   * substring and range filter components).
   *
   * @return  The short-circuit threshold that the server should use when
   *          determining whether to continue with index processing for
   *          evaluation that may be more expensive than what falls into the
   *          "fast" category, zero if the server should never short circuit
   *          when performing slow index processing, or {@code null} if the
   *          server should determine the appropriate slow short-circuit
   *          threshold to use.
   */
  @Nullable()
  public Long getSlowShortCircuitThreshold()
  {
    return slowShortCircuitThreshold;
  }



  /**
   * Specifies the short-circuit threshold that the server should use when
   * determining whether to continue with index processing for evaluation that
   * may be more expensive than what falls into the "fast" category (e.g.,
   * substring and range filter components).
   *
   * @param  slowShortCircuitThreshold
   *              The short-circuit threshold that the server should use when
   *              determining whether to continue with index processing for
   *              evaluation that may be more expensive than what falls into the
   *              "fast" category.  A value that is less than or equal to zero
   *              indicates that the server should never short circuit when
   *              performing slow index processing.  A value of {@code null}
   *              indicates that the server should determine the appropriate
   *              slow short-circuit threshold to use.
   */
  public void setSlowShortCircuitThreshold(
                   @Nullable final Long slowShortCircuitThreshold)
  {
    if ((slowShortCircuitThreshold == null) || (slowShortCircuitThreshold >= 0))
    {
      this.slowShortCircuitThreshold = slowShortCircuitThreshold;
    }
    else
    {
      this.slowShortCircuitThreshold = 0L;
    }
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
   * Indicates whether the server may include extended response data in the
   * corresponding response control, which may provide information like whether
   * all of the identified candidate entries are within the scope of the search
   * and any unindexed or unevaluated portion of the search filter.
   * <BR><BR>
   * Note that before setting this to {@code true}, the client should first
   * verify that the server supports this functionality by checking to see if
   * {@link com.unboundid.ldap.sdk.RootDSE#supportsFeature} returns {@code true}
   * for {@link
   * MatchingEntryCountRequestControl#EXTENDED_RESPONSE_DATA_FEATURE_OID}.
   * Setting this value to {@code true} for servers that do not support this
   * feature may cause the server to reject the request.
   *
   * @param  includeExtendedResponseData  Indicates whether the server may
   *                                      include extended response data in the
   *                                      corresponding response control.
   */
  public void setIncludeExtendedResponseData(
                   final boolean includeExtendedResponseData)
  {
    this.includeExtendedResponseData = includeExtendedResponseData;
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
   * Specifies whether the server should include debug information in the
   * response control that provides additional information about how the server
   * arrived at the result.
   *
   * @param  includeDebugInfo  Indicates whether the server should include debug
   *                           information in the response control that provides
   *                           additional information about how the server
   *                           arrived at the result.
   */
  public void setIncludeDebugInfo(final boolean includeDebugInfo)
  {
    this.includeDebugInfo = includeDebugInfo;
  }



  /**
   * Retrieves a string representation of the matching entry count request
   * control properties.
   *
   * @return  A string representation of the matching entry count request
   *          control properties.
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
   * Appends a string representation of the matching entry count request control
   * properties to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MatchingEntryCountRequestControlProperties(" +
         "maxCandidatesToExamine=");
    buffer.append(maxCandidatesToExamine);
    buffer.append(", alwaysExamineCandidates=");
    buffer.append(alwaysExamineCandidates);
    buffer.append(", processSearchIfUnindexed=");
    buffer.append(processSearchIfUnindexed);
    buffer.append(", skipResolvingExplodedIndexes=");
    buffer.append(skipResolvingExplodedIndexes);

    if (fastShortCircuitThreshold != null)
    {
      buffer.append(", fastShortCircuitThreshold=");
      buffer.append(fastShortCircuitThreshold);
    }

    if (slowShortCircuitThreshold != null)
    {
      buffer.append(", slowShortCircuitThreshold=");
      buffer.append(slowShortCircuitThreshold);
    }

    buffer.append(", includeExtendedResponseData=");
    buffer.append(includeExtendedResponseData);
    buffer.append(", includeDebugInfo=");
    buffer.append(includeDebugInfo);
    buffer.append(')');
  }
}
