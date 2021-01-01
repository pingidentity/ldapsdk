/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.IntermediateResponseListener;
import com.unboundid.ldap.sdk.LDAPConnection;
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

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request which may be
 * used to retrieve a batch of changes from a Directory Server.
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
 * The changelog batch request value is encoded as follows:
 * <PRE>
 *   ChangelogBatchRequest ::= SEQUENCE {
 *        startingPoint                      CHOICE {
 *             resumeWithToken          [0] OCTET STRING,
 *             resumeWithCSN            [1] OCTET STRING,
 *             beginningOfChangelog     [2] NULL,
 *             endOfChangelog           [3] NULL,
 *             changeTime               [4] OCTET STRING,
 *             ... },
 *        maxChanges                         INTEGER (0 .. maxInt),
 *        maxTimeMillis                      [0] INTEGER DEFAULT 0,
 *        waitForMaxChanges                  [1] BOOLEAN DEFAULT FALSE,
 *        includeBase                        [2] SEQUENCE OF LDAPDN OPTIONAL,
 *        excludeBase                        [3] SEQUENCE OF LDAPDN OPTIONAL,
 *        changeTypes                        [4] SET OF ENUMERATED {
 *             add          (0),
 *             delete       (1),
 *             modify       (2),
 *             modifyDN     (3) } OPTIONAL,
 *        continueOnMissingChanges           [5] BOOLEAN DEFAULT FALSE,
 *        pareEntriesForUserDN               [6] LDAPDN OPTIONAL,
 *        changeSelectionCriteria            [7] CHOICE {
 *             anyAttributes               [1] SEQUENCE OF LDAPString,
 *             allAttributes               [2] SEQUENCE OF LDAPString,
 *             ignoreAttributes            [3] SEQUENCE {
 *                  ignoreAttributes                SEQUENCE OF LDAPString
 *                  ignoreOperationalAttributes     BOOLEAN,
 *                  ... },
 *             notificationDestination     [4] OCTET STRING,
 *             ... } OPTIONAL,
 *        includeSoftDeletedEntryMods        [8] BOOLEAN DEFAULT FALSE,
 *        includeSoftDeletedEntryDeletes     [9] BOOLEAN DEFAULT FALSE,
 *        ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the get changelog batch to
 * iterate across all entries in the changelog.  It will operate in an infinite
 * loop, starting at the beginning of the changelog and then reading 1000
 * entries at a time until all entries have been read.  Once the end of the
 * changelog has been reached, it will continue looking for changes, waiting for
 * up to 5 seconds for new changes to arrive.
 * <PRE>
 * ChangelogBatchStartingPoint startingPoint =
 *      new BeginningOfChangelogStartingPoint();
 * while (true)
 * {
 *   GetChangelogBatchExtendedRequest request =
 *        new GetChangelogBatchExtendedRequest(startingPoint, 1000, 5000L);
 *
 *   GetChangelogBatchExtendedResult result =
 *        (GetChangelogBatchExtendedResult)
 *        connection.processExtendedOperation(request);
 *   List&lt;ChangelogEntryIntermediateResponse&gt; changelogEntries =
 *        result.getChangelogEntries();
 *
 *   startingPoint = new ResumeWithTokenStartingPoint(result.getResumeToken());
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetChangelogBatchExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.10) for the get changelog batch extended
   * request.
   */
  @NotNull public static final String GET_CHANGELOG_BATCH_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.10";



  /**
   * The BER type for the maxTimeMillis element.
   */
  private static final byte TYPE_MAX_TIME = (byte) 0x80;



  /**
   * The BER type for the returnOnAvailableChanges element.
   */
  private static final byte TYPE_WAIT_FOR_MAX_CHANGES = (byte) 0x81;



  /**
   * The BER type for the includeBase element.
   */
  private static final byte TYPE_INCLUDE_BASE = (byte) 0xA2;



  /**
   * The BER type for the excludeBase element.
   */
  private static final byte TYPE_EXCLUDE_BASE = (byte) 0xA3;



  /**
   * The BER type for the changeTypes element.
   */
  private static final byte TYPE_CHANGE_TYPES = (byte) 0xA4;



  /**
   * The BER type for the continueOnMissingChanges element.
   */
  private static final byte TYPE_CONTINUE_ON_MISSING_CHANGES = (byte) 0x85;



  /**
   * The BER type for the pareEntriesForUserDN element.
   */
  private static final byte TYPE_PARE_ENTRIES_FOR_USER_DN = (byte) 0x86;



  /**
   * The BER type for the includeSoftDeletedEntryMods element.
   */
  private static final byte TYPE_INCLUDE_SOFT_DELETED_ENTRY_MODS = (byte) 0x88;



  /**
   * The BER type for the includeSoftDeletedEntryDeletes element.
   */
  private static final byte TYPE_INCLUDE_SOFT_DELETED_ENTRY_DELETES =
       (byte) 0x89;



  /**
   * The value for a change type of add.
   */
  private static final int CHANGE_TYPE_ADD = 0;



  /**
   * The value for a change type of delete.
   */
  private static final int CHANGE_TYPE_DELETE = 1;



  /**
   * The value for a change type of modify.
   */
  private static final int CHANGE_TYPE_MODIFY = 2;



  /**
   * The value for a change type of modify DN.
   */
  private static final int CHANGE_TYPE_MODIFY_DN = 3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3270898150012821635L;



  // Indicates whether to attempt to return changes even if the start point
  // references changes which may have already been purged from the changelog.
  private final boolean continueOnMissingChanges;

  // Indicates whether deletes to soft-deleted entries should be included in the
  // result set.
  private final boolean includeSoftDeletedEntryDeletes;

  // Indicates whether modifications of soft-deleted entries should be included
  // in the result set.
  private final boolean includeSoftDeletedEntryMods;

  // Indicates whether the server should wait for up to the specified time limit
  // for up to the the maximum number of changes to be returned, or whether it
  // should return as soon as there are any results available.
  private final boolean waitForMaxChanges;

  // The change selection criteria for the request, if any.
  @Nullable private final ChangelogBatchChangeSelectionCriteria
       changeSelectionCriteria;

  // The starting point for the batch of changes to retrieve.
  @NotNull private final ChangelogBatchStartingPoint startingPoint;

  // The entry listener for this request.
  @Nullable private final ChangelogEntryListener entryListener;

  // The maximum number of changes to retrieve in the batch.
  private final int maxChanges;

  // The list of base DNs for entries to exclude from the results.
  @NotNull private final List<String> excludeBaseDNs;

  // The list of base DNs for entries to include in the results.
  @NotNull private final List<String> includeBaseDNs;

  // The maximum length of time in milliseconds to wait for changes to become
  // available.
  private final long maxWaitTimeMillis;

  // The set of change types for changes to include in the results.
  @NotNull private final Set<ChangeType> changeTypes;

  // The DN of a user for whom to pare down the contents of changelog entries
  // based on access control and sensitive attribute restrictions, if defined.
  @Nullable private final String pareEntriesForUserDN;



  /**
   * Creates a new get changelog batch extended request with the provided
   * information.  It will include all changes processed anywhere in the server,
   * and will request that the result be returned as soon as any changes are
   * available.
   *
   * @param  startingPoint      An object which indicates the starting point for
   *                            the batch of changes to retrieve.  It must not
   *                            be {@code null}.
   * @param  maxChanges         The maximum number of changes that should be
   *                            retrieved before the server should return the
   *                            corresponding extended result.  A value less
   *                            than or equal to zero may be used to indicate
   *                            that the server should not return any entries
   *                            but should just return a result containing a
   *                            token which represents the starting point.
   * @param  maxWaitTimeMillis  The maximum length of time in milliseconds to
   *                            wait for changes.  A value less than or equal to
   *                            zero indicates that there should not be any wait
   *                            and the result should be returned as soon as all
   *                            immediately-available changes (up to the
   *                            specified maximum count) have been returned.
   * @param  controls           The set of controls to include in the request.
   *                            It may be {@code null} or empty if there should
   *                            be no controls.
   */
  public GetChangelogBatchExtendedRequest(
              @NotNull final ChangelogBatchStartingPoint startingPoint,
              final int maxChanges, final long maxWaitTimeMillis,
              @Nullable final Control... controls)
  {
    this(null, startingPoint, maxChanges, maxWaitTimeMillis, false, null, null,
         null, false, null, null, false, false, controls);
  }



  /**
   * Creates a new get changelog batch extended request with the provided
   * information.  It will include all changes processed anywhere in the server,
   * and will request that the result be returned as soon as any changes are
   * available.
   *
   * @param  entryListener      The listener that will be notified of any
   *                            changelog entries (or other types of
   *                            intermediate response) returned during the
   *                            course of processing this request.  It may be
   *                            {@code null} if changelog entries should be
   *                            collected and made available in the extended
   *                            result.
   * @param  startingPoint      An object which indicates the starting point for
   *                            the batch of changes to retrieve.  It must not
   *                            be {@code null}.
   * @param  maxChanges         The maximum number of changes that should be
   *                            retrieved before the server should return the
   *                            corresponding extended result.  A value less
   *                            than or equal to zero may be used to indicate
   *                            that the server should not return any entries
   *                            but should just return a result containing a
   *                            token which represents the starting point.
   * @param  maxWaitTimeMillis  The maximum length of time in milliseconds to
   *                            wait for changes.  A value less than or equal to
   *                            zero indicates that there should not be any wait
   *                            and the result should be returned as soon as all
   *                            immediately-available changes (up to the
   *                            specified maximum count) have been returned.
   * @param  controls           The set of controls to include in the request.
   *                            It may be {@code null} or empty if there should
   *                            be no controls.
   */
  public GetChangelogBatchExtendedRequest(
              @Nullable final ChangelogEntryListener entryListener,
              @NotNull final ChangelogBatchStartingPoint startingPoint,
              final int maxChanges, final long maxWaitTimeMillis,
              @Nullable final Control... controls)
  {
    this(entryListener, startingPoint, maxChanges, maxWaitTimeMillis, false,
         null, null, null, false, null, null, false, false, controls);
  }



  /**
   * Creates a new get changelog batch extended request with the provided
   * information.
   *
   * @param  startingPoint             An object which indicates the starting
   *                                   point for the batch of changes to
   *                                   retrieve.  It must not be {@code null}.
   * @param  maxChanges                The maximum number of changes that should
   *                                   be retrieved before the server should
   *                                   return the corresponding extended result.
   *                                   A value less than or equal to zero may be
   *                                   used to indicate that the server should
   *                                   not return any entries but should just
   *                                   return a result containing a token which
   *                                   represents the starting point.
   * @param  maxWaitTimeMillis         The maximum length of time in
   *                                   milliseconds to wait for changes.  A
   *                                   value less than or equal to zero
   *                                   indicates that there should not be any
   *                                   wait and the result should be returned as
   *                                   soon as all immediately-available changes
   *                                   (up to the specified maximum count) have
   *                                   been returned.
   * @param  waitForMaxChanges         Indicates whether the server should wait
   *                                   for up to the maximum length of time for
   *                                   up to the maximum number of changes to be
   *                                   returned.  If this is {@code false}, then
   *                                   the result will be returned as soon as
   *                                   any changes are available (after sending
   *                                   those changes), even if the number of
   *                                   available changes is less than
   *                                   {@code maxChanges}.  Otherwise, the
   *                                   result will not be returned until either
   *                                   the maximum number of changes have been
   *                                   returned or the maximum wait time has
   *                                   elapsed.
   * @param  includeBaseDNs            A list of base DNs for entries to include
   *                                   in the set of changes to be returned.
   * @param  excludeBaseDNs            A list of base DNs for entries to exclude
   *                                   from the set of changes to be returned.
   * @param  changeTypes               The types of changes that should be
   *                                   returned.  If this is {@code null} or
   *                                   empty, then all change types will be
   *                                   included.
   * @param  continueOnMissingChanges  Indicates whether the server should make
   *                                   a best-effort attempt to return changes
   *                                   even if the starting point represents a
   *                                   point that is before the first available
   *                                   change in the changelog and therefore the
   *                                   results returned may be missing changes.
   * @param  controls                  The set of controls to include in the
   *                                   request.  It may be {@code null} or empty
   *                                   if there should be no controls.
   */
  public GetChangelogBatchExtendedRequest(
              @NotNull final ChangelogBatchStartingPoint startingPoint,
              final int maxChanges, final long maxWaitTimeMillis,
              final boolean waitForMaxChanges,
              @Nullable final List<String> includeBaseDNs,
              @Nullable final List<String> excludeBaseDNs,
              @Nullable final Set<ChangeType> changeTypes,
              final boolean continueOnMissingChanges,
              @Nullable final Control... controls)
  {
    this(null, startingPoint, maxChanges, maxWaitTimeMillis, waitForMaxChanges,
         includeBaseDNs, excludeBaseDNs, changeTypes, continueOnMissingChanges,
         null, null, false, false, controls);
  }



  /**
   * Creates a new get changelog batch extended request with the provided
   * information.
   *
   * @param  entryListener             The listener that will be notified of any
   *                                   changelog entries (or other types of
   *                                   intermediate response) returned during
   *                                   the course of processing this request.
   *                                   It may be {@code null} if changelog
   *                                   entries should be collected and made
   *                                   available in the extended result.
   * @param  startingPoint             An object which indicates the starting
   *                                   point for the batch of changes to
   *                                   retrieve.  It must not be {@code null}.
   * @param  maxChanges                The maximum number of changes that should
   *                                   be retrieved before the server should
   *                                   return the corresponding extended result.
   *                                   A value less than or equal to zero may be
   *                                   used to indicate that the server should
   *                                   not return any entries but should just
   *                                   return a result containing a token which
   *                                   represents the starting point.
   * @param  maxWaitTimeMillis         The maximum length of time in
   *                                   milliseconds to wait for changes.  A
   *                                   value less than or equal to zero
   *                                   indicates that there should not be any
   *                                   wait and the result should be returned as
   *                                   soon as all immediately-available changes
   *                                   (up to the specified maximum count) have
   *                                   been returned.
   * @param  waitForMaxChanges         Indicates whether the server should wait
   *                                   for up to the maximum length of time for
   *                                   up to the maximum number of changes to be
   *                                   returned.  If this is {@code false}, then
   *                                   the result will be returned as soon as
   *                                   any changes are available (after sending
   *                                   those changes), even if the number of
   *                                   available changes is less than
   *                                   {@code maxChanges}.  Otherwise, the
   *                                   result will not be returned until either
   *                                   the maximum number of changes have been
   *                                   returned or the maximum wait time has
   *                                   elapsed.
   * @param  includeBaseDNs            A list of base DNs for entries to include
   *                                   in the set of changes to be returned.
   * @param  excludeBaseDNs            A list of base DNs for entries to exclude
   *                                   from the set of changes to be returned.
   * @param  changeTypes               The types of changes that should be
   *                                   returned.  If this is {@code null} or
   *                                   empty, then all change types will be
   *                                   included.
   * @param  continueOnMissingChanges  Indicates whether the server should make
   *                                   a best-effort attempt to return changes
   *                                   even if the starting point represents a
   *                                   point that is before the first available
   *                                   change in the changelog and therefore the
   *                                   results returned may be missing changes.
   * @param  controls                  The set of controls to include in the
   *                                   request.  It may be {@code null} or empty
   *                                   if there should be no controls.
   */
  public GetChangelogBatchExtendedRequest(
              @Nullable final ChangelogEntryListener entryListener,
              @NotNull final ChangelogBatchStartingPoint startingPoint,
              final int maxChanges, final long maxWaitTimeMillis,
              final boolean waitForMaxChanges,
              @Nullable final List<String> includeBaseDNs,
              @Nullable final List<String> excludeBaseDNs,
              @Nullable final Set<ChangeType> changeTypes,
              final boolean continueOnMissingChanges,
              @Nullable final Control... controls)
  {
    this(entryListener, startingPoint, maxChanges, maxWaitTimeMillis,
         waitForMaxChanges, includeBaseDNs, excludeBaseDNs, changeTypes,
         continueOnMissingChanges, null, null, false, false, controls);
  }



  /**
   * Creates a new get changelog batch extended request with the provided
   * information.
   *
   * @param  entryListener             The listener that will be notified of any
   *                                   changelog entries (or other types of
   *                                   intermediate response) returned during
   *                                   the course of processing this request.
   *                                   It may be {@code null} if changelog
   *                                   entries should be collected and made
   *                                   available in the extended result.
   * @param  startingPoint             An object which indicates the starting
   *                                   point for the batch of changes to
   *                                   retrieve.  It must not be {@code null}.
   * @param  maxChanges                The maximum number of changes that should
   *                                   be retrieved before the server should
   *                                   return the corresponding extended result.
   *                                   A value less than or equal to zero may be
   *                                   used to indicate that the server should
   *                                   not return any entries but should just
   *                                   return a result containing a token which
   *                                   represents the starting point.
   * @param  maxWaitTimeMillis         The maximum length of time in
   *                                   milliseconds to wait for changes.  A
   *                                   value less than or equal to zero
   *                                   indicates that there should not be any
   *                                   wait and the result should be returned as
   *                                   soon as all immediately-available changes
   *                                   (up to the specified maximum count) have
   *                                   been returned.
   * @param  waitForMaxChanges         Indicates whether the server should wait
   *                                   for up to the maximum length of time for
   *                                   up to the maximum number of changes to be
   *                                   returned.  If this is {@code false}, then
   *                                   the result will be returned as soon as
   *                                   any changes are available (after sending
   *                                   those changes), even if the number of
   *                                   available changes is less than
   *                                   {@code maxChanges}.  Otherwise, the
   *                                   result will not be returned until either
   *                                   the maximum number of changes have been
   *                                   returned or the maximum wait time has
   *                                   elapsed.
   * @param  includeBaseDNs            A list of base DNs for entries to include
   *                                   in the set of changes to be returned.
   * @param  excludeBaseDNs            A list of base DNs for entries to exclude
   *                                   from the set of changes to be returned.
   * @param  changeTypes               The types of changes that should be
   *                                   returned.  If this is {@code null} or
   *                                   empty, then all change types will be
   *                                   included.
   * @param  continueOnMissingChanges  Indicates whether the server should make
   *                                   a best-effort attempt to return changes
   *                                   even if the starting point represents a
   *                                   point that is before the first available
   *                                   change in the changelog and therefore the
   *                                   results returned may be missing changes.
   * @param  pareEntriesForUserDN      The DN of a user for whom to pare down
   *                                   the contents of changelog entries based
   *                                   on the access control and sensitive
   *                                   attribute restrictions defined for that
   *                                   user.  It may be {@code null} if
   *                                   changelog entries should not be pared
   *                                   down for any user, an empty string if
   *                                   changelog entries should be pared down to
   *                                   what is available to anonymous users, or
   *                                   a user DN to pare down entries for the
   *                                   specified user.
   * @param  changeSelectionCriteria   The optional criteria to use to pare down
   *                                   the changelog entries that should be
   *                                   returned.  It may be {@code null} if all
   *                                   changelog entries should be returned.
   * @param  controls                  The set of controls to include in the
   *                                   request.  It may be {@code null} or empty
   *                                   if there should be no controls.
   */
  public GetChangelogBatchExtendedRequest(
              @Nullable final ChangelogEntryListener entryListener,
              @NotNull final ChangelogBatchStartingPoint startingPoint,
              final int maxChanges, final long maxWaitTimeMillis,
              final boolean waitForMaxChanges,
              @Nullable final List<String> includeBaseDNs,
              @Nullable final List<String> excludeBaseDNs,
              @Nullable final Set<ChangeType> changeTypes,
              final boolean continueOnMissingChanges,
              @Nullable final String pareEntriesForUserDN,
              @Nullable final ChangelogBatchChangeSelectionCriteria
                         changeSelectionCriteria,
              @Nullable final Control... controls)
  {
    this(entryListener, startingPoint, maxChanges, maxWaitTimeMillis,
         waitForMaxChanges, includeBaseDNs, excludeBaseDNs, changeTypes,
         continueOnMissingChanges, pareEntriesForUserDN,
         changeSelectionCriteria, false, false, controls);
  }



  /**
   * Creates a new get changelog batch extended request with the provided
   * information.
   *
   * @param  entryListener                   The listener that will be notified
   *                                         of any changelog entries (or other
   *                                         types of intermediate response)
   *                                         returned during the course of
   *                                         processing this request.  It may be
   *                                         {@code null} if changelog entries
   *                                         should be collected and made
   *                                         available in the extended result.
   * @param  startingPoint                   An object which indicates the
   *                                         starting point for the batch of
   *                                         changes to retrieve.  It must not
   *                                         be {@code null}.
   * @param  maxChanges                      The maximum number of changes that
   *                                         should be retrieved before the
   *                                         server should return the
   *                                         corresponding extended result.  A
   *                                         value less than or equal to zero
   *                                         may be used to indicate that the
   *                                         server should not return any
   *                                         entries but should just return a
   *                                         result containing a token which
   *                                         represents the starting point.
   * @param  maxWaitTimeMillis               The maximum length of time in
   *                                         milliseconds to wait for changes.
   *                                         A value less than or equal to zero
   *                                         indicates that there should not be
   *                                         any wait and the result should be
   *                                         returned as soon as all
   *                                         immediately-available changes (up
   *                                         to the specified maximum count)
   *                                         have been returned.
   * @param  waitForMaxChanges               Indicates whether the server should
   *                                         wait for up to the maximum length
   *                                         of time for up to the maximum
   *                                         number of changes to be returned.
   *                                         If this is {@code false}, then the
   *                                         result will be returned as soon as
   *                                         any changes are available (after
   *                                         sending those changes), even if the
   *                                         number of available changes is less
   *                                         than {@code maxChanges}.
   *                                         Otherwise, the result will not be
   *                                         returned until either the maximum
   *                                         number of changes have been
   *                                         returned or the maximum wait time
   *                                         has elapsed.
   * @param  includeBaseDNs                  A list of base DNs for entries to
   *                                         include in the set of changes to be
   *                                         returned.
   * @param  excludeBaseDNs                  A list of base DNs for entries to
   *                                         exclude from the set of changes to
   *                                         be returned.
   * @param  changeTypes                     The types of changes that should be
   *                                         returned.  If this is {@code null}
   *                                         or empty, then all change types
   *                                         will be included.
   * @param  continueOnMissingChanges        Indicates whether the server should
   *                                         make a best-effort attempt to
   *                                         return changes even if the starting
   *                                         point represents a point that is
   *                                         before the first available change
   *                                         in the changelog and therefore the
   *                                         results returned may be missing
   *                                         changes.
   * @param  pareEntriesForUserDN            The DN of a user for whom to pare
   *                                         down the contents of changelog
   *                                         entries based on the access control
   *                                         and sensitive attribute
   *                                         restrictions defined for that user.
   *                                         It may be {@code null} if changelog
   *                                         entries should not be pared down
   *                                         for any user, an empty string if
   *                                         changelog entries should be pared
   *                                         down to what is available to
   *                                         anonymous users, or a user DN to
   *                                         pare down entries for the specified
   *                                         user.
   * @param  changeSelectionCriteria         The optional criteria to use to
   *                                         pare down the changelog entries
   *                                         that should be returned.  It may be
   *                                         {@code null} if all changelog
   *                                         entries should be returned.
   * @param  includeSoftDeletedEntryMods     Indicates whether to include
   *                                         changelog entries that represent
   *                                         changes to soft-deleted entries.
   * @param  includeSoftDeletedEntryDeletes  Indicates whether to include
   *                                         changelog entries that represent
   *                                         deletes of soft-deleted entries.
   * @param  controls                        The set of controls to include in
   *                                         the request.  It may be
   *                                         {@code null} or empty if there
   *                                         should be no controls.
   */
  public GetChangelogBatchExtendedRequest(
              @Nullable final ChangelogEntryListener entryListener,
              @NotNull final ChangelogBatchStartingPoint startingPoint,
              final int maxChanges, final long maxWaitTimeMillis,
              final boolean waitForMaxChanges,
              @Nullable final List<String> includeBaseDNs,
              @Nullable final List<String> excludeBaseDNs,
              @Nullable final Set<ChangeType> changeTypes,
              final boolean continueOnMissingChanges,
              @Nullable final String pareEntriesForUserDN,
              @Nullable final ChangelogBatchChangeSelectionCriteria
                         changeSelectionCriteria,
              final boolean includeSoftDeletedEntryMods,
              final boolean includeSoftDeletedEntryDeletes,
              @Nullable final Control... controls)
  {
    super(GET_CHANGELOG_BATCH_REQUEST_OID,
         encodeValue(startingPoint, maxChanges, maxWaitTimeMillis,
              waitForMaxChanges, includeBaseDNs, excludeBaseDNs, changeTypes,
              continueOnMissingChanges, pareEntriesForUserDN,
              changeSelectionCriteria, includeSoftDeletedEntryMods,
              includeSoftDeletedEntryDeletes),
         controls);

    this.entryListener                  = entryListener;
    this.startingPoint                  = startingPoint;
    this.maxWaitTimeMillis              = maxWaitTimeMillis;
    this.waitForMaxChanges              = waitForMaxChanges;
    this.continueOnMissingChanges       = continueOnMissingChanges;
    this.pareEntriesForUserDN           = pareEntriesForUserDN;
    this.changeSelectionCriteria        = changeSelectionCriteria;
    this.includeSoftDeletedEntryMods    = includeSoftDeletedEntryMods;
    this.includeSoftDeletedEntryDeletes = includeSoftDeletedEntryDeletes;

    if (maxChanges <= 0)
    {
      this.maxChanges = 0;
    }
    else
    {
      this.maxChanges = maxChanges;
    }

    if (includeBaseDNs == null)
    {
      this.includeBaseDNs = Collections.emptyList();
    }
    else
    {
      this.includeBaseDNs = Collections.unmodifiableList(includeBaseDNs);
    }

    if (excludeBaseDNs == null)
    {
      this.excludeBaseDNs = Collections.emptyList();
    }
    else
    {
      this.excludeBaseDNs = Collections.unmodifiableList(excludeBaseDNs);
    }

    if ((changeTypes == null) || changeTypes.isEmpty())
    {
      this.changeTypes =
           Collections.unmodifiableSet(EnumSet.allOf(ChangeType.class));
    }
    else
    {
      this.changeTypes = Collections.unmodifiableSet(changeTypes);
    }
  }



  /**
   * Creates a new get changelog batch extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to be decoded as a
   *                          get changelog batch extended request.
   *
   * @throws  LDAPException  If the provided generic request cannot be decoded
   *                         as a get changelog batch extended request.
   */
  public GetChangelogBatchExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest.getOID(), extendedRequest.getValue(),
         extendedRequest.getControls());

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CHANGELOG_BATCH_REQ_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      valueSequence = ASN1Sequence.decodeAsSequence(value.getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CHANGELOG_BATCH_REQ_VALUE_NOT_SEQUENCE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }

    final ASN1Element[] elements = valueSequence.elements();
    if (elements.length < 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CHANGELOG_BATCH_REQ_TOO_FEW_ELEMENTS.get());
    }

    try
    {
      startingPoint = ChangelogBatchStartingPoint.decode(elements[0]);

      final int mc = ASN1Integer.decodeAsInteger(elements[1]).intValue();
      if (mc > 0)
      {
        maxChanges = mc;
      }
      else
      {
        maxChanges = 0;
      }

      boolean waitForMax = false;
      long maxTime = 0L;
      List<String> includeBase = Collections.emptyList();
      List<String> excludeBase = Collections.emptyList();
      Set<ChangeType> types =
           Collections.unmodifiableSet(EnumSet.allOf(ChangeType.class));
      boolean continueOnMissing = false;
      String pareForDN = null;
      ChangelogBatchChangeSelectionCriteria changeCriteria = null;
      boolean includeSDMods = false;
      boolean includeSDDeletes = false;

      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_MAX_TIME:
            maxTime = ASN1Long.decodeAsLong(elements[i]).longValue();
            if (maxTime < 0L)
            {
              maxTime = 0L;
            }
            break;

          case TYPE_WAIT_FOR_MAX_CHANGES:
            waitForMax =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_INCLUDE_BASE:
            final ASN1Element[] includeElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            final ArrayList<String> includeList =
                 new ArrayList<>(includeElements.length);
            for (final ASN1Element e : includeElements)
            {
              includeList.add(
                   ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            includeBase = Collections.unmodifiableList(includeList);
            break;

          case TYPE_EXCLUDE_BASE:
            final ASN1Element[] excludeElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            final ArrayList<String> excludeList =
                 new ArrayList<>(excludeElements.length);
            for (final ASN1Element e : excludeElements)
            {
              excludeList.add(
                   ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            excludeBase = Collections.unmodifiableList(excludeList);
            break;

          case TYPE_CHANGE_TYPES:
            final EnumSet<ChangeType> ctSet = EnumSet.noneOf(ChangeType.class);
            for (final ASN1Element e :
                 ASN1Set.decodeAsSet(elements[i]).elements())
            {
              final int v = ASN1Enumerated.decodeAsEnumerated(e).intValue();
              switch (v)
              {
                case CHANGE_TYPE_ADD:
                  ctSet.add(ChangeType.ADD);
                  break;
                case CHANGE_TYPE_DELETE:
                  ctSet.add(ChangeType.DELETE);
                  break;
                case CHANGE_TYPE_MODIFY:
                  ctSet.add(ChangeType.MODIFY);
                  break;
                case CHANGE_TYPE_MODIFY_DN:
                  ctSet.add(ChangeType.MODIFY_DN);
                  break;
                default:
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_GET_CHANGELOG_BATCH_REQ_VALUE_UNRECOGNIZED_CT.get(
                            v));
              }
            }
            types = Collections.unmodifiableSet(ctSet);
            break;

          case TYPE_CONTINUE_ON_MISSING_CHANGES:
            continueOnMissing =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_PARE_ENTRIES_FOR_USER_DN:
            pareForDN =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case ChangelogBatchChangeSelectionCriteria.TYPE_SELECTION_CRITERIA:
            changeCriteria =
                 ChangelogBatchChangeSelectionCriteria.decode(elements[i]);
            break;

          case TYPE_INCLUDE_SOFT_DELETED_ENTRY_MODS:
            includeSDMods =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case TYPE_INCLUDE_SOFT_DELETED_ENTRY_DELETES:
            includeSDDeletes =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_CHANGELOG_BATCH_REQ_VALUE_UNRECOGNIZED_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      entryListener                  = null;
      maxWaitTimeMillis              = maxTime;
      waitForMaxChanges              = waitForMax;
      includeBaseDNs                 = includeBase;
      excludeBaseDNs                 = excludeBase;
      changeTypes                    = types;
      continueOnMissingChanges       = continueOnMissing;
      pareEntriesForUserDN           = pareForDN;
      changeSelectionCriteria        = changeCriteria;
      includeSoftDeletedEntryMods    = includeSDMods;
      includeSoftDeletedEntryDeletes = includeSDDeletes;
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
           ERR_GET_CHANGELOG_BATCH_REQ_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * Encodes the value for this extended request using the provided information.
   *
   * @param  startingPoint                   An object which indicates the
   *                                         starting point for the batch of
   *                                         changes to retrieve.  It must not
   *                                         be {@code null}.
   * @param  maxChanges                      The maximum number of changes that
   *                                         should be retrieved before the
   *                                         server should return the
   *                                         corresponding extended result.  A
   *                                         value less than or equal to zero
   *                                         may be used to indicate that the
   *                                         server should not return any
   *                                         entries but should just return a
   *                                         result containing a token which
   *                                         represents the starting point.
   * @param  maxWaitTimeMillis               The maximum length of time in
   *                                         milliseconds to wait for changes.
   *                                         A value less than or equal to zero
   *                                         indicates that there should not be
   *                                         any wait and the result should be
   *                                         returned as soon as all
   *                                         immediately-available changes (up
   *                                         to the specified maximum count)
   *                                         have been returned.
   * @param  waitForMaxChanges               Indicates whether the server should
   *                                         wait for up to the maximum length
   *                                         of time for up to the maximum
   *                                         number of changes to be returned.
   *                                         If this is {@code false}, then the
   *                                         result will be returned as soon as
   *                                         any changes are available (after
   *                                         sending those changes), even if the
   *                                         number of available changes is less
   *                                         than {@code maxChanges}.
   *                                         Otherwise, the result will not be
   *                                         returned until either the maximum
   *                                         number of changes have been
   *                                         returned or the maximum wait time
   *                                         has elapsed.
   * @param  includeBaseDNs                  A list of base DNs for entries to
   *                                         include in the set of changes to be
   *                                         returned.
   * @param  excludeBaseDNs                  A list of base DNs for entries to
   *                                         exclude from the set of changes to
   *                                         be returned.
   * @param  changeTypes                     The types of changes that should be
   *                                         returned.  If this is {@code null}
   *                                         or empty, then all change types
   *                                         will be included.
   * @param  continueOnMissingChanges        Indicates whether the server should
   *                                         make a best-effort attempt to
   *                                         return changes even if the starting
   *                                         point represents a point that is
   *                                         before the first available change
   *                                         in the changelog and therefore the
   *                                         results returned may be missing
   *                                         changes.
   * @param  pareEntriesForUserDN            The DN of a user for whom to pare
   *                                         down the contents of changelog
   *                                         entries based on the access control
   *                                         and sensitive attribute
   *                                         restrictions defined for that user.
   *                                         It may be {@code null} if changelog
   *                                         entries should not be pared down
   *                                         for any user, an empty string if
   *                                         changelog entries should be pared
   *                                         down to what is available to
   *                                         anonymous users, or a user DN to
   *                                         pare down entries for the specified
   *                                         user.
   * @param  changeSelectionCriteria         The optional criteria to use to
   *                                         pare down the changelog entries
   *                                         that should be returned.  It may be
   *                                         {@code null} if all changelog
   *                                         entries should be returned.
   * @param  includeSoftDeletedEntryMods     Indicates whether to include
   *                                         changelog entries that represent
   *                                         changes to soft-deleted entries.
   * @param  includeSoftDeletedEntryDeletes  Indicates whether to include
   *                                         changelog entries that represent
   *                                         deletes of soft-deleted entries.
   *
   * @return  The value for the extended request.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @NotNull final ChangelogBatchStartingPoint startingPoint,
       final int maxChanges, final long maxWaitTimeMillis,
       final boolean waitForMaxChanges,
       @Nullable final List<String> includeBaseDNs,
       @Nullable final List<String> excludeBaseDNs,
       @Nullable final Set<ChangeType> changeTypes,
       final boolean continueOnMissingChanges,
       @Nullable final String pareEntriesForUserDN,
       @Nullable final ChangelogBatchChangeSelectionCriteria
            changeSelectionCriteria,
       final boolean includeSoftDeletedEntryMods,
       final boolean includeSoftDeletedEntryDeletes)
  {
    Validator.ensureNotNull(startingPoint);

    final ArrayList<ASN1Element> elements = new ArrayList<>(12);

    elements.add(startingPoint.encode());

    if (maxChanges > 0)
    {
      elements.add(new ASN1Integer(maxChanges));
    }
    else
    {
      elements.add(new ASN1Integer(0));
    }

    if (maxWaitTimeMillis > 0L)
    {
      elements.add(new ASN1Long(TYPE_MAX_TIME, maxWaitTimeMillis));
    }

    if (waitForMaxChanges)
    {
      elements.add(new ASN1Boolean(TYPE_WAIT_FOR_MAX_CHANGES, true));
    }

    if ((includeBaseDNs != null) && (! includeBaseDNs.isEmpty()))
    {
      final ArrayList<ASN1Element> l = new ArrayList<>(includeBaseDNs.size());
      for (final String s : includeBaseDNs)
      {
        l.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_INCLUDE_BASE, l));
    }

    if ((excludeBaseDNs != null) && (! excludeBaseDNs.isEmpty()))
    {
      final ArrayList<ASN1Element> l = new ArrayList<>(excludeBaseDNs.size());
      for (final String s : excludeBaseDNs)
      {
        l.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_EXCLUDE_BASE, l));
    }

    if ((changeTypes != null) && (! changeTypes.isEmpty()) &&
        (! changeTypes.equals(EnumSet.allOf(ChangeType.class))))
    {
      final ArrayList<ASN1Element> l = new ArrayList<>(changeTypes.size());
      for (final ChangeType t : changeTypes)
      {
        switch (t)
        {
          case ADD:
            l.add(new ASN1Enumerated(CHANGE_TYPE_ADD));
            break;
          case DELETE:
            l.add(new ASN1Enumerated(CHANGE_TYPE_DELETE));
            break;
          case MODIFY:
            l.add(new ASN1Enumerated(CHANGE_TYPE_MODIFY));
            break;
          case MODIFY_DN:
            l.add(new ASN1Enumerated(CHANGE_TYPE_MODIFY_DN));
            break;
        }
      }
      elements.add(new ASN1Set(TYPE_CHANGE_TYPES, l));
    }

    if (continueOnMissingChanges)
    {
      elements.add(new ASN1Boolean(TYPE_CONTINUE_ON_MISSING_CHANGES, true));
    }

    if (pareEntriesForUserDN != null)
    {
      elements.add(new ASN1OctetString(TYPE_PARE_ENTRIES_FOR_USER_DN,
           pareEntriesForUserDN));
    }

    if (changeSelectionCriteria != null)
    {
      elements.add(changeSelectionCriteria.encode());
    }

    if (includeSoftDeletedEntryMods)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_SOFT_DELETED_ENTRY_MODS, true));
    }

    if (includeSoftDeletedEntryDeletes)
    {
      elements.add(new ASN1Boolean(TYPE_INCLUDE_SOFT_DELETED_ENTRY_DELETES,
           true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the starting point for the batch of changes to retrieve.
   *
   * @return  The starting point for the batch of changes to retrieve.
   */
  @NotNull()
  public ChangelogBatchStartingPoint getStartingPoint()
  {
    return startingPoint;
  }



  /**
   * Retrieves the maximum number of changes that should be returned before the
   * operation completes.  A value of zero indicates that the server should not
   * return any entries but should just return a result containing a token which
   * represents the starting point.
   *
   * @return  The maximum number of changes that should be returned before the
   *          operation completes.
   */
  public int getMaxChanges()
  {
    return maxChanges;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that the server should
   * wait for changes to become available before returning the corresponding
   * extended result to the client.  A value of zero indicates that the server
   * should return only those results which are immediately available without
   * waiting.
   *
   * @return  The maximum length of time in milliseconds that the server should
   *          wait for changes to become available, or 0 if the server should
   *          not wait at all.
   */
  public long getMaxWaitTimeMillis()
  {
    return maxWaitTimeMillis;
  }



  /**
   * Indicates whether the server should wait for up to the maximum length of
   * time for up to the maximum number of changes to be returned before sending
   * the extended result.
   *
   * @return  {@code false} if the server should return the corresponding
   *          extended result as soon as any changes are available (after
   *          sending those available changes), or {@code true} if the result
   *          should not be returned until either the maximum number of changes
   *          have been returned or the maximum wait time has elapsed.
   */
  public boolean waitForMaxChanges()
  {
    return waitForMaxChanges;
  }



  /**
   * Retrieves a list of base DNs below which the server should return
   * information about changes that have been processed.  If any include base
   * DNs are specified, then the server should return only changes to entries
   * which reside at or below one of the include base DNs and not at or below
   * any of the exclude base DNs.  If no include or exclude base DNs are
   * defined, then the server should return information about changes processed
   * anywhere within the DIT.
   *
   * @return  A list of the include base DNs for changes to retrieve, or an
   *          empty list if there are none.
   */
  @NotNull()
  public List<String> getIncludeBaseDNs()
  {
    return includeBaseDNs;
  }



  /**
   * Retrieves a list of base DNs below which the server should exclude
   * information about changes processed.  If any exclude base DNs are
   * specified, then the server should not return changes to entries which
   * reside at or below any of the exclude base DNs, even if they are also below
   * an include base DN (and as such, the request should not include any exclude
   * base DNs which are at or below any include base DNs).  If no include or
   * exclude base DNs are defined, then the server should return information
   * about changes processed anywhere within the DIT.
   *
   * @return  A list of the exclude base DNs for changes to retrieve, or an
   *          empty list if there are none.
   */
  @NotNull()
  public List<String> getExcludeBaseDNs()
  {
    return excludeBaseDNs;
  }



  /**
   * Retrieves the set of change types for changes to be returned to the client.
   *
   * @return  The set of change types for changes to be returned to the client.
   */
  @NotNull()
  public Set<ChangeType> getChangeTypes()
  {
    return changeTypes;
  }



  /**
   * Indicates whether the server should make a best-effort attempt to return
   * changes to the client even if the starting point represents a time before
   * the start of the changelog and there may be missing changes.
   *
   * @return  {@code true} if the server should attempt to return as many
   *          changes as possible even if some may be missing, or {@code false}
   *          if the server should return an error if there may be missing
   *          changes.
   */
  public boolean continueOnMissingChanges()
  {
    return continueOnMissingChanges;
  }



  /**
   * Retrieves the possibly-empty DN of the user for whom changelog entries
   * should be pared based on access control and sensitive attribute
   * restrictions, if defined.
   *
   * @return  The possibly-empty DN of the user form whom changelog entries
   *          should be pared based on access control and sensitive attribute
   *          restrictions, or {@code null} if changelog entries should not be
   *          pared based for any user.
   */
  @Nullable()
  public String getPareEntriesForUserDN()
  {
    return pareEntriesForUserDN;
  }



  /**
   * Retrieves the change selection criteria for this get changelog batch
   * extended request, if defined.
   *
   * @return  The change selection criteria for this get changelog batch
   *          extended request, or {@code null} if none is defined.
   */
  @Nullable()
  public ChangelogBatchChangeSelectionCriteria getChangeSelectionCriteria()
  {
    return changeSelectionCriteria;
  }



  /**
   * Indicates whether to include changes that represent modifications to
   * soft-deleted entries.
   *
   * @return  {@code true} if the result set should include modifications to
   *          soft-deleted entries, or {@code false} if not.
   */
  public boolean includeSoftDeletedEntryMods()
  {
    return includeSoftDeletedEntryMods;
  }



  /**
   * Indicates whether to include changes that represent deletes of soft-deleted
   * entries.
   *
   * @return  {@code true} if the result set should include deletes of
   *          soft-deleted entries, or {@code false} if not.
   */
  public boolean includeSoftDeletedEntryDeletes()
  {
    return includeSoftDeletedEntryDeletes;
  }



  /**
   * Retrieves the changelog entry listener that will be used for this request,
   * if applicable.
   *
   * @return  The changelog entry listener that will be used for this request,
   *          or {@code null} if the entries will be made available in the
   *          extended result.
   */
  @Nullable()
  public ChangelogEntryListener getEntryListener()
  {
    return entryListener;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetChangelogBatchExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final IntermediateResponseListener l = getIntermediateResponseListener();
    if (l != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_GET_CHANGELOG_BATCH_REQ_IR_LISTENER_NOT_ALLOWED.get());
    }

    final GetChangelogBatchIntermediateResponseListener listener;
    if (entryListener == null)
    {
      listener = new GetChangelogBatchIntermediateResponseListener(
           new DefaultChangelogEntryListener(this));
    }
    else
    {
      listener =
           new GetChangelogBatchIntermediateResponseListener(entryListener);
    }

    setIntermediateResponseListener(listener);

    ExtendedResult r;
    try
    {
      r = super.process(connection, depth);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      r = new ExtendedResult(getLastMessageID(), le.getResultCode(),
           le.getDiagnosticMessage(), le.getMatchedDN(), le.getReferralURLs(),
           null, null, le.getResponseControls());
    }
    finally
    {
      setIntermediateResponseListener(null);
    }

    if (entryListener == null)
    {
      final DefaultChangelogEntryListener defaultEntryListener =
           (DefaultChangelogEntryListener) listener.getEntryListener();
      return new GetChangelogBatchExtendedResult(r,
           defaultEntryListener.getEntryList());
    }
    else
    {
      return new GetChangelogBatchExtendedResult(r, listener.getEntryCount());
    }
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public GetChangelogBatchExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public GetChangelogBatchExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GetChangelogBatchExtendedRequest r =
         new GetChangelogBatchExtendedRequest(entryListener, startingPoint,
              maxChanges, maxWaitTimeMillis, waitForMaxChanges, includeBaseDNs,
              excludeBaseDNs, changeTypes, continueOnMissingChanges,
              pareEntriesForUserDN, changeSelectionCriteria,
              includeSoftDeletedEntryMods, includeSoftDeletedEntryDeletes,
              controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_GET_CHANGELOG_BATCH_REQ_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetChangelogBatchExtendedRequest(startingPoint=");
    startingPoint.toString(buffer);

    buffer.append(", maxChanges=");
    buffer.append(maxChanges);
    buffer.append(", maxWaitTimeMillis=");
    buffer.append(maxWaitTimeMillis);
    buffer.append(", waitForMaxChanges=");
    buffer.append(waitForMaxChanges);
    buffer.append(", includeBase={");

    final Iterator<String> includeIterator = includeBaseDNs.iterator();
    while (includeIterator.hasNext())
    {
      buffer.append('"');
      buffer.append(includeIterator.next());
      buffer.append('"');
      if (includeIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, excludeBase={");

    final Iterator<String> excludeIterator = excludeBaseDNs.iterator();
    while (excludeIterator.hasNext())
    {
      buffer.append('"');
      buffer.append(excludeIterator.next());
      buffer.append('"');
      if (excludeIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, changeTypes={");

    final Iterator<ChangeType> typeIterator = changeTypes.iterator();
    while (typeIterator.hasNext())
    {
      buffer.append(typeIterator.next().getName());
      if (typeIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, continueOnMissingChanges=");
    buffer.append(continueOnMissingChanges);

    if (pareEntriesForUserDN != null)
    {
      buffer.append(", pareEntriesForUserDN='");
      buffer.append(pareEntriesForUserDN);
      buffer.append('\'');
    }

    if (changeSelectionCriteria != null)
    {
      buffer.append(", changeSelectionCriteria=");
      changeSelectionCriteria.toString(buffer);
    }

    buffer.append(", includeSoftDeletedEntryMods=");
    buffer.append(includeSoftDeletedEntryMods);
    buffer.append(", includeSoftDeletedEntryDeletes=");
    buffer.append(includeSoftDeletedEntryDeletes);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
