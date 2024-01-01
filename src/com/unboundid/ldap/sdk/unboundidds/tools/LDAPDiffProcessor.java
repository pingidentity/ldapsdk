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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.List;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.parallel.Processor;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an implementation of a processor that can be used to
 * attempt to retrieve an entry from the source and target servers and identify
 * differences between them.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class LDAPDiffProcessor
      implements Processor<LDAPDiffCompactDN,LDAPDiffProcessorResult>
{
  /**
   * A flag that indicates that diffing should not ignore the entry's RDN.
   */
  private static final boolean DO_NOT_IGNORE_RDN = false;



  /**
   * A flag that indicates that the diffing should report changes in reversible
   * mode.
   */
  private static final boolean USE_REVERSIBLE_MODE = true;



  // Indicates whether to use a byte-for-byte comparison rather than logical
  // equivalence.
  private final boolean byteForByte;

  // Indicates whether to only report entries that exist on one server but not
  // the other.
  private final boolean missingOnly;

  // The common base DN to use in processing.
  @NotNull private final DN baseDN;

  // A connection pool that may be used to communicate with the source server.
  @NotNull private final LDAPConnectionPool sourcePool;

  // A connection pool that may be used to communicate with the target server.
  @NotNull private final LDAPConnectionPool targetPool;

  // The schema to use during processing.
  @Nullable private final Schema schema;

  // The attributes to request when retrieving entries.
  @NotNull private final String[] attributes;



  /**
   * Creates a new instance of this processor with the provided information.
   *
   * @param  sourcePool   A connection pool that may be used to communicate with
   *                      the source server.  It must not be {@code null} and
   *                      must be established.
   * @param  targetPool   A connection pool that may be used to communicate with
   *                      the target server.  It must not be {@code null} and
   *                      must be established.
   * @param  baseDN       The common base DN to use in processing.  It must not
   *                      be {@code null}.
   * @param  schema       The schema to use in processing.  It may optionally be
   *                      {@code null} if no schema is available.
   * @param  byteForByte  Indicates whether to use a byte-for-byte comparison
   *                      rather than logical equivalence when comparing
   *                      entries.
   * @param  attributes   The set of attributes to request when retrieving
   *                      entries from the source and target servers.  It must
   *                      not be {@code null} but may be empty.
   * @param  missingOnly  Indicates whether to only report on entries that exist
   *                      on one server but not the other.
   */
  LDAPDiffProcessor(
       @NotNull final LDAPConnectionPool sourcePool,
       @NotNull final LDAPConnectionPool targetPool,
       @NotNull final DN baseDN,
       @Nullable final Schema schema,
       final boolean byteForByte,
       @NotNull final String[] attributes,
       final boolean missingOnly)
  {
    this.sourcePool = sourcePool;
    this.targetPool = targetPool;
    this.baseDN = baseDN;
    this.schema = schema;
    this.byteForByte = byteForByte;
    this.attributes = attributes;
    this.missingOnly = missingOnly;
  }




  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPDiffProcessorResult process(
              @NotNull final LDAPDiffCompactDN compactDN)
         throws LDAPException
  {
    // Convert the provided compact DN to a full DN.
    final DN dn = compactDN.toDN(baseDN, schema);
    final String dnString = dn.toString();


    // Retrieve the entry from the source and target servers.
    final ReadOnlyEntry sourceEntry;
    try
    {
      sourceEntry = sourcePool.getEntry(dnString, attributes);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(e.getResultCode(),
           ERR_LDAP_DIFF_PROCESSOR_ERROR_GETTING_ENTRY_FROM_SOURCE.get(
                dnString, StaticUtils.getExceptionMessage(e)),
           e);
    }

    final ReadOnlyEntry targetEntry;
    try
    {
      targetEntry = targetPool.getEntry(dnString, attributes);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(e.getResultCode(),
           ERR_LDAP_DIFF_PROCESSOR_ERROR_GETTING_ENTRY_FROM_TARGET.get(
                dnString, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // If the source entry is null, then see if the target entry is also null.
    // If so, then the entry doesn't exist on either server, so it's the same.
    // Otherwise, it needs to be added.
    if (sourceEntry == null)
    {
      if (targetEntry == null)
      {
        return LDAPDiffProcessorResult.createEntryMissingResult(dnString);
      }
      else
      {
        return LDAPDiffProcessorResult.createAddResult(targetEntry);
      }
    }


    // If the target entry is null, then the entry needs to be removed.
    if (targetEntry == null)
    {
      return LDAPDiffProcessorResult.createDeleteResult(sourceEntry);
    }


    // The entry exists in both servers.  If we're operating in missingOnly
    // mode, then we'll blindly consider the entry to be equivalent.  Otherwise,
    // perform a diff to see if the entries are the same or different.
    if (missingOnly)
    {
      return LDAPDiffProcessorResult.createNoChangesResult(sourceEntry.getDN());
    }
    else
    {
      final List<Modification> mods = Entry.diff(sourceEntry, targetEntry,
           DO_NOT_IGNORE_RDN, USE_REVERSIBLE_MODE, byteForByte);
      if (mods.isEmpty())
      {
        return LDAPDiffProcessorResult.createNoChangesResult(
             sourceEntry.getDN());
      }
      else
      {
        return LDAPDiffProcessorResult.createModifyResult(sourceEntry.getDN(),
             mods);
      }
    }
  }
}
