/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds the result of processing an
 * entry via the {@link LDAPDiffProcessor} class.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class LDAPDiffProcessorResult
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1461317955346577315L;



  // Indicates whether the entry was missing from both servers.
  private final boolean entryMissing;

  // The change type associated with the result.
  @Nullable private final ChangeType changeType;

  // The list of changes associated with the result.
  @Nullable private final List<Modification> modifications;

  // The entry associated with the result.
  @Nullable private final ReadOnlyEntry entry;

  // A string representation of the DN for the target entry.
  @NotNull private final String dn;



  /**
   * Creates a new result with the provided information.
   *
   * @param  dn             A string representation of the DN for the target
   *                        entry.  It must not be {@code null}.
   * @param  entryMissing   Indicates whether the entry was missing from both
   *                        servers.
   * @param  changeType     The change type with which this change is
   *                        associated.  It must be {@link ChangeType#ADD} for
   *                        the case in which the entry exists only in the
   *                        target server, {@link ChangeType#DELETE} for the
   *                        case in which it exists only in the source server,
   *                        {@link ChangeType#MODIFY} for the case in which the
   *                        entry exists in both servers but differs between
   *                        them, or {@code null} for the case in which the
   *                        entry exists in both servers and is the same between
   *                        them.
   * @param  entry          The entry associated with this change.  It must be
   *                        non-{@code null} if the {@code changeType} value is
   *                        either {@link ChangeType#ADD} or
   *                        {@link ChangeType#DELETE}; otherwise, it must be
   *                        {@code null}.
   * @param  modifications  The list of modifications associated with this
   *                        change.  It must be non-{@code null}, non-empty, and
   *                        unmodifiable for results in which the
   *                        {@code changeType} is {@link ChangeType#MODIFY}, and
   *                        it must be {@code null} for all other
   *                        {@code changeType} values (including {@code null}).
   */
  private LDAPDiffProcessorResult(
               @NotNull final String dn,
               final boolean entryMissing,
               @Nullable final ChangeType changeType,
               @Nullable final ReadOnlyEntry entry,
               @Nullable final List<Modification> modifications)
  {
    this.dn = dn;
    this.entryMissing = entryMissing;
    this.changeType = changeType;
    this.entry = entry;
    this.modifications = modifications;
  }



  /**
   * Creates a result indicating that the associated entry was missing from
   * both the source and target servers.
   *
   * @param  dn  A string representation of the DN for the target entry.  It
   *             must not be {@code null}.
   *
   * @return  The entry missing result that was created.
   */
  @NotNull()
  static LDAPDiffProcessorResult createEntryMissingResult(
              @NotNull final String dn)
  {
    return new LDAPDiffProcessorResult(dn, true, null, null, null);
  }



  /**
   * Creates a result indicating that the associated entry is the same on both
   * the source and target servers.
   *
   * @param  dn  A string representation of the DN for the target entry.  It
   *             must not be {@code null}.
   *
   * @return  The no changes result that was created.
   */
  @NotNull()
  static LDAPDiffProcessorResult createNoChangesResult(
              @NotNull final String dn)
  {
    return new LDAPDiffProcessorResult(dn, false, null, null, null);
  }



  /**
   * Creates a result indicating that the provided entry exists only on the
   * target server and needs to be added to the source server.
   *
   * @param  entry  The entry with which the add is associated.  It must not be
   *                {@code null}.
   *
   * @return  The add result that was created.
   */
  @NotNull()
  static LDAPDiffProcessorResult createAddResult(
              @NotNull final ReadOnlyEntry entry)
  {
    return new LDAPDiffProcessorResult(entry.getDN(), false, ChangeType.ADD,
         entry, null);
  }



  /**
   * Creates a result indicating that the provided entry exists only on the
   * source server and needs to be removed from that server.
   *
   * @param  entry  The entry with which the delete is associated.  It must not
   *                be {@code null}.
   *
   * @return  The delete result that was created.
   */
  @NotNull()
  static LDAPDiffProcessorResult createDeleteResult(
              @NotNull final ReadOnlyEntry entry)
  {
    return new LDAPDiffProcessorResult(entry.getDN(), false,
         ChangeType.DELETE, entry, null);
  }



  /**
   * Creates a result indicating that the provided entry exists in both servers
   * but is different between the source and target server.
   *
   * @param  dn             The DN of the target entry.  It must not be
   *                        {@code null}.
   * @param  modifications  The set of modifications needed to convert the entry
   *                        from the source server to match the entry in the
   *                        target server.  It must not be {@code null} or
   *                        empty.
   *
   * @return  The modify result that was created.
   */
  @NotNull()
  static LDAPDiffProcessorResult createModifyResult(
              @NotNull final String dn,
              @NotNull final List<Modification> modifications)
  {
    return new LDAPDiffProcessorResult(dn, false, ChangeType.MODIFY, null,
         Collections.unmodifiableList(modifications));
  }



  /**
   * Retrieves the DN of the target entry.
   *
   * @return  The DN of the target entry.
   */
  @NotNull()
  String getDN()
  {
    return dn;
  }



  /**
   * Indicates whether the associated entry was missing from both servers.
   *
   * @return  {@code true} if the entry was missing from both servers, or
   *          {@code false} if not.
   */
  public boolean isEntryMissing()
  {
    return entryMissing;
  }



  /**
   * Retrieves the change type for this result.
   *
   * @return  The change type for this result, or {@code null} if the entry is
   *          the same in the source and target server.
   */
  @Nullable()
  ChangeType getChangeType()
  {
    return changeType;
  }



  /**
   * Retrieves the entry for this result.
   *
   * @return  The entry for this result if it has a change type of
   *          {@link ChangeType#ADD} or {@link ChangeType#DELETE}, or
   *          {@code null} if it has a change type of {@link ChangeType#MODIFY}
   *          or {@code null}.
   */
  @Nullable()
  ReadOnlyEntry getEntry()
  {
    return entry;
  }



  /**
   * Retrieves an unmodifiable list of the modifications for this result.
   *
   * @return  An unmodifiable list of the modifications for this result, or
   *          {@code null} if this result has a change type of anything other
   *          than {@link ChangeType#MODIFY}.
   */
  @Nullable()
  List<Modification> getModifications()
  {
    return modifications;
  }



  /**
   * Retrieves a string representation of this result.
   *
   * @return  A string representation of this result.
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
   * Appends a string representation of this result to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.  It must not be {@code null}.
   */
  void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPDiffProcessorResult(dn='");
    buffer.append(dn);
    buffer.append("', entryMissing=");
    buffer.append(entryMissing);
    buffer.append(", changeType=");
    buffer.append(changeType);
    buffer.append(')');
  }
}
