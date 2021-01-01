/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines an API that may be implemented by classes which wish
 * to be notified of processing performed in the course of moving a subtree
 * between servers.
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
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface MoveSubtreeListener
{
  /**
   * Performs any processing which may be needed before the provided entry is
   * added to the target server.
   *
   * @param  entry  A read-only representation of the entry to be added to the
   *                target server.
   *
   * @return  The original entry if the add should proceed without changes, a
   *          new entry (which must have the same DN as the provided entry) if
   *          the entry should be added with changes, or {@code null} if the
   *          entry should not be added to the target server (but will still be
   *          removed from the source server).
   */
  @Nullable()
  ReadOnlyEntry doPreAddProcessing(@NotNull ReadOnlyEntry entry);



  /**
   * Performs any processing which may be needed after the provided entry has
   * been added to the target server.
   *
   * @param  entry  A read-only representation of the entry that was added to
   *                the target server.  Note that depending on the algorithm
   *                used to perform the move, the entry may not yet be
   *                accessible in the target server.  Also note that the add may
   *                potentially be reverted if move processing encounters an
   *                error later in its processing.
   */
  void doPostAddProcessing(@NotNull ReadOnlyEntry entry);



  /**
   * Performs any processing which may be needed before the specified entry is
   * deleted from the source server.
   *
   * @param  entryDN  The DN of the entry that is to be removed from the
   *                  source server.  Note that depending on the algorithm used
   *                  to perform the move, the entry may already be inaccessible
   *                  in the source server.
   */
  void doPreDeleteProcessing(@NotNull DN entryDN);



  /**
   * Performs any processing which may be needed after the specified entry has
   * been deleted from the source server.
   *
   * @param  entryDN  The DN of the entry that has been removed from the source
   *                  server.  Note that the delete may potentially be reverted
   *                  if move processing encounters an error later in its
   *                  processing.
   */
  void doPostDeleteProcessing(@NotNull DN entryDN);
}
