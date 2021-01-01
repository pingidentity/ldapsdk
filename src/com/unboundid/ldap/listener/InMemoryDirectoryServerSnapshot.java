/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an opaque data structure which represents a point-in-time
 * snapshot for an in-memory directory server instance. Note that this snapshot
 * will reflect only data held in the server (including both user data and any
 * changelog information, if that is enabled), but will not alter the settings
 * of the server which are defined through configuration.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InMemoryDirectoryServerSnapshot
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4691579754615787705L;



  // The first change number value at the time the snapshot was created.
  private final long firstChangeNumber;

  // The last change number value at the time the snapshot was created.
  private final long lastChangeNumber;

  // The set of entries held in the server at the time the snapshot was created.
  @NotNull private final Map<DN,ReadOnlyEntry> entryMap;



  /**
   * Creates a new in-memory directory server snapshot with the provided
   * information.
   *
   * @param  m                  A map of the entries contained in the server
   *                            (including changelog entries) at the time the
   *                            snapshot was created.
   * @param  firstChangeNumber  The first change number value at the time the
   *                            snapshot was created.
   * @param  lastChangeNumber   The last change number value at the time the
   *                            snapshot was created.
   */
  InMemoryDirectoryServerSnapshot(@NotNull final Map<DN,ReadOnlyEntry> m,
                                  final long firstChangeNumber,
                                  final long lastChangeNumber)
  {
    this.firstChangeNumber = firstChangeNumber;
    this.lastChangeNumber  = lastChangeNumber;

    entryMap = Collections.unmodifiableMap(new TreeMap<>(m));
  }



  /**
   * Retrieves an unmodifiable map of all entries defined in the server at the
   * time the snapshot was created.  This will include user-defined entries as
   * sell as changelog entries, but it will exclude the root DSE and the schema
   * subentry (since they are dynamically generated from the configuration).
   *
   * @return  An unmodifiable map of all entries defined in the server at the
   *          time the snapshot was created.
   */
  @NotNull()
  public Map<DN,ReadOnlyEntry> getEntryMap()
  {
    return entryMap;
  }



  /**
   * Retrieves the first change number for the server at the time the snapshot
   * was created.
   *
   * @return  The first change number for the server at the time the snapshot
   *          was created.
   */
  public long getFirstChangeNumber()
  {
    return firstChangeNumber;
  }



  /**
   * Retrieves the last change number for the server at the time the snapshot
   * was created.
   *
   * @return  The last change number for the server at the time the snapshot
   *          was created.
   */
  public long getLastChangeNumber()
  {
    return lastChangeNumber;
  }
}
