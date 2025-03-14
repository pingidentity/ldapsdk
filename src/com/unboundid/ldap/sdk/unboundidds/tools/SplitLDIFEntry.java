/*
 * Copyright 2016-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2025 Ping Identity Corporation
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
 * Copyright (C) 2016-2025 Ping Identity Corporation
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



import java.util.Set;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotNull;



/**
 * This class provides an entry that is to be used as the output generated by an
 * {@link com.unboundid.ldif.LDIFReaderEntryTranslator} used by the
 * {@link SplitLDIF} tool.  It includes a pre-encoded LDIF representation of the
 * entry, and may include the sets to which the entry should be written.
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
final class SplitLDIFEntry
      extends Entry
{
  /**
   * The name of the set that will be used to indicate that the entry should be
   * written to a file dedicated to entries outside the split.
   */
  @NotNull static final String SET_NAME_OUTSIDE_SPLIT = ".outside-split";



  /**
   * The name of the set that will be used to indicate that an error occurred
   * in the course of determining which set(s) should be used for an entry.
   */
  @NotNull static final String SET_NAME_ERRORS = ".errors";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3082656046595242989L;



  // The bytes that comprise the LDIF representation of the entry.
  @NotNull private final byte[] ldifBytes;

  // The names of the sets to which this entry should be written.
  @NotNull private final Set<String> sets;



  /**
   * Creates a new instance of this entry with the provided information.
   *
   * @param  e          The entry to be wrapped.
   * @param  ldifBytes  The bytes that comprise the LDIF representation of the
   *                    entry.
   * @param  sets       The names of the sets to which this entry should be
   *                    written.  This may be {@code null} if the appropriate
   *                    collection of sets has not yet been determined.
   */
  SplitLDIFEntry(@NotNull final Entry e,
                 @NotNull final byte[] ldifBytes,
                 @NotNull final Set<String> sets)
  {
    super(e);

    this.ldifBytes = ldifBytes;
    this.sets = sets;
  }



  /**
   * Retrieves the bytes that comprise the LDIF representation of the entry.
   *
   * @return  The bytes that comprise the LDIF representation of the entry.
   */
  @NotNull()
  byte[] getLDIFBytes()
  {
    return ldifBytes;
  }



  /**
   * Retrieves the sets to which this entry should be written, if determined.
   *
   * @return  The sets to which this entry should be written, or {@code null} if
   *          it has not yet been determined.
   */
  @NotNull()
  Set<String> getSets()
  {
    return sets;
  }
}
