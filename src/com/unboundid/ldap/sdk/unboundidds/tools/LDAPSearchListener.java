/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultListener;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.transformations.EntryTransformation;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a search result listener that will be used to report
 * information about search result entries and references returned for a search
 * operation.
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
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class LDAPSearchListener
      implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1334215024363357539L;



  // The result writer to use to output the results.
  @NotNull private final LDAPResultWriter resultWriter;

  // The entry transformations to apply.
  @Nullable private final List<EntryTransformation> entryTransformations;



  /**
   * Creates a new LDAP search listener with the provided output handler.
   *
   * @param  resultWriter          The result writer to use to output the
   *                               results.  It must not be {@code null}.
   * @param  entryTransformations  The entry transformations to apply.  It may
   *                               be {@code null} or empty if no
   *                               transformations are needed.
   */
  LDAPSearchListener(@NotNull final LDAPResultWriter resultWriter,
       @Nullable final List<EntryTransformation> entryTransformations)
  {
    this.resultWriter = resultWriter;
    this.entryTransformations = entryTransformations;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    final SearchResultEntry sre;
    if (entryTransformations == null)
    {
      sre = searchEntry;
    }
    else
    {
      Entry e = searchEntry;
      for (final EntryTransformation t : entryTransformations)
      {
        e = t.transformEntry(e);
        if (e == null)
        {
          return;
        }
      }

      sre = new SearchResultEntry(searchEntry.getMessageID(), e,
           searchEntry.getControls());
    }

    resultWriter.writeSearchResultEntry(sre);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    resultWriter.writeSearchResultReference(searchReference);
  }
}
