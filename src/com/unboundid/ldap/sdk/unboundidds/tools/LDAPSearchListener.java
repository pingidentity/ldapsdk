/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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



  // The output handler to use to display the results.
  private final LDAPSearchOutputHandler outputHandler;

  // The entry transformations to apply.
  private final List<EntryTransformation> entryTransformations;



  /**
   * Creates a new LDAP search listener with the provided output handler.
   *
   * @param  outputHandler         The output handler to use to display the
   *                               results.
   * @param  entryTransformations  The entry transformations to apply.  It may
   *                               be {@code null} or empty if no
   *                               transformations are needed.
   */
  LDAPSearchListener(final LDAPSearchOutputHandler outputHandler,
                     final List<EntryTransformation> entryTransformations)
  {
    this.outputHandler        = outputHandler;
    this.entryTransformations = entryTransformations;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
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
      }

      sre = new SearchResultEntry(searchEntry.getMessageID(), e,
           searchEntry.getControls());
    }

    outputHandler.formatSearchResultEntry(sre);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    outputHandler.formatSearchResultReference(searchReference);
  }
}
