/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides the default changelog entry listener that will be used if
 * none is explicitly provided for the associated get changelog batch extended
 * operation.  It will collect the changelog entries in a list that will be made
 * available as part of the extended result.
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
final class DefaultChangelogEntryListener
      implements ChangelogEntryListener, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4372347455698298062L;



  // The list that will be used to collect entries that are returned.
  private final ArrayList<ChangelogEntryIntermediateResponse> entryList;



  /**
   * Creates a new instance of this entry listener to process the provided
   * request.
   *
   * @param  r  The request to be processed.
   */
  DefaultChangelogEntryListener(final GetChangelogBatchExtendedRequest r)
  {
    entryList =
         new ArrayList<ChangelogEntryIntermediateResponse>(r.getMaxChanges());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleChangelogEntry(final ChangelogEntryIntermediateResponse ir)
  {
    entryList.add(ir);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleMissingChangelogEntries(
                   final MissingChangelogEntriesIntermediateResponse ir)
  {
    // This response will be ignored.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleOtherIntermediateResponse(final IntermediateResponse ir)
  {
    // This response will be ignored.
  }



  /**
   * Retrieves the list of changelog entries returned during the course of
   * processing the operation.
   *
   * @return  The list of changelog entries returned during the course of
   *          processing the operation.
   */
  List<ChangelogEntryIntermediateResponse> getEntryList()
  {
    return entryList;
  }
}
