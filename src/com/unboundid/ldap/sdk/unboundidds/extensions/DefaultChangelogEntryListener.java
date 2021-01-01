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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.util.NotNull;
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
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
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
  @NotNull private final ArrayList<ChangelogEntryIntermediateResponse>
       entryList;



  /**
   * Creates a new instance of this entry listener to process the provided
   * request.
   *
   * @param  r  The request to be processed.
   */
  DefaultChangelogEntryListener(
       @NotNull final GetChangelogBatchExtendedRequest r)
  {
    entryList = new ArrayList<>(r.getMaxChanges());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleChangelogEntry(
       @NotNull final ChangelogEntryIntermediateResponse ir)
  {
    entryList.add(ir);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleMissingChangelogEntries(
       @NotNull final MissingChangelogEntriesIntermediateResponse ir)
  {
    // This response will be ignored.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleOtherIntermediateResponse(
       @NotNull final IntermediateResponse ir)
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
  @NotNull()
  List<ChangelogEntryIntermediateResponse> getEntryList()
  {
    return entryList;
  }
}
