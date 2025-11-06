/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a search result listener that will
 * simply ignore all search result entries and references returned by the
 * server.  This is primarily intended for use in cases where a search should
 * be performed, but the actual results aren't needed (e.g., when performing
 * automated tests).  The number of entries and references returned will still
 * be available in the search result.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DiscardResultsSearchResultListener
       implements SearchResultListener
{
  /**
   * The singleton instance of this listener.
   */
  @NotNull private static final DiscardResultsSearchResultListener INSTANCE =
       new DiscardResultsSearchResultListener();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9080502715469552786L;



  /**
   * Creates a new instance of this search result listener.
   */
  private DiscardResultsSearchResultListener()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the singleton instance of this search result listener.
   *
   * @return  The singleton instance of this search result listener.
   */
  @NotNull()
  public static DiscardResultsSearchResultListener getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchEntryReturned(@NotNull final SearchResultEntry searchEntry)
  {
    // No implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void searchReferenceReturned(
                   @NotNull final SearchResultReference searchReference)
  {
    // No implementation is required.
  }
}
