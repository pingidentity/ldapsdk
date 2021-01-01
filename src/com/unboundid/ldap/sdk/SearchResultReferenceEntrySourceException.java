/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
 * This class defines an exception that may be thrown if a search result
 * reference is received from the directory server while using the
 * {@link EntrySource} API (e.g., an {@link LDAPEntrySource} object).
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchResultReferenceEntrySourceException
       extends EntrySourceException
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4389660042011914324L;



  // The search result reference returned from the server.
  @NotNull private final SearchResultReference searchReference;



  /**
   * Creates a new search result reference entry source exception with the
   * provided search result reference.
   *
   * @param  searchReference  The search result reference returned by the
   *                          directory server.  It must not be {@code null}.
   */
  public SearchResultReferenceEntrySourceException(
              @NotNull final SearchResultReference searchReference)
  {
    super(true, new LDAPException(ResultCode.REFERRAL,
         ResultCode.REFERRAL.getName(), null,
         searchReference.getReferralURLs(), searchReference.getControls(),
         null));

    this.searchReference = searchReference;
  }



  /**
   * Retrieves the search result reference for this entry source exception.
   *
   * @return  The search result reference for this entry source exception.
   */
  @NotNull()
  public SearchResultReference getSearchReference()
  {
    return searchReference;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SearchResultReferenceEntrySourceException(searchReference=");
    searchReference.toString(buffer);
    buffer.append("')");
  }
}
