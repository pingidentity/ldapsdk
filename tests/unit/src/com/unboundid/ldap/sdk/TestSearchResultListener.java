/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



/**
 * This class provides a search result listener implementation that can be used
 * for testing purposes.
 */
public class TestSearchResultListener
       implements SearchResultListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8647326852734851378L;



  // The number of entries provided to this listener.
  private int numEntries;

  // The number of references provided to this listener.
  private int numReferences;

  // The DN of the first entry provided to this listener.
  private String firstDN;



  /**
   * Creates a new instance of this test search result listener.
   */
  public TestSearchResultListener()
  {
    numEntries    = 0;
    numReferences = 0;
    firstDN       = null;
  }



  /**
   * Indicates that the provided search result entry has been returned by the
   * server and may be processed by this search result listener.
   *
   * @param  searchEntry  The search result entry that has been returned by the
   *                      server.
   */
  @Override()
  public void searchEntryReturned(final SearchResultEntry searchEntry)
  {
    numEntries++;
    if (firstDN == null)
    {
      firstDN = searchEntry.getDN();
    }
  }



  /**
   * Indicates that the provided search result reference has been returned by
   * the server and may be processed by this search result listener.
   *
   * @param  searchReference  The search result reference that has been returned
   *                          by the server.
   */
  @Override()
  public void searchReferenceReturned(
                   final SearchResultReference searchReference)
  {
    numReferences++;
  }



  /**
   * Retrieves the number of entries that have been provided to this listener.
   *
   * @return  The number of entries that have been provided to this listener.
   */
  public int getNumEntries()
  {
    return numEntries;
  }



  /**
   * Retrieves the number of references that have been provided to this
   * listener.
   *
   * @return  The number of references that have been provided to this listener.
   */
  public int getNumReferences()
  {
    return numReferences;
  }



  /**
   * Retrieves the DN of the first entry returned through this listener.
   *
   * @return  The DN of the first entry returned through this listener.
   */
  public String getFirstEntryDN()
  {
    return firstDN;
  }



  /**
   * Resets this test search result listener back to its initial state.
   */
  public void reset()
  {
    numEntries   = 0;
    numReferences = 0;
    firstDN       = null;
  }
}
