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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;



/**
 * This class provides a thread that may be used to provide a search result done
 * message to an {@code LDAPSearchResults} object after a specified delay.
 */
class TestDelayedResultProvider
      extends Thread
{
  // The LDAPSearchResults object to be updated.
  private final LDAPSearchResults results;

  // The delay in milliseconds before updating the results.
  private final long delay;



  /**
   * Creates a new instance of this object.
   *
   * @param  results  The search results to be updated.
   * @param  delay    The length of time to wait before updating the results.
   */
  TestDelayedResultProvider(final LDAPSearchResults results,
                            final long delay)
  {
    this.results = results;
    this.delay   = delay;
  }



  /**
   * Runs this thread, sleeping for the specified period of time before updating
   * the results.
   */
  @Override()
  public void run()
  {
    try
    {
      Thread.sleep(delay);
    } catch (Exception e) {}

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true)
    };
    results.searchResultReceived(
         InternalSDKHelper.createAsyncRequestID(1, null),
         new SearchResult(1, ResultCode.NO_SUCH_OBJECT, null,
              "dc=example,dc=com", null, 0, 0, controls));
  }
}
