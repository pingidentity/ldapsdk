/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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
package com.unboundid.android.ldap.browser;



import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class defines a thread that will be used to perform a search and
 * provide the result to the activity that started it.
 */
class SearchThread
      extends Thread
{
  // The filter to use for the search.
  private final Filter filter;

  // The activity that created this thread.
  private final SearchServer caller;

  // The instance in which the search is to be performed.
  private final ServerInstance instance;



  /**
   * Creates a new search thread with the provided information.
   *
   * @param  caller    The activity that created this thread.
   * @param  instance  The instance in which the search is to be performed.
   * @param  filter    The filter to use for the search.
   */
  public SearchThread(final SearchServer caller, final ServerInstance instance,
                      final Filter filter)
  {
    this.caller   = caller;
    this.instance = instance;
    this.filter   = filter;
  }



  /**
   * Processes the search and returns the result to the caller.
   */
  @Override()
  public void run()
  {
    // Perform the search.
    SearchResult result;
    LDAPConnection conn = null;
    try
    {
      conn = instance.getConnection();

      SearchRequest request = new SearchRequest(instance.getBaseDN(),
           SearchScope.SUB, filter);
      request.setSizeLimit(100);
      request.setTimeLimitSeconds(30);

      result = conn.search(request);
    }
    catch (LDAPSearchException lse)
    {
      result = lse.getSearchResult();
    }
    catch (LDAPException le)
    {
      result = new SearchResult(0, le.getResultCode(), le.getMessage(),
           le.getMatchedDN(), le.getReferralURLs(), 0, 0, null);
    }
    finally
    {
      if (conn != null)
      {
        conn.close();
      }
    }

    caller.searchDone(result);
  }
}
