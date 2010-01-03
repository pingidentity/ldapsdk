/*
 * Copyright 2009-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2010 UnboundID Corp.
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



import java.util.ArrayList;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.Entry;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class defines a thread that will be used to test the validity of a
 * server instance and the ability to communicate with that server.
 */
class TestServerThread
      extends Thread
{
  // The activity that created this thread if it was the add caller.
  private final AddServer addCaller;

  // The activity that created this thread if it was the edit caller.
  private final EditServer editCaller;

  // The instance in which the search is to be performed.
  private final ServerInstance instance;



  /**
   * Creates a new test server thread with the provided information.
   *
   * @param  caller    The activity that created this thread.
   * @param  instance  The instance in which the search is to be performed.
   */
  public TestServerThread(final AddServer caller, final ServerInstance instance)
  {
    this.instance = instance;

    addCaller  = caller;
    editCaller = null;
  }



  /**
   * Creates a new test server thread with the provided information.
   *
   * @param  caller    The activity that created this thread.
   * @param  instance  The instance in which the search is to be performed.
   */
  public TestServerThread(final EditServer caller,
                          final ServerInstance instance)
  {
    this.instance = instance;

    addCaller  = null;
    editCaller = caller;
  }



  /**
   * Processes the search and returns the result to the caller.
   */
  @Override()
  public void run()
  {
    boolean acceptable;
    ArrayList<String> reasons = new ArrayList<String>();

    acceptable = instance.isDefinitionValid(reasons);
    if (acceptable)
    {
      LDAPConnection conn = null;
      try
      {
        conn = instance.getConnection();

        Entry e = conn.getEntry(instance.getBaseDN());
        if (e == null)
        {
          acceptable = false;
          reasons.add("Base entry '" + instance.getBaseDN() +
                      "' does not exist or could not be retrieved.");
        }
      }
      catch (Exception e)
      {
        acceptable = false;
        reasons.add(getExceptionMessage(e));
      }
      finally
      {
        if (conn != null)
        {
          conn.close();
        }
      }
    }

    if (addCaller == null)
    {
      editCaller.testCompleted(acceptable, reasons);
    }
    else
    {
      addCaller.testCompleted(acceptable, reasons);
    }
  }
}
