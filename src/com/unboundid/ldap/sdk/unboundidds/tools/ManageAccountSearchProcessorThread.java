/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;



/**
 * This class provides a thread that may be used to parallelize the process of
 * searching for entries on which to invoke password policy state operations.
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
final class ManageAccountSearchProcessorThread
       extends Thread
{
  // The manage-account search processor that will actually do the majority of
  // the work.
  @NotNull private final ManageAccountSearchProcessor searchProcessor;

  // The search operation currently being processed by this thread.
  @Nullable private volatile ManageAccountSearchOperation activeSearchOperation;



  /**
   * Creates a new manage-account search processor thread with the provided
   * information.
   *
   * @param  threadNumber     The thread number for this thread.  This will only
   *                          be used for informational purposes in the thread
   *                          name.
   * @param  searchProcessor  The manage-account search processor that will
   *                          actually do the majority of the work.  It must not
   *                          be {@code null}.
   */
  ManageAccountSearchProcessorThread(final int threadNumber,
       @NotNull final ManageAccountSearchProcessor searchProcessor)
  {
    setName("manage-account Search Processor Thread " + threadNumber);

    this.searchProcessor = searchProcessor;

    activeSearchOperation = null;
  }



  /**
   * Performs the processing for this thread.
   */
  @Override()
  public void run()
  {
    while (true)
    {
      try
      {
        activeSearchOperation = searchProcessor.getSearchOperation();
        if (activeSearchOperation == null)
        {
          return;
        }
        else
        {
          activeSearchOperation.doSearch();
        }
      }
      finally
      {
        activeSearchOperation = null;
      }
    }
  }



  /**
   * Cancels processing on the active search operation.
   */
  void cancelSearch()
  {
    final ManageAccountSearchOperation o = activeSearchOperation;
    if (o != null)
    {
      o.cancelSearch();
    }
  }
}
