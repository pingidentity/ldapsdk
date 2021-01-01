/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.TimerTask;

import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a timer task that can be used to ensure that operation
 * timeouts for asynchronous operations are properly respected.
 */
final class AsyncTimeoutTimerTask
      extends TimerTask
{
  // The async helper with which this task is associated.
  @NotNull private final CommonAsyncHelper helper;



  /**
   * Creates a new timer task that will provide a timeout response for an
   * asynchronous operation if no other response has been received first.
   *
   * @param  helper  The async helper with which this task is associated.
   */
  AsyncTimeoutTimerTask(@NotNull final CommonAsyncHelper helper)
  {
    this.helper = helper;
  }



  /**
   * Generates a timeout response for the associated operation.
   */
  @Override()
  public void run()
  {
    final long waitTimeNanos = System.nanoTime() - helper.getCreateTimeNanos();
    final long waitTimeMillis = waitTimeNanos / 1_000_000L;

    final LDAPConnection conn = helper.getConnection();
    final boolean abandon = conn.getConnectionOptions().abandonOnTimeout();

    final String message;
    if (abandon)
    {
      message = INFO_ASYNC_OPERATION_TIMEOUT_WITH_ABANDON.get(waitTimeMillis);
    }
    else
    {
      message =
           INFO_ASYNC_OPERATION_TIMEOUT_WITHOUT_ABANDON.get(waitTimeMillis);
    }

    final LDAPResponse response;
    final int messageID = helper.getAsyncRequestID().getMessageID();
    switch (helper.getOperationType())
    {
      case ADD:
      case DELETE:
      case MODIFY:
      case MODIFY_DN:
        response = new LDAPResult(messageID, ResultCode.TIMEOUT, message, null,
             StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
        break;
      case COMPARE:
        response = new CompareResult(messageID, ResultCode.TIMEOUT, message,
             null, StaticUtils.NO_STRINGS, StaticUtils.NO_CONTROLS);
        break;
      case SEARCH:
        final AsyncSearchHelper searchHelper = (AsyncSearchHelper) helper;
        response = new SearchResult(messageID, ResultCode.TIMEOUT, message,
             null, StaticUtils.NO_STRINGS, searchHelper.getNumEntries(),
             searchHelper.getNumReferences(), StaticUtils.NO_CONTROLS);
        break;
      default:
        // This should never happen.
        return;
    }

    try
    {
      try
      {
        final LDAPConnectionReader connectionReader =
             conn.getConnectionInternals(true).getConnectionReader();
        connectionReader.deregisterResponseAcceptor(messageID);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      helper.responseReceived(response);
      if (abandon)
      {
        conn.abandon(helper.getAsyncRequestID());
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
    }
  }
}
