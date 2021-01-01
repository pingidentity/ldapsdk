/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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

import com.unboundid.util.NotNull;



/**
 * This class implements a timer task that will be used to periodically check
 * the availability of any servers on the blacklist of an associated
 * {@link ServerSetBlacklistManager}.
 */
final class ServerSetBlacklistManagerTimerTask
      extends TimerTask
{
  // The server set blacklist manager with which this timer task is associated.
  @NotNull private final ServerSetBlacklistManager blacklistManager;



  /**
   * Creates a new instance of this timer task.
   *
   * @param  blacklistManager  The blacklist manager with which this timer task
   *                           is associated.  It must not be {@code null}.
   */
  ServerSetBlacklistManagerTimerTask(
       @NotNull final ServerSetBlacklistManager blacklistManager)
  {
    this.blacklistManager = blacklistManager;
  }



  /**
   * Checks the availability of the servers on the associated blacklist.
   */
  @Override()
  public void run()
  {
    blacklistManager.checkBlacklistedServers();
  }
}
