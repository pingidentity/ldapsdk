/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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



/**
 * This class implements a timer task that will be used to periodically check
 * the availability of any servers on the blacklist of an associated
 * {@link ServerSetBlacklistManager}.
 */
final class ServerSetBlacklistManagerTimerTask
      extends TimerTask
{
  // The server set blacklist manager with which this timer task is associated.
  private final ServerSetBlacklistManager blacklistManager;



  /**
   * Creates a new instance of this timer task.
   *
   * @param  blacklistManager  The blacklist manager with which this timer task
   *                           is associated.  It must not be {@code null}.
   */
  ServerSetBlacklistManagerTimerTask(
       final ServerSetBlacklistManager blacklistManager)
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
