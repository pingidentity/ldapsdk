/*
 * Copyright 2008-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 Ping Identity Corporation
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



import java.util.concurrent.atomic.AtomicInteger;



/**
 * This class provides a simple disconnect notification handler that may be
 * used for testing purposes.
 */
public class TestDisconnectHandler
       implements DisconnectHandler
{
  // The number of times the handler has been invoked.
  private final AtomicInteger notificationCount;



  /**
   * Creates a new instance of this test disconnect handler.
   */
  public TestDisconnectHandler()
  {
    notificationCount = new AtomicInteger(0);
  }



  /**
   * Retrieves the number of times this disconnect handler has been invoked.
   *
   * @return  The number of times this disconnect handler has been invoked.
   */
  public int getNotificationCount()
  {
    return notificationCount.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleDisconnect(final LDAPConnection connection,
                               final String host, final int port,
                               final DisconnectType disconnectType,
                               final String message, final Throwable cause)
  {
    notificationCount.incrementAndGet();
  }
}

