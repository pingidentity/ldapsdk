/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.examples;



import java.util.logging.Handler;

import com.unboundid.ldap.listener.LDAPListener;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a thread that will be started whenever the JVM running
 * the LDAP debugger is shut down.  It will be used to ensure that the LDAP
 * listener and log handler are properly closed.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class LDAPDebuggerShutdownListener
      extends Thread
{
  // The log handler that will be closed.
  @NotNull private final Handler logHandler;

  // The LDAP listener that will be closed.
  @NotNull private final LDAPListener listener;



  /**
   * Creates a new shutdown listener that will shut down the LDAP listener and
   * close the log handler when the JVM is shutting down.
   *
   * @param  listener    The LDAP listener to be shut down.
   * @param  logHandler  The log handler to be closed.
   */
  LDAPDebuggerShutdownListener(@NotNull final LDAPListener listener,
                               @NotNull final Handler logHandler)
  {
    this.listener   = listener;
    this.logHandler = logHandler;
  }



  /**
   * Starts this thread to shut down the listener and close the log handler.
   */
  @Override()
  public void run()
  {
    listener.shutDown(true);
    logHandler.close();
  }
}
