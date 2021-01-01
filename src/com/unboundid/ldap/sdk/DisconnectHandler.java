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



import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines an API that may be implemented by a class that should
 * be notified whenever an LDAP connection is closed for any reason. (whether
 * the connection was closed at the request of the client via a method like
 * {@link LDAPConnection#close}, terminated by the server, or closed due to an
 * internal error).  This interface may be used by applications to attempt to
 * automatically re-establish connections as soon as they are terminated,
 * potentially falling over to another server.
 * <BR><BR>
 * It is acceptable to attempt to re-connect the connection that has been
 * disconnected, but in general that should only be attempted if
 * {@link DisconnectType#isExpected(DisconnectType)} returns {@code true} for
 * the provided {@code disconnectType} value.  The disconnect handler will be
 * temporarily de-registered from the connection so that closing the connection
 * in the course of processing the {@link DisconnectHandler#handleDisconnect}
 * method will not cause it to be recursively re-invoked.
 * <BR><BR>
 * Implementations of this interface should be threadsafe to ensure that
 * multiple connections will be able to safely use the same
 * {@code DisconnectHandler} instance.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface DisconnectHandler
{
  /**
   * Performs any processing that may be necessary in response to the closure
   * of the provided connection.
   *
   * @param  connection      The connection that has been closed.
   * @param  host            The address of the server to which the connection
   *                         had been established.
   * @param  port            The port of the server to which the connection had
   *                         been established.
   * @param  disconnectType  The disconnect type, which provides general
   *                         information about the nature of the disconnect.
   * @param  message         A message that may be associated with the
   *                         disconnect.  It may be {@code null} if no message
   *                         is available.
   * @param  cause           A {@code Throwable} that was caught and triggered
   *                         the disconnect.  It may be {@code null} if the
   *                         disconnect was not triggered by a client-side
   *                         exception or error.
   */
  void handleDisconnect(@NotNull LDAPConnection connection,
                        @NotNull String host, int port,
                        @NotNull DisconnectType disconnectType,
                        @Nullable String message,
                        @Nullable Throwable cause);
}
