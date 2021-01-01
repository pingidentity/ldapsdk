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
package com.unboundid.ldap.listener;



import java.net.Socket;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines an API that may be implemented by a class that should
 * be notified whenever a problem occurs with the LDAP listener or any of its
 * associated connections in a manner that may not be directly visible to the
 * caller.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LDAPListenerExceptionHandler
{
  /**
   * Indicates that the specified connection is about to be terminated because
   * an unexpected error occurred during processing.
   *
   * @param  socket  The socket to be used for the failed connection.  It may be
   *                 {@code null} if the failure occurred while attempting to
   *                 accept the socket rather than attempting to create the
   *                 client connection from an accepted socket.
   * @param  cause   An exception providing additional information about the
   *                 problem that occurred.  It will not be {@code null}.
   */
  void connectionCreationFailure(@Nullable Socket socket,
                                 @NotNull Throwable cause);



  /**
   * Indicates that the specified connection is about to be terminated because
   * an unexpected error occurred during processing.
   *
   * @param  connection  The connection that will be terminated.  It will not be
   *                     {@code null}.
   * @param  cause       An exception providing additional information about the
   *                     reason for the termination.  It will not be
   *                     {@code null}.
   */
  void connectionTerminated(@NotNull LDAPListenerClientConnection connection,
                            @NotNull LDAPException cause);
}
