/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure with information about the reason a
 * connection was closed.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class DisconnectInfo
{
  // Indicates whether the disconnect handler has been notified of a disconnect.
  @NotNull private final AtomicBoolean handlerNotified;

  // The disconnect type.
  @NotNull private final DisconnectType type;

  // The port to which the connection was established.
  private final int port;

  // The connection with which this disconnect info is associated.
  @NotNull private final LDAPConnection connection;

  // The address to which the connection was established.
  @NotNull private final String host;

  // The disconnect message, if available.
  @Nullable private final String message;

  // The disconnect cause, if available.
  @Nullable private final Throwable cause;



  /**
   * Creates a new disconnect info object with the provided information.
   *
   * @param  connection  The connection with which this disconnect info object
   *                     is associated.  It must not be {@code null}.
   * @param  type        The disconnect type.  It must not be {@code null}.
   * @param  message     A message providing additional information about the
   *                     disconnect.  It may be {@code null} if no message is
   *                     available.
   * @param  cause       The exception that was caught to trigger the
   *                     disconnect.  It may be {@code null} if the disconnect
   *                     was not triggered by an exception.
   */
  DisconnectInfo(@NotNull final LDAPConnection connection,
                 @NotNull final DisconnectType type,
                 @Nullable final String message,
                 @Nullable final Throwable cause)
  {
    Validator.ensureNotNull(connection);
    Validator.ensureNotNull(type);

    this.connection = connection;
    this.type       = type;
    this.message    = message;
    this.cause      = cause;

    handlerNotified = new AtomicBoolean(false);
    host = connection.getConnectedAddress();
    port = connection.getConnectedPort();
  }



  /**
   * Retrieves the disconnect type.
   *
   * @return  The disconnect type.
   */
  @NotNull()
  DisconnectType getType()
  {
    return type;
  }



  /**
   * Retrieves the disconnect message, if available.
   *
   * @return  The disconnect message, or {@code null} if none was provided.
   */
  @Nullable()
  String getMessage()
  {
    return message;
  }



  /**
   * Retrieves the disconnect cause, if available.
   *
   * @return  The disconnect cause, or {@code null} if none was provided.
   */
  @Nullable()
  Throwable getCause()
  {
    return cause;
  }



  /**
   * Notifies the disconnect handler that the associated connection has been
   * closed.
   */
  void notifyDisconnectHandler()
  {
    final boolean alreadyNotified = handlerNotified.getAndSet(true);
    if (alreadyNotified)
    {
      return;
    }

    final ServerSet serverSet = connection.getServerSet();
    if (serverSet != null)
    {
      serverSet.handleConnectionClosed(connection, host, port, type, message,
           cause);
    }

    final DisconnectHandler handler =
         connection.getConnectionOptions().getDisconnectHandler();
    if (handler != null)
    {
      handler.handleDisconnect(connection, host, port, type, message, cause);
    }
  }



  /**
   * Retrieves a string representation of this disconnect info object.
   *
   * @return  A string representation of this disconnect info object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this disconnect info object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DisconnectInfo(type=");
    buffer.append(type.name());

    if (message != null)
    {
      buffer.append(", message='");
      buffer.append(message);
      buffer.append('\'');
    }

    if (cause != null)
    {
      buffer.append(", cause=");
      buffer.append(StaticUtils.getExceptionMessage(cause));
    }

    buffer.append(')');
  }
}
