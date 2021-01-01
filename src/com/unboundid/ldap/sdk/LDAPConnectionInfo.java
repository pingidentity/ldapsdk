/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.net.InetAddress;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSession;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a number of methods that may be used to obtain
 * information about an LDAP connection.  This should be treated as a
 * read-only interface, and when a connection is used in the context of this
 * interface, no processing should be performed that would alter any state.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public interface LDAPConnectionInfo
{
  /**
   * Indicates whether this connection is currently established.
   *
   * @return  {@code true} if this connection is currently established, or
   *          {@code false} if it is not.
   */
  boolean isConnected();



  /**
   * Retrieves the socket factory that was used when creating the socket for the
   * last connection attempt (whether successful or unsuccessful) for this LDAP
   * connection.
   *
   * @return  The socket factory that was used when creating the socket for the
   *          last connection attempt for this LDAP connection, or {@code null}
   *          if no attempt has yet been made to establish this connection.
   */
  @Nullable()
  SocketFactory getLastUsedSocketFactory();



  /**
   * Retrieves the socket factory to use to create the socket for subsequent
   * connection attempts.  This may or may not be the socket factory that was
   * used to create the current established connection.
   *
   * @return  The socket factory to use to create the socket for subsequent
   *          connection attempts.
   */
  @NotNull()
  SocketFactory getSocketFactory();



  /**
   * Retrieves the {@code SSLSession} currently being used to secure
   * communication on this connection.  This may be available for connections
   * that were secured at the time they were created (via an
   * {@code SSLSocketFactory}), or for connections secured after their creation
   * (via the StartTLS extended operation).  This will not be available for
   * unencrypted connections, or connections secured in other ways (e.g., via
   * SASL QoP).
   *
   * @return  The {@code SSLSession} currently being used to secure
   *          communication on this connection, or {@code null} if no
   *          {@code SSLSession} is available.
   */
  @Nullable()
  SSLSession getSSLSession();



  /**
   * Retrieves a value that uniquely identifies this connection within the JVM
   * Each {@code LDAPConnection} object will be assigned a different connection
   * ID, and that connection ID will not change over the life of the object,
   * even if the connection is closed and re-established (whether re-established
   * to the same server or a different server).
   *
   * @return  A value that uniquely identifies this connection within the JVM.
   */
  long getConnectionID();



  /**
   * Retrieves the user-friendly name that has been assigned to this connection.
   *
   * @return  The user-friendly name that has been assigned to this connection,
   *          or {@code null} if none has been assigned.
   */
  @Nullable()
  String getConnectionName();



  /**
   * Retrieves the user-friendly name that has been assigned to the connection
   * pool with which this connection is associated.
   *
   * @return  The user-friendly name that has been assigned to the connection
   *          pool with which this connection is associated, or {@code null} if
   *          none has been assigned or this connection is not associated with a
   *          connection pool.
   */
  @Nullable()
  String getConnectionPoolName();



  /**
   * Retrieves a string representation of the host and port for the server to
   * to which the last connection attempt was made.  It does not matter whether
   * the connection attempt was successful, nor does it matter whether it is
   * still established.  This is primarily intended for internal use in error
   * messages.
   *
   * @return  A string representation of the host and port for the server to
   *          which the last connection attempt was made, or an empty string if
   *          no connection attempt has yet been made on this connection.
   */
  @NotNull()
  String getHostPort();



  /**
   * Retrieves the address of the directory server to which this connection is
   * currently established.
   *
   * @return  The address of the directory server to which this connection is
   *          currently established, or {@code null} if the connection is not
   *          established.
   */
  @Nullable()
  String getConnectedAddress();



  /**
   * Retrieves the string representation of the IP address to which this
   * connection is currently established.
   *
   * @return  The string representation of the IP address to which this
   *          connection is currently established, or {@code null} if the
   *          connection is not established.
   */
  @Nullable()
  String getConnectedIPAddress();



  /**
   * Retrieves an {@code InetAddress} object that represents the address of the
   * server to which this  connection is currently established.
   *
   * @return  An {@code InetAddress} that represents the address of the server
   *          to which this connection is currently established, or {@code null}
   *          if the connection is not established.
   */
  @Nullable()
  InetAddress getConnectedInetAddress();



  /**
   * Retrieves the port of the directory server to which this connection is
   * currently established.
   *
   * @return  The port of the directory server to which this connection is
   *          currently established, or -1 if the connection is not established.
   */
  int getConnectedPort();



  /**
   * Retrieves a stack trace of the thread that last attempted to establish this
   * connection.  Note that this will only be available if an attempt has been
   * made to establish this connection and the
   * {@link LDAPConnectionOptions#captureConnectStackTrace()} method for the
   * associated connection options returns {@code true}.
   *
   * @return  A stack trace of the thread that last attempted to establish this
   *          connection, or {@code null} connect stack traces are not enabled,
   *          or if no attempt has been made to establish this connection.
   */
  @Nullable()
  StackTraceElement[] getConnectStackTrace();



  /**
   * Retrieves the disconnect type for this connection, if available.
   *
   * @return  The disconnect type for this connection, or {@code null} if no
   *          disconnect type has been set.
   */
  @Nullable()
  DisconnectType getDisconnectType();



  /**
   * Retrieves the disconnect message for this connection, which may provide
   * additional information about the reason for the disconnect, if available.
   *
   * @return  The disconnect message for this connection, or {@code null} if
   *          no disconnect message has been set.
   */
  @Nullable()
  String getDisconnectMessage();



  /**
   * Retrieves the disconnect cause for this connection, which is an exception
   * or error that triggered the connection termination, if available.
   *
   * @return  The disconnect cause for this connection, or {@code null} if no
   *          disconnect cause has been set.
   */
  @Nullable()
  Throwable getDisconnectCause();



  /**
   * Retrieves the last successful bind request processed on this connection.
   *
   * @return  The last successful bind request processed on this connection.  It
   *          may be {@code null} if no bind has been performed, or if the last
   *          bind attempt was not successful.
   */
  @Nullable()
  BindRequest getLastBindRequest();



  /**
   * Retrieves the StartTLS request used to secure this connection.
   *
   * @return  The StartTLS request used to secure this connection, or
   *          {@code null} if StartTLS has not been used to secure this
   *          connection.
   */
  @Nullable()
  ExtendedRequest getStartTLSRequest();



  /**
   * Indicates whether this connection is operating in synchronous mode.
   *
   * @return  {@code true} if this connection is operating in synchronous mode,
   *          or {@code false} if not.
   */
  boolean synchronousMode();



  /**
   * Retrieves the time that this connection was established in the number of
   * milliseconds since January 1, 1970 UTC (the same format used by
   * {@code System.currentTimeMillis}.
   *
   * @return  The time that this connection was established, or -1 if the
   *          connection is not currently established.
   */
  long getConnectTime();



  /**
   * Retrieves the time that this connection was last used to send or receive an
   * LDAP message.  The value will represent the number of milliseconds since
   * January 1, 1970 UTC (the same format used by
   * {@code System.currentTimeMillis}.
   *
   * @return  The time that this connection was last used to send or receive an
   *          LDAP message.  If the connection is not established, then -1 will
   *          be returned.  If the connection is established but no
   *          communication has been performed over the connection since it was
   *          established, then the value of {@link #getConnectTime()} will be
   *          returned.
   */
  long getLastCommunicationTime();



  /**
   * Retrieves the connection statistics for this LDAP connection.
   *
   * @return  The connection statistics for this LDAP connection.
   */
  @NotNull()
  LDAPConnectionStatistics getConnectionStatistics();



  /**
   * Retrieves the number of outstanding operations on this LDAP connection
   * (i.e., the number of operations currently in progress).  The value will
   * only be valid for connections not configured to use synchronous mode.
   *
   * @return  The number of outstanding operations on this LDAP connection, or
   *          -1 if it cannot be determined (e.g., because the connection is not
   *          established or is operating in synchronous mode).
   */
  int getActiveOperationCount();



  /**
   * Retrieves a string representation of this LDAP connection.
   *
   * @return  A string representation of this LDAP connection.
   */
  @Override()
  @NotNull()
  String toString();



  /**
   * Appends a string representation of this LDAP connection to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this LDAP connection.
   */
  void toString(@NotNull final StringBuilder buffer);
}
