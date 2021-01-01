/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that can be used to select between multiple
 * directory servers when establishing a connection.  Implementations are free
 * to use any kind of logic that they desire when selecting the server to which
 * the connection is to be established.  They may also support the use of
 * health checks to determine whether the created connections are suitable for
 * use.
 * <BR><BR>
 * Implementations MUST be threadsafe to allow for multiple concurrent attempts
 * to establish new connections.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ServerSet
{
  /**
   * Creates a new instance of this server set.
   */
  protected ServerSet()
  {
    // No implementation is required.
  }



  /**
   * Indicates whether connections created by this server set will be
   * authenticated.
   *
   * @return  {@code true} if connections created by this server set will be
   *          authenticated, or {@code false} if not.
   */
  public boolean includesAuthentication()
  {
    return false;
  }



  /**
   * Indicates whether connections created by this server set will have
   * post-connect processing performed.
   *
   * @return  {@code true} if connections created by this server set will have
   *          post-connect processing performed, or {@code false} if not.
   */
  public boolean includesPostConnectProcessing()
  {
    return false;
  }



  /**
   * Attempts to establish a connection to one of the directory servers in this
   * server set.  The connection that is returned must be established.  The
   * {@link #includesAuthentication()} must return true if and only if the
   * connection will also be authenticated, and the
   * {@link #includesPostConnectProcessing()} method must return true if and
   * only if pre-authentication and post-authentication post-connect processing
   * will have been performed.  The caller may determine the server to which the
   * connection is established using the
   * {@link LDAPConnection#getConnectedAddress} and
   * {@link LDAPConnection#getConnectedPort} methods.
   *
   * @return  An {@code LDAPConnection} object that is established to one of the
   *          servers in this server set.
   *
   * @throws  LDAPException  If it is not possible to establish a connection to
   *                         any of the servers in this server set.
   */
  @NotNull()
  public abstract LDAPConnection getConnection()
         throws LDAPException;



  /**
   * Attempts to establish a connection to one of the directory servers in this
   * server set, using the provided health check to further validate the
   * connection.  The connection that is returned must be established.  The
   * {@link #includesAuthentication()} must return true if and only if the
   * connection will also be authenticated, and the
   * {@link #includesPostConnectProcessing()} method must return true if and
   * only if pre-authentication and post-authentication post-connect processing
   * will have been performed.  The caller may determine the server to which the
   * connection is established using the
   * {@link LDAPConnection#getConnectedAddress} and
   * {@link LDAPConnection#getConnectedPort} methods.
   *
   * @param  healthCheck  The health check to use to verify the health of the
   *                      newly-created connection.  It may be {@code null} if
   *                      no additional health check should be performed.  If it
   *                      is non-{@code null} and this server set performs
   *                      authentication, then the health check's
   *                      {@code ensureConnectionValidAfterAuthentication}
   *                      method will be invoked immediately after the bind
   *                      operation is processed (regardless of whether the bind
   *                      was successful or not).  And regardless of whether
   *                      this server set performs authentication, the
   *                      health check's {@code ensureNewConnectionValid}
   *                      method must be invoked on the connection to ensure
   *                      that it is valid immediately before it is returned.
   *
   * @return  An {@code LDAPConnection} object that is established to one of the
   *          servers in this server set.
   *
   * @throws  LDAPException  If it is not possible to establish a connection to
   *                         any of the servers in this server set.
   */
  @NotNull()
  public LDAPConnection getConnection(
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
         throws LDAPException
  {
    final LDAPConnection c = getConnection();

    if (healthCheck != null)
    {
      try
      {
        healthCheck.ensureNewConnectionValid(c);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        c.close();
        throw le;
      }
    }

    return c;
  }



  /**
   * Performs the appropriate bind, post-connect, and health check processing
   * for  the provided connection, in the provided order.  The processing
   * performed will include:
   * <OL>
   *   <LI>
   *     If the provided {@code postConnectProcessor} is not {@code null}, then
   *     invoke its {@code processPreAuthenticatedConnection} method on the
   *     provided connection.  If this method throws an {@code LDAPException},
   *     then it will propagated up to the caller of this method.
   *   </LI>
   *   <LI>
   *     If the provided {@code bindRequest} is not {@code null}, then
   *     authenticate the connection using that request.  If the provided
   *     {@code healthCheck} is also not {@code null}, then invoke its
   *     {@code ensureConnectionValidAfterAuthentication} method on the
   *     connection, even if the bind was not successful.  If the health check
   *     throws an {@code LDAPException}, then it will be propagated up to the
   *     caller of this method.  If there is no health check or if it did not
   *     throw an exception but the bind attempt did throw an exception, then
   *     propagate that exception instead.
   *   </LI>
   *   <LI>
   *     If the provided {@code postConnectProcessor} is not {@code null}, then
   *     invoke its {@code processPostAuthenticatedConnection} method on the
   *     provided connection.  If this method throws an {@code LDAPException},
   *     then it will propagated up to the caller of this method.
   *   </LI>
   *   <LI>
   *     If the provided {@code healthCheck} is not {@code null}, then invoke
   *     its {@code ensureNewConnectionValid} method on the provided connection.
   *     If this method throws an {@code LDAPException}, then it will be
   *     propagated up to the caller of this method.
   *   </LI>
   * </OL>
   *
   * @param  connection            The connection to be processed.  It must not
   *                               be {@code null}, and it must be established.
   *                               Note that if an {@code LDAPException} is
   *                               thrown by this method or anything that it
   *                               calls, then the connection will have been
   *                               closed before that exception has been
   *                               propagated up to the caller of this method.
   * @param  bindRequest           The bind request to use to authenticate the
   *                               connection.  It may be {@code null} if no
   *                               authentication should be performed.
   * @param  postConnectProcessor  The post-connect processor to invoke on the
   *                               provided connection.  It may be {@code null}
   *                               if no post-connect processing should be
   *                               performed.
   * @param  healthCheck           The health check to use to verify the health
   *                               of connection.  It may be {@code null} if no
   *                               health check processing should be performed.
   *
   * @throws  LDAPException  If a problem is encountered during any of the
   *                         processing performed by this method.  If an
   *                         exception is thrown, then the provided connection
   *                         will have been closed.
   */
  protected static void doBindPostConnectAndHealthCheckProcessing(
                 @NotNull final LDAPConnection connection,
                 @Nullable final BindRequest bindRequest,
                 @Nullable final PostConnectProcessor postConnectProcessor,
                 @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
            throws LDAPException
  {
    try
    {
      if (postConnectProcessor != null)
      {
        postConnectProcessor.processPreAuthenticatedConnection(connection);
      }

      if (bindRequest != null)
      {
        BindResult bindResult;
        LDAPException bindException = null;
        try
        {
          bindResult = connection.bind(bindRequest.duplicate());
        }
        catch (final LDAPException le)
        {
          Debug.debugException(le);
          bindException = le;
          bindResult = new BindResult(le);
        }

        if (healthCheck != null)
        {
          healthCheck.ensureConnectionValidAfterAuthentication(connection,
               bindResult);
        }

        if (bindException != null)
        {
          throw bindException;
        }
      }

      if (postConnectProcessor != null)
      {
        postConnectProcessor.processPostAuthenticatedConnection(connection);
      }

      if (healthCheck != null)
      {
        healthCheck.ensureNewConnectionValid(connection);
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      connection.closeWithoutUnbind();
      throw le;
    }
  }



  /**
   * Updates the provided connection to indicate that it was created by this
   * server set.
   *
   * @param  connection  The connection to be updated to indicate it was created
   *                     by this server set.
   */
  protected final void associateConnectionWithThisServerSet(
                            @NotNull final LDAPConnection connection)
  {
    if (connection != null)
    {
      connection.setServerSet(this);
    }
  }



  /**
   * Performs any processing that may be required when the provided connection
   * is closed.  This will only be invoked for connections created by this
   * server set, and only if the {@link #associateConnectionWithThisServerSet}
   * method was called on the connection when it was created by this server set.
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
  protected void handleConnectionClosed(
                      @NotNull final LDAPConnection connection,
                      @NotNull final String host, final int port,
                      @NotNull final DisconnectType disconnectType,
                      @Nullable final String message,
                      @Nullable final Throwable cause)
  {
    // No action is taken by default.
  }



  /**
   * Shuts down this server set and frees any resources associated with it.
   */
  public void shutDown()
  {
    // No implementation required by default.
  }



  /**
   * Retrieves a string representation of this server set.
   *
   * @return  A string representation of this server set.
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
   * Appends a string representation of this server set to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ServerSet(className=");
    buffer.append(getClass().getName());
    buffer.append(')');
  }
}
