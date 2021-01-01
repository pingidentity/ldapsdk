/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an API that may be used to determine whether connections
 * associated with a connection pool are valid and suitable for use.  It
 * provides the ability to check the validity of a connection at the following
 * times:
 * <UL>
 *   <LI>Whenever a new connection is created for use in the pool, the
 *       {@link #ensureNewConnectionValid(LDAPConnection)} method will be called
 *       before making that connection available.  The default implementation
 *       provided in this class does not perform any kind of processing, but
 *       subclasses may override this behavior if desired.</LI>
 *   <LI>Whenever a connection is checked out from the pool (including
 *       connections checked out internally for operations performed in the
 *       pool), the {@link #ensureConnectionValidForCheckout(LDAPConnection)}
 *       method will be called.  The default implementation provided in this
 *       class does not perform any kind of processing, but subclasses may
 *       override this behavior if desired.</LI>
 *   <LI>Whenever a connection is released back to the pool (including
 *       connections checked out internally for operations performed in the
 *       pool), the {@link #ensureConnectionValidForRelease(LDAPConnection)}
 *       method will be called.  The default implementation provided in this
 *       class does not perform any kind of processing, but subclasses may
 *       override this behavior if desired.</LI>
 *   <LI>The {@link #ensureConnectionValidForContinuedUse(LDAPConnection)}
 *       method will be invoked periodically by a background thread created by
 *       the connection pool to determine whether available connections within
 *       the pool are still valid.  The default implementation provided in this
 *       class does not perform any kind of processing, but subclasses may
 *       override this behavior if desired.</LI>
 *   <LI>The {@link #ensureConnectionValidAfterException} method may be invoked
 *       if an exception is caught while processing an operation with a
 *       connection that is part of a connection pool.  The default
 *       implementation provided in this class only examines the result code of
 *       the provided exception and uses the
 *       {@link ResultCode#isConnectionUsable(ResultCode)} method to make the
 *       determination, but subclasses may override this behavior if
 *       desired.</LI>
 * </UL>
 * Note that health check implementations should be designed so that they are
 * suitable for use with connections having any authentication state.  The
 * {@link #ensureNewConnectionValid(LDAPConnection)} method will be invoked on
 * unauthenticated connections, and the remaining health check methods will be
 * invoked using whatever credentials are assigned to connections in the
 * associated connection pool.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public class LDAPConnectionPoolHealthCheck
{
  /**
   * Creates a new instance of this LDAP connection pool health check.
   */
  public LDAPConnectionPoolHealthCheck()
  {
    // No implementation is required.
  }



  /**
   * Performs any desired processing to determine whether the provided new
   * connection is available to be checked out and used for processing
   * operations.  This method will be invoked by either {@link ServerSet} used
   * by the connection pool (if it supports enhanced health checking) or by the
   * connection pool itself at the time that a new connection is created.  No
   * authentication will have been performed on this connection at the time the
   * health check is invoked.
   *
   * @param  connection  The connection to be examined.
   *
   * @throws  LDAPException  If a problem is detected that suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureNewConnectionValid(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    // No processing is performed in this default implementation.
  }



  /**
   * Performs any desired processing to determine whether the provided
   * connection is valid after processing a bind operation with the provided
   * result.
   * <BR><BR>
   * This method will be invoked under the following circumstances:
   * <UL>
   *   <LI>
   *     If you create a connection pool with a {@link ServerSet} and a
   *     non-{@code null} {@link BindRequest}, then this health check method
   *     will be invoked for every new connection created by the pool after
   *     processing that {@code BindRequest} on the connection.  If you create a
   *     connection pool with a {@code ServerSet} but a {@code null}
   *     {@code BindRequest}, then no authentication will be attempted (and
   *     therefore this health check method will not be invoked for)
   *     newly-created connections.
   *   </LI>
   *   <LI>
   *     If you create a connection pool with an {@link LDAPConnection} after
   *     having performed a bind operation on that connection, then every new
   *     connection created by the pool will attempt to perform the same type of
   *     bind operation and this health check method will be invoked after that
   *     bind attempt has completed.  If you create a connection pool with an
   *     {@code LDAPConnection} that has not been authenticated, then no
   *     authentication will be attempted (and therefore this health check
   *     method will not be invoked for) newly-created connections.
   *   </LI>
   *   <LI>
   *     If you call a connection pool's {@code bindAndRevertAuthentication}
   *     method, then this health check method will be called after the second
   *     bind operation (the one used to revert authentication) has completed.
   *     In this case, this health check method will be called even if the
   *     connection pool was created with a {@code null} {@code BindRequest} or
   *     with an unauthenticated {@code LDAPConnection}.  In that case, the
   *     bind operation used to revert authentication will be a
   *     {@link SimpleBindRequest} with an empty DN and password.
   *   </LI>
   *   <LI>
   *     If you call a connection pool's
   *     {@code releaseAndReAuthenticateConnection} method, then this health
   *     check method will be called after the bind operation has completed.  As
   *     with {@code bindAndRevertAuthentication}, this health check method will
   *     be called even if the connection pool was created with a {@code null}
   *     {@code BindRequest} or with an unauthenticated {@code LDAPConnection}.
   *   </LI>
   * </UL>
   * <BR><BR>
   * Note that this health check method may be invoked even if the bind
   * attempt was not successful.  This is useful because it allows the health
   * check to intercept a failed authentication attempt and differentiate it
   * from other types of failures in the course of trying to create or check out
   * a connection.  In the event that it is invoked with a {@code BindResult}
   * that has a result code other than {@link ResultCode#SUCCESS}, if this
   * method throws an exception then that exception will be propagated to the
   * caller.  If this method does not throw an exception when provided with a
   * non-{@code SUCCESS} result, then the connection pool itself will throw an
   * exception using the information in the bind result.
   *
   * @param  connection  The connection to be examined.
   * @param  bindResult  The bind result obtained from the authentication
   *                     process.
   *
   * @throws  LDAPException  If a problem is detected that suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidAfterAuthentication(
                   @NotNull final LDAPConnection connection,
                   @NotNull final BindResult bindResult)
         throws LDAPException
  {
    // No processing is performed in this default implementation.
  }



  /**
   * Performs any desired processing to determine whether the provided
   * connection is available to be checked out and used for processing
   * operations.  This method will be invoked by the
   * {@link LDAPConnectionPool#getConnection()} method before handing out a
   * connection.  This method should return normally if the connection is
   * believed to be valid, or should throw an {@code LDAPException} if a problem
   * is detected.
   *
   * @param  connection  The connection to be examined.
   *
   * @throws  LDAPException  If a problem is detected that suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidForCheckout(
                    @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    // No processing is performed in this default implementation.
  }



  /**
   * Performs any desired processing to determine whether the provided
   * connection is valid and should be released back to the pool to be used for
   * processing other operations.  This method will be invoked by the
   * {@link LDAPConnectionPool#releaseConnection(LDAPConnection)} method before
   * making the connection available for use in processing other operations.
   * This method should return normally if the connection is believed to be
   * valid, or should throw an {@code LDAPException} if a problem is detected.
   *
   * @param  connection  The connection to be examined.
   *
   * @throws  LDAPException  If a problem is detected that suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidForRelease(
                   @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    // No processing is performed in this default implementation.
  }



  /**
   * Performs any desired processing to determine whether the provided
   * connection is valid and should continue to be made available for
   * processing operations.  This method will be periodically invoked by a
   * background thread used to test availability of connections within the pool.
   * This method should return normally if the connection is believed to be
   * valid, or should throw an {@code LDAPException} if a problem is detected.
   *
   * @param  connection  The connection to be examined.
   *
   * @throws  LDAPException  If a problem is detected that suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidForContinuedUse(
                   @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    // No processing is performed in this default implementation.
  }



  /**
   * Performs any processing that may be appropriate on an ongoing basis for the
   * connection pool that is not related to the pool itself rather than any
   * individual connection.  This method will be invoked by the pool's
   * {@link LDAPConnectionPoolHealthCheckThread} at an interval specified by the
   * pool's {@link AbstractConnectionPool#getHealthCheckIntervalMillis()}
   * method.  This method will be invoked after all other periodic processing
   * (for example, after calling {@link #ensureConnectionValidForContinuedUse}
   * on each available connection, if appropriate for the pool implementation)
   * has been performed during the interval.
   *
   * @param  pool  The connection pool on which to perform maintenance.
   */
  public void performPoolMaintenance(@NotNull final AbstractConnectionPool pool)
  {
    // No processing is performed in this default implementation.
  }



  /**
   * Indicates whether the provided connection may still be considered valid
   * after an attempt to process an operation yielded the given exception.  This
   * method will be invoked by the
   * {@link LDAPConnectionPool#releaseConnectionAfterException} method, and it
   * may also be manually invoked by external callers if an exception is
   * encountered while processing an operation on a connection checked out from
   * the pool.  It may make a determination based solely on the provided
   * exception, or it may also attempt to use the provided connection to further
   * test its validity.  This method should return normally if the connection is
   * believed to be valid, or should throw an {@code LDAPException} if a problem
   * is detected.
   *
   * @param  connection  The connection to be examined.
   * @param  exception   The exception that was caught while processing an
   *                     operation on the connection.
   *
   * @throws  LDAPException  If a problem is detected that suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidAfterException(
                   @NotNull final LDAPConnection connection,
                   @NotNull final LDAPException exception)
         throws LDAPException
  {
    if (! ResultCode.isConnectionUsable(exception.getResultCode()))
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_POOL_HEALTH_CHECK_CONN_INVALID_AFTER_EXCEPTION.get(
                StaticUtils.getExceptionMessage(exception)),
           exception);
    }
  }



  /**
   * Retrieves a string representation of this LDAP connection pool health
   * check.
   *
   * @return  A string representation of this LDAP connection pool health check.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP connection pool health check
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionPoolHealthCheck()");
  }
}
