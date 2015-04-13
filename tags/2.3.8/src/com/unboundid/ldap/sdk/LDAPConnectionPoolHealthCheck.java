/*
 * Copyright 2009-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2014 UnboundID Corp.
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.StaticUtils.*;



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
 *       connection which is part of a connection pool.  The default
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
   * connection pool itself at the time that a new connection is created.
   *
   * @param  connection  The connection to be examined.
   *
   * @throws  LDAPException  If a problem is detected which suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureNewConnectionValid(final LDAPConnection connection)
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
   * @throws  LDAPException  If a problem is detected which suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidForCheckout(final LDAPConnection connection)
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
   * @throws  LDAPException  If a problem is detected which suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidForRelease(final LDAPConnection connection)
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
   * @throws  LDAPException  If a problem is detected which suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidForContinuedUse(
                   final LDAPConnection connection)
         throws LDAPException
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
   * @throws  LDAPException  If a problem is detected which suggests that the
   *                         provided connection is not suitable for use.
   */
  public void ensureConnectionValidAfterException(
                   final LDAPConnection connection,
                   final LDAPException exception)
         throws LDAPException
  {
    if (! ResultCode.isConnectionUsable(exception.getResultCode()))
    {
      throw new LDAPException(ResultCode.SERVER_DOWN,
           ERR_POOL_HEALTH_CHECK_CONN_INVALID_AFTER_EXCEPTION.get(
                getExceptionMessage(exception)),
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionPoolHealthCheck()");
  }
}
