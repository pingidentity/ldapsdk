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



import java.io.Serializable;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an LDAP connection pool health check implementation that
 * may be used to check the health of the associated server by verifying that a
 * specified entry can be retrieved in an acceptable period of time.  If the
 * entry cannot be retrieved (either because it does not exist, or because an
 * error occurs while attempting to retrieve it), or if it takes too long to
 * retrieve the entry, then the associated connection will be classified as
 * unavailable.
 * <BR><BR>
 * It is possible to control under which conditions an attempt should be made to
 * retrieve the target entry, and also to specify a maximum acceptable response
 * time.  For best results, the target entry should be available to be retrieved
 * by a client with any authentication state.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetEntryLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
       implements Serializable
{
  /**
   * The default maximum response time value in milliseconds, which is set to
   * 30,000 milliseconds or 30 seconds.
   */
  private static final long DEFAULT_MAX_RESPONSE_TIME = 30_000L;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3400259782503254645L;



  // Indicates whether to invoke the test after a connection has been
  // authenticated.
  private final boolean invokeAfterAuthentication;

  // Indicates whether to invoke the test during background health checks.
  private final boolean invokeForBackgroundChecks;

  // Indicates whether to invoke the test when checking out a connection.
  private final boolean invokeOnCheckout;

  // Indicates whether to invoke the test when creating a new connection.
  private final boolean invokeOnCreate;

  // Indicates whether to invoke the test whenever an exception is encountered
  // when using the connection.
  private final boolean invokeOnException;

  // Indicates whether to invoke the test when releasing a connection.
  private final boolean invokeOnRelease;

  // The maximum response time value in milliseconds.
  private final long maxResponseTime;

  // The search request to send to the server.
  @NotNull private final SearchRequest searchRequest;

  // The DN of the entry to retrieve.
  @NotNull private final String entryDN;



  /**
   * Creates a new instance of this get entry LDAP connection pool health check.
   *
   * @param  entryDN                    The DN of the entry to retrieve from
   *                                    the target server.  If this is
   *                                    {@code null}, then the server's root DSE
   *                                    will be used.
   * @param  maxResponseTime            The maximum length of time in
   *                                    milliseconds that should be allowed when
   *                                    attempting to retrieve the entry.  If
   *                                    the provided value is less than or equal
   *                                    to zero, then the default value of 30000
   *                                    milliseconds (30 seconds) will be used.
   * @param  invokeOnCreate             Indicates whether to test for the
   *                                    existence of the target entry whenever a
   *                                    new connection is created for use in the
   *                                    pool.  Note that this check will be
   *                                    performed immediately after the
   *                                    connection has been established and
   *                                    before any attempt has been made to
   *                                    authenticate that connection.
   * @param  invokeOnCheckout           Indicates whether to test for the
   *                                    existence of the target entry
   *                                    immediately before a connection is
   *                                    checked out of the pool.
   * @param  invokeOnRelease            Indicates whether to test for the
   *                                    existence of the target entry
   *                                    immediately after a connection has been
   *                                    released back to the pool.
   * @param  invokeForBackgroundChecks  Indicates whether to test for the
   *                                    existence of the target entry during
   *                                    periodic background health checks.
   * @param  invokeOnException          Indicates whether to test for the
   *                                    existence of the target entry if an
   *                                    exception is encountered when using the
   *                                    connection.
   */
  public GetEntryLDAPConnectionPoolHealthCheck(@NotNull final String entryDN,
              final long maxResponseTime, final boolean invokeOnCreate,
              final boolean invokeOnCheckout, final boolean invokeOnRelease,
              final boolean invokeForBackgroundChecks,
              final boolean invokeOnException)
  {
    this(entryDN, maxResponseTime, invokeOnCreate, false, invokeOnCheckout,
         invokeOnRelease, invokeForBackgroundChecks, invokeOnException);
  }



  /**
   * Creates a new instance of this get entry LDAP connection pool health check.
   *
   * @param  entryDN
   *              The DN of the entry to retrieve from the target server.  If
   *              this is {@code null}, then the server's root DSE will be used.
   * @param  maxResponseTime
   *              The maximum length of time in milliseconds that should be
   *              allowed when attempting to retrieve the entry.  If the
   *              provided value is less than or equal to zero, then the
   *              default value of 30000 milliseconds (30 seconds) will be used.
   * @param  invokeOnCreate
   *              Indicates whether to test for the existence of the target
   *              entry whenever a new connection is created for use in the
   *              pool.  Note that this check will be performed immediately
   *              after the connection has been established and before any
   *              attempt has been made to authenticate that connection.
   * @param  invokeAfterAuthentication
   *              Indicates whether to test for the existence of the target
   *              entry immediately after a connection has been authenticated.
   *              This includes immediately after a newly-created connection
   *              has been authenticated, after a call to the connection pool's
   *              {@code bindAndRevertAuthentication} method, and after a call
   *              to the connection pool's
   *              {@code releaseAndReAuthenticateConnection} method.  Note that
   *              even if this is {@code true}, the health check will only be
   *              performed if the provided bind result indicates that the bind
   *              was successful.
   * @param  invokeOnCheckout
   *              Indicates whether to test for the existence of the target
   *              entry immediately before a connection is checked out of the
   *              pool.
   * @param  invokeOnRelease
   *              Indicates whether to test for the existence of the target
   *              entry immediately after a connection has been released back
   *              to the pool.
   * @param  invokeForBackgroundChecks
   *              Indicates whether to test for the existence of the target
   *              entry during periodic background health checks.
   * @param  invokeOnException
   *              Indicates whether to test for the existence of the target
   *              entry if an exception is encountered when using the
   *              connection.
   */
  public GetEntryLDAPConnectionPoolHealthCheck(@NotNull final String entryDN,
              final long maxResponseTime, final boolean invokeOnCreate,
              final boolean invokeAfterAuthentication,
              final boolean invokeOnCheckout, final boolean invokeOnRelease,
              final boolean invokeForBackgroundChecks,
              final boolean invokeOnException)
  {
    this.invokeOnCreate            = invokeOnCreate;
    this.invokeAfterAuthentication = invokeAfterAuthentication;
    this.invokeOnCheckout          = invokeOnCheckout;
    this.invokeOnRelease           = invokeOnRelease;
    this.invokeForBackgroundChecks = invokeForBackgroundChecks;
    this.invokeOnException         = invokeOnException;

    if (entryDN == null)
    {
      this.entryDN = "";
    }
    else
    {
      this.entryDN = entryDN;
    }

    if (maxResponseTime > 0L)
    {
      this.maxResponseTime = maxResponseTime;
    }
    else
    {
      this.maxResponseTime = DEFAULT_MAX_RESPONSE_TIME;
    }

    searchRequest = new SearchRequest(this.entryDN, SearchScope.BASE,
         Filter.createPresenceFilter("objectClass"), "1.1");
    searchRequest.setResponseTimeoutMillis(this.maxResponseTime);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureNewConnectionValid(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeOnCreate)
    {
      getEntry(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidAfterAuthentication(
                   @NotNull final LDAPConnection connection,
                   @NotNull final BindResult bindResult)
         throws LDAPException
  {
    if (invokeAfterAuthentication &&
         (bindResult.getResultCode() == ResultCode.SUCCESS))
    {
      getEntry(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForCheckout(
                   @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeOnCheckout)
    {
      getEntry(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForRelease(
                   @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeOnRelease)
    {
      getEntry(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForContinuedUse(
                   @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    if (invokeForBackgroundChecks)
    {
      getEntry(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidAfterException(
                   @NotNull final LDAPConnection connection,
                   @NotNull final LDAPException exception)
         throws LDAPException
  {
    if (invokeOnException &&
         (! ResultCode.isConnectionUsable(exception.getResultCode())))
    {
      getEntry(connection);
    }
  }



  /**
   * Retrieves the DN of the entry that will be retrieved when performing the
   * health checks.
   *
   * @return  The DN of the entry that will be retrieved when performing the
   *          health checks.
   */
  @NotNull()
  public String getEntryDN()
  {
    return entryDN;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that this health
   * check should wait for the entry to be returned.
   *
   * @return  The maximum length of time in milliseconds that this health check
   *          should wait for the entry to be returned.
   */
  public long getMaxResponseTimeMillis()
  {
    return maxResponseTime;
  }



  /**
   * Indicates whether this health check will test for the existence of the
   * target entry whenever a new connection is created.
   *
   * @return  {@code true} if this health check will test for the existence of
   *          the target entry whenever a new connection is created, or
   *          {@code false} if not.
   */
  public boolean invokeOnCreate()
  {
    return invokeOnCreate;
  }



  /**
   * Indicates whether this health check will test for the existence of the
   * target entry after a connection has been authenticated, including after
   * authenticating a newly-created connection, as well as after calls to the
   * connection pool's {@code bindAndRevertAuthentication} and
   * {@code releaseAndReAuthenticateConnection} methods.
   *
   * @return  {@code true} if this health check will test for the existence of
   *          the target entry whenever a connection has been authenticated, or
   *          {@code false} if not.
   */
  public boolean invokeAfterAuthentication()
  {
    return invokeAfterAuthentication;
  }



  /**
   * Indicates whether this health check will test for the existence of the
   * target entry whenever a connection is to be checked out for use.
   *
   * @return  {@code true} if this health check will test for the existence of
   *          the target entry whenever a connection is to be checked out, or
   *          {@code false} if not.
   */
  public boolean invokeOnCheckout()
  {
    return invokeOnCheckout;
  }



  /**
   * Indicates whether this health check will test for the existence of the
   * target entry whenever a connection is to be released back to the pool.
   *
   * @return  {@code true} if this health check will test for the existence of
   *          the target entry whenever a connection is to be released, or
   *          {@code false} if not.
   */
  public boolean invokeOnRelease()
  {
    return invokeOnRelease;
  }



  /**
   * Indicates whether this health check will test for the existence of the
   * target entry during periodic background health checks.
   *
   * @return  {@code true} if this health check will test for the existence of
   *          the target entry during periodic background health checks, or
   *          {@code false} if not.
   */
  public boolean invokeForBackgroundChecks()
  {
    return invokeForBackgroundChecks;
  }



  /**
   * Indicates whether this health check will test for the existence of the
   * target entry if an exception is caught while processing an operation on a
   * connection.
   *
   * @return  {@code true} if this health check will test for the existence of
   *          the target entry whenever an exception is caught, or {@code false}
   *          if not.
   */
  public boolean invokeOnException()
  {
    return invokeOnException;
  }



  /**
   * Attempts to retrieve the target entry.  If the attempt fails, or if the
   * connection takes too long then an exception will be thrown.
   *
   * @param  conn  The connection to be checked.
   *
   * @throws  LDAPException  If a problem occurs while trying to retrieve the
   *                         entry, or if it cannot be retrieved in an
   *                         acceptable length of time.
   */
  private void getEntry(@NotNull final LDAPConnection conn)
          throws LDAPException
  {
    try
    {
      final SearchResult result = conn.search(searchRequest.duplicate());
      if (result.getEntryCount() != 1)
      {
        throw new LDAPException(ResultCode.NO_RESULTS_RETURNED,
             ERR_GET_ENTRY_HEALTH_CHECK_NO_ENTRY_RETURNED.get());
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      final String msg = ERR_GET_ENTRY_HEALTH_CHECK_FAILURE.get(entryDN,
           StaticUtils.getExceptionMessage(e));

      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, msg, e);
      throw new LDAPException(ResultCode.SERVER_DOWN, msg, e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetEntryLDAPConnectionPoolHealthCheck(entryDN='");
    buffer.append(entryDN);
    buffer.append("', maxResponseTimeMillis=");
    buffer.append(maxResponseTime);
    buffer.append(", invokeOnCreate=");
    buffer.append(invokeOnCreate);
    buffer.append(", invokeAfterAuthentication=");
    buffer.append(invokeAfterAuthentication);
    buffer.append(", invokeOnCheckout=");
    buffer.append(invokeOnCheckout);
    buffer.append(", invokeOnRelease=");
    buffer.append(invokeOnRelease);
    buffer.append(", invokeForBackgroundChecks=");
    buffer.append(invokeForBackgroundChecks);
    buffer.append(", invokeOnException=");
    buffer.append(invokeOnException);
    buffer.append(')');
  }
}
