/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.Serializable;

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DisconnectType;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides an LDAP connection pool health check implementation that
 * can determine whether a Ping Identity Directory Server instance is currently
 * in lockdown mode.  Any server found to be in lockdown mode will be considered
 * unavailable.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LockdownModeLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
       implements Serializable
{
  /**
   * The default maximum response time value in milliseconds, which is set to
   * 5,000 milliseconds or 5 seconds.
   */
  private static final long DEFAULT_MAX_RESPONSE_TIME_MILLIS = 5_000L;



  /**
   * The name of the attribute in the status health summary monitor entry that
   * will be used to determine whether the server is in lockdown mode.
   */
  @NotNull()
  private static final String IS_IN_LOCKDOWN_MODE_ATTRIBUTE_NAME =
       "is-in-lockdown-mode";



  /**
   * The DN of the status health summary monitor entry that will be examined.
   */
  @NotNull()
  private static final String STATUS_HEALTH_SUMMARY_MONITOR_ENTRY_DN =
       "cn=Status Health Summary,cn=monitor";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 11911667291461474L;



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
  private final long maxResponseTimeMillis;

  // The search request that will be used to retrieve the monitor entry.
  @NotNull private final SearchRequest searchRequest;



  /**
   * Creates a new instance of this LDAP connection pool health check with the
   * provided information.
   *
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
   * @param  maxResponseTimeMillis
   *              The maximum length of time, in milliseconds, to wait for the
   *              monitor entry to be retrieved.  If the monitor entry cannot be
   *              retrieved within this length of time, the health check will
   *              fail.  If the provided value is less than or equal to zero,
   *              then a default timeout of 5,000 milliseconds (5 seconds) will
   *              be used.
   */
  public LockdownModeLDAPConnectionPoolHealthCheck(
              final boolean invokeOnCreate,
              final boolean invokeAfterAuthentication,
              final boolean invokeOnCheckout,
              final boolean invokeOnRelease,
              final boolean invokeForBackgroundChecks,
              final boolean invokeOnException,
              final long maxResponseTimeMillis)
  {
    this.invokeOnCreate = invokeOnCreate;
    this.invokeAfterAuthentication = invokeAfterAuthentication;
    this.invokeOnCheckout = invokeOnCheckout;
    this.invokeOnRelease = invokeOnRelease;
    this.invokeForBackgroundChecks = invokeForBackgroundChecks;
    this.invokeOnException = invokeOnException;

    if (maxResponseTimeMillis > 0L)
    {
      this.maxResponseTimeMillis = maxResponseTimeMillis;
    }
    else
    {
      this.maxResponseTimeMillis = DEFAULT_MAX_RESPONSE_TIME_MILLIS;
    }

    int timeLimitSeconds = (int) (this.maxResponseTimeMillis / 1_000L);
    if ((this.maxResponseTimeMillis % 1_000L) != 0L)
    {
      timeLimitSeconds++;
    }

    searchRequest = new SearchRequest(STATUS_HEALTH_SUMMARY_MONITOR_ENTRY_DN,
         SearchScope.BASE, DereferencePolicy.NEVER, 1, timeLimitSeconds, false,
         Filter.createANDFilter(), IS_IN_LOCKDOWN_MODE_ATTRIBUTE_NAME);
    searchRequest.setResponseTimeoutMillis(this.maxResponseTimeMillis);
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
      checkForLockdownMode(connection);
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
      checkForLockdownMode(connection);
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
      checkForLockdownMode(connection);
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
      checkForLockdownMode(connection);
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
      checkForLockdownMode(connection);
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
      checkForLockdownMode(connection);
    }
  }



  /**
   * Indicates whether this health check will check for lockdown mode whenever a
   * new connection is created.
   *
   * @return  {@code true} if this health check will check for lockdown mode
   *          whenever a new connection is created, or {@code false} if not.
   */
  public boolean invokeOnCreate()
  {
    return invokeOnCreate;
  }



  /**
   * Indicates whether this health check will check for lockdown mode after a
   * connection has been authenticated, including after authenticating a
   * newly-created connection, as well as after calls to the connection pool's
   * {@code bindAndRevertAuthentication} and
   * {@code releaseAndReAuthenticateConnection} methods.
   *
   * @return  {@code true} if this health check will check for lockdown mode
   *          whenever a connection has been authenticated, or {@code false} if
   *          not.
   */
  public boolean invokeAfterAuthentication()
  {
    return invokeAfterAuthentication;
  }



  /**
   * Indicates whether this health check will check for lockdown mode whenever a
   * connection is to be checked out for use.
   *
   * @return  {@code true} if this health check will check for lockdown mode
   *          whenever a connection is to be checked out, or {@code false} if
   *          not.
   */
  public boolean invokeOnCheckout()
  {
    return invokeOnCheckout;
  }



  /**
   * Indicates whether this health check will check for lockdown mode whenever a
   * connection is to be released back to the pool.
   *
   * @return  {@code true} if this health check will check for lockdown mode
   *          whenever a connection is to be released, or {@code false} if not.
   */
  public boolean invokeOnRelease()
  {
    return invokeOnRelease;
  }



  /**
   * Indicates whether this health check will check for lockdown mode during
   * periodic background health checks.
   *
   * @return  {@code true} if this health check will check for lockdown mode
   *          during periodic background health checks, or {@code false} if not.
   */
  public boolean invokeForBackgroundChecks()
  {
    return invokeForBackgroundChecks;
  }



  /**
   * Indicates whether this health check will check for lockdown mode if an
   * exception is caught while processing an operation on a connection.
   *
   * @return  {@code true} if this health check will check for lockdown mode
   *          whenever an exception is caught, or {@code false} if not.
   */
  public boolean invokeOnException()
  {
    return invokeOnException;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that this health
   * check should wait for the target monitor entry to be returned.
   *
   * @return  The maximum length of time in milliseconds that this health check
   *          should wait for the target monitor entry to be returned.
   */
  public long getMaxResponseTimeMillis()
  {
    return maxResponseTimeMillis;
  }



  /**
   * Retrieves the status health summary monitor entry and uses it to determine
   * whether the server is currently in lockdown mode.  If the server is in
   * lockdown mode, or if a problem occurs while attempting to amek the
   * determination, then an exception will be thrown.
   *
   * @param  conn  The connection to be checked.
   *
   * @throws  LDAPException  If a problem occurs while trying to retrieve the
   *                         target monitor entry, if it cannot be retrieved in
   *                         an acceptable length of time, or if the server
   *                         reports that it is in lockdown mode.
   */
  private void checkForLockdownMode(@NotNull final LDAPConnection conn)
          throws LDAPException
  {
    final SearchResultEntry monitorEntry;
    try
    {
      monitorEntry = conn.searchForEntry(searchRequest.duplicate());
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);

      final String message =
           ERR_LOCKDOWN_MODE_HEALTH_CHECK_ERROR_GETTING_MONITOR_ENTRY.get(
                STATUS_HEALTH_SUMMARY_MONITOR_ENTRY_DN,  conn.getHostPort(),
                StaticUtils.getExceptionMessage(e));
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           e);
      throw new LDAPException(e.getResultCode(), message, e);
    }


    if (monitorEntry == null)
    {
      final String message =
           ERR_LOCKDOWN_MODE_HEALTH_CHECK_NO_MONITOR_ENTRY.get(
                STATUS_HEALTH_SUMMARY_MONITOR_ENTRY_DN, conn.getHostPort());
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           null);
      throw new LDAPException(ResultCode.NO_RESULTS_RETURNED, message);
    }


    final Boolean isInLockdownMode = monitorEntry.getAttributeValueAsBoolean(
         IS_IN_LOCKDOWN_MODE_ATTRIBUTE_NAME);
    if (isInLockdownMode == null)
    {
      final String message =
           ERR_LOCKDOWN_MODE_HEALTH_CHECK_NO_MONITOR_ATTR.get(
                STATUS_HEALTH_SUMMARY_MONITOR_ENTRY_DN, conn.getHostPort(),
                IS_IN_LOCKDOWN_MODE_ATTRIBUTE_NAME);
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           null);
      throw new LDAPException(ResultCode.NO_SUCH_ATTRIBUTE, message);
    }
    else if (Boolean.TRUE.equals(isInLockdownMode))
    {
      final String message =
           ERR_LOCKDOWN_MODE_HEALTH_CHECK_IS_IN_LOCKDOWN_MODE.get(
                conn.getHostPort());
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           null);
      throw new LDAPException(ResultCode.UNAVAILABLE, message);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LockdownMOdeLDAPConnectionPoolHealthCheck(invokeOnCreate=");
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
    buffer.append(", maxResponseTimeMillis=");
    buffer.append(maxResponseTimeMillis);
    buffer.append(')');
  }
}
