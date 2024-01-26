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
import java.util.Date;

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
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides an LDAP connection pool health check implementation that
 * can be used to examine the replication backlog (reflecting changes that have
 * been made in other replicas but have not yet been applied in the local
 * instance) of a Ping Identity Directory Server instance.  It can consider both
 * the number of changes in the replication backlog and the age of the oldest
 * outstanding change.
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
public final class ReplicationBacklogLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
       implements Serializable
{
  /**
   * The default maximum response time value in milliseconds, which is set to
   * 5,000 milliseconds or 5 seconds.
   */
  private static final long DEFAULT_MAX_RESPONSE_TIME_MILLIS = 5_000L;



  /**
   * The name of the attribute used to specify the base DN for the target
   * replication domain.
   */
  @NotNull()
  private static final String BASE_DN_ATTRIBUTE_NAME = "base-dn";



  /**
   * The name of the attribute used to specify the number of changes currently
   * in the replication backlog.
   */
  @NotNull()
  private static final String BACKLOG_COUNT_ATTRIBUTE_NAME =
       "replication-backlog";



  /**
   * The name of the attribute used to specify the time that the oldest change
   * in the replication backlog was first applied to another instance.
   */
  @NotNull()
  private static final String OLDEST_BACKLOG_CHANGE_TIME_ATTRIBUTE_NAME =
       "age-of-oldest-backlog-change";



  /**
   * The name of the object class used for replica monitor entries.
   */
  @NotNull()
  private static final String REPLICA_MONITOR_ENTRY_OBJECT_CLASS_NAME =
       "ds-replica-monitor-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2201740505566813382L;



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

  // The maximum allowed age, in milliseconds, of any change in the replication
  // backlog.
  @Nullable private final Long maxAllowedBacklogAgeMillis;

  // The maximum allowed number of changes iun the replication backlog.
  @Nullable private final Long maxAllowedBacklogCount;

  // The maximum response time value in milliseconds.
  private final long maxResponseTimeMillis;

  // The search request that will be used to retrieve the monitor entry.
  @NotNull private final SearchRequest searchRequest;

  // The base DN for the target replication domain.
  @NotNull private final String baseDN;



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
   * @param  baseDN
   *              The base DN for the target replication domain.  This is
   *              typically the base DN for the backend containing the
   *              replicated data.  It must not be {@code null}.
   * @param  maxAllowedBacklogCount
   *              The maximum number of changes that may be contained in the
   *              replication backlog before a server will be considered
   *              unavailable.  This may be {@code null} if the backlog is to
   *              be evaluated only based on the age of the oldest outstanding
   *              change, but at least one of {@code maxAllowedBacklogCount} and
   *              {@code maxAllowedBacklogAgeMillis} must be specified.
   * @param  maxAllowedBacklogAgeMillis
   *              The maximum length of time, in milliseconds, that a change may
   *              be contained in the replication backlog before a server will
   *              be considered unavailable.  This may be {@code null} if the
   *              backlog is to be evaluated only based on the number of
   *              outstanding changes, but at least one of
   *              {@code maxAllowedBacklogCount} and
   *              {@code maxAllowedBacklogAgeMillis} must be specified.
   */
  public ReplicationBacklogLDAPConnectionPoolHealthCheck(
              final boolean invokeOnCreate,
              final boolean invokeAfterAuthentication,
              final boolean invokeOnCheckout,
              final boolean invokeOnRelease,
              final boolean invokeForBackgroundChecks,
              final boolean invokeOnException,
              final long maxResponseTimeMillis,
              @NotNull final String baseDN,
              @Nullable final Long maxAllowedBacklogCount,
              @Nullable final Long maxAllowedBacklogAgeMillis)
  {
    Validator.ensureNotNullWithMessage(baseDN,
         "ReplicationBacklogLDAPConnectionPoolHealthCheck.baseDN must not be " +
              "null.");

    if (maxAllowedBacklogCount == null)
    {
      if (maxAllowedBacklogAgeMillis == null)
      {
        Validator.violation("At least one of maxAllowedBacklogCount or " +
             "maxAllowedBacklogAgeMillis must be non-null for the " +
             "ReplicationBacklogLDAPConnectionPoolHealthCheck");
      }
    }
    else
    {
      Validator.ensureTrue((maxAllowedBacklogCount > 0L),
           "If specified, ReplicationBacklogLDAPConnectionPoolHealthCheck." +
                "maxAllowedBacklogCount must be greater than zero.");
    }

    if (maxAllowedBacklogAgeMillis != null)
    {
      Validator.ensureTrue((maxAllowedBacklogAgeMillis > 0L),
           "If specified, ReplicationBacklogLDAPConnectionPoolHealthCheck." +
                "maxAllowedBacklogAgeMillis must be greater than zero.");
    }

    this.invokeOnCreate = invokeOnCreate;
    this.invokeAfterAuthentication = invokeAfterAuthentication;
    this.invokeOnCheckout = invokeOnCheckout;
    this.invokeOnRelease = invokeOnRelease;
    this.invokeForBackgroundChecks = invokeForBackgroundChecks;
    this.invokeOnException = invokeOnException;
    this.baseDN = baseDN;
    this.maxAllowedBacklogCount = maxAllowedBacklogCount;
    this.maxAllowedBacklogAgeMillis = maxAllowedBacklogAgeMillis;

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

    final Filter filter = Filter.createANDFilter(
         Filter.createEqualityFilter("objectClass",
              REPLICA_MONITOR_ENTRY_OBJECT_CLASS_NAME),
         Filter.createEqualityFilter(BASE_DN_ATTRIBUTE_NAME, baseDN));
    searchRequest = new SearchRequest("cn=monitor", SearchScope.SUB,
         DereferencePolicy.NEVER, 1, timeLimitSeconds, false, filter,
         BACKLOG_COUNT_ATTRIBUTE_NAME,
         OLDEST_BACKLOG_CHANGE_TIME_ATTRIBUTE_NAME);
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
      checkReplicationBacklog(connection);
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
      checkReplicationBacklog(connection);
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
      checkReplicationBacklog(connection);
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
      checkReplicationBacklog(connection);
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
      checkReplicationBacklog(connection);
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
      checkReplicationBacklog(connection);
    }
  }



  /**
   * Indicates whether this health check will check the replication backlog
   * whenever a new connection is created.
   *
   * @return  {@code true} if this health check will check the replication
   *          backlog whenever a new connection is created, or {@code false} if
   *          not.
   */
  public boolean invokeOnCreate()
  {
    return invokeOnCreate;
  }



  /**
   * Indicates whether this health check will check the replication backlog
   * after a connection has been authenticated, including after authenticating a
   * newly-created connection, as well as after calls to the connection pool's
   * {@code bindAndRevertAuthentication} and
   * {@code releaseAndReAuthenticateConnection} methods.
   *
   * @return  {@code true} if this health check will check the replication
   *          backlog whenever a connection has been authenticated, or
   *          {@code false} if not.
   */
  public boolean invokeAfterAuthentication()
  {
    return invokeAfterAuthentication;
  }



  /**
   * Indicates whether this health check will check the replication backlog
   * whenever a connection is to be checked out for use.
   *
   * @return  {@code true} if this health check will check the replication
   *          backlog whenever a connection is to be checked out, or
   *          {@code false} if not.
   */
  public boolean invokeOnCheckout()
  {
    return invokeOnCheckout;
  }



  /**
   * Indicates whether this health check will check the replication backlog
   * whenever a connection is to be released back to the pool.
   *
   * @return  {@code true} if this health check will check the replication
   *          backlog whenever a connection is to be released, or {@code false}
   *          if not.
   */
  public boolean invokeOnRelease()
  {
    return invokeOnRelease;
  }



  /**
   * Indicates whether this health check will check the replication backlog
   * during periodic background health checks.
   *
   * @return  {@code true} if this health check will check the replication
   *          backlog during periodic background health checks, or {@code false}
   *          if not.
   */
  public boolean invokeForBackgroundChecks()
  {
    return invokeForBackgroundChecks;
  }



  /**
   * Indicates whether this health check will check the replication backlog if
   * an exception is caught while processing an operation on a connection.
   *
   * @return  {@code true} if this health check will check the replication
   *          backlog whenever an exception is caught, or {@code false} if not.
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
   * Retrieves the base DN for the target replication domain.
   *
   * @return  The base DN for the target replication domain.
   */
  @NotNull()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the maximum number of changes that may be contained in the
   * replication backlog before a server will be considered unavailable.
   *
   * @return  The maximum number of changes that may be contained in the
   *          replication backlog before a server will be considered
   *          unavailable, or {@code null} if the backlog will be evaluated only
   *          based on the age of the oldest outstanding change.
   */
  @Nullable()
  public Long getMaxAllowedBacklogCount()
  {
    return maxAllowedBacklogCount;
  }



  /**
   * Retrieves the maximum length of time, in milliseconds, that a change may be
   * contained in the replication backlog before a server will be considered
   * unavailable.
   *
   * @return  The maximum length of time, in milliseconds, that a change may be
   *          contained in the replication backlog before a server will be
   *          considered unavailable, or {@code null} if the backlog will be
   *          evaluated only based on the number of outstanding changes.
   */
  @Nullable()
  public Long getMaxAllowedBacklogAgeMillis()
  {
    return maxAllowedBacklogAgeMillis;
  }



  /**
   * Retrieves the replica monitor entry for the target base DN and uses it to
   * determine the size and age of the replication backlog.  If the server has
   * too many outstanding changes, if the oldest change is too old, or if a
   * problem occurs while attempting to make the determination, then an
   * exception will be thrown.
   *
   * @param  conn  The connection to be checked.
   *
   * @throws  LDAPException  If a problem occurs while trying to retrieve the
   *                         target monitor entry, if it cannot be retrieved in
   *                         an acceptable length of time, or if the server has
   *                         an unacceptable replication backlog.
   */
  private void checkReplicationBacklog(@NotNull final LDAPConnection conn)
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
           ERR_REPLICATION_BACKLOG_HEALTH_CHECK_ERROR_GETTING_MONITOR_ENTRY.get(
                baseDN, conn.getHostPort(), StaticUtils.getExceptionMessage(e));
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           e);
      throw new LDAPException(e.getResultCode(), message, e);
    }


    if (monitorEntry == null)
    {
      // If no monitor entry was returned, then we'll assume that the backlog
      // is acceptable.
      return;
    }


    if (maxAllowedBacklogCount != null)
    {
      final Long currentBacklogCount =
           monitorEntry.getAttributeValueAsLong(BACKLOG_COUNT_ATTRIBUTE_NAME);
      if ((currentBacklogCount != null) &&
           (currentBacklogCount > maxAllowedBacklogCount))
      {
        final String message =
             ERR_REPLICATION_BACKLOG_HEALTH_CHECK_COUNT_EXCEEDED.get(
                  currentBacklogCount, baseDN, conn.getHostPort(),
                  maxAllowedBacklogCount);
        conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
             message, null);
        throw new LDAPException(ResultCode.UNAVAILABLE, message);
      }
    }


    if (maxAllowedBacklogAgeMillis != null)
    {
      final Date oldestChangeDate = monitorEntry.getAttributeValueAsDate(
           OLDEST_BACKLOG_CHANGE_TIME_ATTRIBUTE_NAME);
      if (oldestChangeDate != null)
      {
        final long oldestChangeAgeMillis =
             System.currentTimeMillis() - oldestChangeDate.getTime();
        if (oldestChangeAgeMillis > maxAllowedBacklogAgeMillis)
        {
          final String message =
               ERR_REPLICATION_BACKLOG_HEALTH_CHECK_AGE_EXCEEDED.get(
                    baseDN, conn.getHostPort(),
                    StaticUtils.millisToHumanReadableDuration(
                         oldestChangeAgeMillis),
                    StaticUtils.millisToHumanReadableDuration(
                         maxAllowedBacklogAgeMillis));
          conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
               message, null);
          throw new LDAPException(ResultCode.UNAVAILABLE, message);
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReplicationBacklogLDAPConnectionPoolHealthCheck(");
    buffer.append("invokeOnCreate=");
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
    buffer.append(", baseDN='");
    buffer.append(baseDN);
    buffer.append('\'');

    if (maxAllowedBacklogCount != null)
    {
      buffer.append(", maxAllowedBacklogCount=");
      buffer.append(maxAllowedBacklogCount);
    }

    if (maxAllowedBacklogAgeMillis != null)
    {
      buffer.append(", maxAllowedBacklogAgeMillis=");
      buffer.append(maxAllowedBacklogAgeMillis);
    }

    buffer.append(')');
  }
}
