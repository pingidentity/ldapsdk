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
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.Map;

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

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides an LDAP connection pool health check implementation that
 * will attempt to retrieve the general monitor entry from a Ping Identity
 * Directory Server instance to determine if it has any degraded and/or
 * unavailable alert types.  If a server considers itself to be degraded or
 * unavailable, then it may be considered unsuitable for use in a connection
 * pool.
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
public final class ActiveAlertsLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
       implements Serializable
{
  /**
   * The default maximum response time value in milliseconds, which is set to
   * 5,000 milliseconds or 5 seconds.
   */
  private static final long DEFAULT_MAX_RESPONSE_TIME_MILLIS = 5_000L;



  /**
   * The name of the attribute in the general monitor entry that holds the list
   * of active degraded alert types.
   */
  @NotNull()
  private static final String DEGRADED_ALERT_TYPE_ATTRIBUTE_NAME =
       "degraded-alert-type";



  /**
   * The DN of the general monitor entry that will be examined.
   */
  @NotNull()
  private static final String GENERAL_MONITOR_ENTRY_DN = "cn=monitor";



  /**
   * The name of the attribute in the general monitor entry that holds the list
   * of active unavailable alert types.
   */
  @NotNull()
  private static final String UNAVAILABLE_ALERT_TYPE_ATTRIBUTE_NAME =
       "unavailable-alert-type";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8889308187890719816L;



  // Indicates whether to ignore all degraded alert types.
  private final boolean ignoreAllDegradedAlertTypes;

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

  // A set of degraded alert types that should not cause the health check to
  // fail.
  @NotNull private final Map<String,String> ignoredDegradedAlertTypes;

  // A set of unavailable alert types that should not cause the health check to
  // fail.
  @NotNull private final Map<String,String> ignoredUnavailableAlertTypes;

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
   * @param  ignoreAllDegradedAlertTypes
   *              Indicates whether to ignore all degraded alert types.  If this
   *              is {@code true}, then the presence of degraded alert types
   *              will not cause the health check to fail.
   * @param  ignoredDegradedAlertTypes
   *              An optional set of the names of degraded alert types that
   *              should be ignored so that they will not cause the health
   *              check to fail.  This may be {@code null} or empty if no
   *              specific degraded alert types should be ignored.
   * @param  ignoredUnavailableAlertTypes
   *              An optional set of the names of unavailable alert types that
   *              should be ignored so that they will not cause the health
   *              check to fail.  This may be {@code null} or empty if no
   *              specific unavailable alert types should be ignored.
   */
  public ActiveAlertsLDAPConnectionPoolHealthCheck(
              final boolean invokeOnCreate,
              final boolean invokeAfterAuthentication,
              final boolean invokeOnCheckout,
              final boolean invokeOnRelease,
              final boolean invokeForBackgroundChecks,
              final boolean invokeOnException,
              final long maxResponseTimeMillis,
              final boolean ignoreAllDegradedAlertTypes,
              @Nullable final Collection<String> ignoredDegradedAlertTypes,
              @Nullable final Collection<String> ignoredUnavailableAlertTypes)
  {
    this.invokeOnCreate = invokeOnCreate;
    this.invokeAfterAuthentication = invokeAfterAuthentication;
    this.invokeOnCheckout = invokeOnCheckout;
    this.invokeOnRelease = invokeOnRelease;
    this.invokeForBackgroundChecks = invokeForBackgroundChecks;
    this.invokeOnException = invokeOnException;
    this.ignoreAllDegradedAlertTypes = ignoreAllDegradedAlertTypes;

    this.ignoredDegradedAlertTypes =
         getIgnoredAlertTypes(ignoredDegradedAlertTypes);
    this.ignoredUnavailableAlertTypes =
         getIgnoredAlertTypes(ignoredUnavailableAlertTypes);

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

    searchRequest = new SearchRequest(GENERAL_MONITOR_ENTRY_DN,
         SearchScope.BASE, DereferencePolicy.NEVER, 1, timeLimitSeconds, false,
         Filter.createANDFilter(),
         DEGRADED_ALERT_TYPE_ATTRIBUTE_NAME,
         UNAVAILABLE_ALERT_TYPE_ATTRIBUTE_NAME);
  }



  /**
   * Retrieves a map containing the names of the provided alert types (if any).
   * The keys of the map will be the values in a form that is suitable for
   * efficient comparison (in all lowercase, with underscores converted to
   * dashes), while the corresponding values will be the names as they were
   * originally
   *
   * @param  alertTypes  The collection of alert type names to use.  It may
   *                     be {@code null} or empty if no ignored alert types
   *                     should be used.
   *
   * @return  A map containing the names of the provided alert types in a form
   *          that is efficient for comparison, or an empty map if the provided
   *          collection is {@code null} or empty.
   */
  @NotNull()
  private static Map<String,String> getIgnoredAlertTypes(
               @Nullable final Collection<String> alertTypes)
  {
    if ((alertTypes == null) || alertTypes.isEmpty())
    {
      return Collections.emptyMap();
    }

    final Map<String,String> alertTypeMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(alertTypes.size()));
    for (final String alertType : alertTypes)
    {
      alertTypeMap.put(formatAlertTypeForComparison(alertType), alertType);
    }

    return Collections.unmodifiableMap(alertTypeMap);
  }



  /**
   * Retrieves the provided alert type name in a format this is suited for
   * efficient comparison.  Tbe name will be converted to lowercase, and any
   * underscores will be converted to dashes.
   *
   * @param  name  The name to be converted.  It must not be {@code null}.
   *
   * @return  A version of the name that is suitable for efficient comparison.
   */
  @NotNull()
  private static String formatAlertTypeForComparison(@NotNull final String name)
  {
    return StaticUtils.toLowerCase(name).replace('_', '-');
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
      checkActiveAlertTypes(connection);
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
      checkActiveAlertTypes(connection);
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
      checkActiveAlertTypes(connection);
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
      checkActiveAlertTypes(connection);
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
      checkActiveAlertTypes(connection);
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
      checkActiveAlertTypes(connection);
    }
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
   * Retrieves the maximum length of time in milliseconds that this health
   * check should wait for the entry to be returned.
   *
   * @return  The maximum length of time in milliseconds that this health check
   *          should wait for the entry to be returned.
   */
  public long getMaxResponseTimeMillis()
  {
    return maxResponseTimeMillis;
  }



  /**
   * Indicates whether to ignore all degraded alert types.
   *
   * @return  {@code true} if all degraded alert types should be ignored, and
   *          the presence of active degraded alerts will not cause the health
   *          check to fail, or {@code false} if degraded alert types will be
   *          considered significant unless they are explicitly included in the
   *          value returned by {@link #getIgnoredDegradedAlertTypes()}.
   */
  public boolean ignoreAllDegradedAlertTypes()
  {
    return ignoreAllDegradedAlertTypes;
  }



  /**
   * A collection of alert type names that will be ignored when evaluating the
   * set of degraded alert types.  This will only be used if
   * {@link #ignoreAllDegradedAlertTypes()} returns {@code false}.
   *
   * @return  A collection of alert type names that will be ignored when
   *          evaluating the set of degraded alert types, or an empty collection
   *          if all degraded alert types should be considered significant.
   */
  @NotNull()
  public Collection<String> getIgnoredDegradedAlertTypes()
  {
    return ignoredDegradedAlertTypes.values();
  }



  /**
   * A collection of alert type names that will be ignored when evaluating the
   * set of unavailable alert types.
   *
   * @return  A collection of alert type names that will be ignored when
   *          evaluating the set of unavailable alert types, or an empty
   *          collection if all unavailable alert types should be considered
   *          significant.
   */
  @NotNull()
  public Collection<String> getIgnoredUnavailableAlertTypes()
  {
    return ignoredUnavailableAlertTypes.values();
  }



  /**
   * Retrieves the general monitor entry and examines it to identify any
   * active degraded or unavailable alert types.  If any are found, the health
   * check will determine whether they should be ignored, and if not, then an
   * exception will be thrown.
   *
   * @param  conn  The connection to be checked.
   *
   * @throws  LDAPException  If a problem occurs while trying to retrieve the
   *                         entry, if it cannot be retrieved in an acceptable
   *                         length of time, or if the server reports that it
   *                         has active degraded or unavailable alert types
   *                         that should not be ignored.
   */
  private void checkActiveAlertTypes(@NotNull final LDAPConnection conn)
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
           ERR_ACTIVE_ALERTS_HEALTH_CHECK_ERROR_GETTING_MONITOR_ENTRY.get(
                GENERAL_MONITOR_ENTRY_DN,  conn.getHostPort(),
                StaticUtils.getExceptionMessage(e));
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           e);
      throw new LDAPException(e.getResultCode(), message, e);
    }


    if (monitorEntry == null)
    {
      final String message =
           ERR_ACTIVE_ALERTS_HEALTH_CHECK_NO_MONITOR_ENTRY.get(
                GENERAL_MONITOR_ENTRY_DN, conn.getHostPort());
      conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT, message,
           null);
      throw new LDAPException(ResultCode.NO_RESULTS_RETURNED, message);
    }


    final String[] unavailableAlertTypes = monitorEntry.getAttributeValues(
         UNAVAILABLE_ALERT_TYPE_ATTRIBUTE_NAME);
    if (unavailableAlertTypes != null)
    {
      for (final String alertType : unavailableAlertTypes)
      {
        if (! ignoredUnavailableAlertTypes.containsKey(
             formatAlertTypeForComparison(alertType)))
        {
          final String message =
               ERR_ACTIVE_ALERTS_HEALTH_CHECK_UNAVAILABLE_ALERT.get(
                    GENERAL_MONITOR_ENTRY_DN, conn.getHostPort(), alertType);
          conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
               message, null);
          throw new LDAPException(ResultCode.UNAVAILABLE, message);
        }
      }
    }


    if (! ignoreAllDegradedAlertTypes)
    {
      final String[] degradedAlertTypes = monitorEntry.getAttributeValues(
           DEGRADED_ALERT_TYPE_ATTRIBUTE_NAME);
      if (degradedAlertTypes != null)
      {
        for (final String alertType : degradedAlertTypes)
        {
          if (! ignoredDegradedAlertTypes.containsKey(
               formatAlertTypeForComparison(alertType)))
          {
            final String message =
                 ERR_ACTIVE_ALERTS_HEALTH_CHECK_DEGRADED_ALERT.get(
                      GENERAL_MONITOR_ENTRY_DN, conn.getHostPort(), alertType);
            conn.setDisconnectInfo(DisconnectType.POOLED_CONNECTION_DEFUNCT,
                 message, null);
            throw new LDAPException(ResultCode.UNAVAILABLE, message);
          }
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
    buffer.append("ActiveAlertsLDAPConnectionPoolHealthCheck(invokeOnCreate=");
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
    buffer.append(", ignoreAllDegradedAlertTypes=");
    buffer.append(ignoreAllDegradedAlertTypes);

    buffer.append(", ignoredDegradedAlertTypes=");
    appendAlertTypes(buffer, ignoredDegradedAlertTypes.values());

    buffer.append(", ignoredUnavailableAlertTypes=");
    appendAlertTypes(buffer, ignoredUnavailableAlertTypes.values());

    buffer.append(')');
  }



  /**
   * Appends a list of the provided alert type names to the given buffer.
   *
   * @param  buffer  The buffer to which the names should be appended.  It must
   *                 not be {@code null}.
   * @param  names   The names of the alert types to append to the buffer.  It
   *                 must not be {@code null}, but may be empty.
   */
  private static void appendAlertTypes(@NotNull final StringBuilder buffer,
                                       @NotNull final Collection<String> names)
  {
    buffer.append("{ ");

    final Iterator<String> iterator = names.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());

      if (iterator.hasNext())
      {
        buffer.append(',');
      }

      buffer.append(' ');
    }

    buffer.append('}');
  }
}
