/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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



import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an implementation of an LDAP connection pool health check
 * that will cause the associated connection pool to consider a connection
 * invalid after it has remained idle (as determined using the
 * {@link LDAPConnection#getLastCommunicationTime()} method) for more than a
 * specified length of time.  This is primarily useful in cases where the
 * associated directory servers (or some intermediate networking equipment) may
 * terminate connections that have remained idle for too long.
 * <BR><BR>
 * Note that in connection pools that may contain connections across multiple
 * servers, you should probably use the
 * {@link LDAPConnectionPool#setMaxConnectionAgeMillis(long)} method instead of
 * this health check to ensure that connections are automatically refreshed
 * after a specified duration, regardless of whether they have been idle.
 * Setting a maximum connection age will help ensure that connections in the
 * pool will return to a relatively balanced state after a failure has caused
 * connections to migrate away from one or more of those servers.
 * <BR><BR>
 * Also note that as an alternative to this health check, you may wish to
 * consider a health check that actually attempts to communicate with the
 * destination server over LDAP (e.g., the
 * {@link GetEntryLDAPConnectionPoolHealthCheck}).  Not only will those types of
 * health checks do a better job of ensuring that the connection is still valid
 * (and that the server to which it is established is responsive), but the
 * communication that they perform will also prevent them from being considered
 * idle.
 *
 * @see  LDAPConnectionPool
 * @see  LDAPConnectionPoolHealthCheck
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MaximumIdleDurationLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // A counter that will be incremented any time an idle connection is
  // identified.
  @NotNull private final LongAdder idleConnectionCounter;

  // The maximum length of time in milliseconds that connections will be allowed
  // to remain idle before they will be replaced by the associated connection
  // pool.
  private final long maximumIdleDurationMillis;



  /**
   * Creates a new instance of this health check that will use the specified
   * maximum idle duration.
   *
   * @param  maximumIdleDurationValue
   *              The value that specifies the maximum length of time, in
   *              conjunction with the specified time unit, that connections
   *              will be allowed to remain idle before they will be replaced
   *              by the associated connection pool.  This value must be greater
   *              than zero.
   * @param  maximumIdleDurationTimeUnit
   *              The time unit to use when interpreting the provided maximum
   *              idle duration value.  It must not be {@code null}.
   */
  public MaximumIdleDurationLDAPConnectionPoolHealthCheck(
       final long maximumIdleDurationValue,
       @NotNull final TimeUnit maximumIdleDurationTimeUnit)
  {
    this(maximumIdleDurationTimeUnit.toMillis(maximumIdleDurationValue));
  }



  /**
   * Creates a new instance of this health check that will use the specified
   * maximum idle duration.
   *
   * @param  maximumIdleDurationMillis
   *              The maximum length of time in milliseconds that connections
   *              will be allowed to remain idle before they will be replaced by
   *              the associated connection pool.  This value must be greater
   *              than zero.
   */
  public MaximumIdleDurationLDAPConnectionPoolHealthCheck(
              final long maximumIdleDurationMillis)
  {
    Validator.ensureTrue((maximumIdleDurationMillis > 0L),
         "MaximumIdleDurationLDAPConnectionPoolHealthCheck." +
              "maximumIdleDurationMillis must be greater than zero.");

    this.maximumIdleDurationMillis = maximumIdleDurationMillis;

    idleConnectionCounter = new LongAdder();
  }



  /**
   * Retrieves the maximum length of time in milliseconds that connections will
   * be allowed to remain idle before they will be replaced by the associated
   * connection pool.
   *
   * @return  The maximum length of time in milliseconds that connections will
   *          be allowed to remain idle before they will be replaced by the
   *          associated connection pool.
   */
  public long getMaximumIdleDurationMillis()
  {
    return maximumIdleDurationMillis;
  }



  /**
   * Retrieves the number of pooled connections that this health check has
   * considered invalid because of their idle duration.
   *
   * @return  The number of pooled connections that this health check has
   *          considered invalid because of their idle duration.
   */
  public long getIdleConnectionCount()
  {
    return idleConnectionCounter.longValue();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForContinuedUse(
                   @NotNull final LDAPConnection connection)
         throws LDAPException
  {
    final long currentTime = System.currentTimeMillis();
    final long lastCommunicationTime = connection.getLastCommunicationTime();
    final long idleDurationMillis = currentTime - lastCommunicationTime;

    if (idleDurationMillis > maximumIdleDurationMillis)
    {
      idleConnectionCounter.increment();
      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_IDLE_HEALTH_CHECK_CONNECTION_IDLE.get(idleDurationMillis,
                maximumIdleDurationMillis));
    }
  }



  /**
   * Appends a string representation of this LDAP connection pool health check
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MaximumIdleDurationLDAPConnectionPoolHealthCheck(" +
         "maximumIdleDurationMillis=");
    buffer.append(maximumIdleDurationMillis);
    buffer.append(')');
  }
}
