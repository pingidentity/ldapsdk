/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an {@link LDAPConnectionPoolHealthCheck} implementation
 * that may be used to invoke a series of subordinate health checks and ensure
 * that all of them consider a connection valid before indicating that the
 * connection is valid.  If any of the subordinate health checks indicates that
 * the connection is invalid, then the connection will be considered invalid.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AggregateLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // The list of subordinate health checks that will be invoked.
  @NotNull private final List<LDAPConnectionPoolHealthCheck> healthChecks;



  /**
   * Creates a new instance of this LDAP connection pool health check.
   *
   * @param  healthChecks  The set of health checks that must all be satisfied
   *                       in order to consider a connection valid.
   */
  public AggregateLDAPConnectionPoolHealthCheck(
              @NotNull final LDAPConnectionPoolHealthCheck... healthChecks)
  {
    this(StaticUtils.toList(healthChecks));
  }



  /**
   * Creates a new instance of this LDAP connection pool health check.
   *
   * @param  healthChecks  The set of health checks that must all be satisfied
   *                       in order to consider a connection valid.
   */
  public AggregateLDAPConnectionPoolHealthCheck(
              @NotNull final Collection<? extends LDAPConnectionPoolHealthCheck>
                   healthChecks)
  {
    if (healthChecks == null)
    {
      this.healthChecks = Collections.emptyList();
    }
    else
    {
      this.healthChecks =
           Collections.unmodifiableList(new ArrayList<>(healthChecks));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureNewConnectionValid(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.ensureNewConnectionValid(connection);
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
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.ensureConnectionValidAfterAuthentication(connection, bindResult);
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
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.ensureConnectionValidForCheckout(connection);
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
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.ensureConnectionValidForRelease(connection);
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
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.ensureConnectionValidForContinuedUse(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void performPoolMaintenance(@NotNull final AbstractConnectionPool pool)
  {
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.performPoolMaintenance(pool);
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
    for (final LDAPConnectionPoolHealthCheck hc : healthChecks)
    {
      hc.ensureConnectionValidAfterException(connection, exception);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AggregateLDAPConnectionPoolHealthCheck(healthChecks={");

    final Iterator<LDAPConnectionPoolHealthCheck> iterator =
         healthChecks.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
