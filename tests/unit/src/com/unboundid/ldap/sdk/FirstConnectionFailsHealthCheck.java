/*
 * Copyright 2012-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2017 UnboundID Corp.
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



import java.util.concurrent.atomic.AtomicBoolean;



/**
 * This class provides an implementation of an LDAP connection pool health check
 * that will always fail the first connection attempt but will accept all
 * subsequent connection attempts.
 */
public final class FirstConnectionFailsHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // Indicates whether a failure has already been generated.
  private final AtomicBoolean failureGenerated;




  /**
   * Creates a new instance of this health check.
   */
  public FirstConnectionFailsHealthCheck()
  {
    failureGenerated = new AtomicBoolean(false);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureNewConnectionValid(final LDAPConnection connection)
         throws LDAPException
  {
    if (failureGenerated.compareAndSet(false, true))
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           "The first connection attempt always fails.");
    }
  }
}
