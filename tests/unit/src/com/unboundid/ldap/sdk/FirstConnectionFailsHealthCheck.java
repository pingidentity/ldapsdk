/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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

import com.unboundid.util.NotNull;



/**
 * This class provides an implementation of an LDAP connection pool health check
 * that will always fail the first connection attempt but will accept all
 * subsequent connection attempts.
 */
public final class FirstConnectionFailsHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // Indicates whether a failure has already been generated.
  @NotNull private final AtomicBoolean failureGenerated;




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
  public void ensureNewConnectionValid(@NotNull final LDAPConnection connection)
         throws LDAPException
  {
    if (failureGenerated.compareAndSet(false, true))
    {
      throw new LDAPException(ResultCode.CONNECT_ERROR,
           "The first connection attempt always fails.");
    }
  }
}
