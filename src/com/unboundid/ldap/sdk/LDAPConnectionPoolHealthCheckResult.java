/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about the result
 * of an LDAP connection pool health check.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPConnectionPoolHealthCheckResult
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7312002973891471180L;



  // The number of connections found to be defunct.
  private final int numDefunct;

  // The number of connections examined during the health check.
  private final int numExamined;

  // The number of connections found to be expired.
  private final int numExpired;



  /**
   * Creates a new health check result with the provided information.
   *
   * @param  numExamined  The number of connections examined during the health
   *                      check.
   * @param  numExpired   The number of connections found to have been
   *                      established for longer than the pool's maximum
   *                      connection age and were attempted to be replaced as
   *                      expired.
   * @param  numDefunct   The number of connections found to be invalid and were
   *                      attempted to be replaced as defunct.
   */
  LDAPConnectionPoolHealthCheckResult(final int numExamined,
                                      final int numExpired,
                                      final int numDefunct)
  {
    this.numExamined = numExamined;
    this.numExpired  = numExpired;
    this.numDefunct  = numDefunct;
  }



  /**
   * Retrieves the number of connections that were examined during the health
   * check.
   *
   * @return  The number of connections that were examined during the health
   *          check.
   */
  public int getNumExamined()
  {
    return numExamined;
  }



  /**
   * Retrieves the number of connections found to have been established for
   * longer than the pool's maximum connection age and were attempted to be
   * replaced as expired.
   *
   * @return  The number of connections found to have been established for
   *          longer than the pool's maximum connection age and were attempted
   *          to be replaced as expired.
   */
  public int getNumExpired()
  {
    return numExpired;
  }



  /**
   * Retrieves the number of connections found to be invalid (e.g., because they
   * were no longer established, or because they failed the health check) and
   * were attempted to be replaced as defunct.
   *
   * @return  The number of connections found to be invalid and were attempted
   *          to be replaced as defunct.
   */
  public int getNumDefunct()
  {
    return numDefunct;
  }



  /**
   * Retrieves a string representation of this connection pool health check
   * result.
   *
   * @return  A string representation of this connection pool health check
   *          result.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this connection pool health check result
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionPoolHealthCheckResult(numExamined=");
    buffer.append(numExamined);
    buffer.append(", numExpired=");
    buffer.append(numExpired);
    buffer.append(", numDefunct=");
    buffer.append(numDefunct);
    buffer.append(')');
  }
}
