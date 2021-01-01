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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the options that may be specified to indicate whether and
 * when to acquire an exclusive lock in the target backend when processing a
 * transaction.
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
 *
 * @see TransactionSettingsRequestControl
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum TransactionSettingsBackendLockBehavior
{
  /**
   * Indicates that the server should not make any attempt to acquire an
   * exclusive lock in the target backend, whether during the initial attempt or
   * a subsequent retry.  This will allow the highest level of concurrency for
   * operations within the backend, but may increase the risk of lock conflicts
   * between transactions in a server processing many operations concurrently.
   * This risk may be mitigated by indicating that the transaction should be
   * retried one or more times.
   */
  DO_NOT_ACQUIRE(0),



  /**
   * Indicates that if the server is unable to successfully commit the
   * associated transaction after one or more attempts without holding an
   * exclusive lock in the target backend, then it should make one more attempt
   * after acquiring the lock.  This will avoid the need to acquire the lock
   * unless the maximum number of attempts have been unsuccessful without it.
   */
  ACQUIRE_AFTER_RETRIES(1),



  /**
   * Indicates that if the server is unable to successfully commit the
   * associated transaction after the first attempt without holding an exclusive
   * lock in the target backend, then it should make one or more
   * additional attempts (as specified by the requested number of retries) after
   * acquiring the lock.  This will avoid the need to acquire the lock for
   * operations that can be completed on the first attempt without it.
   */
  ACQUIRE_BEFORE_RETRIES(2),



  /**
   * Indicates that the server should acquire an exclusive lock in the target
   * backend before performing any backend processing for the operation.  This
   * will limit concurrency, as the backend will not be able to process any
   * other operation while the associated operation is in progress, but this
   * will also minimize the chance of a thread deadlock or lock timeout as a
   * result of a conflict between database interactions from multiple
   * simultaneous operations.
   */
  ACQUIRE_BEFORE_INITIAL_ATTEMPT(3);



  // The integer value for this backend lock behavior.
  private final int intValue;



  /**
   * Creates a new transaction settings backend lock behavior with the provided
   * integer value.
   *
   * @param  intValue  The integer value for this backend lock behavior.
   */
  TransactionSettingsBackendLockBehavior(final int intValue)
  {
    this.intValue = intValue;
  }



  /**
   * Retrieves the integer value for this transaction settings backend lock
   * behavior value.
   *
   * @return  The integer value for this transaction settings backend lock
   *          behavior value.
   */
  public int intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the backend lock behavior value with the specified integer value.
   *
   * @param  intValue  The integer value for the backend lock behavior to
   *                   retrieve.
   *
   * @return  The backend lock behavior value with the specified integer value,
   *          or {@code null} if there is no such backend lock behavior value.
   */
  @Nullable()
  public static TransactionSettingsBackendLockBehavior
                     valueOf(final int intValue)
  {
    for (final TransactionSettingsBackendLockBehavior v : values())
    {
      if (v.intValue == intValue)
      {
        return v;
      }
    }

    return null;
  }



  /**
   * Retrieves the transaction settings backend lock behavior with the specified
   * name.
   *
   * @param  name  The name of the transaction settings backend lock behavior to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The requested transaction settings backend lock behavior, or
   *          {@code null} if no such behavior is defined.
   */
  @Nullable()
  public static TransactionSettingsBackendLockBehavior forName(
                     @NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "donotacquire":
      case "do-not-acquire":
      case "do_not_acquire":
        return DO_NOT_ACQUIRE;
      case "acquireafterretries":
      case "acquire-after-retries":
      case "acquire_after_retries":
        return ACQUIRE_AFTER_RETRIES;
      case "acquirebeforeretries":
      case "acquire-before-retries":
      case "acquire_before_retries":
        return ACQUIRE_BEFORE_RETRIES;
      case "acquirebeforeinitialattempt":
      case "acquire-before-initial-attempt":
      case "acquire_before_initial_attempt":
        return ACQUIRE_BEFORE_INITIAL_ATTEMPT;
      default:
        return null;
    }
  }
}
