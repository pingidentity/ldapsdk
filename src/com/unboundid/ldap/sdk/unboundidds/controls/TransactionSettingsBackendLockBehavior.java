/*
 * Copyright 2014-2016 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2016 UnboundID Corp.
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



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This enum defines the options that may be specified to indicate whether and
 * when to acquire an exclusive lock in the target backend when processing a
 * transaction.
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
  private TransactionSettingsBackendLockBehavior(final int intValue)
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
}
