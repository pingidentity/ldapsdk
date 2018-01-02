/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
package com.unboundid.util;



import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a number of methods that can be used to enforce
 * constraints on the behavior of SDK methods.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Validator
{
  /**
   * Prevent this class from being instantiated.
   */
  private Validator()
  {
    // No implementation is required.
  }



  /**
   * Ensures that the provided object is not {@code null}.
   *
   * @param  o  The object to examine.
   *
   * @throws  LDAPSDKUsageException  If the provided object is {@code null}.
   */
  public static void ensureNotNull(final Object o)
         throws LDAPSDKUsageException
  {
    if (o == null)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(0,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided object is not {@code null}.
   *
   * @param  o        The object to examine.
   * @param  message  The message to include in the exception thrown if the
   *                  provided object is {@code null}.
   *
   * @throws  LDAPSDKUsageException  If the provided object is {@code null}.
   */
  public static void ensureNotNullWithMessage(final Object o,
                                              final String message)
         throws LDAPSDKUsageException
  {
    if (o == null)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that none of the provided objects is {@code null}.
   *
   * @param  o1  The first object for which to make the determination.
   * @param  o2  The second object for which to make the determination.
   *
   * @throws  LDAPSDKUsageException  If any of the provided objects is
   *                                 {@code null}.
   */
  public static void ensureNotNull(final Object o1, final Object o2)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else
      {
        index = 1;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that none of the provided objects is {@code null}.
   *
   * @param  o1  The first object for which to make the determination.
   * @param  o2  The second object for which to make the determination.
   * @param  o3  The third object for which to make the determination.
   *
   * @throws  LDAPSDKUsageException  If any of the provided objects is
   *                                 {@code null}.
   */
  public static void ensureNotNull(final Object o1, final Object o2,
                                   final Object o3)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null) || (o3 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else if (o2 == null)
      {
        index = 1;
      }
      else
      {
        index = 2;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that none of the provided objects is {@code null}.
   *
   * @param  o1  The first object for which to make the determination.
   * @param  o2  The second object for which to make the determination.
   * @param  o3  The third object for which to make the determination.
   * @param  o4  The fourth object for which to make the determination.
   *
   * @throws  LDAPSDKUsageException  If any of the provided objects is
   *                                 {@code null}.
   */
  public static void ensureNotNull(final Object o1, final Object o2,
                                   final Object o3, final Object o4)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null) || (o3 == null) || (o4 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else if (o2 == null)
      {
        index = 1;
      }
      else if (o3 == null)
      {
        index = 2;
      }
      else
      {
        index = 3;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that none of the provided objects is {@code null}.
   *
   * @param  o1  The first object for which to make the determination.
   * @param  o2  The second object for which to make the determination.
   * @param  o3  The third object for which to make the determination.
   * @param  o4  The fourth object for which to make the determination.
   * @param  o5  The fifth object for which to make the determination.
   *
   * @throws  LDAPSDKUsageException  If any of the provided objects is
   *                                 {@code null}.
   */
  public static void ensureNotNull(final Object o1, final Object o2,
                                   final Object o3, final Object o4,
                                   final Object o5)
         throws LDAPSDKUsageException
  {
    if ((o1 == null) || (o2 == null) || (o3 == null) || (o4 == null) ||
        (o5 == null))
    {
      final int index;
      if (o1 == null)
      {
        index = 0;
      }
      else if (o2 == null)
      {
        index = 1;
      }
      else if (o3 == null)
      {
        index = 2;
      }
      else if (o4 == null)
      {
        index = 3;
      }
      else
      {
        index = 4;
      }

      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(index,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided condition is {@code true}.
   *
   * @param  condition  The condition to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided condition is {@code false}.
   */
  public static void ensureTrue(final boolean condition)
         throws LDAPSDKUsageException
  {
    if (! condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_TRUE_CHECK_FAILURE.get(
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided condition is {@code true}.
   *
   * @param  condition  The condition to verify.
   * @param  message    The message to include in the exception thrown if the
   *                    provided object is {@code null}.
   *
   * @throws  LDAPSDKUsageException  If the provided condition is {@code false}.
   */
  public static void ensureTrue(final boolean condition, final String message)
         throws LDAPSDKUsageException
  {
    if (! condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided condition is {@code false}.
   *
   * @param  condition  The condition to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided condition is {@code true}.
   */
  public static void ensureFalse(final boolean condition)
         throws LDAPSDKUsageException
  {
    if (condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FALSE_CHECK_FAILURE.get(
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided condition is {@code false}.
   *
   * @param  condition  The condition to verify.
   * @param  message    The message to include in the exception thrown if the
   *                    provided object is {@code null}.
   *
   * @throws  LDAPSDKUsageException  If the provided condition is {@code true}.
   */
  public static void ensureFalse(final boolean condition, final String message)
         throws LDAPSDKUsageException
  {
    if (condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                getStackTrace(Thread.currentThread().getStackTrace())));
      debugCodingError(e);
      throw e;
    }
  }
}
