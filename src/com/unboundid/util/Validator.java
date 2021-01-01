/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.Collection;
import java.util.Map;

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
  public static void ensureNotNull(@Nullable final Object o)
         throws LDAPSDKUsageException
  {
    if (o == null)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_NULL_CHECK_FAILURE.get(0,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureNotNullWithMessage(@Nullable final Object o,
                                              @NotNull final String message)
         throws LDAPSDKUsageException
  {
    if (o == null)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureNotNull(@Nullable final Object o1,
                                   @Nullable final Object o2)
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
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureNotNull(@Nullable final Object o1,
                                   @Nullable final Object o2,
                                   @Nullable final Object o3)
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
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureNotNull(@Nullable final Object o1,
                                   @Nullable final Object o2,
                                   @Nullable final Object o3,
                                   @Nullable final Object o4)
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
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureNotNull(@Nullable final Object o1,
                                   @Nullable final Object o2,
                                   @Nullable final Object o3,
                                   @Nullable final Object o4,
                                   @Nullable final Object o5)
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
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided collection is not {@code null} and contains at
   * least one item.
   *
   * @param  collection  The collection to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided collection is {@code null}
   *                                 or empty.
   */
  public static void ensureNotNullOrEmpty(
                          @Nullable final Collection<?> collection)
  {
    if (collection == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_COLLECTION_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (collection.isEmpty())
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_COLLECTION_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided collection is not {@code null} and contains at
   * least one item.
   *
   * @param  collection  The collection to verify.
   * @param  message     The message to include in the exception thrown if the
   *                     provided collection is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided collection is {@code null}
   *                                 or empty.
   */
  public static void ensureNotNullOrEmpty(
                          @Nullable final Collection<?> collection,
                          @NotNull final String message)
  {
    if (collection == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_COLLECTION_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (collection.isEmpty())
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_COLLECTION_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided map is not {@code null} and contains at least one
   * item.
   *
   * @param  map  The map to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided map is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final Map<?,?> map)
  {
    if (map == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_MAP_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (map.isEmpty())
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_MAP_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided map is not {@code null} and contains at least one
   * item.
   *
   * @param  map      The map to verify.
   * @param  message  The message to include in the exception thrown if the
   *                  provided map is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided map is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final Map<?,?> map,
                                          @NotNull final String message)
  {
    if (map == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_MAP_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (map.isEmpty())
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_MAP_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array  The array to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final Object[] array)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array    The array to verify.
   * @param  message  The message to include in the exception thrown if the
   *                  provided array is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final Object[] array,
                                          @NotNull final String message)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array  The array to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final byte[] array)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array    The array to verify.
   * @param  message  The message to include in the exception thrown if the
   *                  provided array is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final byte[] array,
                                          @NotNull final String message)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array  The array to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final char[] array)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array    The array to verify.
   * @param  message  The message to include in the exception thrown if the
   *                  provided array is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final char[] array,
                                          @NotNull final String message)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array  The array to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final int[] array)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array    The array to verify.
   * @param  message  The message to include in the exception thrown if the
   *                  provided array is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final int[] array,
                                          @NotNull final String message)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array  The array to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final long[] array)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided array is not {@code null} and has a length of at
   * least one.
   *
   * @param  array    The array to verify.
   * @param  message  The message to include in the exception thrown if the
   *                  provided array is {@code null} or empty.
   *
   * @throws  LDAPSDKUsageException  If the provided array is {@code null} or
   *                                 empty.
   */
  public static void ensureNotNullOrEmpty(@Nullable final long[] array,
                                          @NotNull final String message)
  {
    if (array == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (array.length == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_ARRAY_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided character sequence is not {@code null} and has a
   * length of at least one.
   *
   * @param  charSequence  The character sequence to verify.
   *
   * @throws  LDAPSDKUsageException  If the provided character sequence is
   *                                 {@code null} or empty.
   */
  public static void ensureNotNullOrEmpty(
                          @Nullable final CharSequence charSequence)
  {
    if (charSequence == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_CHAR_SEQUENCE_NULL.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (charSequence.length() == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_CHAR_SEQUENCE_EMPTY.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Ensures that the provided character sequence is not {@code null} and has a
   * length of at least one.
   *
   * @param  charSequence  The character sequence to verify.
   * @param  message        The message to include in the exception thrown if
   *                        the provided character sequence is {@code null} or
   *                        empty.
   *
   * @throws  LDAPSDKUsageException  If the provided character sequence is
   *                                 {@code null} or empty.
   */
  public static void ensureNotNullOrEmpty(
                          @Nullable final CharSequence charSequence,
                          @NotNull final String message)
  {
    if (charSequence == null)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_CHAR_SEQUENCE_NULL_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
    else if (charSequence.length() == 0)
    {
      final LDAPSDKUsageException e =  new LDAPSDKUsageException(
           ERR_VALIDATOR_CHAR_SEQUENCE_EMPTY_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
           ERR_VALIDATOR_TRUE_CHECK_FAILURE.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureTrue(final boolean condition,
                                @NotNull final String message)
         throws LDAPSDKUsageException
  {
    if (! condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
           ERR_VALIDATOR_FALSE_CHECK_FAILURE.get(StaticUtils.getStackTrace(
                Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
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
  public static void ensureFalse(final boolean condition,
                                 @NotNull final String message)
         throws LDAPSDKUsageException
  {
    if (condition)
    {
      final LDAPSDKUsageException e = new LDAPSDKUsageException(
           ERR_VALIDATOR_FAILURE_CUSTOM_MESSAGE.get(message,
                StaticUtils.getStackTrace(
                     Thread.currentThread().getStackTrace())));
      Debug.debugCodingError(e);
      throw e;
    }
  }



  /**
   * Indicates that an expected condition was not true by throwing an
   * {@link LDAPSDKUsageException} with the provided information.
   *
   * @param  message  The message to use for the resulting exception.  It must
   *                  not be {@code null}.
   *
   * @throws  LDAPSDKUsageException  To indicate that a violation occurred.
   */
  public static void violation(@NotNull final String message)
         throws LDAPSDKUsageException
  {
    violation(message, null);
  }



  /**
   * Indicates that an expected condition was not true by throwing an
   * {@link LDAPSDKUsageException} with the provided information.
   *
   * @param  message  The message to use for the resulting exception.  It must
   *                  not be {@code null}.
   * @param  cause    The exception that triggered the violation.  It may be
   *                  {@code null} if there is no associated exception.
   *
   * @throws  LDAPSDKUsageException  To indicate that a violation occurred.
   */
  public static void violation(@NotNull final String message,
                               @Nullable final Throwable cause)
         throws LDAPSDKUsageException
  {
    final LDAPSDKUsageException e = new LDAPSDKUsageException(message, cause);
    Debug.debugCodingError(e);
    throw e;
  }
}
