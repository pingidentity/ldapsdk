/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a mechanism for creating {@link ByteString} values.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ByteStringFactory
{
  /**
   * A pre-allocated ASN.1 octet string with no value.
   */
  @NotNull private static final ASN1OctetString EMPTY_VALUE =
       new ASN1OctetString();



  /**
   * Prevent this class from being instantiated.
   */
  private ByteStringFactory()
  {
    // No implementation required.
  }



  /**
   * Creates a new byte string with no value.
   *
   * @return  The created byte string.
   */
  @NotNull()
  public static ByteString create()
  {
    return EMPTY_VALUE;
  }



  /**
   * Creates a new byte string with the provided value.
   *
   * @param  value  The value to use for the byte string.
   *
   * @return  The created byte string.
   */
  @NotNull()
  public static ByteString create(@Nullable final byte[] value)
  {
    return new ASN1OctetString(value);
  }



  /**
   * Creates a new byte string with the provided value.
   *
   * @param  value   The byte array containing the data to use for the value.
   *                 It must not be {@code null}.
   * @param  offset  The position in the array at which the value begins.  It
   *                 must be greater than or equal to zero and less or equal to
   *                 the end of the array.
   * @param  length  The number of bytes contained in the value.  It must be
   *                 greater than or equal to zero, and the sum of the offset
   *                 and the length must be less than or equal to the end of the
   *                 array.
   *
   * @return  The created byte string.
   */
  @NotNull()
  public static ByteString create(@NotNull final byte[] value, final int offset,
                                  final int length)
  {
    return new ASN1OctetString(value, offset, length);
  }



  /**
   * Creates a new byte string with the provided value.
   *
   * @param  value  The value to use for the byte string.
   *
   * @return  The created byte string.
   */
  @NotNull()
  public static ByteString create(@Nullable final String value)
  {
    return new ASN1OctetString(value);
  }
}
