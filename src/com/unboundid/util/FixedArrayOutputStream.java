/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides an {@code OutputStream} implementation that writes data
 * to a provided byte array.  It is similar to the
 * {@code java.io.ByteArrayOutputStream} class, except that it allows you to
 * pass in the array that it uses, and the array will not grow over time.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class FixedArrayOutputStream
       extends OutputStream
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4678108653480347534L;



  // The byte array used by this class.
  @NotNull private final byte[] array;

  // The initial position for this array.
  private final int initialPosition;

  // The maximum number of bytes that may be written.
  private final int length;

  // The maximum position at which data may be written.
  private final int maxPosition;

  // The current position at which data may be written.
  private int pos;



  /**
   * Creates a new output stream that will write data to the provided array.
   * It will use the entire array.
   *
   * @param  array  The array to which data will be written.  It must not be
   *                {@code null}.
   */
  public FixedArrayOutputStream(@NotNull final byte[] array)
  {
    this(array, 0, array.length);
  }



  /**
   * Creates a new output stream that will write data to the provided array.
   * It will use the specified portion of the array.
   *
   * @param  array  The array to which data will be written.  It must not be
   *                {@code null}.
   * @param  pos    The position at which to start writing data.  It must be
   *                greater than or equal to zero and less than or equal to the
   *                length of the array.
   * @param  len    The maximum number of bytes that may be written.  It must
   *                be greater than or equal to zero and less than or equal to
   *                the difference between the length of the array and the
   *                provided {@code pos} value.
   */
  public FixedArrayOutputStream(@NotNull final byte[] array, final int pos,
                                final int len)
  {
    this.array = array;
    this.pos   = pos;

    initialPosition = pos;
    maxPosition     = pos + len;
    length          = len;

    Validator.ensureTrue((pos >= 0),
         "The position must be greater than or equal to zero.");
    Validator.ensureTrue((len >= 0),
         "The length must be greater than or equal to zero.");
    Validator.ensureTrue((maxPosition <= array.length),
         "The sum of pos and len must not exceed the array length.");
  }



  /**
   * Retrieves the backing array used by this output stream.
   *
   * @return  The backing array used by this output stream.
   */
  @NotNull()
  public byte[] getBackingArray()
  {
    return array;
  }



  /**
   * Retrieves the initial position provided when this output stream was
   * created.
   *
   * @return  The initial position provided when this output stream was created.
   */
  public int getInitialPosition()
  {
    return initialPosition;
  }



  /**
   * Retrieves the maximum number of bytes that may be written to this output
   * stream.
   *
   * @return  The maximum number of bytes that may be written to this output
   *          stream.
   */
  public int getLength()
  {
    return length;
  }



  /**
   * Retrieves the number of bytes that have been written so far to this output
   * stream.
   *
   * @return  The number of bytes that have been written so far to this output
   *          stream.
   */
  public int getBytesWritten()
  {
    return (pos - initialPosition);
  }



  /**
   * Closes this output stream.  This has no effect.
   */
  @Override()
  public void close()
  {
    // No implementation required.
  }



  /**
   * Flushes this output stream.  This has no effect.
   */
  @Override()
  public void flush()
  {
    // No implementation required.
  }



  /**
   * Writes the provided byte to this output stream.
   *
   * @param  b  The byte to be written.
   *
   * @throws  IOException  If an attempt was made to write beyond the end of the
   *                       array.
   */
  @Override()
  public void write(final int b)
         throws IOException
  {
    if (pos >= maxPosition)
    {
      throw new IOException(ERR_FIXED_ARRAY_OS_WRITE_BEYOND_END.get());
    }

    array[pos++] = (byte) b;
  }



  /**
   * Writes the contents of the provided array to this output stream.
   *
   * @param  b  The byte array containing the data to be written.  It must not
   *            be {@code null}.
   *
   * @throws  IOException  If an attempt was made to write beyond the end of the
   *                       array.
   */
  @Override()
  public void write(@NotNull final byte[] b)
         throws IOException
  {
    write(b, 0, b.length);
  }



  /**
   * Writes the contents of the provided array to this output stream.
   *
   * @param  b    The byte array containing the data to be written.  It must not
   *              be {@code null}.
   * @param  off  The offset within the provided array of the beginning of the
   *              data to be written.  It must be greater than or equal to zero
   *              and less than or equal to the length of the provided array.
   * @param  len  The number of bytes to be written.  It must be greater than or
   *              equal to zero, and the sum of {@code off} and {@code len} must
   *              be less than the length of the provided array.
   *
   * @throws  IOException  If an attempt was made to write beyond the end of the
   *                       array.
   */
  @Override()
  public void write(@NotNull final byte[] b, final int off, final int len)
         throws IOException
  {
    Validator.ensureTrue((off >= 0),
         "The provided offset must be greater than or equal to zero.");
    Validator.ensureTrue((len >= 0),
         "The provided length must be greater than or equal to zero.");
    Validator.ensureTrue(((off + len) <= b.length),
         "The sum of off and len must not exceed the array length.");

    if ((pos + len) > maxPosition)
    {
      throw new IOException(ERR_FIXED_ARRAY_OS_WRITE_BEYOND_END.get());
    }

    System.arraycopy(b, off, array, pos, len);
    pos += len;
  }
}
