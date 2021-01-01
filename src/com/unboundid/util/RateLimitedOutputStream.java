/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



/**
 * This class provides an {@code OutputStream} implementation that uses a
 * {@link FixedRateBarrier} to impose an upper bound on the rate (in bytes per
 * second) at which data can be written to a wrapped {@code OutputStream}.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class RateLimitedOutputStream
       extends OutputStream
{
  // Indicates whether to automatically flush the stream after each write.
  private final boolean autoFlush;

  // The fixed-rate barrier that will serve as a rate limiter for this class.
  @NotNull private final FixedRateBarrier rateLimiter;

  // The output stream to which the data will actually be written.
  @NotNull private final OutputStream wrappedStream;

  // The maximum number of bytes that can be written in any single call to the
  // rate limiter.
  private final int maxBytesPerWrite;



  /**
   * Creates a new instance of this rate-limited output stream that wraps the
   * provided output stream.
   *
   * @param  wrappedStream      The output stream to which the data will
   *                            actually be written.  It must not be
   *                            {@code null}.
   * @param  maxBytesPerSecond  The maximum number of bytes per second that can
   *                            be written using this output stream.  It must be
   *                            greater than zero.
   * @param  autoFlush          Indicates whether to automatically flush the
   *                            wrapped output stream after each write.
   */
  public RateLimitedOutputStream(@NotNull final OutputStream wrappedStream,
                                 final int maxBytesPerSecond,
                                 final boolean autoFlush)
  {
    Validator.ensureTrue((wrappedStream != null),
         "RateLimitedOutputStream.wrappedStream must not be null.");
    Validator.ensureTrue((maxBytesPerSecond > 0),
         "RateLimitedOutputStream.maxBytesPerSecond must be greater than " +
              "zero.  The provided value was " + maxBytesPerSecond);

    this.wrappedStream = wrappedStream;
    this.autoFlush = autoFlush;

    rateLimiter = new FixedRateBarrier(1000L, maxBytesPerSecond);
    maxBytesPerWrite = Math.max(1, (maxBytesPerSecond / 100));
  }



  /**
   * Closes this output stream and the wrapped stream.
   *
   * @throws  IOException  If a problem is encountered while closing the wrapped
   *                       output stream.
   */
  @Override()
  public void close()
         throws IOException
  {
    wrappedStream.close();
  }



  /**
   * Writes a single byte of data to the wrapped output stream.
   *
   * @param  b  The byte of data to be written.  Only the least significant
   *            eight bits will be written.
   *
   * @throws  IOException  If a problem is encountered while writing to the
   *                       wrapped stream.
   */
  @Override()
  public void write(final int b)
         throws IOException
  {
    rateLimiter.await();
    wrappedStream.write(b);

    if (autoFlush)
    {
      wrappedStream.flush();
    }
  }



  /**
   * Writes the contents of the provided array to the wrapped output stream.
   *
   * @param  b  The byte array containing the data to be written.  It must not
   *            be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while writing to the
   *                       wrapped stream.
   */
  @Override()
  public void write(@NotNull final byte[] b)
         throws IOException
  {
    write(b, 0, b.length);
  }



  /**
   * Writes the contents of the specified portion of the provided array to the
   * wrapped output stream.
   *
   * @param  b       The byte array containing the data to be written.  It must
   *                 not be {@code null}.
   * @param  offset  The position in the provided array at which the data to
   *                 write begins.  It must be greater than or equal to zero and
   *                 less than the length of the provided array.
   * @param  length  The number of bytes to be written.  It must not be
   *                 negative, and the sum of offset and length must be less
   *                 than or equal to the length of the provided array.
   *
   * @throws  IOException  If a problem is encountered while writing to the
   *                       wrapped stream.
   */
  @Override()
  public void write(@NotNull final byte[] b, final int offset, final int length)
         throws IOException
  {
    if (length <= 0)
    {
      return;
    }

    if (length <= maxBytesPerWrite)
    {
      rateLimiter.await(length);
      wrappedStream.write(b, offset, length);
    }
    else
    {
      int pos = offset;
      int remainingToWrite = length;
      while (remainingToWrite > 0)
      {
        final int lengthThisWrite =
             Math.min(remainingToWrite, maxBytesPerWrite);
        rateLimiter.await(lengthThisWrite);
        wrappedStream.write(b, pos, lengthThisWrite);
        pos += lengthThisWrite;
        remainingToWrite -= lengthThisWrite;
      }
    }

    if (autoFlush)
    {
      wrappedStream.flush();
    }
  }



  /**
   * Flushes the contents of the wrapped stream.
   *
   * @throws  IOException  If a problem is encountered while flushing the
   *                       wrapped stream.
   */
  @Override()
  public void flush()
         throws IOException
  {
    wrappedStream.flush();
  }
}
