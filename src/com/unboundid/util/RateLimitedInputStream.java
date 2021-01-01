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



import java.io.InputStream;
import java.io.IOException;



/**
 * This class provides an {@code InputStream} implementation that uses a
 * {@link FixedRateBarrier} to impose an upper bound on the rate (in bytes per
 * second) at which data can be read from a wrapped {@code InputStream}.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class RateLimitedInputStream
       extends InputStream
{
  // The fixed-rate barrier that will serve as a rate limiter for this class.
  @NotNull private final FixedRateBarrier rateLimiter;

  // The input stream from which the data will actually be read.
  @NotNull private final InputStream wrappedStream;

  // The maximum number of bytes that can be read in any single call to the
  // rate limiter.
  private final int maxBytesPerRead;



  /**
   * Creates a new instance of this rate-limited input stream that wraps the
   * provided input stream.
   *
   * @param  wrappedStream      The input stream from which the data will
   *                            actually be read.  It must not be {@code null}.
   * @param  maxBytesPerSecond  The maximum number of bytes per second that can
   *                            be read using this input stream.  It must be
   *                            greater than zero.
   */
  public RateLimitedInputStream(@NotNull final InputStream wrappedStream,
                                final int maxBytesPerSecond)
  {
    Validator.ensureTrue((wrappedStream != null),
         "RateLimitedInputStream.wrappedStream must not be null.");
    Validator.ensureTrue((maxBytesPerSecond > 0),
         "RateLimitedInputStream.maxBytesPerSecond must be greater than " +
              "zero.  The provided value was " + maxBytesPerSecond);

    this.wrappedStream = wrappedStream;

    rateLimiter = new FixedRateBarrier(1000L, maxBytesPerSecond);
    maxBytesPerRead = Math.max(1, (maxBytesPerSecond / 100));
  }



  /**
   * Closes this input stream and the wrapped stream.
   *
   * @throws  IOException  If a problem is encountered while closing the wrapped
   *                       input stream.
   */
  @Override()
  public void close()
         throws IOException
  {
    wrappedStream.close();
  }



  /**
   * Reads a single byte of input from the wrapped input stream.
   *
   * @return  The byte that was read, or -1 if the end of the input stream has
   *          been reached.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from the underlying input stream.
   */
  @Override()
  public int read()
         throws IOException
  {
    rateLimiter.await();
    return wrappedStream.read();
  }



  /**
   * Reads data from the wrapped input stream into the provided array.
   *
   * @param  b  The array into which the data will be placed.
   *
   * @return  The number of bytes that were read, or -1 if the end of the input
   *          stream has been reached.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from the underlying input stream.
   */
  @Override()
  public int read(@NotNull final byte[] b)
         throws IOException
  {
    return read(b, 0, b.length);
  }



  /**
   * Reads data from the wrapped input stream into the specified portion of the
   * provided array.
   *
   * @param  b       The array into which the data will be placed.
   * @param  offset  The index into the provided array at which the data should
   *                 start being added.
   * @param  length  The maximum number of bytes to be added into the array.
   *
   * @return  The number of bytes that were read, or -1 if the end of the input
   *          stream has been reached.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from the underlying input stream.
   */
  @Override()
  public int read(@NotNull final byte[] b, final int offset, final int length)
         throws IOException
  {
    if (length <= 0)
    {
      return 0;
    }

    if (length <= maxBytesPerRead)
    {
      rateLimiter.await(length);
      return wrappedStream.read(b, offset, length);
    }
    else
    {
      int pos = offset;
      int remainingLength = length;
      int totalBytesRead = 0;
      while (remainingLength > 0)
      {
        final int lengthThisRead = Math.min(remainingLength, maxBytesPerRead);
        rateLimiter.await(lengthThisRead);
        final int bytesRead = wrappedStream.read(b, pos, lengthThisRead);
        if (bytesRead < 0)
        {
          break;
        }

        pos += bytesRead;
        totalBytesRead += bytesRead;
        remainingLength -= bytesRead;
      }

      return totalBytesRead;
    }
  }



  /**
   * Retrieves the number of bytes that are immediately available to be read,
   * if the wrapped stream supports this operation.
   *
   * @return  The number of bytes that are immediately available to be read, or
   *          zero if there are no bytes to be read, if the end of the input
   *          stream has been reached, or if the wrapped input stream does not
   *          support this operation.
   */
  @Override()
  public int available()
         throws IOException
  {
    return wrappedStream.available();
  }



  /**
   * Indicates whether this {@code InputStream} implementation supports the use
   * of the {@link #mark(int)} and {@link #reset()} methods.  This
   * implementation will support those methods if the wrapped stream supports
   * them.
   *
   * @return  {@code true} if this {@code InputStream} supports the
   *          {@code mark} and {@code reset} methods, or {@code false} if not.
   */
  @Override()
  public boolean markSupported()
  {
    return wrappedStream.markSupported();
  }



  /**
   * Attempts to mark the current position in the wrapped input stream so that
   * it can optionally be reset after some amount of data has been read.
   * fun
   *
   * @param  readLimit  The maximum number of bytes expected to be read before a
   *                    call to the {@link #reset()} method before the mark will
   *                    no longer be honored.
   */
  @Override()
  public void mark(final int readLimit)
  {
    wrappedStream.mark(readLimit);
  }



  /**
   * Attempts to reset the position of this input stream to the last mark
   * position.
   *
   * @throws  IOException  If the input stream cannot be repositioned to the
   *                       marked location, or if no mark has been set.
   */
  @Override()
  public void reset()
         throws IOException
  {
    wrappedStream.reset();
  }
}
