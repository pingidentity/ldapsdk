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



import java.io.InputStream;
import java.io.IOException;



/**
 * This class defines a custom input stream that will throw an exception after
 * a specified amount of data has been read.
 */
public class TestInputStream
       extends InputStream
{
  // Indicates whether to throw an exception when the stream is closed.
  private final boolean throwOnClose;

  // The underlying input stream that will be used as the source.
  private final InputStream inputStream;

  // The number of bytes that have been read so far.
  private int bytesRead;

  // The number of bytes that should be successfully read before throwing the
  // exception.
  private final int maxBytes;

  // The exception that will be thrown.
  private final IOException ioException;



  /**
   * Creates a new test input stream that wraps the provided input stream and
   * will throw the provided exception after the specified number of bytes have
   * been read.
   *
   * @param  inputStream   The input stream to use as the data source.
   * @param  ioException   The exception to be thrown.
   * @param  maxBytes      The number of bytes to read before throwing an
   *                       exception.
   * @param  throwOnClose  Indicates whether to throw an exception when the
   *                       stream is closed.
   */
  public TestInputStream(final InputStream inputStream,
                         final IOException ioException, final int maxBytes,
                         final boolean throwOnClose)
  {
    this.inputStream  = inputStream;
    this.ioException  = ioException;
    this.maxBytes     = maxBytes;
    this.throwOnClose = throwOnClose;

    bytesRead = 0;
  }



  /**
   * Returns an estimate of the number of bytes that can be read without
   * blocking.
   *
   * @return  An estimate of the number of bytes that can be read without
   *          blocking.
   *
   * @throws  IOException  If a problem occurs while making the determination.
   */
  @Override()
  public int available()
         throws IOException
  {
    return inputStream.available();
  }



  /**
   * Closes this input stream and the underlying input stream.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void close()
         throws IOException
  {
    inputStream.close();

    if (throwOnClose)
    {
      throw ioException;
    }
  }



  /**
   * Reads a single byte from this input stream.
   *
   * @return  The next byte of data read from the input stream, or a negative
   *          value to indicate that the end of the stream has been reached.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read()
         throws IOException
  {
    if (bytesRead >= maxBytes)
    {
      inputStream.close();
      throw ioException;
    }

    bytesRead++;
    return inputStream.read();
  }



  /**
   * Reads data from the underlying input stream into the provided array.
   *
   * @param  b  The array into which the data should be placed.
   *
   * @return  The number of bytes read from the input stream, or a negative
   *          value to indicate that the end of the stream has been reached.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read(final byte[] b)
         throws IOException
  {
    return read(b, 0, b.length);
  }



  /**
   * Reads data from the underlying input stream into the provided array.
   *
   * @param  b       The array into which the data should be placed.
   * @param  offset  The position in the array at which to begin adding the data
   *                 that was read.
   * @param  length  The maximum number of bytes to read.
   *
   * @return  The number of bytes read from the input stream, or a negative
   *          value to indicate that the end of the stream has been reached.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read(final byte[] b, final int offset, final int length)
         throws IOException
  {
    if (bytesRead >= maxBytes)
    {
      inputStream.close();
      throw ioException;
    }

    int numBytes = Math.min(length, (maxBytes - bytesRead));
    bytesRead += numBytes;
    return inputStream.read(b, offset, numBytes);
  }



  /**
   * Reads and discards the specified number of bytes from the input stream.
   *
   * @param  n  The number of bytes to skip.
   *
   * @return  The actual number of bytes skipped.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public long skip(final long n)
         throws IOException
  {
    if (bytesRead >= maxBytes)
    {
      inputStream.close();
      throw ioException;
    }

    long numBytes = Math.min(n, (maxBytes - bytesRead));
    bytesRead += numBytes;
    return inputStream.skip(numBytes);
  }



  /**
   * Indicates whether this input stream supports the mark and reset methods.
   *
   * @return  {@code true} if the mark and reset methods are supported, or
   *          {@code false} if not.
   */
  @Override()
  public boolean markSupported()
  {
    return inputStream.markSupported();
  }



  /**
   * Marks the current position in the input stream.
   *
   * @param  readLimit  The maximum number of bytes that can be read before the
   *                    mark becomes invalid.
   */
  @Override()
  public void mark(final int readLimit)
  {
    inputStream.mark(readLimit);
  }



  /**
   * Resets the position in this input stream to the previous mark.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void reset()
         throws IOException
  {
    inputStream.reset();
  }
}
