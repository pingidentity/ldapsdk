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



/**
 * This class defines a custom input stream that will throw an exception after
 * a specified amount of data has been read.
 */
public class TestOutputStream
       extends OutputStream
{
  // Indicates whether this output stream has been closed.
  private boolean closed;

  // Indicates whether to throw an exception when the stream is closed.
  private final boolean throwOnClose;

  // The underlying output stream that will be used as the source.
  private final OutputStream outputStream;

  // The number of bytes that have been written so far.
  private int bytesWritten;

  // The number of bytes that should be successfully written before throwing the
  // exception.
  private final int maxBytes;

  // The exception that will be thrown.
  private final IOException ioException;



  /**
   * Creates a new test output stream that wraps the provided output stream and
   * will throw the provided exception after the specified number of bytes have
   * been written.
   *
   * @param  outputStream   The output stream to use as the data source.
   * @param  ioException    The exception to be thrown.
   * @param  maxBytes       The number of bytes to written before throwing an
   *                        exception.
   * @param  throwOnClose   Indicates whether to throw an exception when the
   *                        stream is closed.
   */
  public TestOutputStream(final OutputStream outputStream,
                          final IOException ioException, final int maxBytes,
                          final boolean throwOnClose)
  {
    this.outputStream = outputStream;
    this.ioException  = ioException;
    this.maxBytes     = maxBytes;
    this.throwOnClose = throwOnClose;

    bytesWritten = 0;
    closed       = false;
  }



  /**
   * Closes this output stream and the underlying input stream.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void close()
         throws IOException
  {
    closed = true;
    outputStream.close();

    if (throwOnClose)
    {
      throw ioException;
    }
  }



  /**
   * Indicates whether this output stream has been closed.
   *
   * @return  {@code true} if this output stream has been closed, or
   *          {@code false} if not.
   */
  public boolean isClosed()
  {
    return closed;
  }



  /**
   * Flushes the underlying output stream.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void flush()
         throws IOException
  {
    outputStream.flush();
  }



  /**
   * Writes the provided byte to the underlying output stream.
   *
   * @param  b  The byte to be written.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void write(final int b)
         throws IOException
  {
    if (bytesWritten >= maxBytes)
    {
      throw ioException;
    }

    outputStream.write(b);
    bytesWritten++;
  }



  /**
   * Writes the contents of the provided array to the underlying output stream.
   *
   * @param  b  The array containing the data to be written.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void write(final byte[] b)
         throws IOException
  {
    write(b, 0, b.length);
  }



  /**
   * Writes the specified portion of the provided array to the underlying output
   * stream.
   *
   * @param  b    The array containing the data to be written.
   * @param  off  The offset within the array at which to start writing data.
   * @param  len  The number of bytes to be written.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void write(final byte[] b, final int off, final int len)
         throws IOException
  {
    if (bytesWritten >= maxBytes)
    {
      throw ioException;
    }

    final int maxLength = Math.min(len, maxBytes - bytesWritten);
    outputStream.write(b, off, maxLength);
    bytesWritten += maxLength;

    if (maxLength < len)
    {
      throw ioException;
    }
  }
}
