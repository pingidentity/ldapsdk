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



import java.io.IOException;
import java.io.Reader;
import java.nio.CharBuffer;



/**
 * This class defines a custom reader that will throw an exception after
 * a specified amount of data has been read.
 */
public class TestReader
       extends Reader
{
  // Indicates whether to throw an exception when the reader is closed.
  private final boolean throwOnClose;

  // The number of characters that have been read so far.
  private int charsRead;

  // The number of characters that should be successfully read before throwing
  // the exception.
  private final int maxChars;

  // The exception that will be thrown.
  private final IOException ioException;

  // The underlying reader that will be used as the source.
  private final Reader reader;



  /**
   * Creates a new test reader that wraps the provided reader and will throw the
   * provided exception after the specified number of characters have been read.
   *
   * @param  reader        The reader to use as the input source.
   * @param  ioException   The exception to be thrown.
   * @param  maxChars      The number of characters to read before throwing an
   *                       exception.
   * @param  throwOnClose  Indicates whether to throw an exception when the
   *                       reader is closed.
   */
  public TestReader(final Reader reader, final IOException ioException,
                    final int maxChars, final boolean throwOnClose)
  {
    this.reader       = reader;
    this.ioException  = ioException;
    this.maxChars     = maxChars;
    this.throwOnClose = throwOnClose;

    charsRead = 0;
  }



  /**
   * Indicates whether this reader is ready to be read without blocking.
   *
   * @return  {@code true} if data is available for reading without blocking, or
   *          {@code false} if not.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public boolean ready()
         throws IOException
  {
    return reader.ready();
  }



  /**
   * Closes this reader and the underlying reader.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void close()
         throws IOException
  {
    reader.close();

    if (throwOnClose)
    {
      throw ioException;
    }
  }



  /**
   * Reads a single character from this reader.
   *
   * @return  The next character read from the reader, or a negative value to
   *          indicate that the end of the stream has been reached.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read()
         throws IOException
  {
    if (charsRead >= maxChars)
    {
      reader.close();
      throw ioException;
    }

    charsRead++;
    return reader.read();
  }



  /**
   * Reads data from the underlying reader into the provided array.
   *
   * @param  c  The array into which the data should be placed.
   *
   * @return  The number of characters read from the reader, or a negative
   *          value to indicate that the end of the stream has been reached.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read(final char[] c)
         throws IOException
  {
    return read(c, 0, c.length);
  }



  /**
   * Reads data from the underlying reader into the provided array.
   *
   * @param  c       The array into which the data should be placed.
   * @param  offset  The position in the array at which to begin adding the data
   *                 that was read.
   * @param  length  The maximum number of characters to read.
   *
   * @return  The number of characters read from the reader, or a negative value
   *          to indicate that the end of the stream has been reached.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read(final char[] c, final int offset, final int length)
         throws IOException
  {
    if (charsRead >= maxChars)
    {
      reader.close();
      throw ioException;
    }

    int numChars = Math.min(length, (maxChars - charsRead));
    charsRead += numChars;
    return reader.read(c, offset, numChars);
  }



  /**
   * Reads data from the underlying reader into the provided character buffer.
   *
   * @param  b  The buffer into which the data should be read.
   *
   * @return  The number of characters added to the buffer.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public int read(final CharBuffer b)
         throws IOException
  {
    if (charsRead >= maxChars)
    {
      reader.close();
      throw ioException;
    }

    int numChars = Math.min((b.limit() - b.position()), (maxChars - charsRead));
    for (int i=0; i < numChars; i++)
    {
      int ch = reader.read();
      charsRead++;
      if (ch < 0)
      {
        return i;
      }
      else
      {
        b.append((char) ch);
      }
    }

    return numChars;
  }



  /**
   * Reads and discards the specified number of characters from the reader.
   *
   * @param  n  The number of characters to skip.
   *
   * @return  The actual number of characters skipped.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public long skip(final long n)
         throws IOException
  {
    if (charsRead >= maxChars)
    {
      reader.close();
      throw ioException;
    }

    long numChars = Math.min(n, (maxChars - charsRead));
    charsRead += numChars;
    return reader.skip(numChars);
  }



  /**
   * Indicates whether this reader supports the mark and reset methods.
   *
   * @return  {@code true} if the mark and reset methods are supported, or
   *          {@code false} if not.
   */
  @Override()
  public boolean markSupported()
  {
    return reader.markSupported();
  }



  /**
   * Marks the current position in the reader.
   *
   * @param  readLimit  The maximum number of characters that can be read before
   *                    the mark becomes invalid.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void mark(final int readLimit)
         throws IOException
  {
    reader.mark(readLimit);
  }



  /**
   * Resets the position in this reader to the previous mark.
   *
   * @throws  IOException  If a problem occurs.
   */
  @Override()
  public void reset()
         throws IOException
  {
    reader.reset();
  }
}
