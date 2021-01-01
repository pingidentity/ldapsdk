/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides an input stream implementation that can aggregate
 * multiple input streams.  When reading data from this input stream, it will
 * read from the first input stream until the end of it is reached, at point it
 * will close it and start reading from the next one, and so on until all input
 * streams have been exhausted.  Closing the aggregate input stream will cause
 * all remaining input streams to be closed.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class AggregateInputStream
       extends InputStream
{
  // The currently-active input stream.
  @Nullable private volatile InputStream activeInputStream;

  // The iterator that will be used to access the input streams.
  @NotNull private final Iterator<InputStream> streamIterator;



  /**
   * Creates a new aggregate input stream that will use the provided set of
   * input streams.
   *
   * @param  inputStreams  The input streams to be used by this aggregate input
   *                       stream.  It must not be {@code null}.
   */
  public AggregateInputStream(@NotNull final InputStream... inputStreams)
  {
    this(StaticUtils.toList(inputStreams));
  }



  /**
   * Creates a new aggregate input stream that will use the provided set of
   * input streams.
   *
   * @param  inputStreams  The input streams to be used by this aggregate input
   *                       stream.  It must not be {@code null}.
   */
  public AggregateInputStream(
              @NotNull final Collection<? extends InputStream> inputStreams)
  {
    Validator.ensureNotNull(inputStreams);

    final ArrayList<InputStream> streamList = new ArrayList<>(inputStreams);
    streamIterator = streamList.iterator();
    activeInputStream = null;
  }



  /**
   * Creates a new aggregate input stream that will read data from the specified
   * files.
   *
   * @param  files  The set of files to be read by this aggregate input stream.
   *                It must not be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       create input streams for the provided files.
   */
  public AggregateInputStream(@NotNull final File... files)
         throws IOException
  {
    this(false, files);
  }



  /**
   * Creates a new aggregate input stream that will read data from the specified
   * files.
   *
   * @param  ensureBlankLinesBetweenFiles  Indicates whether to ensure that
   *                                       there is at least one completely
   *                                       blank line between files.  This may
   *                                       be useful when blank lines are
   *                                       used as delimiters (for example, when
   *                                       reading LDIF data), there is a chance
   *                                       that the files may not end with blank
   *                                       lines, and the inclusion of extra
   *                                       blank lines between files will not
   *                                       cause any harm.
   * @param  files                         The set of files to be read by this
   *                                       aggregate input stream.  It must not
   *                                       be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       create input streams for the provided files.
   */
  public AggregateInputStream(final boolean ensureBlankLinesBetweenFiles,
                              @NotNull final File... files)
         throws IOException
  {
    Validator.ensureNotNull(files);

    final ArrayList<InputStream> streamList = new ArrayList<>(2 * files.length);

    IOException ioException = null;
    for (final File f : files)
    {
      if (ensureBlankLinesBetweenFiles && (! streamList.isEmpty()))
      {
        final ByteStringBuffer buffer = new ByteStringBuffer(4);
        buffer.append(StaticUtils.EOL_BYTES);
        buffer.append(StaticUtils.EOL_BYTES);
        streamList.add(new ByteArrayInputStream(buffer.toByteArray()));
      }

      try
      {
        streamList.add(new FileInputStream(f));
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        ioException = ioe;
        break;
      }
    }

    if (ioException != null)
    {
      for (final InputStream s : streamList)
      {
        if (s != null)
        {
          try
          {
            s.close();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }
        }
      }

      throw ioException;
    }

    streamIterator = streamList.iterator();
    activeInputStream = null;
  }



  /**
   * Reads the next byte of data from the current active input stream, switching
   * to the next input stream in the set if appropriate.
   *
   * @return  The next byte of data that was read, or -1 if all streams have
   *          been exhausted.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from an input stream.
   */
  @Override()
  public int read()
         throws IOException
  {
    while (true)
    {
      if (activeInputStream == null)
      {
        if (streamIterator.hasNext())
        {
          activeInputStream = streamIterator.next();
          continue;
        }
        else
        {
          return -1;
        }
      }

      final int byteRead = activeInputStream.read();
      if (byteRead < 0)
      {
        activeInputStream.close();
        activeInputStream = null;
      }
      else
      {
        return byteRead;
      }
    }
  }



  /**
   * Reads data from the current active input stream into the provided array,
   * switching to the next input stream in the set if appropriate.
   *
   * @param  b  The array into which the data read should be placed, starting
   *            with an index of zero.  It must not be {@code null}.
   *
   * @return  The number of bytes read into the array, or -1 if all streams have
   *          been exhausted.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from an input stream.
   */
  @Override()
  public int read(@NotNull final byte[] b)
         throws IOException
  {
    return read(b, 0, b.length);
  }



  /**
   * Reads data from the current active input stream into the provided array,
   * switching to the next input stream in the set if appropriate.
   *
   * @param  b    The array into which the data read should be placed.  It must
   *              not be {@code null}.
   * @param  off  The position in the array at which to start writing data.
   * @param  len  The maximum number of bytes that may be read.
   *
   * @return  The number of bytes read into the array, or -1 if all streams have
   *          been exhausted.
   *
   * @throws  IOException  If a problem is encountered while attempting to read
   *                       data from an input stream.
   */
  @Override()
  public int read(@NotNull final byte[] b, final int off, final int len)
         throws IOException
  {
    while (true)
    {
      if (activeInputStream == null)
      {
        if (streamIterator.hasNext())
        {
          activeInputStream = streamIterator.next();
          continue;
        }
        else
        {
          return -1;
        }
      }

      final int bytesRead = activeInputStream.read(b, off, len);
      if (bytesRead < 0)
      {
        activeInputStream.close();
        activeInputStream = null;
      }
      else
      {
        return bytesRead;
      }
    }
  }



  /**
   * Attempts to skip and discard up to the specified number of bytes from the
   * input stream.
   *
   * @param  n  The number of bytes to attempt to skip.
   *
   * @return  The number of bytes actually skipped.
   *
   * @throws  IOException  If a problem is encountered while attempting to skip
   *                       data from the input stream.
   */
  @Override()
  public long skip(final long n)
         throws IOException
  {
    if (activeInputStream == null)
    {
      if (streamIterator.hasNext())
      {
        activeInputStream = streamIterator.next();
        return activeInputStream.skip(n);
      }
      else
      {
        return 0L;
      }
    }
    else
    {
      return activeInputStream.skip(n);
    }
  }



  /**
   * Retrieves an estimate of the number of bytes that can be read without
   * blocking.
   *
   * @return  An estimate of the number of bytes that can be read without
   *          blocking.
   *
   * @throws  IOException  If a problem is encountered while attempting to make
   *                       the determination.
   */
  @Override()
  public int available()
         throws IOException
  {
    if (activeInputStream == null)
    {
      if (streamIterator.hasNext())
      {
        activeInputStream = streamIterator.next();
        return activeInputStream.available();
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return activeInputStream.available();
    }
  }



  /**
   * Indicates whether this input stream supports the use of the {@code mark}
   * and {@code reset} methods.  This implementation does not support that
   * capability.
   *
   * @return  {@code false} to indicate that this input stream implementation
   *          does not support the use of {@code mark} and {@code reset}.
   */
  @Override()
  public boolean markSupported()
  {
    return false;
  }



  /**
   * Marks the current position in the input stream.  This input stream does not
   * support this functionality, so no action will be taken.
   *
   * @param  readLimit  The maximum number of bytes that the caller may wish to
   *                    read before being able to reset the stream.
   */
  @Override()
  public void mark(final int readLimit)
  {
    // No implementation is required.
  }



  /**
   * Attempts to reset the position of this input stream to the mark location.
   * This implementation does not support {@code mark} and {@code reset}
   * functionality, so this method will always throw an exception.
   *
   * @throws  IOException  To indicate that reset is not supported.
   */
  @Override()
  public void reset()
         throws IOException
  {
    throw new IOException(ERR_AGGREGATE_INPUT_STREAM_MARK_NOT_SUPPORTED.get());
  }



  /**
   * Closes this input stream.  All associated input streams will be closed.
   *
   * @throws  IOException  If an exception was encountered while attempting to
   *                       close any of the associated streams.  Note that even
   *                       if an exception is encountered, an attempt will be
   *                       made to close all streams.
   */
  @Override()
  public void close()
         throws IOException
  {
    IOException firstException = null;

    if (activeInputStream != null)
    {
      try
      {
        activeInputStream.close();
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        firstException = ioe;
      }
      activeInputStream = null;
    }

    while (streamIterator.hasNext())
    {
      final InputStream s = streamIterator.next();
      try
      {
        s.close();
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        if (firstException == null)
        {
          firstException = ioe;
        }
      }
    }

    if (firstException != null)
    {
      throw firstException;
    }
  }
}
