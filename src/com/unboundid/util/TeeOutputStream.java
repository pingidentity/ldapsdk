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



import java.io.OutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;



/**
 * This class provides an {@code OutputStream} implementation that can cause
 * everything provided to it to be written to multiple output streams (e.g.,
 * to both a file and to standard output, or to both a file and a network
 * socket).  Any number of destination streams (including zero, if desired) may
 * be specified.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TeeOutputStream
       extends OutputStream
{
  // The set of target output streams to which any data received will be
  // written.
  @NotNull private final List<OutputStream> streams;



  /**
   * Creates a new instance of this output stream that will write any data
   * received to each of the provided target streams.
   *
   * @param  targetStreams  The set of output streams to which any data received
   *                        will be written.  If it is {@code null} or empty,
   *                        then any data received will simply be discarded.
   */
  public TeeOutputStream(@Nullable final OutputStream... targetStreams)
  {
    if (targetStreams == null)
    {
      streams = Collections.emptyList();
    }
    else
    {
      streams = Collections.unmodifiableList(
           new ArrayList<>(Arrays.asList(targetStreams)));
    }
  }



  /**
   * Creates a new instance of this output stream that will write any data
   * received to each of the provided target streams.
   *
   * @param  targetStreams  The set of output streams to which any data received
   *                        will be written.  If it is {@code null} or empty,
   *                        then any data received will simply be discarded.
   */
  public TeeOutputStream(
              @Nullable final Collection<? extends OutputStream> targetStreams)
  {
    if (targetStreams == null)
    {
      streams = Collections.emptyList();
    }
    else
    {
      streams = Collections.unmodifiableList(new ArrayList<>(targetStreams));
    }
  }



  /**
   * Writes the provided byte of data to each of the target output streams.
   *
   * @param  b  The byte of data to be written.  Only the lower eight bits
   *            of the provided value will be written.
   *
   * @throws  IOException  If a problem occurs while writing the provided byte
   *                       to any of the target output streams.
   */
  @Override()
  public void write(final int b)
         throws IOException
  {
    for (final OutputStream s : streams)
    {
      s.write(b);
    }
  }



  /**
   * Writes the entire contents of the provided byte array to each of the target
   * output streams.
   *
   * @param  b  The byte array containing the data to be written.
   *
   * @throws  IOException  If a problem occurs while writing the provided data
   *                       to any of the target output streams.
   */
  @Override()
  public void write(@NotNull final byte[] b)
         throws IOException
  {
    for (final OutputStream s : streams)
    {
      s.write(b);
    }
  }



  /**
   * Writes a portion of the contents of the provided byte array to each of the
   * target output streams.
   *
   * @param  b    The byte array containing the data to be written.
   * @param  off  The offset within the array at which the data should start
   *              being written.
   * @param  len  The number of bytes from the array that should be written.
   *
   * @throws  IOException  If a problem occurs while writing the provided data
   *                       to any of the target output streams.
   */
  @Override()
  public void write(@NotNull final byte[] b, final int off, final int len)
         throws IOException
  {
    for (final OutputStream s : streams)
    {
      s.write(b, off, len);
    }
  }



  /**
   * Flushes each of the target output streams to force any buffered content to
   * be written out.
   *
   * @throws  IOException  If a problem occurs while flushing any of the target
   *                       output streams.
   */
  @Override()
  public void flush()
         throws IOException
  {
    for (final OutputStream s : streams)
    {
      s.flush();
    }
  }



  /**
   * Closes each of the target output streams.
   *
   * @throws  IOException  If a problem occurs while closing any of the target
   *                       output streams.  Note that even if an exception is
   *                       thrown, an attempt will be made to close all target
   *                       streams.  If multiple target streams throw an
   *                       exception, then the first exception encountered will
   *                       be thrown.
   */
  @Override()
  public void close()
         throws IOException
  {
    IOException exceptionToThrow = null;

    for (final OutputStream s : streams)
    {
      try
      {
        s.close();
      }
      catch (final IOException ioe)
      {
        Debug.debugException(ioe);
        if (exceptionToThrow == null)
        {
          exceptionToThrow = ioe;
        }
      }
    }

    if (exceptionToThrow != null)
    {
      throw exceptionToThrow;
    }
  }
}
