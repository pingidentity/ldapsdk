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



import java.io.File;
import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class defines a stream file value pattern component, which may be used
 * to provide string values read from a specified local file.  Values will only
 * be accessed in sequential order, and only a relatively small amount of data
 * will be held in memory at any given time, so this may be a suitable option
 * for dealing with very large files.
 */
final class StreamFileValuePatternComponent
      extends ValuePatternComponent
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4557045230341165225L;



  // A value that tracks the position at which the next line of data should be
  // read from the file.
  @NotNull private final AtomicLong nextReadPosition;

  // A reference that holds this thread and makes it available to the associated
  // StreamFileValuePatternComponent.
  @NotNull private final AtomicReference<StreamFileValuePatternReaderThread>
       threadRef;

  // The file from which the data will be read.
  @NotNull private final File file;

  // The queue that will be used to hold the lines of data read from the file.
  @NotNull private final LinkedBlockingQueue<String> lineQueue;

  // The maximum length of time in milliseconds that an attempt to offer a
  // string to the queue will be allowed to block before the associated reader
  // thread will exit.
  private final long maxOfferBlockTimeMillis;



  /**
   * Creates a new stream file value pattern component that will read data from
   * the specified file.  It will use a queue size of 1000 strings and a maximum
   * block time of 60,000 milliseconds (1 minute).
   *
   * @param  path  The path to the file from which data is to be read.
   *
   * @throws  IOException  If a problem is encountered while trying to open the
   *                       specified file for reading.
   */
  StreamFileValuePatternComponent(@NotNull final String path)
       throws IOException
  {
    this(path, 10_000, 60_000L);
  }



  /**
   * Creates a new stream file value pattern component that will read data from
   * the specified file.
   *
   * @param  path                     The path to the file from which data is to
   *                                  be read.  It must not be {@code null}, and
   *                                  it must reference a file that exists.
   * @param  queueSize                The maximum number of lines read from the
   *                                  file that should be held in memory at any
   *                                  given time.  It must be greater than zero.
   * @param  maxOfferBlockTimeMillis  The maximum length of time in milliseconds
   *                                  that an attempt to offer a string into the
   *                                  queue will be allowed to block before the
   *                                  associated reader thread will exit.  It
   *                                  must be greater than zero.
   *
   * @throws  IOException  If a problem is encountered while trying to open the
   *                       specified file for reading.
   */
  StreamFileValuePatternComponent(@NotNull final String path,
                                  final int queueSize,
                                  final long maxOfferBlockTimeMillis)
       throws IOException
  {
    Validator.ensureNotNull(path);
    Validator.ensureTrue(queueSize > 0);
    Validator.ensureTrue(maxOfferBlockTimeMillis > 0L);

    this.maxOfferBlockTimeMillis = maxOfferBlockTimeMillis;

    file = new File(path);
    if (! file.exists())
    {
      throw new IOException(ERR_STREAM_FILE_VALUE_PATTERN_PATH_MISSING.get(
           file.getAbsolutePath()));
    }

    if (! file.isFile())
    {
      throw new IOException(ERR_STREAM_FILE_VALUE_PATTERN_PATH_NOT_FILE.get(
           file.getAbsolutePath()));
    }

    if (file.length() <= 0)
    {
      throw new IOException(ERR_STREAM_FILE_VALUE_PATTERN_FILE_EMPTY.get(
           file.getAbsolutePath()));
    }

    lineQueue = new LinkedBlockingQueue<>(queueSize);
    nextReadPosition = new AtomicLong(0L);
    threadRef = new AtomicReference<>();

    final StreamFileValuePatternReaderThread readerThread =
         new StreamFileValuePatternReaderThread(file, lineQueue,
              maxOfferBlockTimeMillis, nextReadPosition, threadRef);
    threadRef.set(readerThread);
    readerThread.start();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  void append(@NotNull final StringBuilder buffer)
  {
    String line = lineQueue.poll();
    if (line != null)
    {
      buffer.append(line);
      return;
    }

    while (true)
    {
      try
      {
        StreamFileValuePatternReaderThread readerThread;
        synchronized (this)
        {
          readerThread = threadRef.get();
          if (readerThread == null)
          {
            readerThread = new StreamFileValuePatternReaderThread(file,
                 lineQueue, maxOfferBlockTimeMillis, nextReadPosition,
                 threadRef);
            threadRef.set(readerThread);
            readerThread.start();
          }
        }

        line = lineQueue.poll(10L, TimeUnit.MILLISECONDS);
        if (line != null)
        {
          buffer.append(line);
          return;
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPRuntimeException(
             new LDAPException(ResultCode.LOCAL_ERROR,
                  ERR_STREAM_FILE_VALUE_PATTERN_ERROR_GETTING_NEXT_VALUE.get(
                       file.getAbsolutePath(),
                       StaticUtils.getExceptionMessage(e)),
                  e));
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  boolean supportsBackReference()
  {
    return true;
  }
}
