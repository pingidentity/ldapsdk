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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;



/**
 * This class provides a background thread that will be used to read data from
 * a file and make it available for consumption by a
 * {@link StreamFileValuePatternComponent} instance.  This thread will
 * automatically close the associated file and exit after a period of
 * inactivity.
 */
final class StreamFileValuePatternReaderThread
      extends Thread
{
  // The number of lines that have been read from the file so far.
  @NotNull private final AtomicLong nextLineNumber;

  // A reference to the reader used to read lines from the file.
  @NotNull private final AtomicReference<BufferedReader> fileReader;

  // A reference that holds this thread and makes it available to the associated
  // StreamFileValuePatternComponent.
  @NotNull private final AtomicReference<StreamFileValuePatternReaderThread>
       threadRef;

  // The file from which the data is to be read.
  @NotNull private final File file;

  // The queue that will be used to hold the lines of data read from the file.
  @NotNull private final LinkedBlockingQueue<String> lineQueue;

  // The maximum length of time in milliseconds that an attempt to offer a
  // string to the queue will be allowed to block before the associated reader
  // thread will exit.
  private final long maxOfferBlockTimeMillis;



  /**
   * Creates a new reader thread instance that will read data from the specified
   * file.
   *
   * @param  file                     The file from which the data is to be
   *                                  read.  It must not be {@code null}, and it
   *                                  must reference a file that exists.
   * @param  lineQueue                The queue that will be used to hold the
   *                                  lines of data read from the file.  It must
   *                                  not be {@code null}.
   * @param  maxOfferBlockTimeMillis  The maximum length of time in milliseconds
   *                                  that an attempt to offer a string into the
   *                                  queue will be allowed to block before the
   *                                  associated reader thread will exit.  It
   *                                  must be greater than zero.
   * @param  nextLineNumber           The line number for the next line to read
   *                                  from the file.  It must not be
   *                                  {@code null}.
   * @param  threadRef                An object that will be used to hold a
   *                                  reference to this thread from within the
   *                                  associated
   *                                  {@link StreamFileValuePatternComponent}.
   *                                  This thread will clear out the reference
   *                                  when it exits as a signal that a new
   *                                  thread may need to be created.
   *
   * @throws  IOException  If a problem is encountered while attempting to open
   *                       the specified file for reading.
   */
  StreamFileValuePatternReaderThread(@NotNull final File file,
       @NotNull final LinkedBlockingQueue<String> lineQueue,
       final long maxOfferBlockTimeMillis,
       @NotNull final AtomicLong nextLineNumber,
       @NotNull final AtomicReference<StreamFileValuePatternReaderThread>
            threadRef)
       throws IOException
  {
    setName("StreamFileValuePatternReaderThread for file '" +
         file.getAbsolutePath() + '\'');
    setDaemon(true);

    this.file = file;
    this.lineQueue = lineQueue;
    this.maxOfferBlockTimeMillis = maxOfferBlockTimeMillis;
    this.nextLineNumber = nextLineNumber;
    this.threadRef = threadRef;

    final BufferedReader bufferedReader =
         new BufferedReader(new FileReader(file));
    fileReader = new AtomicReference<>(bufferedReader);

    final long linesToSkip = nextLineNumber.get();
    for (long i =0; i < linesToSkip; i++)
    {
      if (bufferedReader.readLine() == null)
      {
        break;
      }
    }
  }



  /**
   * Operates in a loop, reading data from the specified file and offering it to
   * the provided queue.  If the offer attempt blocks for longer than the
   * configured maximum offer block time, the file will be closed and the thread
   * will exit.
   */
  @Override()
  public void run()
  {
    BufferedReader bufferedReader = fileReader.get();

    try
    {
      while (true)
      {
        // Read the next line of data from the file.  If we hit the end of the
        // file, then reset the next line number to zero and re-open the file.
        // If we encounter an error, then the thread will exit.
        final String line;
        try
        {
          line = bufferedReader.readLine();
          if (line == null)
          {
            nextLineNumber.set(0);
            bufferedReader.close();
            bufferedReader = new BufferedReader(new FileReader(file));
            fileReader.set(bufferedReader);
            continue;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          nextLineNumber.set(0L);
          return;
        }


        // Offer the line that we read to the queue.  If it succeeds, then
        // update the next read position to reflect our current position in the
        // file.  If it times out, or if we encounter an error, then exit this
        // thread without updating the position, which will cause the next read
        // attempt from the next thread instance to pick up where this one left
        // off.
        try
        {
          if (lineQueue.offer(line, maxOfferBlockTimeMillis,
               TimeUnit.MILLISECONDS))
          {
            nextLineNumber.incrementAndGet();
          }
          else
          {
            return;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          return;
        }
      }
    }
    finally
    {
      // Clear the reference to this thread from the associated value pattern
      // component.
      threadRef.set(null);


      // Close the file.
      try
      {
        bufferedReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
      finally
      {
        fileReader.set(null);
      }
    }
  }
}
