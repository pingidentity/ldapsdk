/*
 * Copyright 2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Ping Identity Corporation
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
import java.util.Timer;



/**
 * This class provides a mechanism for writing to an output stream with a
 * timeout.  If the write attempt blocks for longer than the allotted timeout
 * period, then the output stream will be closed.
 * <BR><BR>
 * This is primarily intended for use when writing to sockets, which can block
 * for an indefinite length of time if the send buffer becomes full.  The
 * SO_TIMEOUT socket option only applies to reads, and does not have any effect
 * on writes.  As such, the only way to recover from a blocked write attempt is
 * to close the output stream and thereby its underlying socket.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class WriteWithTimeout
{
  /**
   * The timer used to enforce the write timeouts.
   */
  private static final Timer TIMER =
       new Timer("WriteWithTimeoutHandler Timer", true);



  /**
   * Ensures that this utility class cannot be instantiated.
   */
  private WriteWithTimeout()
  {
    // No implementation required.
  }



  /**
   * Attempts to write the provided data to the given output stream.  If the
   * write attempt does not complete within the specified timeout, then the
   * output stream will be closed.
   *
   * @param  outputStream   The output stream to which the data is to be
   *                        written.  It must not be {@code null}.
   * @param  byteToWrite    The byte to be written.  Note that only the lower
   *                        eight bits of the value will be used.
   * @param  flush          Indicates whether to flush the output stream after
   *                        the data has been written.
   * @param  timeoutMillis  The maximum length of time, in milliseconds, that
   *                        the write attempt will be allowed to block.  If the
   *                        value is less than or equal to zero, then the write
   *                        attempt will be allowed to block indefinitely.
   *
   * @throws  IOException  If a problem is encountered while trying to write to
   *                       or flush the output stream.
   */
  public static void write(final OutputStream outputStream,
                           final int byteToWrite, final boolean flush,
                           final long timeoutMillis)
         throws IOException
  {
    write(outputStream, StaticUtils.byteArray(byteToWrite), 0, 1, flush,
         timeoutMillis);
  }



  /**
   * Attempts to write the provided data to the given output stream.  If the
   * write attempt does not complete within the specified timeout, then the
   * output stream will be closed.
   *
   * @param  outputStream   The output stream to which the data is to be
   *                        written.  It must not be {@code null}.
   * @param  data           A byte array containing the data to be written.  It
   *                        must not be {@code null}.
   * @param  flush          Indicates whether to flush the output stream after
   *                        the data has been written.
   * @param  timeoutMillis  The maximum length of time, in milliseconds, that
   *                        the write attempt will be allowed to block.  If the
   *                        value is less than or equal to zero, then the write
   *                        attempt will be allowed to block indefinitely.
   *
   * @throws  IOException  If a problem is encountered while trying to write to
   *                       or flush the output stream.
   */
  public static void write(final OutputStream outputStream, final byte[] data,
                           final boolean flush, final long timeoutMillis)
         throws IOException
  {
    write(outputStream, data, 0, data.length, flush, timeoutMillis);
  }



  /**
   * Attempts to write the provided data to the given output stream.  If the
   * write attempt does not complete within the specified timeout, then the
   * output stream will be closed.
   *
   * @param  outputStream   The output stream to which the data is to be
   *                        written.  It must not be {@code null}.
   * @param  data           A byte array containing the data to be written.  It
   *                        must not be {@code null}.
   * @param  offset         The offset within the provided array of the start of
   *                        the data to be written.  It must be greater than
   *                        or equal to zero, and less than the capacity of the
   *                        {@code data} array minus the provided {@code length}
   *                        value.
   * @param  length         The number of bytes to be written.  It must be
   *                        greater than or equal to zero and less than or
   *                        equal to the length of the {@code data array} minus
   *                        the provided {@code offset} value.
   * @param  flush          Indicates whether to flush the output stream after
   *                        the data has been written.
   * @param  timeoutMillis  The maximum length of time, in milliseconds, that
   *                        the write attempt will be allowed to block.  If the
   *                        value is less than or equal to zero, then the write
   *                        attempt will be allowed to block indefinitely.
   *
   * @throws  IOException  If a problem is encountered while trying to write to
   *                       or flush the output stream.
   */
  public static void write(final OutputStream outputStream, final byte[] data,
                           final int offset, final int length,
                           final boolean flush, final long timeoutMillis)
         throws IOException
  {
    if ((data == null) || (length == 0))
    {
      return;
    }

    if (timeoutMillis > 0L)
    {
      final WriteWithTimeoutTimerTask timerTask =
           new WriteWithTimeoutTimerTask(outputStream);
      TIMER.schedule(timerTask, timeoutMillis);
      try
      {
        outputStream.write(data, offset, length);
        if (flush)
        {
          outputStream.flush();
        }
      }
      finally
      {
        timerTask.writeCompleted();
      }
    }
    else
    {
      outputStream.write(data, offset, length);
      if (flush)
      {
        outputStream.flush();
      }
    }
  }
}
