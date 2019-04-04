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



import java.io.OutputStream;
import java.util.TimerTask;



/**
 * This class implements a timer task that works in conjunction with the
 * {@link WriteWithTimeout} class to close an output stream if an attempt to
 * write data to it blocks for longer than a specified length of time.
 */
final class WriteWithTimeoutTimerTask
      extends TimerTask
{
  // Indicates whether the write attempt completed.
  private volatile boolean writeCompleted;

  // The output stream to be closed if the write attempt did not complete within
  // an acceptable length of time.
  private final OutputStream outputStream;



  /**
   * Creates a new instance of this timer task that will close the provided
   * output stream if the write does not complete within the acceptable timeout
   * period.
   *
   * @param  outputStream  The output stream to be closed.  It must not be
   *                       {@code null}.
   */
  WriteWithTimeoutTimerTask(final OutputStream outputStream)
  {
    this.outputStream = outputStream;
    writeCompleted = false;
  }



  /**
   * Closes the associated output stream if the attempted write has not yet
   * completed.
   */
  @Override()
  public void run()
  {
    if (! writeCompleted)
    {
      try
      {
        outputStream.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Indicates that the write completed, that the socket should not be closed,
   * and that this timer task should be cancelled.
   */
  void writeCompleted()
  {
    writeCompleted = true;
    cancel();
  }
}
