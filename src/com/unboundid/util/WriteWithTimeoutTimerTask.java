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
import java.net.Socket;
import java.util.TimerTask;



/**
 * This class implements a timer task that works in conjunction with the
 * {@link WriteWithTimeout} class to close a socket or an output stream if an
 * attempt to write data to it blocks for longer than a specified length of
 * time.
 */
final class WriteWithTimeoutTimerTask
      extends TimerTask
{
  // Indicates whether the write attempt completed.
  private volatile boolean writeCompleted;

  // The output stream to be closed if the write attempt did not complete within
  // an acceptable length of time.
  private final OutputStream outputStream;

  // The socket to be closed if the write attempt did not complete within an
  // acceptable length of time.
  private final Socket socket;



  /**
   * Creates a new instance of this timer task that will close the provided
   * output stream if the write does not complete within the acceptable timeout
   * period.
   *
   * @param  outputStream  The output stream to be closed if the provided
   *                       socket is {@code null}.  This must not be
   *                       {@code null}.
   * @param  socket        The socket to be closed, if available.  This may be
   *                       {@code null} if no socket is available.
   */
  WriteWithTimeoutTimerTask(final OutputStream outputStream,
                            final Socket socket)
  {
    this.outputStream = outputStream;
    this.socket = socket;
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
        if (socket == null)
        {
          outputStream.close();
        }
        else
        {
          socket.close();
        }
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
