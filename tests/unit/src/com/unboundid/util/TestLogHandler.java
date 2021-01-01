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



import java.util.LinkedList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;



/**
 * This class provides an implementation of a log handler that we can use for
 * testing purposes.
 */
public class TestLogHandler
       extends Handler
{
  // An atomic integer that will be used to keep track of the number of times
  // log messages have been written to this logger.
  private int messageCount;

  // The list that will be used to hold messages read.
  private LinkedList<LogRecord> messageList;



  /**
   * Creates a new instance of this test log handler.
   */
  public TestLogHandler()
  {
    messageCount = 0;
    messageList  = new LinkedList<LogRecord>();
  }



  /**
   * Closes this logger.  This has no effect.
   */
  @Override()
  public void close()
  {
    // No implementation is required.
  }



  /**
   * Flushes any buffered output.  This has no effect.
   */
  @Override()
  public void flush()
  {
    // No implementation is required.
  }



  /**
   * Publishes the provided log record.  This will simply increment the message
   * counter.
   *
   * @param  record  The record to be published.
   */
  @Override()
  public synchronized void publish(final LogRecord record)
  {
    messageCount++;
    messageList.add(record);

    // In case this gets used while other tests are running, we'll cap the size
    // of the message list to avoid running out of memory.
    if (messageCount > 50)
    {
      messageList.removeFirst();
    }
  }



  /**
   * Gets the current message count for this test log handler.
   *
   * @return  The current message count for this test log handler.
   */
  public synchronized int getMessageCount()
  {
    return messageCount;
  }



  /**
   * Resets the message count so that the next call to {@code publish} will be
   * recorded as the first invocation.
   */
  public synchronized void resetMessageCount()
  {
    messageCount = 0;
    messageList.clear();
  }



  /**
   * Retrieves a string representation of all messages held in this handler.
   *
   * @return  A string representation of all messages held in this handler.
   */
  public synchronized String getMessagesString()
  {
    StringBuilder buffer = new StringBuilder();
    String EOL = System.getProperty("line.separator", "\n");

    for (LogRecord r : messageList)
    {
      String message = r.getMessage();
      buffer.append(message);
      buffer.append(EOL);
    }

    return buffer.toString();
  }
}
