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



import java.util.ArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;



/**
 * This class provides a Java logging handler that holds all messages logged in
 * memory in a list that can be retrieved and cleared at any time.
 */
public final class MemoryBasedLogHandler
       extends Handler
{
  // The list that will hold the messages that have been logged.
  private final ArrayList<String> messageList;



  /**
   * Creates a new instance of this log handler.
   */
  public MemoryBasedLogHandler()
  {
    messageList = new ArrayList<>(100);
  }



  /**
   * Logs the provided record by adding its string representation to the
   * in-memory list.
   *
   * @param  record  The record to be logged.
   */
  @Override()
  public synchronized void publish(final LogRecord record)
  {
    messageList.add(getFormatter().format(record));
  }



  /**
   * Flushes any output.  This has no effect.
   */
  @Override()
  public void flush()
  {
    // No implementation required.
  }



  /**
   * Closes this log handler.  This will clear the message list, but it may
   * still continue to be used.
   */
  @Override()
  public synchronized void close()
  {
    messageList.clear();
  }



  /**
   * Retrieves the messages that have been logged so far.
   *
   * @param  clear  Indicates whether to clear the list of messages before
   *                returning.
   *
   * @return  The messages that have been logged so far.
   */
  public synchronized String[] getMessages(final boolean clear)
  {
    final String[] messageArray = new String[messageList.size()];
    messageList.toArray(messageArray);

    if (clear)
    {
      messageList.clear();
    }

    return messageArray;
  }



  /**
   * Clears the message list.
   */
  public synchronized void clear()
  {
    messageList.clear();
  }



  /**
   * Retrieves the number of messages currently available to be read.
   *
   * @return  The number of messages currently available to be read.
   */
  public synchronized int size()
  {
    return messageList.size();
  }
}
