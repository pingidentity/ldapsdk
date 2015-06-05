/*
 * Copyright 2009-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides a mechanism for reading message from a Directory Server
 * error log.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ErrorLogReader
{
  // The reader used to read the contents of the log file.
  private final BufferedReader reader;



  /**
   * Creates a new error log reader that will read messages from the specified
   * log file.
   *
   * @param  path  The path of the log file to read.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public ErrorLogReader(final String path)
         throws IOException
  {
    reader = new BufferedReader(new FileReader(path));
  }



  /**
   * Creates a new error log reader that will read messages from the specified
   * log file.
   *
   * @param  file  The log file to read.
   *
   * @throws  IOException  If a problem occurs while opening the file for
   *                       reading.
   */
  public ErrorLogReader(final File file)
         throws IOException
  {
    reader = new BufferedReader(new FileReader(file));
  }



  /**
   * Creates a new error log reader that will read messages using the provided
   * {@code Reader} object.
   *
   * @param  reader  The reader to use to read log messages.
   */
  public ErrorLogReader(final Reader reader)
  {
    if (reader instanceof BufferedReader)
    {
      this.reader = (BufferedReader) reader;
    }
    else
    {
      this.reader = new BufferedReader(reader);
    }
  }



  /**
   * Reads the next error log message from the log file.
   *
   * @return  The error log message read from the log file, or {@code null} if
   *          there are no more messages to be read.
   *
   * @throws  IOException  If an error occurs while trying to read from the
   *                       file.
   *
   * @throws  LogException  If an error occurs while trying to parse the log
   *                        message.
   */
  public ErrorLogMessage read()
         throws IOException, LogException
  {
    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        return null;
      }

      if ((line.length() == 0) || (line.charAt(0) == '#'))
      {
        continue;
      }

      return new ErrorLogMessage(line);
    }
  }



  /**
   * Closes this error log reader.
   *
   * @throws  IOException  If a problem occurs while closing the reader.
   */
  public void close()
         throws IOException
  {
    reader.close();
  }
}
