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



import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;



/**
 * This class provides a log formatter for use in the Java logging framework
 * that may be used to minimize the formatting applied to log messages.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MinimalLogFormatter
       extends Formatter
       implements Serializable
{
  /**
   * The default format string that will be used for generating timestamps.
   */
  @NotNull public static final String DEFAULT_TIMESTAMP_FORMAT =
       "'['dd/MMM/yyyy:HH:mm:ss Z']'";



  /**
   * The set of thread-local date formatters that will be used for generating
   * message timestamps.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat> DATE_FORMATTERS =
       new ThreadLocal<>();



  /**
   * The set of thread-local buffers that will be used for generating the
   * message.
   */
  @NotNull private static final ThreadLocal<StringBuilder> BUFFERS =
       new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2884878613513769233L;



  // Indicates whether to include the log level in the message header.
  private final boolean includeLevel;

  // Indicates whether to include a line break after the header.
  private final boolean lineBreakAfterHeader;

  // Indicates whether to include a line break after the message.
  private final boolean lineBreakAfterMessage;

  // The format string that will be used to generate timestamps, if appropriate.
  @Nullable private final String timestampFormat;



  /**
   * Creates a new instance of this log formatter with the default settings.
   * Generated messages will include a timestamp generated using the format
   * string "{@code '['dd/MMM/yyyy:HH:mm:ss Z']'}", will not include the log
   * level, and will not include a line break after the timestamp or the
   * message.
   */
  public MinimalLogFormatter()
  {
    this(DEFAULT_TIMESTAMP_FORMAT, false, false, false);
  }



  /**
   * Creates a new instance of this log formatter with the provided
   * configuration.
   *
   * @param  timestampFormat        The format string used to generate
   *                                timestamps.  If this is {@code null}, then
   *                                timestamps will not be included in log
   *                                messages.
   * @param  includeLevel           Indicates whether to include the log level
   *                                in the generated messages.
   * @param  lineBreakAfterHeader   Indicates whether to insert a line break
   *                                after the timestamp and/or log level.
   * @param  lineBreakAfterMessage  Indicates whether to insert aline break
   *                                after the generated message.
   */
  public MinimalLogFormatter(@Nullable final String timestampFormat,
                             final boolean includeLevel,
                             final boolean lineBreakAfterHeader,
                             final boolean lineBreakAfterMessage)
  {
    this.timestampFormat       = timestampFormat;
    this.includeLevel          = includeLevel;
    this.lineBreakAfterHeader  = lineBreakAfterHeader;
    this.lineBreakAfterMessage = lineBreakAfterMessage;
  }



  /**
   * Formats the provided log record.
   *
   * @param  record  The log record to be formatted.
   *
   * @return  A string containing the formatted log record.
   */
  @Override()
  @NotNull()
  public String format(@NotNull final LogRecord record)
  {
    StringBuilder b = BUFFERS.get();
    if (b == null)
    {
      b = new StringBuilder();
      BUFFERS.set(b);
    }
    else
    {
      b.setLength(0);
    }

    if (timestampFormat != null)
    {
      SimpleDateFormat f = DATE_FORMATTERS.get();
      if (f == null)
      {
        f = new SimpleDateFormat(timestampFormat);
        DATE_FORMATTERS.set(f);
      }

      b.append(f.format(new Date()));
    }

    if (includeLevel)
    {
      if (b.length() > 0)
      {
        b.append(' ');
      }

      b.append(record.getLevel().toString());
    }

    if (lineBreakAfterHeader)
    {
      b.append(StaticUtils.EOL);
    }
    else if (b.length() > 0)
    {
      b.append(' ');
    }

    b.append(formatMessage(record));

    if (lineBreakAfterMessage)
    {
      b.append(StaticUtils.EOL);
    }

    return b.toString();
  }
}
