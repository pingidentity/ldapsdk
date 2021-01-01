/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.android.ldap.client;



import java.text.MessageFormat;

import android.util.Log;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a simplified interface for interacting with the Android
 * logging framework.
 */
public final class Logger
{
  /**
   * The log level that should be used for debug messages.  For official
   * releases, it should be set to "Log.DEBUG", but for intermediate releases
   * you can raise it to something like Log.INFO to make the messages easier to
   * see.
   */
  private static final int LOG_LEVEL_DEBUG = Log.DEBUG;



  /**
   * Ensure that this utility class can't be instantiated.
   */
  private Logger()
  {
    // No implementation required.
  }



  /**
   * Writes an error message with the provided information.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name of the method logging this message.
   * @param  msg     The message to be written.  It must not be {@code null},
   *                 and it must not require any arguments.
   */
  public static void logError(final String tag, final String method,
                              final String msg)
  {
    if (Log.isLoggable(tag, Log.ERROR))
    {
      Log.e(tag, "Error in " + method + " -- " + msg);
    }
  }



  /**
   * Writes an error message about an exception that has been caught.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name of the method in which the exception was caught.
   *                 It must not be {@code null}.
   * @param  t       The exception that was caught.  It must not be
   *                 {@code null}.
   */
  public static void logException(final String tag, final String method,
                                  final Throwable t)
  {
    if (Log.isLoggable(tag, Log.ERROR))
    {
      Log.e(tag, "Caught in " + method + " -- " + getExceptionMessage(t), t);
    }
  }



  /**
   * Writes a warning message with the provided information.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name of the method logging this message.
   * @param  msg     The message to be written.  It must not be {@code null},
   *                 and it must not require any arguments.
   */
  public static void logWarning(final String tag, final String method,
                                final String msg)
  {
    if (Log.isLoggable(tag, Log.WARN))
    {
      Log.w(tag, "Warning in " + method + " -- " + msg);
    }
  }



  /**
   * Writes an informational message with the provided information.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name of the method logging this message.
   * @param  msg     The message to be written.  It must not be {@code null},
   *                 and it must not require any arguments.
   */
  public static void logInfo(final String tag, final String method,
                             final String msg)
  {
    if (Log.isLoggable(tag, Log.INFO))
    {
      Log.i(tag, "Info in " + method + " -- " + msg);
    }
  }



  /**
   * Writes a debug message with the provided information.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name of the method logging this message.
   * @param  msg     The message to be written.  It must not be {@code null},
   *                 and it must not require any arguments.
   */
  public static void logDebug(final String tag, final String method,
                              final String msg)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Debug in " + method + " -- " + msg);
    }
  }



  /**
   * Writes a debug message with the provided information.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name of the method logging this message.
   * @param  msg     The message to be written.  It must not be {@code null}.
   * @param  args    The arguments to include in the message.
   */
  public static void logDebug(final String tag, final String method,
                              final String msg, final Object... args)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Debug in " + method + " -- " +
           MessageFormat.format(msg, args));
    }
  }



  /**
   * Writes a debug message with information about method entry.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method being invoked.  It must not be
   *                 {@code null}.
   */
  public static void logEnter(final String tag, final String method)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Enter " + method + "()");
    }
  }



  /**
   * Writes a debug message with information about method entry.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method being invoked.  It must not be
   *                 {@code null}.
   * @param  arg1    The first argument for the method.
   */
  public static void logEnter(final String tag, final String method,
                              final Object arg1)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Enter " + method + "(arg1=" + arg1 + ')');
    }
  }



  /**
   * Writes a debug message with information about method entry.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method being invoked.  It must not be
   *                 {@code null}.
   * @param  arg1    The first argument for the method.
   * @param  arg2    The second argument for the method.
   */
  public static void logEnter(final String tag, final String method,
                              final Object arg1, final Object arg2)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Enter " + method + "(arg1=" + arg1 + ", arg2=" + arg2 + ')');
    }
  }



  /**
   * Writes a debug message with information about method entry.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method being invoked.  It must not be
   *                 {@code null}.
   * @param  arg1    The first argument for the method.
   * @param  arg2    The second argument for the method.
   * @param  arg3    The third argument for the method.
   */
  public static void logEnter(final String tag, final String method,
                              final Object arg1, final Object arg2,
                              final Object arg3)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Enter " + method + "(arg1=" + arg1 + ", arg2=" + arg2 +
           ", arg3=" + arg3 + ')');
    }
  }



  /**
   * Writes a debug message with information about method entry.
   *
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method being invoked.  It must not be
   *                 {@code null}.
   * @param  arg1    The first argument for the method.
   * @param  arg2    The second argument for the method.
   * @param  arg3    The third argument for the method.
   * @param  arg4    The fourth argument for the method.
   */
  public static void logEnter(final String tag, final String method,
                              final Object arg1, final Object arg2,
                              final Object arg3, final Object arg4)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Enter " + method + "(arg1=" + arg1 + ", arg2=" + arg2 +
           ", arg3=" + arg3 + ", arg4=" + arg4 + ')');
    }
  }



  /**
   * Writes a debug message with information about method entry.
   *
   * @param  tag            The tag for the message to be written.  It must not
   *                        be {@code null}.
   * @param  method         The name for the method being invoked.  It must not
   *                        be {@code null}.
   * @param  arg1           The first argument for the method.
   * @param  arg2           The second argument for the method.
   * @param  arg3           The third argument for the method.
   * @param  arg4           The fourth argument for the method.
   * @param  remainingArgs  The remaining arguments for the method.
   */
  public static void logEnter(final String tag, final String method,
                              final Object arg1, final Object arg2,
                              final Object arg3, final Object arg4,
                              final Object... remainingArgs)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      final StringBuilder buffer = new StringBuilder();
      buffer.append("Enter ");
      buffer.append(method);
      buffer.append("(arg1=");
      buffer.append(arg1);
      buffer.append(", arg2=");
      buffer.append(arg2);
      buffer.append(", arg3=");
      buffer.append(arg3);
      buffer.append(", arg4=");
      buffer.append(arg4);

      int i=5;
      for (final Object o : remainingArgs)
      {
        buffer.append(", arg");
        buffer.append(i++);
        buffer.append('=');
        buffer.append(o);
      }

      buffer.append(')');

      Log.i(tag, buffer.toString());
    }
  }



  /**
   * Write a debug message with information about a getter.  It will log both
   * the method name and the return value.
   *
   * @param  <T>     The type for the value.
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method being invoked.  It must not be
   *                 {@code null}.
   * @param  value   The value that will be returned.
   *
   * @return  The provided value.
   */
  public static <T> T logGetter(final String tag, final String method,
                                final T value)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Getter " + method + "() returning " + value);
    }

    return value;
  }



  /**
   * Writes a debug message with information about a method returning a value.
   *
   * @param  <T>     The type for the value.
   * @param  tag     The tag for the message to be written.  It must not be
   *                 {@code null}.
   * @param  method  The name for the method returning the value.  It must not
   *                 be {@code null}.
   * @param  value   The value being returned.
   *
   * @return  The provided value.
   */
  public static <T> T logReturn(final String tag, final String method,
                                final T value)
  {
    if (Log.isLoggable(tag, LOG_LEVEL_DEBUG))
    {
      Log.i(tag, "Return " + method + " -> " + value);
    }

    return value;
  }
}
