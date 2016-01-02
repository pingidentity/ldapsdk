/*
 * Copyright 2009-2016 UnboundID Corp.
 * All Rights Reserved.
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
