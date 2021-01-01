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



import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.sdk.AbstractConnectionPool;
import com.unboundid.ldap.sdk.DisconnectType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPRequest;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldif.LDIFRecord;
import com.unboundid.util.json.JSONBuffer;



/**
 * This class provides a means of enabling and configuring debugging in the LDAP
 * SDK.
 * <BR><BR>
 * Access to debug information can be enabled through applications that use the
 * SDK by calling the {@link Debug#setEnabled} methods, or it can also be
 * enabled without any code changes through the use of system properties.  In
 * particular, the {@link Debug#PROPERTY_DEBUG_ENABLED},
 * {@link Debug#PROPERTY_DEBUG_LEVEL}, and {@link Debug#PROPERTY_DEBUG_TYPE}
 * properties may be used to control debugging without the need to alter any
 * code within the application that uses the SDK.
 * <BR><BR>
 * The LDAP SDK debugging subsystem uses the Java logging framework available
 * through the {@code java.util.logging} package with a logger name of
 * "{@code com.unboundid.ldap.sdk}".  The {@link Debug#getLogger} method may
 * be used to access the logger instance used by the LDAP SDK.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process that may be used to enable
 * debugging within the LDAP SDK and write information about all messages with
 * a {@code WARNING} level or higher to a specified file:
 * <PRE>
 * Debug.setEnabled(true);
 * Logger logger = Debug.getLogger();
 *
 * FileHandler fileHandler = new FileHandler(logFilePath);
 * fileHandler.setLevel(Level.WARNING);
 * logger.addHandler(fileHandler);
 * </PRE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Debug
       implements Serializable
{
  /**
   * The name of the system property that will be used to enable debugging in
   * the UnboundID LDAP SDK for Java.  The fully-qualified name for this
   * property is "{@code com.unboundid.ldap.sdk.debug.enabled}".  If it is set,
   * then it should have a value of either "true" or "false".
   */
  @NotNull public static final String PROPERTY_DEBUG_ENABLED =
       "com.unboundid.ldap.sdk.debug.enabled";



  /**
   * The name of the system property that may be used to indicate whether stack
   * trace information for the thread calling the debug method should be
   * included in debug log messages.  The fully-qualified name for this property
   * is "{@code com.unboundid.ldap.sdk.debug.includeStackTrace}".  If it is set,
   * then it should have a value of either "true" or "false".
   */
  @NotNull public static final String PROPERTY_INCLUDE_STACK_TRACE =
       "com.unboundid.ldap.sdk.debug.includeStackTrace";



  /**
   * The name of the system property that will be used to set the initial level
   * for the debug logger.  The fully-qualified name for this property is
   * "{@code com.unboundid.ldap.sdk.debug.level}".  If it is set, then it should
   * be one of the strings "{@code SEVERE}", "{@code WARNING}", "{@code INFO}",
   * "{@code CONFIG}", "{@code FINE}", "{@code FINER}", or "{@code FINEST}".
   */
  @NotNull public static final String PROPERTY_DEBUG_LEVEL =
       "com.unboundid.ldap.sdk.debug.level";



  /**
   * The name of the system property that will be used to indicate that
   * debugging should be enabled for specific types of messages.  The
   * fully-qualified name for this property is
   * "{@code com.unboundid.ldap.sdk.debug.type}". If it is set, then it should
   * be a comma-delimited list of the names of the desired debug types.  See the
   * {@link DebugType} enum for the available debug types.
   */
  @NotNull public static final String PROPERTY_DEBUG_TYPE =
       "com.unboundid.ldap.sdk.debug.type";



  /**
   * The name of the system property that will be used to indicate whether the
   * LDAP SDK should default to including information about the exception's
   * cause in an exception message obtained from the
   * {@link StaticUtils#getExceptionMessage(Throwable)} method.  By default,
   * the cause will not be included in most messages.
   */
  @NotNull public static final String
       PROPERTY_INCLUDE_CAUSE_IN_EXCEPTION_MESSAGES =
            "com.unboundid.ldap.sdk.debug.includeCauseInExceptionMessages";



  /**
   * The name of the system property that will be used to indicate whether the
   * LDAP SDK should default to including a full stack trace (albeit in
   * condensed form) in an exception message obtained from the
   * {@link StaticUtils#getExceptionMessage(Throwable)} method.  By default,
   * stack traces will not be included in most messages.
   */
  @NotNull public static final String
       PROPERTY_INCLUDE_STACK_TRACE_IN_EXCEPTION_MESSAGES =
            "com.unboundid.ldap.sdk.debug.includeStackTraceInExceptionMessages";



  /**
   * The name that will be used for the Java logger that will actually handle
   * the debug messages if debugging is enabled.
   */
  @NotNull public static final String LOGGER_NAME = "com.unboundid.ldap.sdk";



  /**
   * The logger that will be used to handle the debug messages if debugging is
   * enabled.
   */
  @NotNull private static final Logger logger = Logger.getLogger(LOGGER_NAME);



  /**
   * A set of thread-local formatters that may be used to generate timestamps.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       TIMESTAMP_FORMATTERS = new ThreadLocal<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6079754380415146030L;



  // Indicates whether any debugging is currently enabled for the SDK.
  private static boolean debugEnabled;

  // Indicates whether to capture a thread stack trace whenever a debug message
  // is logged.
  private static boolean includeStackTrace;

  // The set of debug types for which debugging is enabled.
  @NotNull private static EnumSet<DebugType> debugTypes=
       EnumSet.allOf(DebugType.class);



  static
  {
    initialize(StaticUtils.getSystemProperties(PROPERTY_DEBUG_ENABLED,
         PROPERTY_DEBUG_LEVEL, PROPERTY_DEBUG_TYPE,
         PROPERTY_INCLUDE_STACK_TRACE));
  }



  /**
   * Prevent this class from being instantiated.
   */
  private Debug()
  {
    // No implementation is required.
  }



  /**
   * Initializes this debugger with the default settings.  Debugging will be
   * disabled, the set of debug types will include all types, and the debug
   * level will be "ALL".
   */
  public static void initialize()
  {
    includeStackTrace = false;
    debugEnabled      = false;
    debugTypes        = EnumSet.allOf(DebugType.class);

    StaticUtils.setLoggerLevel(logger, Level.ALL);
  }



  /**
   * Initializes this debugger with settings from the provided set of
   * properties.  Any debug setting that isn't configured in the provided
   * properties will be initialized with its default value.
   *
   * @param  properties  The set of properties to use to initialize this
   *                     debugger.
   */
  public static void initialize(@Nullable final Properties properties)
  {
    // First, apply the default values for the properties.
    initialize();
    if ((properties == null) || properties.isEmpty())
    {
      // No properties were provided, so we don't need to do anything.
      return;
    }

    final String enabledProp = properties.getProperty(PROPERTY_DEBUG_ENABLED);
    if ((enabledProp != null) && (! enabledProp.isEmpty()))
    {
      if (enabledProp.equalsIgnoreCase("true"))
      {
        debugEnabled = true;
      }
      else if (enabledProp.equalsIgnoreCase("false"))
      {
        debugEnabled = false;
      }
      else
      {
        throw new IllegalArgumentException("Invalid value '" + enabledProp +
                                           "' for property " +
                                           PROPERTY_DEBUG_ENABLED +
                                           ".  The value must be either " +
                                           "'true' or 'false'.");
      }
    }

    final String stackProp =
         properties.getProperty(PROPERTY_INCLUDE_STACK_TRACE);
    if ((stackProp != null) && (! stackProp.isEmpty()))
    {
      if (stackProp.equalsIgnoreCase("true"))
      {
        includeStackTrace = true;
      }
      else if (stackProp.equalsIgnoreCase("false"))
      {
        includeStackTrace = false;
      }
      else
      {
        throw new IllegalArgumentException("Invalid value '" + stackProp +
                                           "' for property " +
                                           PROPERTY_INCLUDE_STACK_TRACE +
                                           ".  The value must be either " +
                                           "'true' or 'false'.");
      }
    }

    final String typesProp = properties.getProperty(PROPERTY_DEBUG_TYPE);
    if ((typesProp != null) && (! typesProp.isEmpty()))
    {
      debugTypes = EnumSet.noneOf(DebugType.class);
      final StringTokenizer t = new StringTokenizer(typesProp, ", ");
      while (t.hasMoreTokens())
      {
        final String debugTypeName = t.nextToken();
        final DebugType debugType = DebugType.forName(debugTypeName);
        if (debugType == null)
        {
          // Throw a runtime exception to indicate that the debug type is
          // invalid.
          throw new IllegalArgumentException("Invalid value '" + debugTypeName +
                      "' for property " + PROPERTY_DEBUG_TYPE +
                      ".  Allowed values include:  " +
                      DebugType.getTypeNameList() + '.');
        }
        else
        {
          debugTypes.add(debugType);
        }
      }
    }

    final String levelProp = properties.getProperty(PROPERTY_DEBUG_LEVEL);
    if ((levelProp != null) && (! levelProp.isEmpty()))
    {
      StaticUtils.setLoggerLevel(logger, Level.parse(levelProp));
    }
  }



  /**
   * Retrieves the logger that will be used to write the debug messages.
   *
   * @return  The logger that will be used to write the debug messages.
   */
  @NotNull()
  public static Logger getLogger()
  {
    return logger;
  }



  /**
   * Indicates whether any form of debugging is enabled.
   *
   * @return  {@code true} if debugging is enabled, or {@code false} if not.
   */
  public static boolean debugEnabled()
  {
    return debugEnabled;
  }



  /**
   * Indicates whether debugging is enabled for messages of the specified debug
   * type.
   *
   * @param  debugType  The debug type for which to make the determination.
   *
   * @return  {@code true} if debugging is enabled for messages of the specified
   *          debug type, or {@code false} if not.
   */
  public static boolean debugEnabled(@NotNull final DebugType debugType)
  {
    return (debugEnabled && debugTypes.contains(debugType));
  }



  /**
   * Specifies whether debugging should be enabled.  If it should be, then it
   * will be enabled for all debug types.
   *
   * @param  enabled  Specifies whether debugging should be enabled.
   */
  public static void setEnabled(final boolean enabled)
  {
    debugTypes   = EnumSet.allOf(DebugType.class);
    debugEnabled = enabled;
  }



  /**
   * Specifies whether debugging should be enabled.  If it should be, then it
   * will be enabled for all debug types in the provided set.
   *
   * @param  enabled  Specifies whether debugging should be enabled.
   * @param  types    The set of debug types that should be enabled.  It may be
   *                  {@code null} or empty to indicate that it should be for
   *                  all debug types.
   */
  public static void setEnabled(final boolean enabled,
                                @Nullable final Set<DebugType> types)
  {
    if ((types == null) || types.isEmpty())
    {
      debugTypes = EnumSet.allOf(DebugType.class);
    }
    else
    {
      debugTypes = EnumSet.copyOf(types);
    }

    debugEnabled = enabled;
  }



  /**
   * Indicates whether log messages should include a stack trace of the thread
   * that invoked the debug method.
   *
   * @return  {@code true} if log messages should include a stack trace of the
   *          thread that invoked the debug method, or {@code false} if not.
   */
  public static boolean includeStackTrace()
  {
    return includeStackTrace;
  }



  /**
   * Specifies whether log messages should include a stack trace of the thread
   * that invoked the debug method.
   *
   * @param  includeStackTrace  Indicates whether log messages should include a
   *                            stack trace of the thread that invoked the debug
   *                            method.
   */
  public static void setIncludeStackTrace(final boolean includeStackTrace)
  {
    Debug.includeStackTrace = includeStackTrace;
  }



  /**
   * Retrieves the set of debug types that will be used if debugging is enabled.
   *
   * @return  The set of debug types that will be used if debugging is enabled.
   */
  @NotNull()
  public static EnumSet<DebugType> getDebugTypes()
  {
    return debugTypes;
  }



  /**
   * Writes debug information about the provided exception, if appropriate.  If
   * it is to be logged, then it will be sent to the underlying logger using the
   * {@code WARNING} level.
   *
   * @param  t  The exception for which debug information should be written.
   */
  public static void debugException(@NotNull final Throwable t)
  {
    if (debugEnabled && debugTypes.contains(DebugType.EXCEPTION))
    {
      debugException(Level.WARNING, t);
    }
  }



  /**
   * Writes debug information about the provided exception, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  t  The exception for which debug information should be written.
   */
  public static void debugException(@NotNull final Level l,
                                    @NotNull final Throwable t)
  {
    if (debugEnabled && debugTypes.contains(DebugType.EXCEPTION))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.EXCEPTION);
      addCaughtException(buffer, "caught-exception", t);
      addCommonFooter(buffer);

      log(l, buffer, t);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * established, if appropriate.  If it is to be logged, then it will be sent
   * to the underlying logger using the {@code INFO} level.
   *
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   */
  public static void debugConnect(@NotNull final String h, final int p)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugConnect(Level.INFO, h, p, null);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * established, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   */
  public static void debugConnect(@NotNull final Level l,
                                  @NotNull final String h, final int p)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugConnect(l, h, p, null);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * established, if appropriate.  If it is to be logged, then it will be sent
   * to the underlying logger using the {@code INFO} level.
   *
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   * @param  c  The connection object for the connection that has been
   *            established.  It may be {@code null} for historic reasons, but
   *            should be non-{@code null} in new uses.
   */
  public static void debugConnect(@NotNull final String h, final int p,
                                  @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugConnect(Level.INFO, h, p, c);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * established, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   * @param  c  The connection object for the connection that has been
   *            established.  It may be {@code null} for historic reasons, but
   *            should be non-{@code null} in new uses.
   */
  public static void debugConnect(@NotNull final Level l,
                                  @NotNull final String h, final int p,
                                  @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.CONNECT);
      buffer.appendString("connected-to-address", h);
      buffer.appendNumber("connected-to-port", p);

      if (c != null)
      {
        buffer.appendNumber("connection-id", c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.appendString("connection-name", connectionName);
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.appendString("connection-pool-name", connectionPoolName);
        }
      }

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * terminated, if appropriate.  If it is to be logged, then it will be sent
   * to the underlying logger using the {@code INFO} level.
   *
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   * @param  t  The disconnect type.
   * @param  m  The disconnect message, if available.
   * @param  e  The disconnect cause, if available.
   */
  public static void debugDisconnect(@NotNull final String h,
                                     final int p,
                                     @NotNull final DisconnectType t,
                                     @Nullable final String m,
                                     @Nullable final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugDisconnect(Level.INFO, h, p, null, t, m, e);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * terminated, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   * @param  t  The disconnect type.
   * @param  m  The disconnect message, if available.
   * @param  e  The disconnect cause, if available.
   */
  public static void debugDisconnect(@NotNull final Level l,
                                     @NotNull final String h, final int p,
                                     @NotNull final DisconnectType t,
                                     @Nullable final String m,
                                     @Nullable final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugDisconnect(l, h, p, null, t, m, e);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * terminated, if appropriate.  If it is to be logged, then it will be sent
   * to the underlying logger using the {@code INFO} level.
   *
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   * @param  c  The connection object for the connection that has been closed.
   *            It may be {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   * @param  t  The disconnect type.
   * @param  m  The disconnect message, if available.
   * @param  e  The disconnect cause, if available.
   */
  public static void debugDisconnect(@NotNull final String h, final int p,
                                     @Nullable final LDAPConnection c,
                                     @NotNull final DisconnectType t,
                                     @Nullable final String m,
                                     @Nullable final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      debugDisconnect(Level.INFO, h, p, c, t, m, e);
    }
  }



  /**
   * Writes debug information to indicate that a connection has been
   * terminated, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  h  The address of the server to which the connection was
   *            established.
   * @param  p  The port of the server to which the connection was established.
   * @param  c  The connection object for the connection that has been closed.
   *            It may be {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   * @param  t  The disconnect type.
   * @param  m  The disconnect message, if available.
   * @param  e  The disconnect cause, if available.
   */
  public static void debugDisconnect(@NotNull final Level l,
                                     @NotNull final String h, final int p,
                                     @Nullable final LDAPConnection c,
                                     @NotNull final DisconnectType t,
                                     @Nullable final String m,
                                     @Nullable final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECT))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.CONNECT);

      if (c != null)
      {
        buffer.appendNumber("connection-id", c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.appendString("connection-name", connectionName);
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.appendString("connection-pool-name", connectionPoolName);
        }

        buffer.appendString("disconnected-from-address", h);
        buffer.appendNumber("disconnected-from-port", p);
        buffer.appendString("disconnect-type", t.name());

        if (m != null)
        {
          buffer.appendString("disconnect-message", m);
        }

      }

      if (e != null)
      {
        addCaughtException(buffer, "disconnect-cause", e);
      }

      addCommonFooter(buffer);
      log(l, buffer, e);
    }
  }



  /**
   * Writes debug information about the provided request, if appropriate.  If
   * it is to be logged, then it will be sent to the underlying logger using the
   * {@code INFO} level.
   *
   * @param  r  The LDAP request for which debug information should be written.
   */
  public static void debugLDAPRequest(@NotNull final LDAPRequest r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(Level.INFO, r, -1, null);
    }
  }



  /**
   * Writes debug information about the provided request, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  r  The LDAP request for which debug information should be written.
   */
  public static void debugLDAPRequest(@NotNull final Level l,
                                      @NotNull final LDAPRequest r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(l, r, -1, null);
    }
  }



  /**
   * Writes debug information about the provided request, if appropriate.  If
   * it is to be logged, then it will be sent to the underlying logger using the
   * {@code INFO} level.
   *
   * @param  r  The LDAP request for which debug information should be written.
   * @param  i  The message ID for the request that will be sent.  It may be
   *            negative if no message ID is available.
   * @param  c  The connection on which the request will be sent.  It may be
   *            {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   */
  public static void debugLDAPRequest(@NotNull final LDAPRequest r, final int i,
                                      @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(Level.INFO, r, i, c);
    }
  }



  /**
   * Writes debug information about the provided request, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  r  The LDAP request for which debug information should be written.
   * @param  i  The message ID for the request that will be sent.  It may be
   *            negative if no message ID is available.
   * @param  c  The connection on which the request will be sent.  It may be
   *            {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   */
  public static void debugLDAPRequest(@NotNull final Level l,
                                      @NotNull final LDAPRequest r,
                                      final int i,
                                      @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPRequest(l, String.valueOf(r), i, c);
    }
  }



  /**
   * Writes debug information about the provided request, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  s  A string representation of the LDAP request for which debug
   *            information should be written.
   * @param  i  The message ID for the request that will be sent.  It may be
   *            negative if no message ID is available.
   * @param  c  The connection on which the request will be sent.  It may be
   *            {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   */
  public static void debugLDAPRequest(@NotNull final Level l,
                                      @NotNull final String s,
                                      final int i,
                                      @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.LDAP);

      if (c != null)
      {
        buffer.appendNumber("connection-id", c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.appendString("connection-name", connectionName);
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.appendString("connection-pool-name", connectionPoolName);
        }

        final String connectedAddress = c.getConnectedAddress();
        if (connectedAddress != null)
        {
          buffer.appendString("connected-to-address", connectedAddress);
          buffer.appendNumber("connected-to-port", c.getConnectedPort());
        }

        try
        {
          final int soTimeout = InternalSDKHelper.getSoTimeout(c);
          buffer.appendNumber("socket-timeout-millis", soTimeout);
        } catch (final Exception e) {}
      }

      if (i >= 0)
      {
        buffer.appendNumber("message-id", i);
      }

      buffer.appendString("sending-ldap-request", s);

      addCommonFooter(buffer);
      log(l,  buffer);
    }
  }



  /**
   * Writes debug information about the provided result, if appropriate.  If
   * it is to be logged, then it will be sent to the underlying logger using the
   * {@code INFO} level.
   *
   * @param  r  The result for which debug information should be written.
   */
  public static void debugLDAPResult(@NotNull final LDAPResponse r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPResult(Level.INFO, r, null);
    }
  }



  /**
   * Writes debug information about the provided result, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  r  The result for which debug information should be written.
   */
  public static void debugLDAPResult(@NotNull final Level l,
                                     @NotNull final LDAPResponse r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPResult(l, r, null);
    }
  }



  /**
   * Writes debug information about the provided result, if appropriate.  If
   * it is to be logged, then it will be sent to the underlying logger using the
   * {@code INFO} level.
   *
   * @param  r  The result for which debug information should be written.
   * @param  c  The connection on which the response was received.  It may be
   *            {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   */
  public static void debugLDAPResult(@NotNull final LDAPResponse r,
                                     @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      debugLDAPResult(Level.INFO, r, c);
    }
  }



  /**
   * Writes debug information about the provided result, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  r  The result for which debug information should be written.
   * @param  c  The connection on which the response was received.  It may be
   *            {@code null} for historic reasons, but should be
   *            non-{@code null} in new uses.
   */
  public static void debugLDAPResult(@NotNull final Level l,
                                     @NotNull final LDAPResponse r,
                                     @Nullable final LDAPConnection c)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDAP))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.LDAP);

      if (c != null)
      {
        buffer.appendNumber("connection-id", c.getConnectionID());

        final String connectionName = c.getConnectionName();
        if (connectionName != null)
        {
          buffer.appendString("connection-name", connectionName);
        }

        final String connectionPoolName = c.getConnectionPoolName();
        if (connectionPoolName != null)
        {
          buffer.appendString("connection-pool-name", connectionPoolName);
        }

        final String connectedAddress = c.getConnectedAddress();
        if (connectedAddress != null)
        {
          buffer.appendString("connected-to-address", connectedAddress);
          buffer.appendNumber("connected-to-port", c.getConnectedPort());
        }
      }

      buffer.appendString("read-ldap-result", r.toString());

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element to be written,
   * if appropriate.  If it is to be logged, then it will be sent to the
   * underlying logger using the {@code INFO} level.
   *
   * @param  e  The ASN.1 element for which debug information should be written.
   */
  public static void debugASN1Write(@NotNull final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      debugASN1Write(Level.INFO, e);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element to be written,
   * if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  e  The ASN.1 element for which debug information should be written.
   */
  public static void debugASN1Write(@NotNull final Level l,
                                    @NotNull final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.ASN1);
      buffer.appendString("writing-asn1-element", e.toString());

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element to be written,
   * if appropriate.  If it is to be logged, then it will be sent to the
   * underlying logger using the {@code INFO} level.
   *
   * @param  b  The ASN.1 buffer with the information to be written.
   */
  public static void debugASN1Write(@NotNull final ASN1Buffer b)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      debugASN1Write(Level.INFO, b);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element to be written,
   * if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  b  The ASN1Buffer with the information to be written.
   */
  public static void debugASN1Write(@NotNull final Level l,
                                    @NotNull final ASN1Buffer b)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.ASN1);
      buffer.appendString("writing-asn1-element",
           StaticUtils.toHex(b.toByteArray()));

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element that was read, if
   * appropriate.  If it is to be logged, then it will be sent to the underlying
   * logger using the {@code INFO} level.
   *
   * @param  e  The ASN.1 element for which debug information should be written.
   */
  public static void debugASN1Read(@NotNull final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      debugASN1Read(Level.INFO, e);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element that was read, if
   * appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  e  The ASN.1 element for which debug information should be written.
   */
  public static void debugASN1Read(@NotNull final Level l,
                                   @NotNull final ASN1Element e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.ASN1);
      buffer.appendString("read-asn1-element", e.toString());

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about the provided ASN.1 element that was read, if
   * appropriate.
   *
   * @param  l         The log level that should be used for the debug
   *                   information.
   * @param  dataType  A string representation of the data type for the data
   *                   that was read.
   * @param  berType   The BER type for the element that was read.
   * @param  length    The number of bytes in the value of the element that was
   *                   read.
   * @param  value     A representation of the value that was read.  The debug
   *                   message will include the string representation of this
   *                   value, unless the value is a byte array in which it will
   *                   be a hex representation of the bytes that it contains.
   *                   It may be {@code null} for an ASN.1 null element.
   */
  public static void debugASN1Read(@NotNull final Level l,
                                   @NotNull final String dataType,
                                   final int berType, final int length,
                                   @Nullable final Object value)
  {
    if (debugEnabled && debugTypes.contains(DebugType.ASN1))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.ASN1);

      buffer.beginObject("read-asn1-element");
      buffer.appendString("data-type", dataType);
      buffer.appendString("ber-type",
           StaticUtils.toHex((byte) (berType & 0xFF)));
      buffer.appendNumber("value-length", length);

      if (value != null)
      {
        if (value instanceof byte[])
        {
          buffer.appendString("value-bytes",
               StaticUtils.toHex((byte[]) value));
        }
        else
        {
          buffer.appendString("value-string", value.toString());
        }
      }

      buffer.endObject();

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about interaction with a connection pool.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  p  The associated connection pool.
   * @param  c  The associated LDAP connection, if appropriate.
   * @param  m  A message with information about the pool interaction.
   * @param  e  An exception to include with the log message, if appropriate.
   */
  public static void debugConnectionPool(@NotNull final Level l,
                          @NotNull final AbstractConnectionPool p,
                          @Nullable final LDAPConnection c,
                          @Nullable final String m, @Nullable final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CONNECTION_POOL))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.CONNECTION_POOL);

      final String poolName = p.getConnectionPoolName();
      if (poolName == null)
      {
        buffer.appendNull("connection-pool-name");
      }
      else
      {
        buffer.appendString("connection-pool-name", poolName);
      }

      if (c != null)
      {
        buffer.appendNumber("connection-id", c.getConnectionID());

        final String connectedAddress = c.getConnectedAddress();
        if (connectedAddress != null)
        {
          buffer.appendString("connected-to-address", connectedAddress);
          buffer.appendNumber("connected-to-port", c.getConnectedPort());
        }
      }

      final long currentAvailable = p.getCurrentAvailableConnections();
      if (currentAvailable >= 0)
      {
        buffer.appendNumber("current-available-connections", currentAvailable);
      }

      final long maxAvailable = p.getMaximumAvailableConnections();
      if (maxAvailable >= 0)
      {
        buffer.appendNumber("maximum-available-connections", maxAvailable);
      }

      if (m != null)
      {
        buffer.appendString("message", m);
      }

      if (e != null)
      {
        addCaughtException(buffer, "caught-exception", e);
      }

      addCommonFooter(buffer);
      log(l, buffer, e);
    }
  }



  /**
   * Writes debug information about the provided LDIF record to be written, if
   * if appropriate.  If it is to be logged, then it will be sent to the
   * underlying logger using the {@code INFO} level.
   *
   * @param  r  The LDIF record for which debug information should be written.
   */
  public static void debugLDIFWrite(@NotNull final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      debugLDIFWrite(Level.INFO, r);
    }
  }



  /**
   * Writes debug information about the provided LDIF record to be written, if
   * appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  r  The LDIF record for which debug information should be written.
   */
  public static void debugLDIFWrite(@NotNull final Level l,
                                    @NotNull final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.LDIF);
      buffer.appendString("writing-ldif-record", r.toString());

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about the provided record read from LDIF, if
   * appropriate.  If it is to be logged, then it will be sent to the underlying
   * logger using the {@code INFO} level.
   *
   * @param  r  The LDIF record for which debug information should be written.
   */
  public static void debugLDIFRead(@NotNull final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      debugLDIFRead(Level.INFO, r);
    }
  }



  /**
   * Writes debug information about the provided record read from LDIF, if
   * appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  r  The LDIF record for which debug information should be written.
   */
  public static void debugLDIFRead(@NotNull final Level l,
                                   @NotNull final LDIFRecord r)
  {
    if (debugEnabled && debugTypes.contains(DebugType.LDIF))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.LDIF);
      buffer.appendString("read-ldif-record", r.toString());

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about monitor entry parsing.  If it is to be
   * logged, then it will be sent to the underlying logger using the
   * {@code FINE} level.
   *
   * @param  e  The entry containing the monitor information being parsed.
   * @param  m  The message to be written to the debug logger.
   */
  public static void debugMonitor(@Nullable final Entry e,
                                  @Nullable final String m)
  {
    if (debugEnabled && debugTypes.contains(DebugType.MONITOR))
    {
      debugMonitor(Level.FINE, e, m);
    }
  }



  /**
   * Writes debug information about monitor entry parsing, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  e  The entry containing the monitor information being parsed.
   * @param  m  The message to be written to the debug logger.
   */
  public static void debugMonitor(@NotNull final Level l,
                                  @Nullable final Entry e,
                                  @Nullable final String m)
  {
    if (debugEnabled && debugTypes.contains(DebugType.MONITOR))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, DebugType.MONITOR);

      if (e != null)
      {
        buffer.appendString("monitor-entry-dn", e.getDN());
      }

      if (m != null)
      {
        buffer.appendString("message", m);
      }

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes debug information about a coding error detected in the use of the
   * LDAP SDK.  If it is to be logged, then it will be sent to the underlying
   * logger using the {@code SEVERE} level.
   *
   * @param  t  The {@code Throwable} object that was created and will be thrown
   *            as a result of the coding error.
   */
  public static void debugCodingError(@NotNull final Throwable t)
  {
    if (debugEnabled && debugTypes.contains(DebugType.CODING_ERROR))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, Level.SEVERE, DebugType.CODING_ERROR);
      addCaughtException(buffer, "coding-error", t);

      addCommonFooter(buffer);
      log(Level.SEVERE, buffer, t);
    }
  }



  /**
   * Writes a generic debug message, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  t  The debug type to use to determine whether to write the message.
   * @param  m  The message to be written.
   */
  public static void debug(@NotNull final Level l,
                           @NotNull final DebugType t, @Nullable final String m)
  {
    if (debugEnabled && debugTypes.contains(t))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, t);

      if (m != null)
      {
        buffer.appendString("message", m);
      }

      addCommonFooter(buffer);
      log(l, buffer);
    }
  }



  /**
   * Writes a generic debug message, if appropriate.
   *
   * @param  l  The log level that should be used for the debug information.
   * @param  t  The debug type to use to determine whether to write the message.
   * @param  m  The message to be written.
   * @param  e  An exception to include with the log message.
   */
  public static void debug(@NotNull final Level l, @NotNull final DebugType t,
                           @Nullable final String m,
                           @Nullable final Throwable e)
  {
    if (debugEnabled && debugTypes.contains(t))
    {
      final JSONBuffer buffer = new JSONBuffer();
      addCommonHeader(buffer, l, t);

      if (m != null)
      {
        buffer.appendString("message", m);
      }

      if (e != null)
      {
        addCaughtException(buffer, "caught-exception", e);
      }

      addCommonFooter(buffer);
      log(l, buffer, e);
    }
  }



  /**
   * Adds common header information to the provided JSON buffer.  It will begin
   * a JSON object for the log message, then add a timestamp, debug type, log
   * level, thread ID, and thread name.
   *
   * @param  buffer  The JSON buffer to which the content should be added.
   * @param  level   The log level for the message that will be written.
   * @param  type    The debug type for the message that will be written.
   */
  private static void addCommonHeader(@NotNull final JSONBuffer buffer,
                                      @NotNull final Level level,
                                      @NotNull final DebugType type)
  {
    buffer.beginObject();
    buffer.appendString("timestamp", getTimestamp());
    buffer.appendString("debug-type", type.getName());
    buffer.appendString("level", level.getName());

    final Thread t = Thread.currentThread();
    buffer.appendNumber("thread-id", t.getId());
    buffer.appendString("thread-name", t.getName());
  }



  /**
   * Retrieves a timestamp that represents the current time.
   *
   * @return  A timestamp that represents the current time.
   */
  @NotNull()
  private static String getTimestamp()
  {
    SimpleDateFormat timestampFormatter = TIMESTAMP_FORMATTERS.get();
    if (timestampFormatter == null)
    {
      timestampFormatter =
           new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH':'mm':'ss.SSS'Z'");
      timestampFormatter.setTimeZone(StaticUtils.getUTCTimeZone());
      TIMESTAMP_FORMATTERS.set(timestampFormatter);
    }

    return timestampFormatter.format(new Date());
  }



  /**
   * Creates a formatted string representation of the provided stack trace
   * frame.
   *
   * @param  e  The stack trace element to be formatted.
   *
   * @return  The formatted string representation of the provided stack trace
   *          frame.
   */
  @NotNull()
  private static String formatStackTraceFrame(
                             @NotNull final StackTraceElement e)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append(e.getMethodName());
    buffer.append('(');
    buffer.append(e.getFileName());

    final int lineNumber = e.getLineNumber();
    if (lineNumber > 0)
    {
      buffer.append(':');
      buffer.append(lineNumber);
    }
    else if (e.isNativeMethod())
    {
      buffer.append(":native");
    }

    buffer.append(')');
    return buffer.toString();
  }



  /**
   * Adds information about a caught exception to the provided JSON buffer.
   *
   * @param  buffer     The JSON buffer to which the information should be
   *                    appended.
   * @param  fieldName  The name to use for the new field to be added with the
   *                    exception information.
   * @param  t          The exception to be included.
   */
  private static void addCaughtException(@NotNull final JSONBuffer buffer,
                                         @NotNull final String fieldName,
                                         @Nullable final Throwable t)
  {
    if (t == null)
    {
      return;
    }

    buffer.beginObject(fieldName);

    final String message = t.getMessage();
    if (message != null)
    {
      buffer.appendString("message", message);
    }

    buffer.beginArray("stack-trace");
    for (final StackTraceElement e : t.getStackTrace())
    {
      buffer.appendString(formatStackTraceFrame(e));
    }
    buffer.endArray();

    final Throwable cause = t.getCause();
    if (cause != null)
    {
      addCaughtException(buffer, "cause", cause);
    }

    buffer.endObject();
  }



  /**
   * Adds common footer information to the provided JSON buffer.  It will
   * include an optional caller stack trace, along with the LDAP SDK version
   * and revision.  It will also end the object that encapsulates the log
   * message.
   *
   * @param  buffer  The JSON buffer to which the content should be added.
   */
  private static void addCommonFooter(@NotNull final JSONBuffer buffer)
  {
    if (includeStackTrace)
    {
      buffer.beginArray("caller-stack-trace");

      boolean foundDebug = false;
      for (final StackTraceElement e : Thread.currentThread().getStackTrace())
      {
        final String className = e.getClassName();
        if (className.equals(Debug.class.getName()))
        {
          foundDebug = true;
        }
        else if (foundDebug)
        {
          buffer.appendString(formatStackTraceFrame(e));
        }
      }

      buffer.endArray();
    }

    buffer.appendString("ldap-sdk-version", Version.NUMERIC_VERSION_STRING);
    buffer.appendString("ldap-sdk-revision", Version.REVISION_ID);
    buffer.endObject();
  }



  /**
   * Logs a JSON-formatted debug message with the given level and fields.
   *
   * @param  level   The log level to use for the message.
   * @param  buffer  The JSON buffer containing the message to be written.
   */
  private static void log(@NotNull final Level level,
                          @NotNull final JSONBuffer buffer)
  {
    logger.log(level, buffer.toString());
  }



  /**
   * Logs a JSON-formatted debug message with the given level and fields.
   *
   * @param  level   The log level to use for the message.
   * @param  buffer  The JSON buffer containing the message to be written.
   * @param  thrown  An exception to be included with the debug message.
   */
  private static void log(@NotNull final Level level,
                          @NotNull final JSONBuffer buffer,
                          @Nullable final Throwable thrown)
  {
    logger.log(level, buffer.toString(), thrown);
  }
}
