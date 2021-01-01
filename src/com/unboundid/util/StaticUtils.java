/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.NameResolver;
import com.unboundid.ldap.sdk.Version;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a number of static utility functions.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StaticUtils
{
  /**
   * A pre-allocated byte array containing zero bytes.
   */
  @NotNull public static final byte[] NO_BYTES = new byte[0];



  /**
   * A pre-allocated empty character array.
   */
  @NotNull public static final char[] NO_CHARS = new char[0];



  /**
   * A pre-allocated empty control array.
   */
  @NotNull public static final Control[] NO_CONTROLS = new Control[0];



  /**
   * A pre-allocated empty string array.
   */
  @NotNull public static final String[] NO_STRINGS = new String[0];



  /**
   * The end-of-line marker for the platform on which the LDAP SDK is
   * currently running.
   */
  @NotNull public static final String EOL =
       getSystemProperty("line.separator", "\n");



  /**
   * The end-of-line marker that consists of a carriage return character
   * followed by a line feed character, as used on Windows systems.
   */
  @NotNull public static final String EOL_CR_LF = "\r\n";



  /**
   * The end-of-line marker that consists of just the line feed character, as
   * used on UNIX-based systems.
   */
  @NotNull public static final String EOL_LF = "\n";



  /**
   * A byte array containing the end-of-line marker for the platform on which
   * the LDAP SDK is currently running.
   */
  @NotNull public static final byte[] EOL_BYTES = getBytes(EOL);



  /**
   * A byte array containing the end-of-line marker that consists of a carriage
   * return character followed by a line feed character, as used on Windows
   * systems.
   */
  @NotNull public static final byte[] EOL_BYTES_CR_LF = getBytes(EOL_CR_LF);



  /**
   * A byte array containing the end-of-line marker that consists of just the
   * line feed character, as used on UNIX-based systems.
   */
  @NotNull public static final byte[] EOL_BYTES_LF = getBytes(EOL_LF);



  /**
   * Indicates whether the unit tests are currently running.
   */
  private static final boolean IS_WITHIN_UNIT_TESTS =
       Boolean.getBoolean("com.unboundid.ldap.sdk.RunningUnitTests") ||
       Boolean.getBoolean("com.unboundid.directory.server.RunningUnitTests");



  /**
   * The thread-local date formatter used to encode generalized time values.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       GENERALIZED_TIME_FORMATTERS = new ThreadLocal<>();



  /**
   * The thread-local date formatter used to encode RFC 3339 time values.
   */
  @NotNull private static final ThreadLocal<SimpleDateFormat>
       RFC_3339_TIME_FORMATTERS = new ThreadLocal<>();



  /**
   * The {@code TimeZone} object that represents the UTC (universal coordinated
   * time) time zone.
   */
  @NotNull private static final TimeZone UTC_TIME_ZONE =
       TimeZone.getTimeZone("UTC");



  /**
   * A set containing the names of attributes that will be considered sensitive
   * by the {@code toCode} methods of various request and data structure types.
   */
  @NotNull private static volatile Set<String>
       TO_CODE_SENSITIVE_ATTRIBUTE_NAMES = setOf("userpassword", "2.5.4.35",
            "authpassword", "1.3.6.1.4.1.4203.1.3.4");



  /**
   * The width of the terminal window, in columns.
   */
  public static final int TERMINAL_WIDTH_COLUMNS;
  static
  {
    // Try to dynamically determine the size of the terminal window using the
    // COLUMNS environment variable.
    int terminalWidth = 80;
    final String columnsEnvVar = getEnvironmentVariable("COLUMNS");
    if (columnsEnvVar != null)
    {
      try
      {
        terminalWidth = Integer.parseInt(columnsEnvVar);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    TERMINAL_WIDTH_COLUMNS = terminalWidth;
  }



  /**
   * Prevent this class from being instantiated.
   */
  private StaticUtils()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the set of currently defined system properties.  If possible,
   * this will simply return the result of a call to
   * {@code System.getProperties}.  However, the LDAP SDK is known to be used in
   * environments where a security manager prevents setting system properties,
   * and in that case, calls to {@code System.getProperties} will be rejected
   * with a {@code SecurityException} because the returned structure is mutable
   * and could be used to alter system property values.  In such cases, a new
   * empty {@code Properties} object will be created, and may optionally be
   * populated with the values of a specific set of named properties.
   *
   * @param  propertyNames  An optional set of property names whose values (if
   *                        defined) should be included in the
   *                        {@code Properties} object that will be returned if a
   *                        security manager prevents retrieving the full set of
   *                        system properties.  This may be {@code null} or
   *                        empty if no specific properties should be retrieved.
   *
   * @return  The value returned by a call to {@code System.getProperties} if
   *          possible, or a newly-created properties map (possibly including
   *          the values of a specified set of system properties) if it is not
   *          possible to get a mutable set of the system properties.
   */
  @NotNull()
  public static Properties getSystemProperties(
                                @Nullable final String... propertyNames)
  {
    try
    {
      final Properties properties = System.getProperties();

      final String forceThrowPropertyName =
           StaticUtils.class.getName() + ".forceGetSystemPropertiesToThrow";

      // To ensure that we can get coverage for the code below in which there is
      // a restrictive security manager in place, look for a system property
      // that will cause us to throw an exception.
      final Object forceThrowPropertyValue =
           properties.getProperty(forceThrowPropertyName);
      if (forceThrowPropertyValue != null)
      {
        throw new SecurityException(forceThrowPropertyName + '=' +
             forceThrowPropertyValue);
      }

      return properties;
    }
    catch (final SecurityException e)
    {
      Debug.debugException(e);
    }


    // If we have gotten here, then we can assume that a security manager
    // prevents us from accessing all system properties.  Create a new proper
    final Properties properties = new Properties();
    if (propertyNames != null)
    {
      for (final String propertyName : propertyNames)
      {
        final Object propertyValue = System.getProperty(propertyName);
        if (propertyValue != null)
        {
          properties.put(propertyName, propertyValue);
        }
      }
    }

    return properties;
  }



  /**
   * Retrieves the value of the specified system property.
   *
   * @param  name  The name of the system property for which to retrieve the
   *               value.
   *
   * @return  The value of the requested system property, or {@code null} if
   *          that variable was not set or its value could not be retrieved
   *          (for example, because a security manager prevents it).
   */
  @Nullable()
  public static String getSystemProperty(@NotNull final String name)
  {
    try
    {
      return System.getProperty(name);
    }
    catch (final Throwable t)
    {
      // It is possible that the call to System.getProperty could fail under
      // some security managers.  In that case, simply swallow the error and
      // act as if that system property is not set.
      Debug.debugException(t);
      return null;
    }
  }



  /**
   * Retrieves the value of the specified system property.
   *
   * @param  name          The name of the system property for which to retrieve
   *                       the value.
   * @param  defaultValue  The default value to return if the specified
   *                       system property is not set or could not be
   *                       retrieved.
   *
   * @return  The value of the requested system property, or the provided
   *          default value if that system property was not set or its value
   *          could not be retrieved (for example, because a security manager
   *          prevents it).
   */
  @Nullable()
  public static String getSystemProperty(@NotNull final String name,
                                         @Nullable final String defaultValue)
  {
    try
    {
      return System.getProperty(name, defaultValue);
    }
    catch (final Throwable t)
    {
      // It is possible that the call to System.getProperty could fail under
      // some security managers.  In that case, simply swallow the error and
      // act as if that system property is not set.
      Debug.debugException(t);
      return defaultValue;
    }
  }



  /**
   * Attempts to set the value of the specified system property.  Note that this
   * may not be permitted by some security managers, in which case the attempt
   * will have no effect.
   *
   * @param  name   The name of the System property to set.  It must not be
   *                {@code null}.
   * @param  value  The value to use for the system property.  If it is
   *                {@code null}, then the property will be cleared.
   *
   * @return  The former value of the system property, or {@code null} if it
   *          did not have a value or if it could not be set (for example,
   *          because a security manager prevents it).
   */
  @Nullable()
  public static String setSystemProperty(@NotNull final String name,
                                         @Nullable final String value)
  {
    try
    {
      if (value == null)
      {
        return System.clearProperty(name);
      }
      else
      {
        return System.setProperty(name, value);
      }
    }
    catch (final Throwable t)
    {
      // It is possible that the call to System.setProperty or
      // System.clearProperty could fail under some security managers.  In that
      // case, simply swallow the error and act as if that system property is
      // not set.
      Debug.debugException(t);
      return null;
    }
  }



  /**
   * Attempts to clear the value of the specified system property.  Note that
   * this may not be permitted by some security managers, in which case the
   * attempt will have no effect.
   *
   * @param  name  The name of the System property to clear.  It must not be
   *               {@code null}.
   *
   * @return  The former value of the system property, or {@code null} if it
   *          did not have a value or if it could not be set (for example,
   *          because a security manager prevents it).
   */
  @Nullable()
  public static String clearSystemProperty(@NotNull final String name)
  {
    try
    {
      return System.clearProperty(name);
    }
    catch (final Throwable t)
    {
      // It is possible that the call to System.clearProperty could fail under
      // some security managers.  In that case, simply swallow the error and
      // act as if that system property is not set.
      Debug.debugException(t);
      return null;
    }
  }



  /**
   * Retrieves a map of all environment variables defined in the JVM's process.
   *
   * @return  A map of all environment variables defined in the JVM's process,
   *          or an empty map if no environment variables are set or the actual
   *          set could not be retrieved (for example, because a security
   *          manager prevents it).
   */
  @NotNull()
  public static Map<String,String> getEnvironmentVariables()
  {
    try
    {
      return System.getenv();
    }
    catch (final Throwable t)
    {
      // It is possible that the call to System.getenv could fail under some
      // security managers.  In that case, simply swallow the error and pretend
      // that the environment variable is not set.
      Debug.debugException(t);
      return Collections.emptyMap();
    }
  }



  /**
   * Retrieves the value of the specified environment variable.
   *
   * @param  name  The name of the environment variable for which to retrieve
   *               the value.
   *
   * @return  The value of the requested environment variable, or {@code null}
   *          if that variable was not set or its value could not be retrieved
   *          (for example, because a security manager prevents it).
   */
  @Nullable()
  public static String getEnvironmentVariable(@NotNull final String name)
  {
    try
    {
      return System.getenv(name);
    }
    catch (final Throwable t)
    {
      // It is possible that the call to System.getenv could fail under some
      // security managers.  In that case, simply swallow the error and pretend
      // that the environment variable is not set.
      Debug.debugException(t);
      return null;
    }
  }



  /**
   * Retrieves the value of the specified environment variable.
   *
   * @param  name          The name of the environment variable for which to
   *                       retrieve the value.
   * @param  defaultValue  The default value to use if the specified environment
   *                       variable is not set.  It may be {@code null} if no
   *                       default should be used.
   *
   * @return  The value of the requested environment variable, or {@code null}
   *          if that variable was not set or its value could not be retrieved
   *          (for example, because a security manager prevents it) and there
   *          is no default value.
   */
  @Nullable()
  public static String getEnvironmentVariable(@NotNull final String name,
                            @Nullable final String defaultValue)
  {
    final String value = getEnvironmentVariable(name);
    if (value == null)
    {
      return defaultValue;
    }
    else
    {
      return value;
    }
  }



  /**
   * Attempts to set the desired log level for the specified logger.  Note that
   * this may not be permitted by some security managers, in which case the
   * attempt will have no effect.
   *
   * @param  logger    The logger whose level should be updated.
   * @param  logLevel  The log level to set for the logger.
   */
  public static void setLoggerLevel(@NotNull final Logger logger,
                                    @NotNull final Level logLevel)
  {
    try
    {
      logger.setLevel(logLevel);
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);
    }
  }



  /**
   * Attempts to set the desired log level for the specified log handler.  Note
   * that this may not be permitted by some security managers, in which case the
   * attempt will have no effect.
   *
   * @param  logHandler  The log handler whose level should be updated.
   * @param  logLevel    The log level to set for the log handler.
   */
  public static void setLogHandlerLevel(@NotNull final Handler logHandler,
                                        @NotNull final Level logLevel)
  {
    try
    {
      logHandler.setLevel(logLevel);
    }
    catch (final Throwable t)
    {
      Debug.debugException(t);
    }
  }



  /**
   * Retrieves a UTF-8 byte representation of the provided string.
   *
   * @param  s  The string for which to retrieve the UTF-8 byte representation.
   *
   * @return  The UTF-8 byte representation for the provided string.
   */
  @NotNull()
  public static byte[] getBytes(@Nullable final String s)
  {
    final int length;
    if ((s == null) || ((length = s.length()) == 0))
    {
      return NO_BYTES;
    }

    final byte[] b = new byte[length];
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if (c <= 0x7F)
      {
        b[i] = (byte) (c & 0x7F);
      }
      else
      {
        return s.getBytes(StandardCharsets.UTF_8);
      }
    }

    return b;
  }



  /**
   * Indicates whether the contents of the provided byte array represent an
   * ASCII string, which is also known in LDAP terminology as an IA5 string.
   * An ASCII string is one that contains only bytes in which the most
   * significant bit is zero.
   *
   * @param  b  The byte array for which to make the determination.  It must
   *            not be {@code null}.
   *
   * @return  {@code true} if the contents of the provided array represent an
   *          ASCII string, or {@code false} if not.
   */
  public static boolean isASCIIString(@NotNull final byte[] b)
  {
    for (final byte by : b)
    {
      if ((by & 0x80) == 0x80)
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether the contents of the provided string represent an ASCII
   * string, which is also known in LDAP terminology as an IA5 string.  An ASCII
   * string is one that contains only bytes in which the most significant bit is
   * zero.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the contents of the provided string represent an
   *          ASCII string, or {@code false} if not.
   */
  public static boolean isASCIIString(@NotNull final String s)
  {
    return isASCIIString(getBytes(s));
  }



  /**
   * Indicates whether the provided character is a printable ASCII character, as
   * per RFC 4517 section 3.2.  The only printable characters are:
   * <UL>
   *   <LI>All uppercase and lowercase ASCII alphabetic letters</LI>
   *   <LI>All ASCII numeric digits</LI>
   *   <LI>The following additional ASCII characters:  single quote, left
   *       parenthesis, right parenthesis, plus, comma, hyphen, period, equals,
   *       forward slash, colon, question mark, space.</LI>
   * </UL>
   *
   * @param  c  The character for which to make the determination.
   *
   * @return  {@code true} if the provided character is a printable ASCII
   *          character, or {@code false} if not.
   */
  public static boolean isPrintable(final char c)
  {
    if (((c >= 'a') && (c <= 'z')) ||
        ((c >= 'A') && (c <= 'Z')) ||
        ((c >= '0') && (c <= '9')))
    {
      return true;
    }

    switch (c)
    {
      case '\'':
      case '(':
      case ')':
      case '+':
      case ',':
      case '-':
      case '.':
      case '=':
      case '/':
      case ':':
      case '?':
      case ' ':
        return true;
      default:
        return false;
    }
  }



  /**
   * Indicates whether the contents of the provided byte array represent a
   * printable LDAP string, as per RFC 4517 section 3.2.  The only characters
   * allowed in a printable string are:
   * <UL>
   *   <LI>All uppercase and lowercase ASCII alphabetic letters</LI>
   *   <LI>All ASCII numeric digits</LI>
   *   <LI>The following additional ASCII characters:  single quote, left
   *       parenthesis, right parenthesis, plus, comma, hyphen, period, equals,
   *       forward slash, colon, question mark, space.</LI>
   * </UL>
   * If the provided array contains anything other than the above characters
   * (i.e., if the byte array contains any non-ASCII characters, or any ASCII
   * control characters, or if it contains excluded ASCII characters like
   * the exclamation point, double quote, octothorpe, dollar sign, etc.), then
   * it will not be considered printable.
   *
   * @param  b  The byte array for which to make the determination.  It must
   *            not be {@code null}.
   *
   * @return  {@code true} if the contents of the provided byte array represent
   *          a printable LDAP string, or {@code false} if not.
   */
  public static boolean isPrintableString(@NotNull final byte[] b)
  {
    for (final byte by : b)
    {
      if ((by & 0x80) == 0x80)
      {
        return false;
      }

      if (((by >= 'a') && (by <= 'z')) ||
          ((by >= 'A') && (by <= 'Z')) ||
          ((by >= '0') && (by <= '9')))
      {
        continue;
      }

      switch (by)
      {
        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '-':
        case '.':
        case '=':
        case '/':
        case ':':
        case '?':
        case ' ':
          continue;
        default:
          return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether the provided string represents a printable LDAP string,
   * as per RFC 4517 section 3.2.  The only characters allowed in a printable
   * string are:
   * <UL>
   *   <LI>All uppercase and lowercase ASCII alphabetic letters</LI>
   *   <LI>All ASCII numeric digits</LI>
   *   <LI>The following additional ASCII characters:  single quote, left
   *       parenthesis, right parenthesis, plus, comma, hyphen, period, equals,
   *       forward slash, colon, question mark, space.</LI>
   * </UL>
   * If the provided array contains anything other than the above characters
   * (i.e., if the byte array contains any non-ASCII characters, or any ASCII
   * control characters, or if it contains excluded ASCII characters like
   * the exclamation point, double quote, octothorpe, dollar sign, etc.), then
   * it will not be considered printable.
   *
   * @param  s  The string for which to make the determination.  It must not be
   *            {@code null}.
   *
   * @return  {@code true} if the provided string represents a printable LDAP
   *          string, or {@code false} if not.
   */
  public static boolean isPrintableString(@NotNull final String s)
  {
    final int length = s.length();
    for (int i=0; i < length; i++)
    {
      final char c = s.charAt(i);
      if ((c & 0x80) == 0x80)
      {
        return false;
      }

      if (((c >= 'a') && (c <= 'z')) ||
          ((c >= 'A') && (c <= 'Z')) ||
          ((c >= '0') && (c <= '9')))
      {
        continue;
      }

      switch (c)
      {
        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '-':
        case '.':
        case '=':
        case '/':
        case ':':
        case '?':
        case ' ':
          continue;
        default:
          return false;
      }
    }

    return true;
  }



  /**
   * Indicates whether the contents of the provided array are valid UTF-8.
   *
   * @param  b  The byte array to examine.  It must not be {@code null}.
   *
   * @return  {@code true} if the byte array can be parsed as a valid UTF-8
   *          string, or {@code false} if not.
   */
  public static boolean isValidUTF8(@NotNull final byte[] b)
  {
    int i = 0;
    while (i < b.length)
    {
      final byte currentByte = b[i++];

      // If the most significant bit is not set, then this represents a valid
      // single-byte character.
      if ((currentByte & 0b1000_0000) == 0b0000_0000)
      {
        continue;
      }

      // If the first byte starts with 0b110, then it must be followed by
      // another byte that starts with 0b10.
      if ((currentByte & 0b1110_0000) == 0b1100_0000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 1))
        {
          return false;
        }

        i++;
        continue;
      }

      // If the first byte starts with 0b1110, then it must be followed by two
      // more bytes that start with 0b10.
      if ((currentByte & 0b1111_0000) == 0b1110_0000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 2))
        {
          return false;
        }

        i += 2;
        continue;
      }

      // If the first byte starts with 0b11110, then it must be followed by
      // three more bytes that start with 0b10.
      if ((currentByte & 0b1111_1000) == 0b1111_0000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 3))
        {
          return false;
        }

        i += 3;
        continue;
      }

      // If the first byte starts with 0b111110, then it must be followed by
      // four more bytes that start with 0b10.
      if ((currentByte & 0b1111_1100) == 0b1111_1000)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 4))
        {
          return false;
        }

        i += 4;
        continue;
      }

      // If the first byte starts with 0b1111110, then it must be followed by
      // five more bytes that start with 0b10.
      if ((currentByte & 0b1111_1110) == 0b1111_1100)
      {
        if (! hasExpectedSubsequentUTF8Bytes(b, i, 5))
        {
          return false;
        }

        i += 5;
        continue;
      }

      // This is not a valid first byte for a UTF-8 character.
      return false;
    }


    // If we've gotten here, then the provided array represents a valid UTF-8
    // string.
    return true;
  }



  /**
   * Ensures that the provided array has the expected number of bytes that start
   * with 0b10 starting at the specified position in the array.
   *
   * @param  b  The byte array to examine.
   * @param  p  The position in the byte array at which to start looking.
   * @param  n  The number of bytes to examine.
   *
   * @return  {@code true} if the provided byte array has the expected number of
   *          bytes that start with 0b10, or {@code false} if not.
   */
  private static boolean hasExpectedSubsequentUTF8Bytes(@NotNull final byte[] b,
                                                        final int p,
                                                        final int n)
  {
    if (b.length < (p + n))
    {
      return false;
    }

    for (int i=0; i < n; i++)
    {
      if ((b[p+i] & 0b1100_0000) != 0b1000_0000)
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves a string generated from the provided byte array using the UTF-8
   * encoding.
   *
   * @param  b  The byte array for which to return the associated string.
   *
   * @return  The string generated from the provided byte array using the UTF-8
   *          encoding.
   */
  @NotNull()
  public static String toUTF8String(@NotNull final byte[] b)
  {
    try
    {
      return new String(b, StandardCharsets.UTF_8);
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      return new String(b);
    }
  }



  /**
   * Retrieves a string generated from the specified portion of the provided
   * byte array using the UTF-8 encoding.
   *
   * @param  b       The byte array for which to return the associated string.
   * @param  offset  The offset in the array at which the value begins.
   * @param  length  The number of bytes in the value to convert to a string.
   *
   * @return  The string generated from the specified portion of the provided
   *          byte array using the UTF-8 encoding.
   */
  @NotNull()
  public static String toUTF8String(@NotNull final byte[] b, final int offset,
                                    final int length)
  {
    try
    {
      return new String(b, offset, length, StandardCharsets.UTF_8);
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      return new String(b, offset, length);
    }
  }



  /**
   * Retrieves a version of the provided string with the first character
   * converted to lowercase but all other characters retaining their original
   * capitalization.
   *
   * @param  s  The string to be processed.
   *
   * @return  A version of the provided string with the first character
   *          converted to lowercase but all other characters retaining their
   *          original capitalization.  It may be {@code null} if the provided
   *          string is {@code null}.
   */
  @Nullable()
  public static String toInitialLowerCase(@Nullable final String s)
  {
    if ((s == null) || s.isEmpty())
    {
      return s;
    }
    else if (s.length() == 1)
    {
      return toLowerCase(s);
    }
    else
    {
      final char c = s.charAt(0);
      if (((c >= 'A') && (c <= 'Z')) || (c < ' ') || (c > '~'))
      {
        final StringBuilder b = new StringBuilder(s);
        b.setCharAt(0, Character.toLowerCase(c));
        return b.toString();
      }
      else
      {
        return s;
      }
    }
  }



  /**
   * Retrieves an all-lowercase version of the provided string.
   *
   * @param  s  The string for which to retrieve the lowercase version.
   *
   * @return  An all-lowercase version of the provided string, or {@code null}
   *          if the provided string was {@code null}.
   */
  @Nullable()
  public static String toLowerCase(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }

    final int length = s.length();
    final char[] charArray = s.toCharArray();
    for (int i=0; i < length; i++)
    {
      switch (charArray[i])
      {
        case 'A':
          charArray[i] = 'a';
          break;
        case 'B':
          charArray[i] = 'b';
          break;
        case 'C':
          charArray[i] = 'c';
          break;
        case 'D':
          charArray[i] = 'd';
          break;
        case 'E':
          charArray[i] = 'e';
          break;
        case 'F':
          charArray[i] = 'f';
          break;
        case 'G':
          charArray[i] = 'g';
          break;
        case 'H':
          charArray[i] = 'h';
          break;
        case 'I':
          charArray[i] = 'i';
          break;
        case 'J':
          charArray[i] = 'j';
          break;
        case 'K':
          charArray[i] = 'k';
          break;
        case 'L':
          charArray[i] = 'l';
          break;
        case 'M':
          charArray[i] = 'm';
          break;
        case 'N':
          charArray[i] = 'n';
          break;
        case 'O':
          charArray[i] = 'o';
          break;
        case 'P':
          charArray[i] = 'p';
          break;
        case 'Q':
          charArray[i] = 'q';
          break;
        case 'R':
          charArray[i] = 'r';
          break;
        case 'S':
          charArray[i] = 's';
          break;
        case 'T':
          charArray[i] = 't';
          break;
        case 'U':
          charArray[i] = 'u';
          break;
        case 'V':
          charArray[i] = 'v';
          break;
        case 'W':
          charArray[i] = 'w';
          break;
        case 'X':
          charArray[i] = 'x';
          break;
        case 'Y':
          charArray[i] = 'y';
          break;
        case 'Z':
          charArray[i] = 'z';
          break;
        default:
          if (charArray[i] > 0x7F)
          {
            return s.toLowerCase();
          }
          break;
      }
    }

    return new String(charArray);
  }



  /**
   * Retrieves an all-uppercase version of the provided string.
   *
   * @param  s  The string for which to retrieve the uppercase version.
   *
   * @return  An all-uppercase version of the provided string, or {@code null}
   *          if the provided string was {@code null}.
   */
  @Nullable()
  public static String toUpperCase(@Nullable final String s)
  {
    if (s == null)
    {
      return null;
    }

    final int length = s.length();
    final char[] charArray = s.toCharArray();
    for (int i=0; i < length; i++)
    {
      switch (charArray[i])
      {
        case 'a':
          charArray[i] = 'A';
          break;
        case 'b':
          charArray[i] = 'B';
          break;
        case 'c':
          charArray[i] = 'C';
          break;
        case 'd':
          charArray[i] = 'D';
          break;
        case 'e':
          charArray[i] = 'E';
          break;
        case 'f':
          charArray[i] = 'F';
          break;
        case 'g':
          charArray[i] = 'G';
          break;
        case 'h':
          charArray[i] = 'H';
          break;
        case 'i':
          charArray[i] = 'I';
          break;
        case 'j':
          charArray[i] = 'J';
          break;
        case 'k':
          charArray[i] = 'K';
          break;
        case 'l':
          charArray[i] = 'L';
          break;
        case 'm':
          charArray[i] = 'M';
          break;
        case 'n':
          charArray[i] = 'N';
          break;
        case 'o':
          charArray[i] = 'O';
          break;
        case 'p':
          charArray[i] = 'P';
          break;
        case 'q':
          charArray[i] = 'Q';
          break;
        case 'r':
          charArray[i] = 'R';
          break;
        case 's':
          charArray[i] = 'S';
          break;
        case 't':
          charArray[i] = 'T';
          break;
        case 'u':
          charArray[i] = 'U';
          break;
        case 'v':
          charArray[i] = 'V';
          break;
        case 'w':
          charArray[i] = 'W';
          break;
        case 'x':
          charArray[i] = 'X';
          break;
        case 'y':
          charArray[i] = 'Y';
          break;
        case 'z':
          charArray[i] = 'Z';
          break;
        default:
          if (charArray[i] > 0x7F)
          {
            return s.toUpperCase();
          }
          break;
      }
    }

    return new String(charArray);
  }



  /**
   * Indicates whether the provided character is a valid hexadecimal digit.
   *
   * @param  c  The character for which to make the determination.
   *
   * @return  {@code true} if the provided character does represent a valid
   *          hexadecimal digit, or {@code false} if not.
   */
  public static boolean isHex(final char c)
  {
    switch (c)
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
      case 'a':
      case 'A':
      case 'b':
      case 'B':
      case 'c':
      case 'C':
      case 'd':
      case 'D':
      case 'e':
      case 'E':
      case 'f':
      case 'F':
        return true;

      default:
        return false;
    }
  }



  /**
   * Retrieves a hexadecimal representation of the provided byte.
   *
   * @param  b  The byte to encode as hexadecimal.
   *
   * @return  A string containing the hexadecimal representation of the provided
   *          byte.
   */
  @NotNull()
  public static String toHex(final byte b)
  {
    final StringBuilder buffer = new StringBuilder(2);
    toHex(b, buffer);
    return buffer.toString();
  }



  /**
   * Appends a hexadecimal representation of the provided byte to the given
   * buffer.
   *
   * @param  b       The byte to encode as hexadecimal.
   * @param  buffer  The buffer to which the hexadecimal representation is to be
   *                 appended.
   */
  public static void toHex(final byte b, @NotNull final StringBuilder buffer)
  {
    switch (b & 0xF0)
    {
      case 0x00:
        buffer.append('0');
        break;
      case 0x10:
        buffer.append('1');
        break;
      case 0x20:
        buffer.append('2');
        break;
      case 0x30:
        buffer.append('3');
        break;
      case 0x40:
        buffer.append('4');
        break;
      case 0x50:
        buffer.append('5');
        break;
      case 0x60:
        buffer.append('6');
        break;
      case 0x70:
        buffer.append('7');
        break;
      case 0x80:
        buffer.append('8');
        break;
      case 0x90:
        buffer.append('9');
        break;
      case 0xA0:
        buffer.append('a');
        break;
      case 0xB0:
        buffer.append('b');
        break;
      case 0xC0:
        buffer.append('c');
        break;
      case 0xD0:
        buffer.append('d');
        break;
      case 0xE0:
        buffer.append('e');
        break;
      case 0xF0:
        buffer.append('f');
        break;
    }

    switch (b & 0x0F)
    {
      case 0x00:
        buffer.append('0');
        break;
      case 0x01:
        buffer.append('1');
        break;
      case 0x02:
        buffer.append('2');
        break;
      case 0x03:
        buffer.append('3');
        break;
      case 0x04:
        buffer.append('4');
        break;
      case 0x05:
        buffer.append('5');
        break;
      case 0x06:
        buffer.append('6');
        break;
      case 0x07:
        buffer.append('7');
        break;
      case 0x08:
        buffer.append('8');
        break;
      case 0x09:
        buffer.append('9');
        break;
      case 0x0A:
        buffer.append('a');
        break;
      case 0x0B:
        buffer.append('b');
        break;
      case 0x0C:
        buffer.append('c');
        break;
      case 0x0D:
        buffer.append('d');
        break;
      case 0x0E:
        buffer.append('e');
        break;
      case 0x0F:
        buffer.append('f');
        break;
    }
  }



  /**
   * Retrieves a hexadecimal representation of the contents of the provided byte
   * array.  No delimiter character will be inserted between the hexadecimal
   * digits for each byte.
   *
   * @param  b  The byte array to be represented as a hexadecimal string.  It
   *            must not be {@code null}.
   *
   * @return  A string containing a hexadecimal representation of the contents
   *          of the provided byte array.
   */
  @NotNull()
  public static String toHex(@NotNull final byte[] b)
  {
    Validator.ensureNotNull(b);

    final StringBuilder buffer = new StringBuilder(2 * b.length);
    toHex(b, buffer);
    return buffer.toString();
  }



  /**
   * Retrieves a hexadecimal representation of the contents of the provided byte
   * array.  No delimiter character will be inserted between the hexadecimal
   * digits for each byte.
   *
   * @param  b       The byte array to be represented as a hexadecimal string.
   *                 It must not be {@code null}.
   * @param  buffer  A buffer to which the hexadecimal representation of the
   *                 contents of the provided byte array should be appended.
   */
  public static void toHex(@NotNull final byte[] b,
                           @NotNull final StringBuilder buffer)
  {
    toHex(b, null, buffer);
  }



  /**
   * Retrieves a hexadecimal representation of the contents of the provided byte
   * array.  No delimiter character will be inserted between the hexadecimal
   * digits for each byte.
   *
   * @param  b          The byte array to be represented as a hexadecimal
   *                    string.  It must not be {@code null}.
   * @param  delimiter  A delimiter to be inserted between bytes.  It may be
   *                    {@code null} if no delimiter should be used.
   * @param  buffer     A buffer to which the hexadecimal representation of the
   *                    contents of the provided byte array should be appended.
   */
  public static void toHex(@NotNull final byte[] b,
                           @Nullable final String delimiter,
                           @NotNull final StringBuilder buffer)
  {
    boolean first = true;
    for (final byte bt : b)
    {
      if (first)
      {
        first = false;
      }
      else if (delimiter != null)
      {
        buffer.append(delimiter);
      }

      toHex(bt, buffer);
    }
  }



  /**
   * Retrieves a hex-encoded representation of the contents of the provided
   * array, along with an ASCII representation of its contents next to it.  The
   * output will be split across multiple lines, with up to sixteen bytes per
   * line.  For each of those sixteen bytes, the two-digit hex representation
   * will be appended followed by a space.  Then, the ASCII representation of
   * those sixteen bytes will follow that, with a space used in place of any
   * byte that does not have an ASCII representation.
   *
   * @param  array   The array whose contents should be processed.
   * @param  indent  The number of spaces to insert on each line prior to the
   *                 first hex byte.
   *
   * @return  A hex-encoded representation of the contents of the provided
   *          array, along with an ASCII representation of its contents next to
   *          it.
   */
  @NotNull()
  public static String toHexPlusASCII(@NotNull final byte[] array,
                                      final int indent)
  {
    final StringBuilder buffer = new StringBuilder();
    toHexPlusASCII(array, indent, buffer);
    return buffer.toString();
  }



  /**
   * Appends a hex-encoded representation of the contents of the provided array
   * to the given buffer, along with an ASCII representation of its contents
   * next to it.  The output will be split across multiple lines, with up to
   * sixteen bytes per line.  For each of those sixteen bytes, the two-digit hex
   * representation will be appended followed by a space.  Then, the ASCII
   * representation of those sixteen bytes will follow that, with a space used
   * in place of any byte that does not have an ASCII representation.
   *
   * @param  array   The array whose contents should be processed.
   * @param  indent  The number of spaces to insert on each line prior to the
   *                 first hex byte.
   * @param  buffer  The buffer to which the encoded data should be appended.
   */
  public static void toHexPlusASCII(@Nullable final byte[] array,
                                    final int indent,
                                    @NotNull final StringBuilder buffer)
  {
    if ((array == null) || (array.length == 0))
    {
      return;
    }

    for (int i=0; i < indent; i++)
    {
      buffer.append(' ');
    }

    int pos = 0;
    int startPos = 0;
    while (pos < array.length)
    {
      toHex(array[pos++], buffer);
      buffer.append(' ');

      if ((pos % 16) == 0)
      {
        buffer.append("  ");
        for (int i=startPos; i < pos; i++)
        {
          if ((array[i] < ' ') || (array[i] > '~'))
          {
            buffer.append(' ');
          }
          else
          {
            buffer.append((char) array[i]);
          }
        }
        buffer.append(EOL);
        startPos = pos;

        if (pos < array.length)
        {
          for (int i=0; i < indent; i++)
          {
            buffer.append(' ');
          }
        }
      }
    }

    // If the last line isn't complete yet, then finish it off.
    if ((array.length % 16) != 0)
    {
      final int missingBytes = (16 - (array.length % 16));
      for (int i=0; i < missingBytes; i++)
      {
        buffer.append("   ");
      }
      buffer.append("  ");
      for (int i=startPos; i < array.length; i++)
      {
        if ((array[i] < ' ') || (array[i] > '~'))
        {
          buffer.append(' ');
        }
        else
        {
          buffer.append((char) array[i]);
        }
      }
      buffer.append(EOL);
    }
  }



  /**
   * Retrieves the bytes that correspond to the provided hexadecimal string.
   *
   * @param  hexString  The hexadecimal string for which to retrieve the bytes.
   *                    It must not be {@code null}, and there must not be any
   *                    delimiter between bytes.
   *
   * @return  The bytes that correspond to the provided hexadecimal string.
   *
   * @throws  ParseException  If the provided string does not represent valid
   *                          hexadecimal data, or if the provided string does
   *                          not contain an even number of characters.
   */
  @NotNull()
  public static byte[] fromHex(@NotNull final String hexString)
         throws ParseException
  {
    if ((hexString.length() % 2) != 0)
    {
      throw new ParseException(
           ERR_FROM_HEX_ODD_NUMBER_OF_CHARACTERS.get(hexString.length()),
           hexString.length());
    }

    final byte[] decodedBytes = new byte[hexString.length() / 2];
    for (int i=0, j=0; i < decodedBytes.length; i++, j+= 2)
    {
      switch (hexString.charAt(j))
      {
        case '0':
          // No action is required.
          break;
        case '1':
          decodedBytes[i] = 0x10;
          break;
        case '2':
          decodedBytes[i] = 0x20;
          break;
        case '3':
          decodedBytes[i] = 0x30;
          break;
        case '4':
          decodedBytes[i] = 0x40;
          break;
        case '5':
          decodedBytes[i] = 0x50;
          break;
        case '6':
          decodedBytes[i] = 0x60;
          break;
        case '7':
          decodedBytes[i] = 0x70;
          break;
        case '8':
          decodedBytes[i] = (byte) 0x80;
          break;
        case '9':
          decodedBytes[i] = (byte) 0x90;
          break;
        case 'a':
        case 'A':
          decodedBytes[i] = (byte) 0xA0;
          break;
        case 'b':
        case 'B':
          decodedBytes[i] = (byte) 0xB0;
          break;
        case 'c':
        case 'C':
          decodedBytes[i] = (byte) 0xC0;
          break;
        case 'd':
        case 'D':
          decodedBytes[i] = (byte) 0xD0;
          break;
        case 'e':
        case 'E':
          decodedBytes[i] = (byte) 0xE0;
          break;
        case 'f':
        case 'F':
          decodedBytes[i] = (byte) 0xF0;
          break;
        default:
          throw new ParseException(ERR_FROM_HEX_NON_HEX_CHARACTER.get(j), j);
      }

      switch (hexString.charAt(j+1))
      {
        case '0':
          // No action is required.
          break;
        case '1':
          decodedBytes[i] |= 0x01;
          break;
        case '2':
          decodedBytes[i] |= 0x02;
          break;
        case '3':
          decodedBytes[i] |= 0x03;
          break;
        case '4':
          decodedBytes[i] |= 0x04;
          break;
        case '5':
          decodedBytes[i] |= 0x05;
          break;
        case '6':
          decodedBytes[i] |= 0x06;
          break;
        case '7':
          decodedBytes[i] |= 0x07;
          break;
        case '8':
          decodedBytes[i] |= 0x08;
          break;
        case '9':
          decodedBytes[i] |= 0x09;
          break;
        case 'a':
        case 'A':
          decodedBytes[i] |= 0x0A;
          break;
        case 'b':
        case 'B':
          decodedBytes[i] |= 0x0B;
          break;
        case 'c':
        case 'C':
          decodedBytes[i] |= 0x0C;
          break;
        case 'd':
        case 'D':
          decodedBytes[i] |= 0x0D;
          break;
        case 'e':
        case 'E':
          decodedBytes[i] |= 0x0E;
          break;
        case 'f':
        case 'F':
          decodedBytes[i] |= 0x0F;
          break;
        default:
          throw new ParseException(ERR_FROM_HEX_NON_HEX_CHARACTER.get(j+1),
               j+1);
      }
    }

    return decodedBytes;
  }



  /**
   * Appends a hex-encoded representation of the provided character to the given
   * buffer.  Each byte of the hex-encoded representation will be prefixed with
   * a backslash.
   *
   * @param  c       The character to be encoded.
   * @param  buffer  The buffer to which the hex-encoded representation should
   *                 be appended.
   */
  public static void hexEncode(final char c,
                               @NotNull final StringBuilder buffer)
  {
    final byte[] charBytes;
    if (c <= 0x7F)
    {
      charBytes = new byte[] { (byte) (c & 0x7F) };
    }
    else
    {
      charBytes = getBytes(String.valueOf(c));
    }

    for (final byte b : charBytes)
    {
      buffer.append('\\');
      toHex(b, buffer);
    }
  }



  /**
   * Appends a hex-encoded representation of the provided code point to the
   * given buffer.  Each byte of the hex-encoded representation will be prefixed
   * with a backslash.
   *
   * @param  codePoint  The code point to be encoded.
   * @param  buffer     The buffer to which the hex-encoded representation
   *                    should be appended.
   */
  public static void hexEncode(final int codePoint,
                               @NotNull final StringBuilder buffer)
  {
    final byte[] charBytes =
         getBytes(new String(new int[] { codePoint }, 0, 1));

    for (final byte b : charBytes)
    {
      buffer.append('\\');
      toHex(b, buffer);
    }
  }



  /**
   * Appends the Java code that may be used to create the provided byte
   * array to the given buffer.
   *
   * @param  array   The byte array containing the data to represent.  It must
   *                 not be {@code null}.
   * @param  buffer  The buffer to which the code should be appended.
   */
  public static void byteArrayToCode(@NotNull final byte[] array,
                                     @NotNull final StringBuilder buffer)
  {
    buffer.append("new byte[] {");
    for (int i=0; i < array.length; i++)
    {
      if (i > 0)
      {
        buffer.append(',');
      }

      buffer.append(" (byte) 0x");
      toHex(array[i], buffer);
    }
    buffer.append(" }");
  }



  /**
   * Retrieves a single-line string representation of the stack trace for the
   * provided {@code Throwable}.  It will include the unqualified name of the
   * {@code Throwable} class, a list of source files and line numbers (if
   * available) for the stack trace, and will also include the stack trace for
   * the cause (if present).
   *
   * @param  t  The {@code Throwable} for which to retrieve the stack trace.
   *
   * @return  A single-line string representation of the stack trace for the
   *          provided {@code Throwable}.
   */
  @NotNull()
  public static String getStackTrace(@NotNull final Throwable t)
  {
    final StringBuilder buffer = new StringBuilder();
    getStackTrace(t, buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of the stack trace for the
   * provided {@code Throwable} to the given buffer.  It will include the
   * unqualified name of the {@code Throwable} class, a list of source files and
   * line numbers (if available) for the stack trace, and will also include the
   * stack trace for the cause (if present).
   *
   * @param  t       The {@code Throwable} for which to retrieve the stack
   *                 trace.
   * @param  buffer  The buffer to which the information should be appended.
   */
  public static void getStackTrace(@NotNull final Throwable t,
                                   @NotNull final StringBuilder buffer)
  {
    buffer.append(getUnqualifiedClassName(t.getClass()));
    buffer.append('(');

    final String message = t.getMessage();
    if (message != null)
    {
      buffer.append("message='");
      buffer.append(message);
      buffer.append("', ");
    }

    buffer.append("trace='");
    getStackTrace(t.getStackTrace(), buffer);
    buffer.append('\'');

    final Throwable cause = t.getCause();
    if (cause != null)
    {
      buffer.append(", cause=");
      getStackTrace(cause, buffer);
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    buffer.append(')');
  }



  /**
   * Returns a single-line string representation of the stack trace.  It will
   * include a list of source files and line numbers (if available) for the
   * stack trace.
   *
   * @param  elements  The stack trace.
   *
   * @return  A single-line string representation of the stack trace.
   */
  @NotNull()
  public static String getStackTrace(
                            @NotNull final StackTraceElement[] elements)
  {
    final StringBuilder buffer = new StringBuilder();
    getStackTrace(elements, buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of the stack trace to the given
   * buffer.  It will include a list of source files and line numbers
   * (if available) for the stack trace.
   *
   * @param  elements  The stack trace.
   * @param  buffer    The buffer to which the information should be appended.
   */
  public static void getStackTrace(@NotNull final StackTraceElement[] elements,
                                   @NotNull final StringBuilder buffer)
  {
    getStackTrace(elements, buffer, -1);
  }



  /**
   * Appends a single-line string representation of the stack trace to the given
   * buffer.  It will include a list of source files and line numbers
   * (if available) for the stack trace.
   *
   * @param  elements         The stack trace.
   * @param  buffer           The buffer to which the information should be
   *                          appended.
   * @param  maxPreSDKFrames  The maximum number of stack trace frames to
   *                          include from code invoked before calling into the
   *                          LDAP SDK.  A value of zero indicates that only
   *                          stack trace frames from the LDAP SDK itself (or
   *                          things that it calls) will be included.  A
   *                          negative value indicates that
   */
  public static void getStackTrace(@NotNull final StackTraceElement[] elements,
                                   @NotNull final StringBuilder buffer,
                                   final int maxPreSDKFrames)
  {
    boolean sdkElementFound = false;
    int numPreSDKElementsFound = 0;
    for (int i=0; i < elements.length; i++)
    {
      if (i > 0)
      {
        buffer.append(" / ");
      }

      if (elements[i].getClassName().startsWith("com.unboundid."))
      {
        sdkElementFound = true;
      }
      else if (sdkElementFound)
      {
        if ((maxPreSDKFrames >= 0) &&
             (numPreSDKElementsFound >= maxPreSDKFrames))
        {
          buffer.append("...");
          return;
        }

        numPreSDKElementsFound++;
      }

      buffer.append(elements[i].getMethodName());
      buffer.append('(');
      buffer.append(elements[i].getFileName());

      final int lineNumber = elements[i].getLineNumber();
      if (lineNumber > 0)
      {
        buffer.append(':');
        buffer.append(lineNumber);
      }
      else if (elements[i].isNativeMethod())
      {
        buffer.append(":native");
      }
      else
      {
        buffer.append(":unknown");
      }
      buffer.append(')');
    }
  }



  /**
   * Retrieves a string representation of the provided {@code Throwable} object
   * suitable for use in a message.  For runtime exceptions and errors, then a
   * full stack trace for the exception will be provided.  For exception types
   * defined in the LDAP SDK, then its {@code getExceptionMessage} method will
   * be used to get the string representation.  For all other types of
   * exceptions, then the standard string representation will be used.
   * <BR><BR>
   * For all types of exceptions, the message will also include the cause if one
   * exists.
   *
   * @param  t  The {@code Throwable} for which to generate the exception
   *            message.
   *
   * @return  A string representation of the provided {@code Throwable} object
   *          suitable for use in a message.
   */
  @NotNull()
  public static String getExceptionMessage(@NotNull final Throwable t)
  {
    final boolean includeCause =
         Boolean.getBoolean(Debug.PROPERTY_INCLUDE_CAUSE_IN_EXCEPTION_MESSAGES);
    final boolean includeStackTrace = Boolean.getBoolean(
         Debug.PROPERTY_INCLUDE_STACK_TRACE_IN_EXCEPTION_MESSAGES);

    return getExceptionMessage(t, includeCause, includeStackTrace);
  }



  /**
   * Retrieves a string representation of the provided {@code Throwable} object
   * suitable for use in a message.  For runtime exceptions and errors, then a
   * full stack trace for the exception will be provided.  For exception types
   * defined in the LDAP SDK, then its {@code getExceptionMessage} method will
   * be used to get the string representation.  For all other types of
   * exceptions, then the standard string representation will be used.
   * <BR><BR>
   * For all types of exceptions, the message will also include the cause if one
   * exists.
   *
   * @param  t                  The {@code Throwable} for which to generate the
   *                            exception message.
   * @param  includeCause       Indicates whether to include information about
   *                            the cause (if any) in the exception message.
   * @param  includeStackTrace  Indicates whether to include a condensed
   *                            representation of the stack trace in the
   *                            exception message.
   *
   * @return  A string representation of the provided {@code Throwable} object
   *          suitable for use in a message.
   */
  @NotNull()
  public static String getExceptionMessage(@Nullable final Throwable t,
                                           final boolean includeCause,
                                           final boolean includeStackTrace)
  {
    if (t == null)
    {
      return ERR_NO_EXCEPTION.get();
    }

    final StringBuilder buffer = new StringBuilder();
    if (t instanceof LDAPSDKException)
    {
      buffer.append(((LDAPSDKException) t).getExceptionMessage());
    }
    else if (t instanceof LDAPSDKRuntimeException)
    {
      buffer.append(((LDAPSDKRuntimeException) t).getExceptionMessage());
    }
    else if (t instanceof NullPointerException)
    {
      // For NullPointerExceptions, we'll always print at least a portion of
      // the stack trace that includes all of the LDAP SDK code, and up to
      // three frames of whatever called into the SDK.
      buffer.append("NullPointerException(");
      getStackTrace(t.getStackTrace(), buffer, 3);
      buffer.append(')');
    }
    else if ((t.getMessage() == null) || t.getMessage().isEmpty() ||
         t.getMessage().equalsIgnoreCase("null"))
    {
      getStackTrace(t, buffer);
    }
    else
    {
      buffer.append(t.getClass().getSimpleName());
      buffer.append('(');
      buffer.append(t.getMessage());
      buffer.append(')');

      if (includeStackTrace)
      {
        buffer.append(" trace=");
        getStackTrace(t, buffer);
      }
      else if (includeCause)
      {
        final Throwable cause = t.getCause();
        if (cause != null)
        {
          buffer.append(" caused by ");
          buffer.append(getExceptionMessage(cause));
        }
      }
    }

    final String ldapSDKVersionString = ", ldapSDKVersion=" +
         Version.NUMERIC_VERSION_STRING + ", revision=" + Version.REVISION_ID;
    if (buffer.indexOf(ldapSDKVersionString) < 0)
    {
      buffer.append(ldapSDKVersionString);
    }

    return buffer.toString();
  }



  /**
   * Retrieves the unqualified name (i.e., the name without package information)
   * for the provided class.
   *
   * @param  c  The class for which to retrieve the unqualified name.
   *
   * @return  The unqualified name for the provided class.
   */
  @NotNull()
  public static String getUnqualifiedClassName(@NotNull final Class<?> c)
  {
    final String className     = c.getName();
    final int    lastPeriodPos = className.lastIndexOf('.');

    if (lastPeriodPos > 0)
    {
      return className.substring(lastPeriodPos+1);
    }
    else
    {
      return className;
    }
  }



  /**
   * Retrieves a {@code TimeZone} object that represents the UTC (universal
   * coordinated time) time zone.
   *
   * @return  A {@code TimeZone} object that represents the UTC time zone.
   */
  @NotNull()
  public static TimeZone getUTCTimeZone()
  {
    return UTC_TIME_ZONE;
  }



  /**
   * Encodes the provided timestamp in generalized time format.
   *
   * @param  timestamp  The timestamp to be encoded in generalized time format.
   *                    It should use the same format as the
   *                    {@code System.currentTimeMillis()} method (i.e., the
   *                    number of milliseconds since 12:00am UTC on January 1,
   *                    1970).
   *
   * @return  The generalized time representation of the provided date.
   */
  @NotNull()
  public static String encodeGeneralizedTime(final long timestamp)
  {
    return encodeGeneralizedTime(new Date(timestamp));
  }



  /**
   * Encodes the provided date in generalized time format.
   *
   * @param  d  The date to be encoded in generalized time format.
   *
   * @return  The generalized time representation of the provided date.
   */
  @NotNull()
  public static String encodeGeneralizedTime(@NotNull final Date d)
  {
    SimpleDateFormat dateFormat = GENERALIZED_TIME_FORMATTERS.get();
    if (dateFormat == null)
    {
      dateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
      dateFormat.setTimeZone(UTC_TIME_ZONE);
      GENERALIZED_TIME_FORMATTERS.set(dateFormat);
    }

    return dateFormat.format(d);
  }



  /**
   * Decodes the provided string as a timestamp in generalized time format.
   *
   * @param  t  The timestamp to be decoded.  It must not be {@code null}.
   *
   * @return  The {@code Date} object decoded from the provided timestamp.
   *
   * @throws  ParseException  If the provided string could not be decoded as a
   *                          timestamp in generalized time format.
   */
  @NotNull()
  public static Date decodeGeneralizedTime(@NotNull final String t)
         throws ParseException
  {
    Validator.ensureNotNull(t);

    // Extract the time zone information from the end of the value.
    int tzPos;
    final TimeZone tz;
    if (t.endsWith("Z"))
    {
      tz = TimeZone.getTimeZone("UTC");
      tzPos = t.length() - 1;
    }
    else
    {
      tzPos = t.lastIndexOf('-');
      if (tzPos < 0)
      {
        tzPos = t.lastIndexOf('+');
        if (tzPos < 0)
        {
          throw new ParseException(ERR_GENTIME_DECODE_CANNOT_PARSE_TZ.get(t),
                                   0);
        }
      }

      tz = TimeZone.getTimeZone("GMT" + t.substring(tzPos));
      if (tz.getRawOffset() == 0)
      {
        // This is the default time zone that will be returned if the value
        // cannot be parsed.  If it's valid, then it will end in "+0000" or
        // "-0000".  Otherwise, it's invalid and GMT was just a fallback.
        if (! (t.endsWith("+0000") || t.endsWith("-0000")))
        {
          throw new ParseException(ERR_GENTIME_DECODE_CANNOT_PARSE_TZ.get(t),
                                   tzPos);
        }
      }
    }


    // See if the timestamp has a sub-second portion.  Note that if there is a
    // sub-second portion, then we may need to massage the value so that there
    // are exactly three sub-second characters so that it can be interpreted as
    // milliseconds.
    final String subSecFormatStr;
    final String trimmedTimestamp;
    int periodPos = t.lastIndexOf('.', tzPos);
    if (periodPos > 0)
    {
      final int subSecondLength = tzPos - periodPos - 1;
      switch (subSecondLength)
      {
        case 0:
          subSecFormatStr  = "";
          trimmedTimestamp = t.substring(0, periodPos);
          break;
        case 1:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, (periodPos+2)) + "00";
          break;
        case 2:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, (periodPos+3)) + '0';
          break;
        default:
          subSecFormatStr  = ".SSS";
          trimmedTimestamp = t.substring(0, periodPos+4);
          break;
      }
    }
    else
    {
      subSecFormatStr  = "";
      periodPos        = tzPos;
      trimmedTimestamp = t.substring(0, tzPos);
    }


    // Look at where the period is (or would be if it existed) to see how many
    // characters are in the integer portion.  This will give us what we need
    // for the rest of the format string.
    final String formatStr;
    switch (periodPos)
    {
      case 10:
        formatStr = "yyyyMMddHH" + subSecFormatStr;
        break;
      case 12:
        formatStr = "yyyyMMddHHmm" + subSecFormatStr;
        break;
      case 14:
        formatStr = "yyyyMMddHHmmss" + subSecFormatStr;
        break;
      default:
        throw new ParseException(ERR_GENTIME_CANNOT_PARSE_INVALID_LENGTH.get(t),
                                 periodPos);
    }


    // We should finally be able to create an appropriate date format object
    // to parse the trimmed version of the timestamp.
    final SimpleDateFormat dateFormat = new SimpleDateFormat(formatStr);
    dateFormat.setTimeZone(tz);
    dateFormat.setLenient(false);
    return dateFormat.parse(trimmedTimestamp);
  }



  /**
   * Encodes the provided timestamp to the ISO 8601 format described in RFC
   * 3339.
   *
   * @param  timestamp  The timestamp to be encoded in the RFC 3339 format.
   *                    It should use the same format as the
   *                    {@code System.currentTimeMillis()} method (i.e., the
   *                    number of milliseconds since 12:00am UTC on January 1,
   *                    1970).
   *
   * @return  The RFC 3339 representation of the provided date.
   */
  @NotNull()
  public static String encodeRFC3339Time(final long timestamp)
  {
    return encodeRFC3339Time(new Date(timestamp));
  }



  /**
   * Encodes the provided timestamp to the ISO 8601 format described in RFC
   * 3339.
   *
   * @param  d  The date to be encoded in the RFC 3339 format.
   *
   * @return  The RFC 3339 representation of the provided date.
   */
  @NotNull()
  public static String encodeRFC3339Time(@NotNull final Date d)
  {
    SimpleDateFormat dateFormat = RFC_3339_TIME_FORMATTERS.get();
    if (dateFormat == null)
    {
      dateFormat = new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH':'mm':'ss.SSS'Z'");
      dateFormat.setTimeZone(UTC_TIME_ZONE);
      RFC_3339_TIME_FORMATTERS.set(dateFormat);
    }

    return dateFormat.format(d);
  }



  /**
   * Decodes the provided string as a timestamp encoded in the ISO 8601 format
   * described in RFC 3339.
   *
   * @param  timestamp  The timestamp to be decoded in the RFC 3339 format.
   *
   * @return  The {@code Date} object decoded from the provided timestamp.
   *
   * @throws  ParseException  If the provided string could not be decoded as a
   *                          timestamp in the RFC 3339 time format.
   */
  @NotNull()
  public static Date decodeRFC3339Time(@NotNull final String timestamp)
         throws ParseException
  {
    // Make sure that the string representation has the minimum acceptable
    // length.
    if (timestamp.length() < 20)
    {
      throw new ParseException(ERR_RFC_3339_TIME_TOO_SHORT.get(timestamp), 0);
    }


    // Parse the year, month, day, hour, minute, and second components from the
    // timestamp, and make sure the appropriate separator characters are between
    // those components.
    final int year = parseRFC3339Number(timestamp, 0, 4);
    validateRFC3339TimestampSeparatorCharacter(timestamp, 4, '-');
    final int month = parseRFC3339Number(timestamp, 5, 2);
    validateRFC3339TimestampSeparatorCharacter(timestamp, 7, '-');
    final int day = parseRFC3339Number(timestamp, 8, 2);
    validateRFC3339TimestampSeparatorCharacter(timestamp, 10, 'T');
    final int hour = parseRFC3339Number(timestamp, 11, 2);
    validateRFC3339TimestampSeparatorCharacter(timestamp, 13, ':');
    final int minute = parseRFC3339Number(timestamp, 14, 2);
    validateRFC3339TimestampSeparatorCharacter(timestamp, 16, ':');
    final int second = parseRFC3339Number(timestamp, 17, 2);


    // Make sure that the month and day values are acceptable.
    switch (month)
    {
      case 1:
      case 3:
      case 5:
      case 7:
      case 8:
      case 10:
      case 12:
        // January, March, May, July, August, October, and December all have 31
        // days.
        if ((day < 1) || (day > 31))
        {
          throw new ParseException(
               ERR_RFC_3339_TIME_INVALID_DAY_FOR_MONTH.get(timestamp, day,
                    month),
               8);
        }
        break;

      case 4:
      case 6:
      case 9:
      case 11:
        // April, June, September, and November all have 30 days.
        if ((day < 1) || (day > 30))
        {
          throw new ParseException(
               ERR_RFC_3339_TIME_INVALID_DAY_FOR_MONTH.get(timestamp, day,
                    month),
               8);
        }
        break;

      case 2:
        // February can have 28 or 29 days, depending on whether it's a leap
        // year.  Although we could determine whether the provided year is a
        // leap year, we'll just always accept up to 29 days for February.
        if ((day < 1) || (day > 29))
        {
          throw new ParseException(
               ERR_RFC_3339_TIME_INVALID_DAY_FOR_MONTH.get(timestamp, day,
                    month),
               8);
        }
        break;

      default:
        throw new ParseException(
             ERR_RFC_3339_TIME_INVALID_MONTH.get(timestamp, month), 5);
    }


    // Make sure that the hour, minute, and second values are acceptable.  Note
    // that while ISO 8601 permits a value of 24 for the hour, RFC 3339 only
    // permits hour values between 0 and 23.  Also note that some minutes can
    // have up to 61 seconds for leap seconds, so we'll always account for that.
    if ((hour < 0) || (hour > 23))
    {
      throw new ParseException(
           ERR_RFC_3339_TIME_INVALID_HOUR.get(timestamp, hour), 11);
    }

    if ((minute < 0) || (minute > 59))
    {
      throw new ParseException(
           ERR_RFC_3339_TIME_INVALID_MINUTE.get(timestamp, minute), 14);
    }

    if ((second < 0) || (second > 60))
    {
      throw new ParseException(
           ERR_RFC_3339_TIME_INVALID_SECOND.get(timestamp, second), 17);
    }


    // See if there is a sub-second portion.  If so, then there will be a
    // period at position 19 followed by at least one digit.  This
    // implementation will only support timestamps with no more than three
    // sub-second digits.
    int milliseconds = 0;
    int timeZoneStartPos = -1;
    if (timestamp.charAt(19) == '.')
    {
      int numDigits = 0;
      final StringBuilder subSecondString = new StringBuilder(3);
      for (int pos=20; pos < timestamp.length(); pos++)
      {
        final char c = timestamp.charAt(pos);
        switch (c)
        {
          case '0':
            numDigits++;
            if (subSecondString.length() > 0)
            {
              // Only add a zero if it's not the first digit.
              subSecondString.append(c);
            }
            break;
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9':
            numDigits++;
            subSecondString.append(c);
            break;
          case 'Z':
          case '+':
          case '-':
            timeZoneStartPos = pos;
            break;
          default:
            throw new ParseException(
                 ERR_RFC_3339_TIME_INVALID_SUB_SECOND_CHAR.get(timestamp, c,
                      pos),
                 pos);
        }

        if (timeZoneStartPos > 0)
        {
          break;
        }

        if (numDigits > 3)
        {
          throw new ParseException(
               ERR_RFC_3339_TIME_TOO_MANY_SUB_SECOND_DIGITS.get(timestamp),
               20);
        }
      }

      if (timeZoneStartPos < 0)
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_MISSING_TIME_ZONE_AFTER_SUB_SECOND.get(
                  timestamp),
             (timestamp.length() - 1));
      }

      if (numDigits == 0)
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_NO_SUB_SECOND_DIGITS.get(timestamp), 19);
      }

      if (subSecondString.length() == 0)
      {
        // This is possible if the sub-second portion is all zeroes.
        subSecondString.append('0');
      }

      milliseconds = Integer.parseInt(subSecondString.toString());
      if (numDigits == 1)
      {
        milliseconds *= 100;
      }
      else if (numDigits == 2)
      {
        milliseconds *= 10;
      }
    }
    else
    {
      timeZoneStartPos = 19;
    }


    // The remainder of the timestamp should be the time zone.
    final TimeZone timeZone;
    if (timestamp.substring(timeZoneStartPos).equals("Z"))
    {
      // This is shorthand for the UTC time zone.
      timeZone = UTC_TIME_ZONE;
    }
    else
    {
      // This is an offset from UTC, which should be in the form "+HH:MM" or
      // "-HH:MM".  Make sure it has the expected length.
      if ((timestamp.length() - timeZoneStartPos) != 6)
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_INVALID_TZ.get(timestamp), timeZoneStartPos);
      }

      // Make sure it starts with "+" or "-".
      final int firstChar = timestamp.charAt(timeZoneStartPos);
      if ((firstChar != '+') && (firstChar != '-'))
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_INVALID_TZ.get(timestamp), timeZoneStartPos);
      }


      // Make sure the hour offset is valid.
      final int timeZoneHourOffset =
           parseRFC3339Number(timestamp, (timeZoneStartPos+1), 2);
      if ((timeZoneHourOffset < 0) || (timeZoneHourOffset > 23))
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_INVALID_TZ.get(timestamp), timeZoneStartPos);
      }


      // Make sure there is a colon between the hour and the minute portions of
      // the offset.
      if (timestamp.charAt(timeZoneStartPos+3) != ':')
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_INVALID_TZ.get(timestamp), timeZoneStartPos);
      }

      final int timeZoneMinuteOffset =
           parseRFC3339Number(timestamp, (timeZoneStartPos+4), 2);
      if ((timeZoneMinuteOffset < 0) || (timeZoneMinuteOffset > 59))
      {
        throw new ParseException(
             ERR_RFC_3339_TIME_INVALID_TZ.get(timestamp), timeZoneStartPos);
      }

      timeZone = TimeZone.getTimeZone(
           "GMT" + timestamp.substring(timeZoneStartPos));
    }


    // Put everything together to construct the appropriate date.
    final GregorianCalendar calendar =
         new GregorianCalendar(year,
              (month-1), // NOTE:  Calendar stupidly uses zero-indexed months.
              day, hour, minute, second);
    calendar.set(GregorianCalendar.MILLISECOND, milliseconds);
    calendar.setTimeZone(timeZone);
    return calendar.getTime();
  }



  /**
   * Ensures that the provided timestamp string has the expected character at
   * the specified position.
   *
   * @param  timestamp     The timestamp to examine.
   *                       It must not be {@code null}.
   * @param  pos           The position of the character to examine.
   * @param  expectedChar  The character expected at the specified position.
   *
   * @throws  ParseException  If the provided timestamp does not have the
   * expected
   */
  private static void validateRFC3339TimestampSeparatorCharacter(
                           @NotNull final String timestamp, final int pos,
                           final char expectedChar)
          throws ParseException
  {
    if (timestamp.charAt(pos) != expectedChar)
    {
      throw new ParseException(
           ERR_RFC_3339_INVALID_SEPARATOR.get(timestamp, timestamp.charAt(pos),
                pos, expectedChar),
           pos);
    }
  }



  /**
   * Parses the number at the specified location in the timestamp.
   *
   * @param  timestamp  The timestamp to examine.  It must not be {@code null}.
   * @param  pos        The position at which to begin parsing the number.
   * @param  numDigits  The number of digits in the number.
   *
   * @return  The number parsed from the provided timestamp.
   *
   * @throws  ParseException  If a problem is encountered while trying to parse
   *                          the number from the timestamp.
   */
  private static int parseRFC3339Number(@NotNull final String timestamp,
                                        final int pos, final int numDigits)
          throws ParseException
  {
    int value = 0;
    for (int i=0; i < numDigits; i++)
    {
      value *= 10;
      switch (timestamp.charAt(pos+i))
      {
        case '0':
          break;
        case '1':
          value += 1;
          break;
        case '2':
          value += 2;
          break;
        case '3':
          value += 3;
          break;
        case '4':
          value += 4;
          break;
        case '5':
          value += 5;
          break;
        case '6':
          value += 6;
          break;
        case '7':
          value += 7;
          break;
        case '8':
          value += 8;
          break;
        case '9':
          value += 9;
          break;
        default:
          throw new ParseException(
               ERR_RFC_3339_INVALID_DIGIT.get(timestamp,
                    timestamp.charAt(pos+i), (pos+i)),
               (pos+i));
      }
    }

    return value;
  }



  /**
   * Trims only leading spaces from the provided string, leaving any trailing
   * spaces intact.
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  The original string if no trimming was required, or a new string
   *          without leading spaces if the provided string had one or more.  It
   *          may be an empty string if the provided string was an empty string
   *          or contained only spaces.
   */
  @NotNull()
  public static String trimLeading(@NotNull final String s)
  {
    Validator.ensureNotNull(s);

    int nonSpacePos = 0;
    final int length = s.length();
    while ((nonSpacePos < length) && (s.charAt(nonSpacePos) == ' '))
    {
      nonSpacePos++;
    }

    if (nonSpacePos == 0)
    {
      // There were no leading spaces.
      return s;
    }
    else if (nonSpacePos >= length)
    {
      // There were no non-space characters.
      return "";
    }
    else
    {
      // There were leading spaces, so return the string without them.
      return s.substring(nonSpacePos, length);
    }
  }



  /**
   * Trims only trailing spaces from the provided string, leaving any leading
   * spaces intact.
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  The original string if no trimming was required, or a new string
   *          without trailing spaces if the provided string had one or more.
   *          It may be an empty string if the provided string was an empty
   *          string or contained only spaces.
   */
  @NotNull()
  public static String trimTrailing(@NotNull final String s)
  {
    Validator.ensureNotNull(s);

    final int lastPos = s.length() - 1;
    int nonSpacePos = lastPos;
    while ((nonSpacePos >= 0) && (s.charAt(nonSpacePos) == ' '))
    {
      nonSpacePos--;
    }

    if (nonSpacePos < 0)
    {
      // There were no non-space characters.
      return "";
    }
    else if (nonSpacePos == lastPos)
    {
      // There were no trailing spaces.
      return s;
    }
    else
    {
      // There were trailing spaces, so return the string without them.
      return s.substring(0, (nonSpacePos+1));
    }
  }



  /**
   * Wraps the contents of the specified line using the given width.  It will
   * attempt to wrap at spaces to preserve words, but if that is not possible
   * (because a single "word" is longer than the maximum width), then it will
   * wrap in the middle of the word at the specified maximum width.
   *
   * @param  line      The line to be wrapped.  It must not be {@code null}.
   * @param  maxWidth  The maximum width for lines in the resulting list.  A
   *                   value less than or equal to zero will cause no wrapping
   *                   to be performed.
   *
   * @return  A list of the wrapped lines.  It may be empty if the provided line
   *          contained only spaces.
   */
  @NotNull()
  public static List<String> wrapLine(@NotNull final String line,
                                      final int maxWidth)
  {
    return wrapLine(line, maxWidth, maxWidth);
  }



  /**
   * Wraps the contents of the specified line using the given width.  It will
   * attempt to wrap at spaces to preserve words, but if that is not possible
   * (because a single "word" is longer than the maximum width), then it will
   * wrap in the middle of the word at the specified maximum width.
   *
   * @param  line                    The line to be wrapped.  It must not be
   *                                 {@code null}.
   * @param  maxFirstLineWidth       The maximum length for the first line in
   *                                 the resulting list.  A value less than or
   *                                 equal to zero will cause no wrapping to be
   *                                 performed.
   * @param  maxSubsequentLineWidth  The maximum length for all lines except the
   *                                 first line.  This must be greater than zero
   *                                 unless {@code maxFirstLineWidth} is less
   *                                 than or equal to zero.
   *
   * @return  A list of the wrapped lines.  It may be empty if the provided line
   *          contained only spaces.
   */
  @NotNull()
  public static List<String> wrapLine(@NotNull final String line,
                                      final int maxFirstLineWidth,
                                      final int maxSubsequentLineWidth)
  {
    if (maxFirstLineWidth > 0)
    {
      Validator.ensureTrue(maxSubsequentLineWidth > 0);
    }

    // See if the provided string already contains line breaks.  If so, then
    // treat it as multiple lines rather than a single line.
    final int breakPos = line.indexOf('\n');
    if (breakPos >= 0)
    {
      final ArrayList<String> lineList = new ArrayList<>(10);
      final StringTokenizer tokenizer = new StringTokenizer(line, "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        lineList.addAll(wrapLine(tokenizer.nextToken(), maxFirstLineWidth,
             maxSubsequentLineWidth));
      }

      return lineList;
    }

    final int length = line.length();
    if ((maxFirstLineWidth <= 0) || (length < maxFirstLineWidth))
    {
      return Collections.singletonList(line);
    }


    int wrapPos = maxFirstLineWidth;
    int lastWrapPos = 0;
    final ArrayList<String> lineList = new ArrayList<>(5);
    while (true)
    {
      final int spacePos = line.lastIndexOf(' ', wrapPos);
      if (spacePos > lastWrapPos)
      {
        // We found a space in an acceptable location, so use it after trimming
        // any trailing spaces.
        final String s = trimTrailing(line.substring(lastWrapPos, spacePos));

        // Don't bother adding the line if it contained only spaces.
        if (! s.isEmpty())
        {
          lineList.add(s);
        }

        wrapPos = spacePos;
      }
      else
      {
        // We didn't find any spaces, so we'll have to insert a hard break at
        // the specified wrap column.
        lineList.add(line.substring(lastWrapPos, wrapPos));
      }

      // Skip over any spaces before the next non-space character.
      while ((wrapPos < length) && (line.charAt(wrapPos) == ' '))
      {
        wrapPos++;
      }

      lastWrapPos = wrapPos;
      wrapPos += maxSubsequentLineWidth;
      if (wrapPos >= length)
      {
        // The last fragment can fit on the line, so we can handle that now and
        // break.
        if (lastWrapPos >= length)
        {
          break;
        }
        else
        {
          final String s = line.substring(lastWrapPos);
          lineList.add(s);
          break;
        }
      }
    }

    return lineList;
  }



  /**
   * This method returns a form of the provided argument that is safe to
   * use on the command line for the local platform. This method is provided as
   * a convenience wrapper around {@link ExampleCommandLineArgument}.  Calling
   * this method is equivalent to:
   *
   * <PRE>
   *  return ExampleCommandLineArgument.getCleanArgument(s).getLocalForm();
   * </PRE>
   *
   * For getting direct access to command line arguments that are safe to
   * use on other platforms, call
   * {@link ExampleCommandLineArgument#getCleanArgument}.
   *
   * @param  s  The string to be processed.  It must not be {@code null}.
   *
   * @return  A cleaned version of the provided string in a form that will allow
   *          it to be displayed as the value of a command-line argument on.
   */
  @NotNull()
  public static String cleanExampleCommandLineArgument(@NotNull final String s)
  {
    return ExampleCommandLineArgument.getCleanArgument(s).getLocalForm();
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  a  The array of strings to concatenate.  It must not be
   *            {@code null} but may be empty.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided array.
   */
  @NotNull()
  public static String concatenateStrings(@NotNull final String... a)
  {
    return concatenateStrings(null, null, "  ", null, null, a);
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  l  The list of strings to concatenate.  It must not be
   *            {@code null} but may be empty.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided list.
   */
  @NotNull()
  public static String concatenateStrings(@NotNull final List<String> l)
  {
    return concatenateStrings(null, null, "  ", null, null, l);
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  beforeList       A string that should be placed at the beginning of
   *                          the list.  It may be {@code null} or empty if
   *                          nothing should be placed at the beginning of the
   *                          list.
   * @param  beforeElement    A string that should be placed before each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed before each element.
   * @param  betweenElements  The separator that should be placed between
   *                          elements in the list.  It may be {@code null} or
   *                          empty if no separator should be placed between
   *                          elements.
   * @param  afterElement     A string that should be placed after each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed after each element.
   * @param  afterList        A string that should be placed at the end of the
   *                          list.  It may be {@code null} or empty if nothing
   *                          should be placed at the end of the list.
   * @param  a                The array of strings to concatenate.  It must not
   *                          be {@code null} but may be empty.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided list.
   */
  @NotNull()
  public static String concatenateStrings(@Nullable final String beforeList,
                            @Nullable final String beforeElement,
                            @Nullable final String betweenElements,
                            @Nullable final String afterElement,
                            @Nullable final String afterList,
                            @NotNull final String... a)
  {
    return concatenateStrings(beforeList, beforeElement, betweenElements,
         afterElement, afterList, Arrays.asList(a));
  }



  /**
   * Retrieves a single string which is a concatenation of all of the provided
   * strings.
   *
   * @param  beforeList       A string that should be placed at the beginning of
   *                          the list.  It may be {@code null} or empty if
   *                          nothing should be placed at the beginning of the
   *                          list.
   * @param  beforeElement    A string that should be placed before each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed before each element.
   * @param  betweenElements  The separator that should be placed between
   *                          elements in the list.  It may be {@code null} or
   *                          empty if no separator should be placed between
   *                          elements.
   * @param  afterElement     A string that should be placed after each element
   *                          in the list.  It may be {@code null} or empty if
   *                          nothing should be placed after each element.
   * @param  afterList        A string that should be placed at the end of the
   *                          list.  It may be {@code null} or empty if nothing
   *                          should be placed at the end of the list.
   * @param  l                The list of strings to concatenate.  It must not
   *                          be {@code null} but may be empty.
   *
   * @return  A string containing a concatenation of all of the strings in the
   *          provided list.
   */
  @NotNull()
  public static String concatenateStrings(@Nullable final String beforeList,
                            @Nullable final String beforeElement,
                            @Nullable final String betweenElements,
                            @Nullable final String afterElement,
                            @Nullable final String afterList,
                            @NotNull final List<String> l)
  {
    Validator.ensureNotNull(l);

    final StringBuilder buffer = new StringBuilder();

    if (beforeList != null)
    {
      buffer.append(beforeList);
    }

    final Iterator<String> iterator = l.iterator();
    while (iterator.hasNext())
    {
      if (beforeElement != null)
      {
        buffer.append(beforeElement);
      }

      buffer.append(iterator.next());

      if (afterElement != null)
      {
        buffer.append(afterElement);
      }

      if ((betweenElements != null) && iterator.hasNext())
      {
        buffer.append(betweenElements);
      }
    }

    if (afterList != null)
    {
      buffer.append(afterList);
    }

    return buffer.toString();
  }



  /**
   * Converts a duration in seconds to a string with a human-readable duration
   * which may include days, hours, minutes, and seconds, to the extent that
   * they are needed.
   *
   * @param  s  The number of seconds to be represented.
   *
   * @return  A string containing a human-readable representation of the
   *          provided time.
   */
  @NotNull()
  public static String secondsToHumanReadableDuration(final long s)
  {
    return millisToHumanReadableDuration(s * 1000L);
  }



  /**
   * Converts a duration in seconds to a string with a human-readable duration
   * which may include days, hours, minutes, and seconds, to the extent that
   * they are needed.
   *
   * @param  m  The number of milliseconds to be represented.
   *
   * @return  A string containing a human-readable representation of the
   *          provided time.
   */
  @NotNull()
  public static String millisToHumanReadableDuration(final long m)
  {
    final StringBuilder buffer = new StringBuilder();
    long numMillis = m;

    final long numDays = numMillis / 86_400_000L;
    if (numDays > 0)
    {
      numMillis -= (numDays * 86_400_000L);
      if (numDays == 1)
      {
        buffer.append(INFO_NUM_DAYS_SINGULAR.get(numDays));
      }
      else
      {
        buffer.append(INFO_NUM_DAYS_PLURAL.get(numDays));
      }
    }

    final long numHours = numMillis / 3_600_000L;
    if (numHours > 0)
    {
      numMillis -= (numHours * 3_600_000L);
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      if (numHours == 1)
      {
        buffer.append(INFO_NUM_HOURS_SINGULAR.get(numHours));
      }
      else
      {
        buffer.append(INFO_NUM_HOURS_PLURAL.get(numHours));
      }
    }

    final long numMinutes = numMillis / 60_000L;
    if (numMinutes > 0)
    {
      numMillis -= (numMinutes * 60_000L);
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      if (numMinutes == 1)
      {
        buffer.append(INFO_NUM_MINUTES_SINGULAR.get(numMinutes));
      }
      else
      {
        buffer.append(INFO_NUM_MINUTES_PLURAL.get(numMinutes));
      }
    }

    if (numMillis == 1000)
    {
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      buffer.append(INFO_NUM_SECONDS_SINGULAR.get(1));
    }
    else if ((numMillis > 0) || (buffer.length() == 0))
    {
      if (buffer.length() > 0)
      {
        buffer.append(", ");
      }

      final long numSeconds = numMillis / 1000L;
      numMillis -= (numSeconds * 1000L);
      if ((numMillis % 1000L) != 0L)
      {
        final double numSecondsDouble = numSeconds + (numMillis / 1000.0);
        final DecimalFormat decimalFormat = new DecimalFormat("0.000");
        buffer.append(INFO_NUM_SECONDS_WITH_DECIMAL.get(
             decimalFormat.format(numSecondsDouble)));
      }
      else
      {
        buffer.append(INFO_NUM_SECONDS_PLURAL.get(numSeconds));
      }
    }

    return buffer.toString();
  }



  /**
   * Converts the provided number of nanoseconds to milliseconds.
   *
   * @param  nanos  The number of nanoseconds to convert to milliseconds.
   *
   * @return  The number of milliseconds that most closely corresponds to the
   *          specified number of nanoseconds.
   */
  public static long nanosToMillis(final long nanos)
  {
    return Math.max(0L, Math.round(nanos / 1_000_000.0d));
  }



  /**
   * Converts the provided number of milliseconds to nanoseconds.
   *
   * @param  millis  The number of milliseconds to convert to nanoseconds.
   *
   * @return  The number of nanoseconds that most closely corresponds to the
   *          specified number of milliseconds.
   */
  public static long millisToNanos(final long millis)
  {
    return Math.max(0L, (millis * 1_000_000L));
  }



  /**
   * Indicates whether the provided string is a valid numeric OID.  A numeric
   * OID must start and end with a digit, must have at least on period, must
   * contain only digits and periods, and must not have two consecutive periods.
   *
   * @param  s  The string to examine.  It must not be {@code null}.
   *
   * @return  {@code true} if the provided string is a valid numeric OID, or
   *          {@code false} if not.
   */
  public static boolean isNumericOID(@NotNull final String s)
  {
    boolean digitRequired = true;
    boolean periodFound   = false;
    for (final char c : s.toCharArray())
    {
      switch (c)
      {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          digitRequired = false;
          break;

        case '.':
          if (digitRequired)
          {
            return false;
          }
          else
          {
            digitRequired = true;
          }
          periodFound = true;
          break;

        default:
          return false;
      }

    }

    return (periodFound && (! digitRequired));
  }



  /**
   * Capitalizes the provided string.  The first character will be converted to
   * uppercase, and the rest of the string will be left unaltered.
   *
   * @param  s  The string to be capitalized.
   *
   * @return  A capitalized version of the provided string, or {@code null} if
   *          the provided string was {@code null}.
   */
  @Nullable()
  public static String capitalize(@Nullable final String s)
  {
    return capitalize(s, false);
  }



  /**
   * Capitalizes the provided string.  The first character of the string (or
   * optionally the first character of each word in the string)
   *
   * @param  s         The string to be capitalized.
   * @param  allWords  Indicates whether to capitalize all words in the string,
   *                   or only the first word.
   *
   * @return  A capitalized version of the provided string, or {@code null} if
   *          the provided string was {@code null}.
   */
  @Nullable()
  public static String capitalize(@Nullable final String s,
                                  final boolean allWords)
  {
    if (s == null)
    {
      return null;
    }

    switch (s.length())
    {
      case 0:
        return s;

      case 1:
        return s.toUpperCase();

      default:
        boolean capitalize = true;
        final char[] chars = s.toCharArray();
        final StringBuilder buffer = new StringBuilder(chars.length);
        for (final char c : chars)
        {
          // Whitespace and punctuation will be considered word breaks.
          if (Character.isWhitespace(c) ||
              (((c >= '!') && (c <= '.')) ||
               ((c >= ':') && (c <= '@')) ||
               ((c >= '[') && (c <= '`')) ||
               ((c >= '{') && (c <= '~'))))
          {
            buffer.append(c);
            capitalize |= allWords;
          }
          else if (capitalize)
          {
            buffer.append(Character.toUpperCase(c));
            capitalize = false;
          }
          else
          {
            buffer.append(c);
          }
        }
        return buffer.toString();
    }
  }



  /**
   * Encodes the provided UUID to a byte array containing its 128-bit
   * representation.
   *
   * @param  uuid  The UUID to be encoded.  It must not be {@code null}.
   *
   * @return  The byte array containing the 128-bit encoded UUID.
   */
  @NotNull()
  public static byte[] encodeUUID(@NotNull final UUID uuid)
  {
    final byte[] b = new byte[16];

    final long mostSignificantBits  = uuid.getMostSignificantBits();
    b[0]  = (byte) ((mostSignificantBits >> 56) & 0xFF);
    b[1]  = (byte) ((mostSignificantBits >> 48) & 0xFF);
    b[2]  = (byte) ((mostSignificantBits >> 40) & 0xFF);
    b[3]  = (byte) ((mostSignificantBits >> 32) & 0xFF);
    b[4]  = (byte) ((mostSignificantBits >> 24) & 0xFF);
    b[5]  = (byte) ((mostSignificantBits >> 16) & 0xFF);
    b[6]  = (byte) ((mostSignificantBits >> 8) & 0xFF);
    b[7]  = (byte) (mostSignificantBits & 0xFF);

    final long leastSignificantBits = uuid.getLeastSignificantBits();
    b[8]  = (byte) ((leastSignificantBits >> 56) & 0xFF);
    b[9]  = (byte) ((leastSignificantBits >> 48) & 0xFF);
    b[10] = (byte) ((leastSignificantBits >> 40) & 0xFF);
    b[11] = (byte) ((leastSignificantBits >> 32) & 0xFF);
    b[12] = (byte) ((leastSignificantBits >> 24) & 0xFF);
    b[13] = (byte) ((leastSignificantBits >> 16) & 0xFF);
    b[14] = (byte) ((leastSignificantBits >> 8) & 0xFF);
    b[15] = (byte) (leastSignificantBits & 0xFF);

    return b;
  }



  /**
   * Decodes the value of the provided byte array as a Java UUID.
   *
   * @param  b  The byte array to be decoded as a UUID.  It must not be
   *            {@code null}.
   *
   * @return  The decoded UUID.
   *
   * @throws  ParseException  If the provided byte array cannot be parsed as a
   *                         UUID.
   */
  @NotNull()
  public static UUID decodeUUID(@NotNull final byte[] b)
         throws ParseException
  {
    if (b.length != 16)
    {
      throw new ParseException(ERR_DECODE_UUID_INVALID_LENGTH.get(toHex(b)), 0);
    }

    long mostSignificantBits = 0L;
    for (int i=0; i < 8; i++)
    {
      mostSignificantBits = (mostSignificantBits << 8) | (b[i] & 0xFF);
    }

    long leastSignificantBits = 0L;
    for (int i=8; i < 16; i++)
    {
      leastSignificantBits = (leastSignificantBits << 8) | (b[i] & 0xFF);
    }

    return new UUID(mostSignificantBits, leastSignificantBits);
  }



  /**
   * Returns {@code true} if and only if the current process is running on
   * a Windows-based operating system.
   *
   * @return  {@code true} if the current process is running on a Windows-based
   *          operating system and {@code false} otherwise.
   */
  public static boolean isWindows()
  {
    final String osName = toLowerCase(getSystemProperty("os.name"));
    return ((osName != null) && osName.contains("windows"));
  }



  /**
   * Retrieves the string that should be appended to the end of all but the last
   * line of a multi-line command to indicate that the command continues onto
   * the next line.
   * <BR><BR>
   * This will be the caret (also called a circumflex accent) character on
   * Windows systems, and a backslash (also called a reverse solidus) character
   * on Linux and UNIX-based systems.
   * <BR><BR>
   * The string value that is returned will not include a space, but it should
   * generally be preceded by one or more space to separate it from the previous
   * component on the command line.
   *
   * @return  The string that should be appended (generally after one or more
   *          spaces to separate it from the previous component) to the end of
   *          all but the last line of a multi-line command to indicate that the
   *          command continues onto the next line.
   */
  @NotNull()
  public static String getCommandLineContinuationString()
  {
    if (isWindows())
    {
      return "^";
    }
    else
    {
      return "\\";
    }
  }



  /**
   * Attempts to parse the contents of the provided string to an argument list
   * (e.g., converts something like "--arg1 arg1value --arg2 --arg3 arg3value"
   * to a list of "--arg1", "arg1value", "--arg2", "--arg3", "arg3value").
   *
   * @param  s  The string to be converted to an argument list.
   *
   * @return  The parsed argument list.
   *
   * @throws  ParseException  If a problem is encountered while attempting to
   *                          parse the given string to an argument list.
   */
  @NotNull()
  public static List<String> toArgumentList(@Nullable final String s)
         throws ParseException
  {
    if ((s == null) || s.isEmpty())
    {
      return Collections.emptyList();
    }

    int quoteStartPos = -1;
    boolean inEscape = false;
    final ArrayList<String> argList = new ArrayList<>(20);
    final StringBuilder currentArg = new StringBuilder();
    for (int i=0; i < s.length(); i++)
    {
      final char c = s.charAt(i);
      if (inEscape)
      {
        currentArg.append(c);
        inEscape = false;
        continue;
      }

      if (c == '\\')
      {
        inEscape = true;
      }
      else if (c == '"')
      {
        if (quoteStartPos >= 0)
        {
          quoteStartPos = -1;
        }
        else
        {
          quoteStartPos = i;
        }
      }
      else if (c == ' ')
      {
        if (quoteStartPos >= 0)
        {
          currentArg.append(c);
        }
        else if (currentArg.length() > 0)
        {
          argList.add(currentArg.toString());
          currentArg.setLength(0);
        }
      }
      else
      {
        currentArg.append(c);
      }
    }

    if (s.endsWith("\\") && (! s.endsWith("\\\\")))
    {
      throw new ParseException(ERR_ARG_STRING_DANGLING_BACKSLASH.get(),
           (s.length() - 1));
    }

    if (quoteStartPos >= 0)
    {
      throw new ParseException(ERR_ARG_STRING_UNMATCHED_QUOTE.get(
           quoteStartPos), quoteStartPos);
    }

    if (currentArg.length() > 0)
    {
      argList.add(currentArg.toString());
    }

    return Collections.unmodifiableList(argList);
  }



  /**
   * Retrieves an array containing the elements of the provided collection.
   *
   * @param  <T>         The type of element included in the provided
   *                     collection.
   * @param  collection  The collection to convert to an array.
   * @param  type        The type of element contained in the collection.
   *
   * @return  An array containing the elements of the provided list, or
   *          {@code null} if the provided list is {@code null}.
   */
  @Nullable()
  public static <T> T[] toArray(@Nullable final Collection<T> collection,
                                @NotNull final Class<T> type)
  {
    if (collection == null)
    {
      return null;
    }

    @SuppressWarnings("unchecked")
    final T[] array = (T[]) Array.newInstance(type, collection.size());

    return collection.toArray(array);
  }



  /**
   * Creates a modifiable list with all of the items of the provided array in
   * the same order.  This method behaves much like {@code Arrays.asList},
   * except that if the provided array is {@code null}, then it will return a
   * {@code null} list rather than throwing an exception.
   *
   * @param  <T>  The type of item contained in the provided array.
   *
   * @param  array  The array of items to include in the list.
   *
   * @return  The list that was created, or {@code null} if the provided array
   *          was {@code null}.
   */
  @Nullable()
  public static <T> List<T> toList(@Nullable final T[] array)
  {
    if (array == null)
    {
      return null;
    }

    final ArrayList<T> l = new ArrayList<>(array.length);
    l.addAll(Arrays.asList(array));
    return l;
  }



  /**
   * Creates a modifiable list with all of the items of the provided array in
   * the same order.  This method behaves much like {@code Arrays.asList},
   * except that if the provided array is {@code null}, then it will return an
   * empty list rather than throwing an exception.
   *
   * @param  <T>  The type of item contained in the provided array.
   *
   * @param  array  The array of items to include in the list.
   *
   * @return  The list that was created, or an empty list if the provided array
   *          was {@code null}.
   */
  @NotNull()
  public static <T> List<T> toNonNullList(@Nullable final T[] array)
  {
    if (array == null)
    {
      return new ArrayList<>(0);
    }

    final ArrayList<T> l = new ArrayList<>(array.length);
    l.addAll(Arrays.asList(array));
    return l;
  }



  /**
   * Indicates whether both of the provided objects are {@code null} or both
   * are logically equal (using the {@code equals} method).
   *
   * @param  o1  The first object for which to make the determination.
   * @param  o2  The second object for which to make the determination.
   *
   * @return  {@code true} if both objects are {@code null} or both are
   *          logically equal, or {@code false} if only one of the objects is
   *          {@code null} or they are not logically equal.
   */
  public static boolean bothNullOrEqual(@Nullable final Object o1,
                                        @Nullable final Object o2)
  {
    if (o1 == null)
    {
      return (o2 == null);
    }
    else if (o2 == null)
    {
      return false;
    }

    return o1.equals(o2);
  }



  /**
   * Indicates whether both of the provided strings are {@code null} or both
   * are logically equal ignoring differences in capitalization (using the
   * {@code equalsIgnoreCase} method).
   *
   * @param  s1  The first string for which to make the determination.
   * @param  s2  The second string for which to make the determination.
   *
   * @return  {@code true} if both strings are {@code null} or both are
   *          logically equal ignoring differences in capitalization, or
   *          {@code false} if only one of the objects is {@code null} or they
   *          are not logically equal ignoring capitalization.
   */
  public static boolean bothNullOrEqualIgnoreCase(@Nullable final String s1,
                                                  @Nullable final String s2)
  {
    if (s1 == null)
    {
      return (s2 == null);
    }
    else if (s2 == null)
    {
      return false;
    }

    return s1.equalsIgnoreCase(s2);
  }



  /**
   * Indicates whether the provided string arrays have the same elements,
   * ignoring the order in which they appear and differences in capitalization.
   * It is assumed that neither array contains {@code null} strings, and that
   * no string appears more than once in each array.
   *
   * @param  a1  The first array for which to make the determination.
   * @param  a2  The second array for which to make the determination.
   *
   * @return  {@code true} if both arrays have the same set of strings, or
   *          {@code false} if not.
   */
  public static boolean stringsEqualIgnoreCaseOrderIndependent(
                             @Nullable final String[] a1,
                             @Nullable final String[] a2)
  {
    if (a1 == null)
    {
      return (a2 == null);
    }
    else if (a2 == null)
    {
      return false;
    }

    if (a1.length != a2.length)
    {
      return false;
    }

    if (a1.length == 1)
    {
      return (a1[0].equalsIgnoreCase(a2[0]));
    }

    final HashSet<String> s1 = new HashSet<>(computeMapCapacity(a1.length));
    for (final String s : a1)
    {
      s1.add(toLowerCase(s));
    }

    final HashSet<String> s2 = new HashSet<>(computeMapCapacity(a2.length));
    for (final String s : a2)
    {
      s2.add(toLowerCase(s));
    }

    return s1.equals(s2);
  }



  /**
   * Indicates whether the provided arrays have the same elements, ignoring the
   * order in which they appear.  It is assumed that neither array contains
   * {@code null} elements, and that no element appears more than once in each
   * array.
   *
   * @param  <T>  The type of element contained in the arrays.
   *
   * @param  a1  The first array for which to make the determination.
   * @param  a2  The second array for which to make the determination.
   *
   * @return  {@code true} if both arrays have the same set of elements, or
   *          {@code false} if not.
   */
  public static <T> boolean arraysEqualOrderIndependent(@Nullable final T[] a1,
                                                        @Nullable final T[] a2)
  {
    if (a1 == null)
    {
      return (a2 == null);
    }
    else if (a2 == null)
    {
      return false;
    }

    if (a1.length != a2.length)
    {
      return false;
    }

    if (a1.length == 1)
    {
      return (a1[0].equals(a2[0]));
    }

    final HashSet<T> s1 = new HashSet<>(Arrays.asList(a1));
    final HashSet<T> s2 = new HashSet<>(Arrays.asList(a2));
    return s1.equals(s2);
  }



  /**
   * Determines the number of bytes in a UTF-8 character that starts with the
   * given byte.
   *
   * @param  b  The byte for which to make the determination.
   *
   * @return  The number of bytes in a UTF-8 character that starts with the
   *          given byte, or -1 if it does not appear to be a valid first byte
   *          for a UTF-8 character.
   */
  public static int numBytesInUTF8CharacterWithFirstByte(final byte b)
  {
    if ((b & 0x7F) == b)
    {
      return 1;
    }
    else if ((b & 0xE0) == 0xC0)
    {
      return 2;
    }
    else if ((b & 0xF0) == 0xE0)
    {
      return 3;
    }
    else if ((b & 0xF8) == 0xF0)
    {
      return 4;
    }
    else
    {
      return -1;
    }
  }



  /**
   * Indicates whether the provided attribute name should be considered a
   * sensitive attribute for the purposes of {@code toCode} methods.  If an
   * attribute is considered sensitive, then its values will be redacted in the
   * output of the {@code toCode} methods.
   *
   * @param  name  The name for which to make the determination.  It may or may
   *               not include attribute options.  It must not be {@code null}.
   *
   * @return  {@code true} if the specified attribute is one that should be
   *          considered sensitive for the
   */
  public static boolean isSensitiveToCodeAttribute(@NotNull final String name)
  {
    final String lowerBaseName = Attribute.getBaseName(name).toLowerCase();
    return TO_CODE_SENSITIVE_ATTRIBUTE_NAMES.contains(lowerBaseName);
  }



  /**
   * Retrieves a set containing the base names (in all lowercase characters) of
   * any attributes that should be considered sensitive for the purposes of the
   * {@code toCode} methods.  By default, only the userPassword and
   * authPassword attributes and their respective OIDs will be included.
   *
   * @return  A set containing the base names (in all lowercase characters) of
   *          any attributes that should be considered sensitive for the
   *          purposes of the {@code toCode} methods.
   */
  @NotNull()
  public static Set<String> getSensitiveToCodeAttributeBaseNames()
  {
    return TO_CODE_SENSITIVE_ATTRIBUTE_NAMES;
  }



  /**
   * Specifies the names of any attributes that should be considered sensitive
   * for the purposes of the {@code toCode} methods.
   *
   * @param  names  The names of any attributes that should be considered
   *                sensitive for the purposes of the {@code toCode} methods.
   *                It may be {@code null} or empty if no attributes should be
   *                considered sensitive.
   */
  public static void setSensitiveToCodeAttributes(
                          @Nullable final String... names)
  {
    setSensitiveToCodeAttributes(toList(names));
  }



  /**
   * Specifies the names of any attributes that should be considered sensitive
   * for the purposes of the {@code toCode} methods.
   *
   * @param  names  The names of any attributes that should be considered
   *                sensitive for the purposes of the {@code toCode} methods.
   *                It may be {@code null} or empty if no attributes should be
   *                considered sensitive.
   */
  public static void setSensitiveToCodeAttributes(
                          @Nullable final Collection<String> names)
  {
    if ((names == null) || names.isEmpty())
    {
      TO_CODE_SENSITIVE_ATTRIBUTE_NAMES = Collections.emptySet();
    }
    else
    {
      final LinkedHashSet<String> nameSet = new LinkedHashSet<>(names.size());
      for (final String s : names)
      {
        nameSet.add(Attribute.getBaseName(s).toLowerCase());
      }

      TO_CODE_SENSITIVE_ATTRIBUTE_NAMES = Collections.unmodifiableSet(nameSet);
    }
  }



  /**
   * Creates a new {@code IOException} with a cause.  The constructor needed to
   * do this wasn't available until Java SE 6, so reflection is used to invoke
   * this constructor in versions of Java that provide it.  In Java SE 5, the
   * provided message will be augmented with information about the cause.
   *
   * @param  message  The message to use for the exception.  This may be
   *                  {@code null} if the message should be generated from the
   *                  provided cause.
   * @param  cause    The underlying cause for the exception.  It may be
   *                  {@code null} if the exception should have only a message.
   *
   * @return  The {@code IOException} object that was created.
   */
  @NotNull()
  public static IOException createIOExceptionWithCause(
                                 @Nullable final String message,
                                 @Nullable final Throwable cause)
  {
    if (cause == null)
    {
      return new IOException(message);
    }
    else if (message == null)
    {
      return new IOException(cause);
    }
    else
    {
      return new IOException(message, cause);
    }
  }



  /**
   * Converts the provided string (which may include line breaks) into a list
   * containing the lines without the line breaks.
   *
   * @param  s  The string to convert into a list of its representative lines.
   *
   * @return  A list containing the lines that comprise the given string.
   */
  @NotNull()
  public static List<String> stringToLines(@Nullable final String s)
  {
    final ArrayList<String> l = new ArrayList<>(10);

    if (s == null)
    {
      return l;
    }

    final BufferedReader reader = new BufferedReader(new StringReader(s));

    try
    {
      while (true)
      {
        try
        {
          final String line = reader.readLine();
          if (line == null)
          {
            return l;
          }
          else
          {
            l.add(line);
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);

          // This should never happen.  If it does, just return a list
          // containing a single item that is the original string.
          l.clear();
          l.add(s);
          return l;
        }
      }
    }
    finally
    {
      try
      {
        // This is technically not necessary in this case, but it's good form.
        reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        // This should never happen, and there's nothing we need to do even if
        // it does.
      }
    }
  }



  /**
   * Creates a string that is a concatenation of all of the provided lines, with
   * a line break (using the end-of-line sequence appropriate for the underlying
   * platform) after each line (including the last line).
   *
   * @param  lines  The lines to include in the string.
   *
   * @return  The string resulting from concatenating the provided lines with
   *          line breaks.
   */
  @NotNull()
  public static String linesToString(@Nullable final CharSequence... lines)
  {
    if (lines == null)
    {
      return "";
    }

    return linesToString(Arrays.asList(lines));
  }



  /**
   * Creates a string that is a concatenation of all of the provided lines, with
   * a line break (using the end-of-line sequence appropriate for the underlying
   * platform) after each line (including the last line).
   *
   * @param  lines  The lines to include in the string.
   *
   * @return  The string resulting from concatenating the provided lines with
   *          line breaks.
   */
  @NotNull()
  public static String linesToString(
                            @Nullable final List<? extends CharSequence> lines)
  {
    if (lines == null)
    {
      return "";
    }

    final StringBuilder buffer = new StringBuilder();
    for (final CharSequence line : lines)
    {
      buffer.append(line);
      buffer.append(EOL);
    }

    return buffer.toString();
  }



  /**
   * Constructs a {@code File} object from the provided path.
   *
   * @param  baseDirectory  The base directory to use as the starting point.
   *                        It must not be {@code null} and is expected to
   *                        represent a directory.
   * @param  pathElements   An array of the elements that make up the remainder
   *                        of the path to the specified file, in order from
   *                        paths closest to the root of the filesystem to
   *                        furthest away (that is, the first element should
   *                        represent a file or directory immediately below the
   *                        base directory, the second is one level below that,
   *                        and so on).  It may be {@code null} or empty if the
   *                        base directory should be used.
   *
   * @return  The constructed {@code File} object.
   */
  @NotNull()
  public static File constructPath(@NotNull final File baseDirectory,
                                   @Nullable final String... pathElements)
  {
    Validator.ensureNotNull(baseDirectory);

    File f = baseDirectory;
    if (pathElements != null)
    {
      for (final String pathElement : pathElements)
      {
        f = new File(f, pathElement);
      }
    }

    return f;
  }



  /**
   * Creates a byte array from the provided integer values.  All of the integer
   * values must be between 0x00 and 0xFF (0 and 255), inclusive.  Any bits
   * set outside of that range will be ignored.
   *
   * @param  bytes  The values to include in the byte array.
   *
   * @return  A byte array with the provided set of values.
   */
  @NotNull()
  public static byte[] byteArray(@Nullable final int... bytes)
  {
    if ((bytes == null) || (bytes.length == 0))
    {
      return NO_BYTES;
    }

    final byte[] byteArray = new byte[bytes.length];
    for (int i=0; i < bytes.length; i++)
    {
      byteArray[i] = (byte) (bytes[i] & 0xFF);
    }

    return byteArray;
  }



  /**
   * Indicates whether the unit tests are currently running in this JVM.
   *
   * @return  {@code true} if the unit tests are currently running, or
   *          {@code false} if not.
   */
  public static boolean isWithinUnitTest()
  {
    return IS_WITHIN_UNIT_TESTS;
  }



  /**
   * Throws an {@code Error} or a {@code RuntimeException} based on the provided
   * {@code Throwable} object.  This method will always throw something,
   * regardless of the provided {@code Throwable} object.
   *
   * @param  throwable  The {@code Throwable} object to use to create the
   *                    exception to throw.
   *
   * @throws  Error  If the provided {@code Throwable} object is an
   *                 {@code Error} instance, then that {@code Error} instance
   *                 will be re-thrown.
   *
   * @throws  RuntimeException  If the provided {@code Throwable} object is a
   *                            {@code RuntimeException} instance, then that
   *                            {@code RuntimeException} instance will be
   *                            re-thrown.  Otherwise, it must be a checked
   *                            exception and that checked exception will be
   *                            re-thrown as a {@code RuntimeException}.
   */
  public static void throwErrorOrRuntimeException(
                          @NotNull final Throwable throwable)
         throws Error, RuntimeException
  {
    Validator.ensureNotNull(throwable);

    if (throwable instanceof Error)
    {
      throw (Error) throwable;
    }
    else if (throwable instanceof RuntimeException)
    {
      throw (RuntimeException) throwable;
    }
    else
    {
      throw new RuntimeException(throwable);
    }
  }



  /**
   * Re-throws the provided {@code Throwable} instance only if it is an
   * {@code Error} or a {@code RuntimeException} instance; otherwise, this
   * method will return without taking any action.
   *
   * @param  throwable  The {@code Throwable} object to examine and potentially
   *                    re-throw.
   *
   * @throws  Error  If the provided {@code Throwable} object is an
   *                 {@code Error} instance, then that {@code Error} instance
   *                 will be re-thrown.
   *
   * @throws  RuntimeException  If the provided {@code Throwable} object is a
   *                            {@code RuntimeException} instance, then that
   *                            {@code RuntimeException} instance will be
   *                            re-thrown.
   */
  public static void rethrowIfErrorOrRuntimeException(
                          @NotNull final Throwable throwable)
         throws Error, RuntimeException
  {
    if (throwable instanceof Error)
    {
      throw (Error) throwable;
    }
    else if (throwable instanceof RuntimeException)
    {
      throw (RuntimeException) throwable;
    }
  }



  /**
   * Re-throws the provided {@code Throwable} instance only if it is an
   * {@code Error}; otherwise, this method will return without taking any
   * action.
   *
   * @param  throwable  The {@code Throwable} object to examine and potentially
   *                    re-throw.
   *
   * @throws  Error  If the provided {@code Throwable} object is an
   *                 {@code Error} instance, then that {@code Error} instance
   *                 will be re-thrown.
   */
  public static void rethrowIfError(@NotNull final Throwable throwable)
         throws Error
  {
    if (throwable instanceof Error)
    {
      throw (Error) throwable;
    }
  }



  /**
   * Computes the capacity that should be used for a map or a set with the
   * expected number of elements, which can help avoid the need to re-hash or
   * re-balance the map if too many items are added.  This method bases its
   * computation on the default map load factor of 0.75.
   *
   * @param  expectedItemCount  The expected maximum number of items that will
   *                            be placed in the map or set.  It must be greater
   *                            than or equal to zero.
   *
   * @return  The capacity that should be used for a map or a set with the
   *          expected number of elements
   */
  public static int computeMapCapacity(final int expectedItemCount)
  {
    switch (expectedItemCount)
    {
      case 0:
        return 0;
      case 1:
        return 2;
      case 2:
        return 3;
      case 3:
        return 5;
      case 4:
        return 6;
      case 5:
        return 7;
      case 6:
        return 9;
      case 7:
        return 10;
      case 8:
        return 11;
      case 9:
        return 13;
      case 10:
        return 14;
      case 11:
        return 15;
      case 12:
        return 17;
      case 13:
        return 18;
      case 14:
        return 19;
      case 15:
        return 21;
      case 16:
        return 22;
      case 17:
        return 23;
      case 18:
        return 25;
      case 19:
        return 26;
      case 20:
        return 27;
      case 30:
        return 41;
      case 40:
        return 54;
      case 50:
        return 67;
      case 60:
        return 81;
      case 70:
        return 94;
      case 80:
        return 107;
      case 90:
        return 121;
      case 100:
        return 134;
      case 110:
        return 147;
      case 120:
        return 161;
      case 130:
        return 174;
      case 140:
        return 187;
      case 150:
        return 201;
      case 160:
        return 214;
      case 170:
        return 227;
      case 180:
        return 241;
      case 190:
        return 254;
      case 200:
        return 267;
      default:
        Validator.ensureTrue((expectedItemCount >= 0),
             "StaticUtils.computeMapOrSetCapacity.expectedItemCount must be " +
                  "greater than or equal to zero.");

        // NOTE:  536,870,911 is Integer.MAX_VALUE/4.  If the value is larger
        // than that, then we'll fall back to using floating-point arithmetic
        //
        if (expectedItemCount > 536_870_911)
        {
          final int computedCapacity = ((int) (expectedItemCount / 0.75)) + 1;
          if (computedCapacity <= expectedItemCount)
          {
            // This suggests that the expected number of items is so big that
            // the computed capacity can't be adequately represented by an
            // integer.  In that case, we'll just return the expected item
            // count and let the map or set get re-hashed/re-balanced if it
            // actually gets anywhere near that size.
            return expectedItemCount;
          }
          else
          {
            return computedCapacity;
          }
        }
        else
        {
          return ((expectedItemCount * 4) / 3) + 1;
        }
    }
  }



  /**
   * Creates an unmodifiable set containing the provided items.  The iteration
   * order of the provided items will be preserved.
   *
   * @param  <T>    The type of item to include in the set.
   * @param  items  The items to include in the set.  It must not be
   *                {@code null}, but may be empty.
   *
   * @return  An unmodifiable set containing the provided items.
   */
  @SafeVarargs()
  @SuppressWarnings("varargs")
  @NotNull()
  public static <T> Set<T> setOf(@NotNull final T... items)
  {
    return Collections.unmodifiableSet(
         new LinkedHashSet<>(Arrays.asList(items)));
  }



  /**
   * Creates a {@code HashSet} containing the provided items.
   *
   * @param  <T>    The type of item to include in the set.
   * @param  items  The items to include in the set.  It must not be
   *                {@code null}, but may be empty.
   *
   * @return  A {@code HashSet} containing the provided items.
   */
  @SafeVarargs()
  @SuppressWarnings("varargs")
  @NotNull()
  public static <T> HashSet<T> hashSetOf(@NotNull final T... items)
  {
    return new HashSet<>(Arrays.asList(items));
  }



  /**
   * Creates a {@code LinkedHashSet} containing the provided items.
   *
   * @param  <T>    The type of item to include in the set.
   * @param  items  The items to include in the set.  It must not be
   *                {@code null}, but may be empty.
   *
   * @return  A {@code LinkedHashSet} containing the provided items.
   */
  @SafeVarargs()
  @SuppressWarnings("varargs")
  @NotNull()
  public static <T> LinkedHashSet<T> linkedHashSetOf(@NotNull final T... items)
  {
    return new LinkedHashSet<>(Arrays.asList(items));
  }



  /**
   * Creates a {@code TreeSet} containing the provided items.
   *
   * @param  <T>    The type of item to include in the set.
   * @param  items  The items to include in the set.  It must not be
   *                {@code null}, but may be empty.
   *
   * @return  A {@code LinkedHashSet} containing the provided items.
   */
  @SafeVarargs()
  @SuppressWarnings("varargs")
  @NotNull()
  public static <T> TreeSet<T> treeSetOf(@NotNull final T... items)
  {
    return new TreeSet<>(Arrays.asList(items));
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>    The type for the map keys.
   * @param  <V>    The type for the map values.
   * @param  key    The only key to include in the map.
   * @param  value  The only value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key,
                                     @NotNull final V value)
  {
    return Collections.singletonMap(key, value);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(2));

    map.put(key1, value1);
    map.put(key2, value2);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(3));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   * @param  key4    The fourth key to include in the map.
   * @param  value4  The fourth value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(4));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   * @param  key4    The fourth key to include in the map.
   * @param  value4  The fourth value to include in the map.
   * @param  key5    The fifth key to include in the map.
   * @param  value5  The fifth value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4,
                                     @NotNull final K key5,
                                     @NotNull final V value5)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(5));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);
    map.put(key5, value5);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   * @param  key4    The fourth key to include in the map.
   * @param  value4  The fourth value to include in the map.
   * @param  key5    The fifth key to include in the map.
   * @param  value5  The fifth value to include in the map.
   * @param  key6    The sixth key to include in the map.
   * @param  value6  The sixth value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4,
                                     @NotNull final K key5,
                                     @NotNull final V value5,
                                     @NotNull final K key6,
                                     @NotNull final V value6)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(6));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);
    map.put(key5, value5);
    map.put(key6, value6);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   * @param  key4    The fourth key to include in the map.
   * @param  value4  The fourth value to include in the map.
   * @param  key5    The fifth key to include in the map.
   * @param  value5  The fifth value to include in the map.
   * @param  key6    The sixth key to include in the map.
   * @param  value6  The sixth value to include in the map.
   * @param  key7    The seventh key to include in the map.
   * @param  value7  The seventh value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4,
                                     @NotNull final K key5,
                                     @NotNull final V value5,
                                     @NotNull final K key6,
                                     @NotNull final V value6,
                                     @NotNull final K key7,
                                     @NotNull final V value7)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(7));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);
    map.put(key5, value5);
    map.put(key6, value6);
    map.put(key7, value7);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   * @param  key4    The fourth key to include in the map.
   * @param  value4  The fourth value to include in the map.
   * @param  key5    The fifth key to include in the map.
   * @param  value5  The fifth value to include in the map.
   * @param  key6    The sixth key to include in the map.
   * @param  value6  The sixth value to include in the map.
   * @param  key7    The seventh key to include in the map.
   * @param  value7  The seventh value to include in the map.
   * @param  key8    The eighth key to include in the map.
   * @param  value8  The eighth value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4,
                                     @NotNull final K key5,
                                     @NotNull final V value5,
                                     @NotNull final K key6,
                                     @NotNull final V value6,
                                     @NotNull final K key7,
                                     @NotNull final V value7,
                                     @NotNull final K key8,
                                     @NotNull final V value8)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(8));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);
    map.put(key5, value5);
    map.put(key6, value6);
    map.put(key7, value7);
    map.put(key8, value8);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>     The type for the map keys.
   * @param  <V>     The type for the map values.
   * @param  key1    The first key to include in the map.
   * @param  value1  The first value to include in the map.
   * @param  key2    The second key to include in the map.
   * @param  value2  The second value to include in the map.
   * @param  key3    The third key to include in the map.
   * @param  value3  The third value to include in the map.
   * @param  key4    The fourth key to include in the map.
   * @param  value4  The fourth value to include in the map.
   * @param  key5    The fifth key to include in the map.
   * @param  value5  The fifth value to include in the map.
   * @param  key6    The sixth key to include in the map.
   * @param  value6  The sixth value to include in the map.
   * @param  key7    The seventh key to include in the map.
   * @param  value7  The seventh value to include in the map.
   * @param  key8    The eighth key to include in the map.
   * @param  value8  The eighth value to include in the map.
   * @param  key9    The ninth key to include in the map.
   * @param  value9  The ninth value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4,
                                     @NotNull final K key5,
                                     @NotNull final V value5,
                                     @NotNull final K key6,
                                     @NotNull final V value6,
                                     @NotNull final K key7,
                                     @NotNull final V value7,
                                     @NotNull final K key8,
                                     @NotNull final V value8,
                                     @NotNull final K key9,
                                     @NotNull final V value9)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(9));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);
    map.put(key5, value5);
    map.put(key6, value6);
    map.put(key7, value7);
    map.put(key8, value8);
    map.put(key9, value9);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>      The type for the map keys.
   * @param  <V>      The type for the map values.
   * @param  key1     The first key to include in the map.
   * @param  value1   The first value to include in the map.
   * @param  key2     The second key to include in the map.
   * @param  value2   The second value to include in the map.
   * @param  key3     The third key to include in the map.
   * @param  value3   The third value to include in the map.
   * @param  key4     The fourth key to include in the map.
   * @param  value4   The fourth value to include in the map.
   * @param  key5     The fifth key to include in the map.
   * @param  value5   The fifth value to include in the map.
   * @param  key6     The sixth key to include in the map.
   * @param  value6   The sixth value to include in the map.
   * @param  key7     The seventh key to include in the map.
   * @param  value7   The seventh value to include in the map.
   * @param  key8     The eighth key to include in the map.
   * @param  value8   The eighth value to include in the map.
   * @param  key9     The ninth key to include in the map.
   * @param  value9   The ninth value to include in the map.
   * @param  key10    The tenth key to include in the map.
   * @param  value10  The tenth value to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @NotNull()
  public static <K,V> Map<K,V> mapOf(@NotNull final K key1,
                                     @NotNull final V value1,
                                     @NotNull final K key2,
                                     @NotNull final V value2,
                                     @NotNull final K key3,
                                     @NotNull final V value3,
                                     @NotNull final K key4,
                                     @NotNull final V value4,
                                     @NotNull final K key5,
                                     @NotNull final V value5,
                                     @NotNull final K key6,
                                     @NotNull final V value6,
                                     @NotNull final K key7,
                                     @NotNull final V value7,
                                     @NotNull final K key8,
                                     @NotNull final V value8,
                                     @NotNull final K key9,
                                     @NotNull final V value9,
                                     @NotNull final K key10,
                                     @NotNull final V value10)
  {
    final LinkedHashMap<K,V> map = new LinkedHashMap<>(computeMapCapacity(10));

    map.put(key1, value1);
    map.put(key2, value2);
    map.put(key3, value3);
    map.put(key4, value4);
    map.put(key5, value5);
    map.put(key6, value6);
    map.put(key7, value7);
    map.put(key8, value8);
    map.put(key9, value9);
    map.put(key10, value10);

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.  The map entries
   * must have the same data type for keys and values.
   *
   * @param  <T>    The type for the map keys and values.
   * @param  items  The items to include in the map.  If it is null or empty,
   *                the map will be empty.  If it is non-empty, then the number
   *                of elements in the array must be a multiple of two.
   *                Elements in even-numbered indexes will be the keys for the
   *                map entries, while elements in odd-numbered indexes will be
   *                the map values.
   *
   * @return  The unmodifiable map that was created.
   */
  @SafeVarargs()
  @NotNull()
  public static <T> Map<T,T> mapOf(@Nullable final T... items)
  {
    if ((items == null) || (items.length == 0))
    {
      return Collections.emptyMap();
    }

    Validator.ensureTrue(((items.length % 2) == 0),
         "StaticUtils.mapOf.items must have an even number of elements");

    final int numEntries = items.length / 2;
    final LinkedHashMap<T,T> map =
         new LinkedHashMap<>(computeMapCapacity(numEntries));
    for (int i=0; i < items.length; )
    {
      map.put(items[i++], items[i++]);
    }

    return Collections.unmodifiableMap(map);
  }



  /**
   * Creates an unmodifiable map containing the provided items.
   *
   * @param  <K>    The type for the map keys.
   * @param  <V>    The type for the map values.
   * @param  items  The items to include in the map.
   *
   * @return  The unmodifiable map that was created.
   */
  @SafeVarargs()
  @NotNull()
  public static <K,V> Map<K,V> mapOfObjectPairs(
                                    @Nullable final ObjectPair<K,V>... items)
  {
    if ((items == null) || (items.length == 0))
    {
      return Collections.emptyMap();
    }

    final LinkedHashMap<K,V> map = new LinkedHashMap<>(
         computeMapCapacity(items.length));
    for (final ObjectPair<K,V> item : items)
    {
      map.put(item.getFirst(), item.getSecond());
    }

    return Collections.unmodifiableMap(map);
  }



  /**
   * Attempts to determine all addresses associated with the local system,
   * including loopback addresses.
   *
   * @param  nameResolver  The name resolver to use to determine the local host
   *                       and loopback addresses.  If this is {@code null},
   *                       then the LDAP SDK's default name resolver will be
   *                       used.
   *
   * @return  A set of the local addresses that were identified.
   */
  @NotNull()
  public static Set<InetAddress> getAllLocalAddresses(
                                      @Nullable final NameResolver nameResolver)
  {
    return getAllLocalAddresses(nameResolver, true);
  }



  /**
   * Attempts to determine all addresses associated with the local system,
   * optionally including loopback addresses.
   *
   * @param  nameResolver     The name resolver to use to determine the local
   *                          host and loopback addresses.  If this is
   *                          {@code null}, then the LDAP SDK's default name
   *                          resolver will be used.
   * @param  includeLoopback  Indicates whether to include loopback addresses in
   *                          the set that is returned.
   *
   * @return  A set of the local addresses that were identified.
   */
  @NotNull()
  public static Set<InetAddress> getAllLocalAddresses(
                                      @Nullable final NameResolver nameResolver,
                                      final boolean includeLoopback)
  {
    final NameResolver resolver;
    if (nameResolver == null)
    {
      resolver = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER;
    }
    else
    {
      resolver = nameResolver;
    }

    final LinkedHashSet<InetAddress> localAddresses =
         new LinkedHashSet<>(computeMapCapacity(10));

    try
    {
      final InetAddress localHostAddress = resolver.getLocalHost();
      if (includeLoopback || (! localHostAddress.isLoopbackAddress()))
      {
        localAddresses.add(localHostAddress);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    try
    {
      final Enumeration<NetworkInterface> networkInterfaces =
           NetworkInterface.getNetworkInterfaces();
      while (networkInterfaces.hasMoreElements())
      {
        final NetworkInterface networkInterface =
             networkInterfaces.nextElement();
        if (includeLoopback || (! networkInterface.isLoopback()))
        {
          final Enumeration<InetAddress> interfaceAddresses =
               networkInterface.getInetAddresses();
          while (interfaceAddresses.hasMoreElements())
          {
            final InetAddress address = interfaceAddresses.nextElement();
            if (includeLoopback || (! address.isLoopbackAddress()))
            {
              localAddresses.add(address);
            }
          }
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    if (includeLoopback)
    {
      try
      {
        localAddresses.add(resolver.getLoopbackAddress());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return Collections.unmodifiableSet(localAddresses);
  }



  /**
   * Retrieves the canonical host name for the provided address, if it can be
   * resolved to a name.
   *
   * @param  nameResolver  The name resolver to use to obtain the canonical
   *                       host name.  If this is {@code null}, then the LDAP
   *                       SDK's default name resolver will be used.
   * @param  address       The {@code InetAddress} for which to attempt to
   *                       obtain the canonical host name.
   *
   * @return  The canonical host name for the provided address, or {@code null}
   *          if it cannot be obtained (either because the attempt returns
   *          {@code null}, which shouldn't happen, or because it matches the
   *          IP address).
   */
  @Nullable()
  public static String getCanonicalHostNameIfAvailable(
                            @Nullable final NameResolver nameResolver,
                            @NotNull final InetAddress address)
  {
    final NameResolver resolver;
    if (nameResolver == null)
    {
      resolver = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER;
    }
    else
    {
      resolver = nameResolver;
    }

    final String hostAddress = address.getHostAddress();
    final String trimmedHostAddress =
         trimInterfaceNameFromHostAddress(hostAddress);

    final String canonicalHostName = resolver.getCanonicalHostName(address);
    if ((canonicalHostName == null) ||
         canonicalHostName.equalsIgnoreCase(hostAddress) ||
         canonicalHostName.equalsIgnoreCase(trimmedHostAddress))
    {
      return null;
    }

    return canonicalHostName;
  }



  /**
   * Retrieves the canonical host names for the provided set of
   * {@code InetAddress} objects.  If any of the provided addresses cannot be
   * resolved to a canonical host name (in which case the attempt to get the
   * canonical host name will return its IP address), it will be excluded from
   * the returned set.
   *
   * @param  nameResolver  The name resolver to use to obtain the canonical
   *                       host names.  If this is {@code null}, then the LDAP
   *                       SDK's default name resolver will be used.
   * @param  addresses     The set of addresses for which to obtain the
   *                       canonical host names.
   *
   * @return  A set of the canonical host names that could be obtained from the
   *          provided addresses.
   */
  @NotNull()
  public static Set<String> getAvailableCanonicalHostNames(
                     @Nullable final NameResolver nameResolver,
                     @NotNull final Collection<InetAddress> addresses)
  {
    final NameResolver resolver;
    if (nameResolver == null)
    {
      resolver = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER;
    }
    else
    {
      resolver = nameResolver;
    }

    final Set<String> canonicalHostNames =
         new LinkedHashSet<>(computeMapCapacity(addresses.size()));
    for (final InetAddress address : addresses)
    {
      final String canonicalHostName =
           getCanonicalHostNameIfAvailable(resolver, address);
      if (canonicalHostName != null)
      {
        canonicalHostNames.add(canonicalHostName);
      }
    }

    return Collections.unmodifiableSet(canonicalHostNames);
  }



  /**
   * Retrieves a version of the provided host address with the interface name
   * stripped off.  Java sometimes follows an IP address with a percent sign and
   * the interface name.  If that interface name is present in the provided
   * host address, then this method will trim it off, leaving just the IP
   * address.  If the provided host address does not include the interface name,
   * then the provided address will be returned as-is.
   *
   * @param  hostAddress  The host address to be trimmed.
   *
   * @return  The provided host address without the interface name.
   */
  @NotNull()
  public static String trimInterfaceNameFromHostAddress(
                            @NotNull final String hostAddress)
  {
    final int percentPos = hostAddress.indexOf('%');
    if (percentPos > 0)
    {
      return hostAddress.substring(0, percentPos);
    }
    else
    {
      return hostAddress;
    }
  }



  /**
   * Indicates whether the provided address is marked as reserved in the IANA
   * IPv4 address space registry at
   * https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt
   * or the IPv6 address space registry at
   * https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.txt.
   *
   * @param  address
   *             The address for which to make the determination.  It must
   *             not be {@code null}, and it must be an IPv4 or IPv6 address.
   * @param  includePrivateUseNetworkAddresses
   *              Indicates whether to consider addresses in a private-use
   *              network address range (including 10.0.0.0/8, 172.16.0.0/12,
   *              192.168.0.0/16, and fc00::/7) as reserved addresses.  If this
   *              is {@code true}, then this method will return {@code true} for
   *              addresses in a private-use network range; if it is
   *              {@code false}, then this method will return {@code false} for
   *              addresses in those ranges.  This does not have any effect for
   *              addresses in other reserved address ranges.
   *
   * @return  {@code true} if the provided address is in a reserved address
   *          range, or {@code false} if not.
   */
  public static boolean isIANAReservedIPAddress(
              @NotNull final InetAddress address,
              final boolean includePrivateUseNetworkAddresses)
  {
    if (address instanceof Inet4Address)
    {
      return isIANAReservedIPv4Address((Inet4Address) address,
           includePrivateUseNetworkAddresses);
    }
    else if (address instanceof Inet6Address)
    {
      return isIANAReservedIPv6Address((Inet6Address) address,
           includePrivateUseNetworkAddresses);
    }
    else
    {
      // It's an unrecognized address type.  We have to assume it's not
      // reserved.
      return false;
    }
  }



  /**
   * Indicates whether the provided address is marked as reserved in the IANA
   * IPv4 address space registry at
   * https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt.
   * This implementation is based on the version of the registry that was
   * updated on 2019-12-27.
   *
   * @param  address
   *             The IPv4 address for which to make the determination.  It must
   *             not be {@code null}, and it must be an IPv4 address.
   * @param  includePrivateUseNetworkAddresses
   *              Indicates whether to consider addresses in a private-use
   *              network address range as reserved addresses.
   *
   * @return  {@code true} if the provided address is in a reserved address
   *          range, or {@code false} if not.
   */
  public static boolean isIANAReservedIPv4Address(
              @NotNull final Inet4Address address,
              final boolean includePrivateUseNetworkAddresses)
  {
    final byte[] addressBytes = address.getAddress();
    final int firstOctet = addressBytes[0] & 0xFF;
    final int secondOctet = addressBytes[1] & 0xFF;
    final int thirdOctet = addressBytes[2] & 0xFF;

    switch (firstOctet)
    {
      // * Addresses 0.*.*.* are reserved for self-identification.
      case 0:

      // * Addresses 127.*.*.* are reserved for loopback addresses.
      case 127:

      // * Addresses 224.*.*.* through 239.*.*.* are reserved for multicast.
      case 224:
      case 225:
      case 226:
      case 227:
      case 228:
      case 229:
      case 230:
      case 231:
      case 232:
      case 233:
      case 234:
      case 235:
      case 236:
      case 237:
      case 238:
      case 239:

      // * Addresses 240.*.*.* through 255.*.*.* are reserved for future use.
      case 240:
      case 241:
      case 242:
      case 243:
      case 244:
      case 245:
      case 246:
      case 247:
      case 248:
      case 249:
      case 250:
      case 251:
      case 252:
      case 253:
      case 254:
      case 255:
        return true;

      // * Addresses 10.*.*.* are reserved for private-use networks.
      case 10:
        return includePrivateUseNetworkAddresses;

      // * Addresses 100.64.0.0 through 100.127.255.255. are in the shared
      //   address space range described in RFC 6598.
      case 100:  // First octet 100 -- Partially reserved
        return ((secondOctet >= 64) && (secondOctet <= 127));

      // * Addresses 169.254.*.* are reserved for link-local addresses.
      case 169:
        return (secondOctet == 254);

      // * Addresses 172.16.0.0 through 172.31.255.255 are reserved for
      //   private-use networks.
      case 172:
        if ((secondOctet >= 16) && (secondOctet <= 31))
        {
          return includePrivateUseNetworkAddresses;
        }
        else
        {
          return false;
        }

      // * Addresses 192.0.0.* are reserved for IPv4 Special Purpose Address.
      // * Addresses 192.0.2.* are reserved for TEST-NET-1.
      // * Addresses 192.88.99.* are reserved for 6to4 Relay Anycast.
      // * Addresses 192.168.*.* are reserved for private-use networks.
      case 192:
        if (secondOctet == 0)
        {
          return ((thirdOctet == 0) || (thirdOctet == 2));
        }
        else if (secondOctet == 88)
        {
          return (thirdOctet == 99);
        }
        else if (secondOctet == 168)
        {
          return includePrivateUseNetworkAddresses;
        }
        else
        {
          return false;
        }

      // * Addresses 198.18.0.0 through 198.19.255.255 are reserved for Network
      //   Interconnect Device Benchmark Testing.
      // * Addresses 198.51.100.* are reserved for TEST-NET-2.
      case 198:
        if ((secondOctet >= 18) && (secondOctet <= 19))
        {
          return true;
        }
        else
        {
          return ((secondOctet == 51) && (thirdOctet == 100));
        }

      // * Addresses 203.0.113.* are reserved for TEST-NET-3.
      case 203:
        return ((secondOctet == 0) && (thirdOctet == 113));

      // All other addresses are not reserved.
      default:
        return false;
    }
  }



  /**
   * Indicates whether the provided address is marked as reserved in the IANA
   * IPv6 address space registry at
   * https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.txt.
   * This implementation is based on the version of the registry that was
   * updated on 2019-09-13.
   *
   * @param  address
   *             The IPv4 address for which to make the determination.  It must
   *             not be {@code null}, and it must be an IPv6 address.
   * @param  includePrivateUseNetworkAddresses
   *              Indicates whether to consider addresses in a private-use
   *              network address range as reserved addresses.
   *
   * @return  {@code true} if the provided address is in a reserved address
   *          range, or {@code false} if not.
   */
  public static boolean isIANAReservedIPv6Address(
              @NotNull final Inet6Address address,
              final boolean includePrivateUseNetworkAddresses)
  {
    final byte[] addressBytes = address.getAddress();
    final int firstOctet = addressBytes[0] & 0xFF;

    // Addresses with a first octet between 0x20 and 0x3F are not reserved.
    if ((firstOctet >= 0x20) && (firstOctet <= 0x3F))
    {
      return false;
    }

    // Addresses with a first octet between 0xFC and 0xFD are reserved for
    // private-use networks.
    if ((firstOctet >= 0xFC) && (firstOctet <= 0xFD))
    {
      return includePrivateUseNetworkAddresses;
    }

    // All other addresses are reserved.
    return true;
  }



  /**
   * Reads the bytes that comprise the specified file.
   *
   * @param  path  The path to the file to be read.
   *
   * @return  The bytes that comprise the specified file.
   *
   * @throws  IOException  If a problem occurs while trying to read the file.
   */
  @NotNull()
  public static byte[] readFileBytes(@NotNull final String path)
         throws IOException
  {
    return readFileBytes(new File(path));
  }



  /**
   * Reads the bytes that comprise the specified file.
   *
   * @param  file  The file to be read.
   *
   * @return  The bytes that comprise the specified file.
   *
   * @throws  IOException  If a problem occurs while trying to read the file.
   */
  @NotNull()
  public static byte[] readFileBytes(@NotNull final File file)
         throws IOException
  {
    final ByteStringBuffer buffer = new ByteStringBuffer((int) file.length());
    buffer.readFrom(file);
    return buffer.toByteArray();
  }



  /**
   * Reads the contents of the specified file as a string.  All line breaks in
   * the file will be preserved, with the possible exception of the one on the
   * last line.
   *
   * @param  path                   The path to the file to be read.
   * @param  includeFinalLineBreak  Indicates whether the final line break (if
   *                                there is one) should be preserved.
   *
   * @return  The contents of the specified file as a string.
   *
   * @throws  IOException  If a problem occurs while trying to read the file.
   */
  @NotNull()
  public static String readFileAsString(@NotNull final String path,
                                        final boolean includeFinalLineBreak)
         throws IOException
  {
    return readFileAsString(new File(path), includeFinalLineBreak);
  }



  /**
   * Reads the contents of the specified file as a string.  All line breaks in
   * the file will be preserved, with the possible exception of the one on the
   * last line.
   *
   * @param  file                   The file to be read.
   * @param  includeFinalLineBreak  Indicates whether the final line break (if
   *                                there is one) should be preserved.
   *
   * @return  The contents of the specified file as a string.
   *
   * @throws  IOException  If a problem occurs while trying to read the file.
   */
  @NotNull()
  public static String readFileAsString(@NotNull final File file,
                                        final boolean includeFinalLineBreak)
         throws IOException
  {
    final ByteStringBuffer buffer = new ByteStringBuffer((int) file.length());
    buffer.readFrom(file);

    if (! includeFinalLineBreak)
    {
      if (buffer.endsWith(EOL_BYTES_CR_LF))
      {
        buffer.setLength(buffer.length() - EOL_BYTES_CR_LF.length);
      }
      else if (buffer.endsWith(EOL_BYTES_LF))
      {
        buffer.setLength(buffer.length() - EOL_BYTES_LF.length);
      }
    }

    return buffer.toString();
  }



  /**
   * Reads the lines that comprise the specified file.
   *
   * @param  path  The path to the file to be read.
   *
   * @return  The lines that comprise the specified file.
   *
   * @throws  IOException  If a problem occurs while trying to read the file.
   */
  @NotNull()
  public static List<String> readFileLines(@NotNull final String path)
         throws IOException
  {
    return readFileLines(new File(path));
  }



  /**
   * Reads the lines that comprise the specified file.
   *
   * @param  file  The file to be read.
   *
   * @return  The lines that comprise the specified file.
   *
   * @throws  IOException  If a problem occurs while trying to read the file.
   */
  @NotNull()
  public static List<String> readFileLines(@NotNull final File file)
         throws IOException
  {
    try (FileReader fileReader = new FileReader(file);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      final List<String> lines = new ArrayList<>();
      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          return Collections.unmodifiableList(lines);
        }

        lines.add(line);
      }
    }
  }



  /**
   * Writes the provided bytes to the specified file.  If the file already
   * exists, it will be overwritten.
   *
   * @param  path   The path to the file to be written.
   * @param  bytes  The bytes to be written to the specified file.
   *
   * @throws  IOException  If a problem is encountered while writing the file.
   */
  public static void writeFile(@NotNull final String path,
                               @NotNull final byte[] bytes)
         throws IOException
  {
    writeFile(new File(path), bytes);
  }



  /**
   * Writes the provided bytes to the specified file.  If the file already
   * exists, it will be overwritten.
   *
   * @param  file   The file to be written.
   * @param  bytes  The bytes to be written to the specified file.
   *
   * @throws  IOException  If a problem is encountered while writing the file.
   */
  public static void writeFile(@NotNull final File file,
                               @NotNull final byte[] bytes)
         throws IOException
  {
    try (FileOutputStream outputStream = new FileOutputStream(file))
    {
      outputStream.write(bytes);
    }
  }



  /**
   * Writes the provided lines to the specified file, with each followed by an
   * appropriate end-of-line marker for the current platform.  If the file
   * already exists, it will be overwritten.
   *
   * @param  path   The path to the file to be written.
   * @param  lines  The lines to be written to the specified file.
   *
   * @throws  IOException  If a problem is encountered while writing the file.
   */
  public static void writeFile(@NotNull final String path,
                               @NotNull final CharSequence... lines)
         throws IOException
  {
    writeFile(new File(path), lines);
  }



  /**
   * Writes the provided lines to the specified file, with each followed by an
   * appropriate end-of-line marker for the current platform.  If the file
   * already exists, it will be overwritten.
   *
   * @param  file   The file to be written.
   * @param  lines  The lines to be written to the specified file.
   *
   * @throws  IOException  If a problem is encountered while writing the file.
   */
  public static void writeFile(@NotNull final File file,
                               @NotNull final CharSequence... lines)
         throws IOException
  {
    writeFile(file, toList(lines));
  }



  /**
   * Writes the provided lines to the specified file, with each followed by an
   * appropriate end-of-line marker for the current platform.  If the file
   * already exists, it will be overwritten.
   *
   * @param  path   The path to the file to be written.
   * @param  lines  The lines to be written to the specified file.
   *
   * @throws  IOException  If a problem is encountered while writing the file.
   */
  public static void writeFile(@NotNull final String path,
                          @Nullable final List<? extends CharSequence> lines)
         throws IOException
  {
    writeFile(new File(path), lines);
  }



  /**
   * Writes the provided lines to the specified file, with each followed by an
   * appropriate end-of-line marker for the current platform.  If the file
   * already exists, it will be overwritten.
   *
   * @param  file   The file to be written.
   * @param  lines  The lines to be written to the specified file.
   *
   * @throws  IOException  If a problem is encountered while writing the file.
   */
  public static void writeFile(@NotNull final File file,
                          @Nullable final List<? extends CharSequence> lines)
         throws IOException
  {
    try (PrintWriter writer = new PrintWriter(file))
    {
      if (lines != null)
      {
        for (final CharSequence line : lines)
        {
          writer.println(line);
        }
      }
    }
  }
}
