/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a mechanism for retrieving the values of specified
 * properties in the form of either Java system properties or process
 * environment variables (using an alternative name generated from the provided
 * property name using the
 * {@link #generateEnvironmentVariableNameFromPropertyName} method).  System
 * properties will be given a higher priority than environment variables, and
 * the value can be parsed in accordance with a number of syntaxes.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PropertyManager
{
  /**
   * A reference to the length of time in milliseconds that property information
   * should be cached after retrieving it.
   */
  @NotNull private static final AtomicInteger CACHE_DURATION_MILLIS =
       new AtomicInteger(0);



  /**
   * A map containing cached property information.
   */
  @NotNull private static final Map<String,PropertyManagerCacheRecord> CACHE =
     new ConcurrentHashMap<>();



  /**
   * Prevents this utility class from being instantiated.
   */
  private PropertyManager()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the value of the specified system property or environment
   * variable.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   *
   * @return  The requested value, or {@code null} if it has not been set as
   *          either a system property or an environment variable.
   */
  @Nullable()
  public static String get(@NotNull final String propertyName)
  {
    return get(propertyName, null);
  }



  /**
   * Retrieves the value of the specified system property or environment
   * variable.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   * @param  defaultValue  The default value to return if neither the system
   *                       property nor associated environment variable have
   *                       been set.  It may be {@code null} if no default value
   *                       should be returned.
   *
   * @return  The requested value, or {@code null} if it has not been set as
   *          either a system property or an environment variable.
   */
  @Nullable()
  public static String get(@NotNull final String propertyName,
                           @Nullable final String defaultValue)
  {
    // See if there is a valid cache record for the property.  If so, then use
    // it.
    final int cacheDurationMillis = CACHE_DURATION_MILLIS.get();
    if (cacheDurationMillis > 0)
    {
      final PropertyManagerCacheRecord cacheRecord = CACHE.get(propertyName);
      if ((cacheRecord != null) && (! cacheRecord.isExpired()))
      {
        return cacheRecord.stringValue(defaultValue);
      }
    }


    // See if the property is defined via a system property.
    final String systemPropertyValue =
         StaticUtils.getSystemProperty(propertyName);
    if (systemPropertyValue != null)
    {
      if (cacheDurationMillis > 0)
      {
        CACHE.put(propertyName, new PropertyManagerCacheRecord(propertyName,
             systemPropertyValue, cacheDurationMillis));
      }

      return systemPropertyValue;
    }


    // See if the property is defined via an environment variable.
    final String environmentVariableValue =
         StaticUtils.getEnvironmentVariable(propertyName);
    if (environmentVariableValue != null)
    {
      if (cacheDurationMillis > 0)
      {
        CACHE.put(propertyName, new PropertyManagerCacheRecord(propertyName,
             environmentVariableValue, cacheDurationMillis));
      }

      return environmentVariableValue;
    }

    final String alternativeEnvironmentVariableName =
         generateEnvironmentVariableNameFromPropertyName(propertyName);
    if (! alternativeEnvironmentVariableName.equals(propertyName))
    {
      final String alternativeEnvironmentVariableValue =
           StaticUtils.getEnvironmentVariable(
                alternativeEnvironmentVariableName);
      if (alternativeEnvironmentVariableValue != null)
      {
        if (cacheDurationMillis > 0)
        {
          CACHE.put(propertyName, new PropertyManagerCacheRecord(propertyName,
               alternativeEnvironmentVariableValue, cacheDurationMillis));
        }

        return alternativeEnvironmentVariableValue;
      }
    }


    // If we've gotten here, then the property is not defined.  Cache that it's
    // not defined, if appropriate.
    if (cacheDurationMillis > 0)
    {
      CACHE.put(propertyName, new PropertyManagerCacheRecord(propertyName,
           null, cacheDurationMillis));
    }

    return defaultValue;
  }



  /**
   * Retrieves the value of the specified property or environment variable as a
   * Boolean value.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   *
   * @return  The Boolean value of the specified property or environment
   *          variable, or {@code null} if neither are set or are set to a
   *          value that cannot be parsed as a Boolean.
   */
  @Nullable()
  public static Boolean getBoolean(@NotNull final String propertyName)
  {
    return getBoolean(propertyName, null);
  }



  /**
   * Retrieves the value of the specified property or environment variable as a
   * Boolean value.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   * @param  defaultValue  The default value to return if neither the system
   *                       property nor associated environment variable have
   *                       been set, or if the value cannot be parsed as a
   *                       Boolean.  It may be {@code null} if no default value
   *                       should be returned.
   *
   * @return  The Boolean value of the specified property or environment
   *          variable, or the provided default value if neither are set or are
   *          set to a value that cannot be parsed as a Boolean.
   */
  @Nullable()
  public static Boolean getBoolean(@NotNull final String propertyName,
                                   @Nullable final Boolean defaultValue)
  {
    return getBoolean(propertyName, defaultValue, false);
  }



  /**
   * Retrieves the value of the specified property or environment variable as a
   * Boolean value.
   *
   * @param  propertyName         The name of the system property to retrieve,
   *                              and to use to generate an alternative
   *                              environment variable.  It must not be
   *                              {@code null} or empty.
   * @param  defaultValue         The default value to return if neither the
   *                              system property nor associated environment
   *                              variable have been set, or if the value cannot
   *                              be parsed as a Boolean and
   *                              {@code throwOnInvalidValue} is {@code false}.
   *                              It may be {@code null} if no default value
   *                              should be returned.
   * @param  throwOnInvalidValue  Indicates whether this method should throw an
   *                              {@code IllegalArgumentException} if the
   *                              system property or environment variable is
   *                              set but its value cannot be parsed as a
   *                              Boolean.
   *
   * @return  The Boolean value of the specified property or environment
   *          variable, or the provided default value if neither are set or are
   *          set to a value that cannot be parsed as a Boolean and
   *          {@code throwOnInvalidValue} is {@code false}.
   *
   * @throws  IllegalArgumentException  If the property or environment variable
   *                                    is set, but its value cannot be parsed
   *                                    as a Boolean, and
   *                                    {@code throwOnInvalidValue} is
   *                                    {@code true}.
   */
  @Nullable()
  public static Boolean getBoolean(@NotNull final String propertyName,
                                   @Nullable final Boolean defaultValue,
                                   final boolean throwOnInvalidValue)
         throws IllegalArgumentException
  {
    // See if there is a valid cache record for the property.  If so, then use
    // it.
    final int cacheDurationMillis = CACHE_DURATION_MILLIS.get();
    if (cacheDurationMillis > 0)
    {
      final PropertyManagerCacheRecord cacheRecord = CACHE.get(propertyName);
      if ((cacheRecord != null) && (! cacheRecord.isExpired()))
      {
        return cacheRecord.booleanValue(defaultValue, throwOnInvalidValue);
      }
    }


    final String stringValue = get(propertyName);
    if (stringValue == null)
    {
      return defaultValue;
    }

    final Boolean booleanValue = parseBoolean(stringValue);
    if (booleanValue == null)
    {
      if (throwOnInvalidValue)
      {
        throw new IllegalArgumentException(
             ERR_PROPERTY_MANAGER_NOT_BOOLEAN.get(
                  getIdentifierString(propertyName), stringValue));
      }
      else
      {
        return defaultValue;
      }
    }
    else
    {
      return booleanValue;
    }
  }



  /**
   * Attempts to parse the provided string value as a {@code Boolean}.
   *
   * @param  stringValue  The string value to parse.  It must not be
   *                      {@code null}.
   *
   * @return  The {@code Boolean} value that was parsed from the given string,
   *          or {@code null} if the provided string could not be parsed as a
   *          {@code Boolean}.
   */
  @Nullable()
  static Boolean parseBoolean(@NotNull final String stringValue)
  {
    final String lowerValue = StaticUtils.toLowerCase(stringValue.trim());
    switch (lowerValue)
    {
      case "true":
      case "t":
      case "yes":
      case "y":
      case "on":
      case "1":
        return Boolean.TRUE;
      case "false":
      case "f":
      case "no":
      case "n":
      case "off":
      case "0":
        return Boolean.FALSE;
      default:
        return null;
    }
  }



  /**
   * Retrieves the value of the specified property or environment variable as an
   * integer.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   *
   * @return  The integer value of the specified property or environment
   *          variable, or {@code null} if neither are set or are set to a
   *          value that cannot be parsed as an integer.
   */
  @Nullable()
  public static Integer getInt(@NotNull final String propertyName)
  {
    return getInt(propertyName, null);
  }



  /**
   * Retrieves the value of the specified property or environment variable as an
   * integer.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   * @param  defaultValue  The default value to return if neither the system
   *                       property nor associated environment variable have
   *                       been set, or if the value cannot be parsed as an
   *                       integer.  It may be {@code null} if no default value
   *                       should be returned.
   *
   * @return  The integer value of the specified property or environment
   *          variable, or the provided default value if neither are set or are
   *          set to a value that cannot be parsed as an integer.
   */
  @Nullable()
  public static Integer getInt(@NotNull final String propertyName,
                               @Nullable final Integer defaultValue)
  {
    return getInt(propertyName, defaultValue, false);
  }



  /**
   * Retrieves the value of the specified property or environment variable as an
   * integer.
   *
   * @param  propertyName         The name of the system property to retrieve,
   *                              and to use to generate an alternative
   *                              environment variable.  It must not be
   *                              {@code null} or empty.
   * @param  defaultValue         The default value to return if neither the
   *                              system property nor associated environment
   *                              variable have been set, or if the value cannot
   *                              be parsed as an integer and
   *                              {@code throwOnInvalidValue} is {@code false}.
   *                              It may be {@code null} if no default value
   *                              should be returned.
   * @param  throwOnInvalidValue  Indicates whether this method should throw an
   *                              {@code IllegalArgumentException} if the
   *                              system property or environment variable is
   *                              set but its value cannot be parsed as an
   *                              integer.
   *
   * @return  The integer value of the specified property or environment
   *          variable, or the provided default value if neither are set or are
   *          set to a value that cannot be parsed as an integer and
   *          {@code throwOnInvalidValue} is {@code false}.
   *
   * @throws  IllegalArgumentException  If the property or environment variable
   *                                    is set, but its value cannot be parsed
   *                                    as an integer, and
   *                                    {@code throwOnInvalidValue} is
   *                                    {@code true}.
   */
  @Nullable()
  public static Integer getInt(@NotNull final String propertyName,
                               @Nullable final Integer defaultValue,
                               final boolean throwOnInvalidValue)
         throws IllegalArgumentException
  {
    // See if there is a valid cache record for the property.  If so, then use
    // it.
    final int cacheDurationMillis = CACHE_DURATION_MILLIS.get();
    if (cacheDurationMillis > 0)
    {
      final PropertyManagerCacheRecord cacheRecord = CACHE.get(propertyName);
      if ((cacheRecord != null) && (! cacheRecord.isExpired()))
      {
        return cacheRecord.intValue(defaultValue, throwOnInvalidValue);
      }
    }


    final String stringValue = get(propertyName);
    if (stringValue == null)
    {
      return defaultValue;
    }

    try
    {
      return Integer.parseInt(stringValue.trim());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (throwOnInvalidValue)
      {
        throw new IllegalArgumentException(
             ERR_PROPERTY_MANAGER_NOT_INT.get(getIdentifierString(propertyName),
                  stringValue),
             e);
      }
      else
      {
        return defaultValue;
      }
    }
  }



  /**
   * Retrieves the value of the specified property or environment variable as a
   * long.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   *
   * @return  The long value of the specified property or environment variable,
   *          or {@code null} if neither are set or are set to a value that
   *          cannot be parsed as a long.
   */
  @Nullable()
  public static Long getLong(@NotNull final String propertyName)
  {
    return getLong(propertyName, null);
  }



  /**
   * Retrieves the value of the specified property or environment variable as a
   * long.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   * @param  defaultValue  The default value to return if neither the system
   *                       property nor associated environment variable have
   *                       been set, or if the value cannot be parsed as a long.
   *                       It may be {@code null} if no default value should be
   *                       returned.
   *
   * @return  The long value of the specified property or environment variable,
   *          or the provided default value if neither are set or are set to a
   *          value that cannot be parsed as a long.
   */
  @Nullable()
  public static Long getLong(@NotNull final String propertyName,
                             @Nullable final Long defaultValue)
  {
    return getLong(propertyName, defaultValue, false);
  }



  /**
   * Retrieves the value of the specified property or environment variable as a
   * long.
   *
   * @param  propertyName         The name of the system property to retrieve,
   *                              and to use to generate an alternative
   *                              environment variable.  It must not be
   *                              {@code null} or empty.
   * @param  defaultValue         The default value to return if neither the
   *                              system property nor associated environment
   *                              variable have been set, or if the value cannot
   *                              be parsed as a long and
   *                              {@code throwOnInvalidValue} is {@code false}.
   *                              It may be {@code null} if no default value
   *                              should be returned.
   * @param  throwOnInvalidValue  Indicates whether this method should throw an
   *                              {@code IllegalArgumentException} if the
   *                              system property or environment variable is
   *                              set but its value cannot be parsed as a
   *                              long.
   *
   * @return  The long value of the specified property or environment variable,
   *          or the provided default value if neither are set or are set to a
   *          value that cannot be parsed as a long and
   *          {@code throwOnInvalidValue} is {@code false}.
   *
   * @throws  IllegalArgumentException  If the property or environment variable
   *                                    is set, but its value cannot be parsed
   *                                    as a long, and
   *                                    {@code throwOnInvalidValue} is
   *                                    {@code true}.
   */
  @Nullable()
  public static Long getLong(@NotNull final String propertyName,
                             @Nullable final Long defaultValue,
                             final boolean throwOnInvalidValue)
         throws IllegalArgumentException
  {
    // See if there is a valid cache record for the property.  If so, then use
    // it.
    final int cacheDurationMillis = CACHE_DURATION_MILLIS.get();
    if (cacheDurationMillis > 0)
    {
      final PropertyManagerCacheRecord cacheRecord = CACHE.get(propertyName);
      if ((cacheRecord != null) && (! cacheRecord.isExpired()))
      {
        return cacheRecord.longValue(defaultValue, throwOnInvalidValue);
      }
    }


    final String stringValue = get(propertyName);
    if (stringValue == null)
    {
      return defaultValue;
    }

    try
    {
      return Long.parseLong(stringValue.trim());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      if (throwOnInvalidValue)
      {
        throw new IllegalArgumentException(
             ERR_PROPERTY_MANAGER_NOT_LONG.get(
                  getIdentifierString(propertyName), stringValue),
             e);
      }
      else
      {
        return defaultValue;
      }
    }
  }



  /**
   * Retrieves the value of the specified property or environment variable as
   * a list of comma-delimited values.  Any spaces around commas will be
   * trimmed.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   *
   * @return  An unmodifiable list containing the comma-delimited values of the
   *          specified property or environment variable, or an empty list if
   *          neither is set.
   */
  @NotNull()
  public static List<String> getCommaDelimitedList(
              @NotNull final String propertyName)
  {
    return getCommaDelimitedList(propertyName, true);
  }



  /**
   * Retrieves the value of the specified property or environment variable as
   * a list of comma-delimited values.  Any spaces around commas will be
   * trimmed.
   *
   * @param  propertyName  The name of the system property to retrieve, and to
   *                       use to generate an alternative environment variable.
   *                       It must not be {@code null} or empty.
   * @param  trimItems     Indicates whether the individual items in the list
   *                       should be trimmed to remove leading and/or trailing
   *                       spaces.
   *
   * @return  An unmodifiable list containing the comma-delimited values of the
   *          specified property or environment variable, or an empty list if
   *          neither is set.
   */
  @NotNull()
  public static List<String> getCommaDelimitedList(
              @NotNull final String propertyName,
              final boolean trimItems)
  {
    final List<String> items = new ArrayList<>();

    final String stringValue = get(propertyName);
    if (stringValue != null)
    {
      int startPos = 0;
      while (true)
      {
        final int commaPos = stringValue.indexOf(',', startPos);
        if (commaPos < 0)
        {
          String substring = stringValue.substring(startPos);
          if (trimItems)
          {
            substring = substring.trim();
          }

          items.add(substring);
          break;
        }
        else
        {
          String substring = stringValue.substring(startPos, commaPos);
          if (trimItems)
          {
            substring = substring.trim();
          }

          items.add(substring);
          startPos = commaPos + 1;
        }
      }
    }

    return Collections.unmodifiableList(items);
  }



  /**
   * Retrieves a {@code Properties} object with values for any of the specified
   * properties that are currently set.
   *
   * @param  propertyNames  The name of the properties whose values should be
   *                        retrieved.  It must not be {@code null}, but may be
   *                        empty.
   *
   * @return  A {@code Properties} object with any of the specified properties
   *          that are set as either JVM system properties or environment
   *          variables.  It may be empty if none of the specified properties
   *          have been set.
   */
  @NotNull()
  public static Properties getProperties(@NotNull final String... propertyNames)
  {
    final Properties properties = new Properties();

    for (final String propertyName : propertyNames)
    {
      final String propertyValue = get(propertyName);
      if (propertyValue != null)
      {
        properties.setProperty(propertyName, propertyValue);
      }
    }

    return properties;
  }



  /**
   * Generates an alternative environment variable name that can be used for a
   * given property name.  All alphabetic letters in the provided name will be
   * converted to uppercase, and all characters other than ASCII letters and
   * digits will be converted to underscores.
   *
   * @param  propertyName  The property name to use to generate the environment
   *                       variable name.  It must not be {@code null} or empty.
   *
   * @return  The alternative environment variable name generated from the given
   *          property name.
   */
  @NotNull()
  public static String generateEnvironmentVariableNameFromPropertyName(
              @NotNull final String propertyName)
  {
    final String upperPropertyName =
         StaticUtils.toUpperCase(propertyName.trim());

    final int length = upperPropertyName.length();
    final StringBuilder buffer = new StringBuilder(length);
    for (int i=0; i < length; i++)
    {
      final char c = upperPropertyName.charAt(i);
      if (((c >= 'A') && (c <= 'Z')) ||
           ((c >= '0') && (c <= '9')))
      {
        buffer.append(c);
      }
      else
      {
        buffer.append('_');
      }
    }

    return buffer.toString();
  }



  /**
   * Retrieves an identifier string that can be used to indicate how the value
   * of the specified property was obtained.  The returned value will be one of:
   * <UL>
   *   <LI>system property '{propertyName}'</LI>
   *   <LI>environment variable '{propertyName}'</LI>
   *   <LI>environment variable '{alternativeName}'</LI>
   * </UL>
   *
   * @param  propertyName  The property name for which to retrieve the
   *                       identifier.
   *
   * @return  The identifier string for the provided property name, or
   *          {@code null} if the specified property is not set as either a
   *          system property or an environment variable (including with an
   *          alternative name).
   */
  @Nullable()
  static String getIdentifierString(@NotNull final String propertyName)
  {
    if (StaticUtils.getSystemProperty(propertyName) != null)
    {
      return INFO_PROPERTY_MANAGER_SYSTEM_PROPERY_IDENTIFIER.get(propertyName);
    }

    if (StaticUtils.getEnvironmentVariable(propertyName) != null)
    {
      return INFO_PROPERTY_MANAGER_ENVIRONMENT_VARIABLE_IDENTIFIER.get(
           propertyName);
    }

    final String alternativeName =
         generateEnvironmentVariableNameFromPropertyName(propertyName);
    if (StaticUtils.getEnvironmentVariable(alternativeName) != null)
    {
      return INFO_PROPERTY_MANAGER_ENVIRONMENT_VARIABLE_IDENTIFIER.get(
           alternativeName);
    }

    return null;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that property values
   * should be cached for faster retrieval.  A value of zero indicates that no
   * caching should be performed.  A value of {@code Integer.MAX_VALUE}
   * indicates that cache records should never expire.
   *
   * @return  The maximum length of time in milliseconds that property values
   *          should be cached for faster retrieval.
   */
  public static int getCacheDurationMillis()
  {
    return CACHE_DURATION_MILLIS.get();
  }



  /**
   * Specifies the maximum length of time in milliseconds that property values
   * should be cached for faster retrieval.
   *
   * @param  cacheDurationMillis  The maximum length of time in milliseconds
   *                              that property values should be cached for
   *                              faster retrieval.  A value that is less than
   *                              or equal to zero indicates that values should
   *                              not be cached.  A value of
   *                              {@code Integer.MAX_VALUE} indicates that cache
   *                              records should never expire.
   */
  public static void setCacheDurationMillis(final int cacheDurationMillis)
  {
    if (cacheDurationMillis > 0)
    {
      PropertyManager.CACHE_DURATION_MILLIS.set(cacheDurationMillis);
    }
    else
    {
      PropertyManager.CACHE_DURATION_MILLIS.set(0);
    }
  }



  /**
   * Retrieves a handle to the cache.  This method is only intended for testing
   * purposes.
   *
   * @return  A handle to the cache.
   */
  @NotNull()
  static Map<String,PropertyManagerCacheRecord> getCache()
  {
    return CACHE;
  }



  /**
   * Populates the cache with current values obtained from system properties
   * and environment variables.  This will not have any effect if caching is
   * disabled.
   */
  public static void populateCache()
  {
    clearCache();

    final int cacheDurationMillis = CACHE_DURATION_MILLIS.get();
    if (cacheDurationMillis <= 0)
    {
      return;
    }

    for (final Map.Entry<String,String> envVar :
         StaticUtils.getEnvironmentVariables().entrySet())
    {
      final String propertyName = envVar.getKey();
      final String stringValue = envVar.getValue();

      CACHE.put(propertyName, new PropertyManagerCacheRecord(propertyName,
           stringValue, cacheDurationMillis));
    }

    for (final Map.Entry<Object,Object> systemProperty :
         StaticUtils.getSystemProperties().entrySet())
    {
      final String propertyName = String.valueOf(systemProperty.getKey());
      final String stringValue = String.valueOf(systemProperty.getValue());

      CACHE.put(propertyName, new PropertyManagerCacheRecord(propertyName,
           stringValue, cacheDurationMillis));
    }
  }



  /**
   * Clears any cached property information.
   */
  public static void clearCache()
  {
    CACHE.clear();
  }
}
