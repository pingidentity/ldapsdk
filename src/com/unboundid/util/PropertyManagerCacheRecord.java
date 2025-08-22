/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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
import java.util.logging.Level;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class defines a data structure that represents a cached value for use by
 * the {@link PropertyManager}.  It may represent either a value that is defined
 * or a value that is not defined, and if it is defined, then it may be
 * pre-parsed as a Boolean, integer, or long value.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class PropertyManagerCacheRecord
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3306871931780281568L;



  // The boolean representation of the value for this property, if applicable.
  @Nullable private final Boolean booleanValue;

  // The integer representation of the value for this property, if applicable.
  @Nullable private final Integer intValue;

  // The time that this cache record expires.
  private final long expirationTimeMillis;

  // The long representation of the value for this property, if applicable.
  @Nullable private final Long longValue;

  // The name for the associated property.
  @NotNull private final String propertyName;

  // The string representation of the value for this property.
  @Nullable private final String stringValue;



  /**
   * Creates a cache record with the provided information.
   *
   * @param  propertyName          The name for the property.  It must not be
   *                               {@code null}.
   * @param  stringValue           The string representation of the value for
   *                               this property.  It may be {@code null} if
   *                               the property is not set.
   * @param  cacheDurationMillis   The length of time in milliseconds tha the
   *                               cache record should be considered valid.
   */
  PropertyManagerCacheRecord(@NotNull final String propertyName,
                             @Nullable final String stringValue,
                             final int cacheDurationMillis)
  {
    this.propertyName = propertyName;
    this.stringValue = stringValue;

    if (cacheDurationMillis == Integer.MAX_VALUE)
    {
      expirationTimeMillis = Long.MAX_VALUE;
    }
    else
    {
      expirationTimeMillis = System.currentTimeMillis() + cacheDurationMillis;
    }

    if (stringValue == null)
    {
      booleanValue = null;
      intValue = null;
      longValue = null;
    }
    else
    {
      booleanValue = PropertyManager.parseBoolean(stringValue);

      Integer i;
      Long l;
      try
      {
        i = Integer.parseInt(stringValue);
        l =  i.longValue();
      }
      catch (final Exception e)
      {
        Debug.debugException(Level.FINEST, e);

        i = null;

        try
        {
          l = Long.parseLong(stringValue);
        }
        catch (final Exception e2)
        {
          Debug.debugException(Level.FINEST, e);

          l = null;
        }
      }

      intValue = i;
      longValue = l;
    }
  }



  /**
   * Retrieves the name of the associated property.
   *
   * @return  The name of the associated property.
   */
  @NotNull()
  String getPropertyName()
  {
    return propertyName;
  }



  /**
   * Retrieves the time that this cache record should expire, expressed as
   * milliseconds since the epoch.
   *
   * @return  The time that this cache record should expire.
   */
  long getExpirationTimeMillis()
  {
    return expirationTimeMillis;
  }



  /**
   * Indicates whether this cache record is currently expired.
   *
   * @return  {@code true} if this cache record is expired, or {@code false} if
   *          not.
   */
  boolean isExpired()
  {
    return (System.currentTimeMillis() > expirationTimeMillis);
  }



  /**
   * Indicates whether this property is defined.
   *
   * @return  {@code true} if this property is defined, or {@code false} if not.
   */
  boolean isDefined()
  {
    return (stringValue != null);
  }



  /**
   * Retrieves the string representation for the property value, if it is
   * defined.
   *
   * @return  The string representation for the property value, or {@code null}
   *          if the property value is not defined.
   */
  @Nullable()
  String stringValue()
  {
    return stringValue;
  }



  /**
   * Retrieves the string representation for the property value, if it is
   * defined.
   *
   * @param  defaultValue  The default value to return if the property is not
   *                       defined.  It may be {@code null} if no default value
   *                       should be returned.
   *
   * @return  The string representation for the property value, or {@code null}
   *          if the property value is not defined.
   */
  @Nullable()
  String stringValue(@Nullable final String defaultValue)
  {
    if (stringValue == null)
    {
      return defaultValue;
    }
    else
    {
      return stringValue;
    }
  }



  /**
   * Retrieves the Boolean representation for the property value, if it is
   * defined and can be parsed as a Boolean.
   *
   * @return  The Boolean representation for the property value, or
   *          {@code null} if the property is not defined or if its value
   *          cannot be parsed as a Boolean.
   */
  @Nullable()
  Boolean booleanValue()
  {
    return booleanValue;
  }



  /**
   * Retrieves the Boolean representation for the property value, if it is
   * defined and can be parsed as a Boolean.
   *
   * @param  defaultValue         The default value to return if the property is
   *                              not defined.  It may be {@code null} if no
   *                              default value should be returned.
   * @param  throwOnInvalidValue  Indicates whether this method should throw an
   *                              {@code IllegalArgumentException} if the
   *                              property value cannot be parsed as a Boolean.
   *
   * @return  The Boolean representation for the property value, or the provided
   *          default value if the property is not defined or if its value
   *          cannot be parsed as a Boolean.
   *
   * @throws  IllegalArgumentException  If the property or environment variable
   *                                    is set, but its value cannot be parsed
   *                                    as a Boolean, and
   *                                    {@code throwOnInvalidValue} is
   *                                    {@code true}.
   */
  @Nullable()
  Boolean booleanValue(@Nullable final Boolean defaultValue,
                       final boolean throwOnInvalidValue)
          throws IllegalArgumentException
  {
    if (booleanValue == null)
    {
      if ((stringValue != null) && throwOnInvalidValue)
      {
        throw new IllegalArgumentException(
             ERR_PROPERTY_MANAGER_NOT_BOOLEAN.get(
                  PropertyManager.getIdentifierString(propertyName),
                  stringValue));
      }

      return defaultValue;
    }
    else
    {
      return booleanValue;
    }
  }



  /**
   * Retrieves the integer representation for the property value, if it is
   * defined and can be parsed as an integer.
   *
   * @return  The integer representation for the property value, or {@code null}
   *          if the property is not defined or if its value cannot be parsed as
   *          an integer.
   */
  @Nullable
  Integer intValue()
  {
    return intValue;
  }



  /**
   * Retrieves the integer representation for the property value, if it is
   * defined and can be parsed as an integer.
   *
   * @param  defaultValue         The default value to return if the property is
   *                              not defined.  It may be {@code null} if no
   *                              default value should be returned.
   * @param  throwOnInvalidValue  Indicates whether this method should throw an
   *                              {@code IllegalArgumentException} if the
   *                              property value cannot be parsed as an integer.
   *
   * @return  The integer representation for the property value, or the provided
   *          default value if the property is not defined or if its value
   *          cannot be parsed as an integer.
   *
   * @throws  IllegalArgumentException  If the property or environment variable
   *                                    is set, but its value cannot be parsed
   *                                    as an integer, and
   *                                    {@code throwOnInvalidValue} is
   *                                    {@code true}.
   */
  @Nullable()
  Integer intValue(@Nullable final Integer defaultValue,
                   final boolean throwOnInvalidValue)
          throws IllegalArgumentException
  {
    if (intValue == null)
    {
      if ((stringValue != null) && throwOnInvalidValue)
      {
        throw new IllegalArgumentException(
             ERR_PROPERTY_MANAGER_NOT_INT.get(
                  PropertyManager.getIdentifierString(propertyName),
                  stringValue));
      }

      return defaultValue;
    }
    else
    {
      return intValue;
    }
  }



  /**
   * Retrieves the long representation for the property value, if it is
   * defined and can be parsed as a long.
   *
   * @return  The long representation for the property value, or {@code null} if
   *          the property is not defined or if its value cannot be parsed as a
   *          long.
   */
  @Nullable
  Long longValue()
  {
    return longValue;
  }



  /**
   * Retrieves the long representation for the property value, if it is defined
   * and can be parsed as a long.
   *
   * @param  defaultValue         The default value to return if the property is
   *                              not defined.  It may be {@code null} if no
   *                              default value should be returned.
   * @param  throwOnInvalidValue  Indicates whether this method should throw an
   *                              {@code IllegalArgumentException} if the
   *                              property value cannot be parsed as a long.
   *
   * @return  The long representation for the property value, or {@code null} if
   *          the property is not defined or if its value cannot be parsed as a
   *          long.
   *
   * @throws  IllegalArgumentException  If the property or environment variable
   *                                    is set, but its value cannot be parsed
   *                                    as an integer, and
   *                                    {@code throwOnInvalidValue} is
   *                                    {@code true}.
   */
  @Nullable()
  Long longValue(@Nullable final Long defaultValue,
                 final boolean throwOnInvalidValue)
       throws IllegalArgumentException
  {
    if (longValue == null)
    {
      if ((stringValue != null) && throwOnInvalidValue)
      {
        throw new IllegalArgumentException(
             ERR_PROPERTY_MANAGER_NOT_LONG.get(
                  PropertyManager.getIdentifierString(propertyName),
                  stringValue));
      }

      return defaultValue;
    }
    else
    {
      return longValue;
    }
  }



  /**
   * Retrieves a string representation of this cache record.
   *
   * @return  A string representation of this cache record.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this cache record to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the cache record should be appended.
   */
  void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PropertyManagerCacheRecord(propertyName='");
    buffer.append(propertyName);
    buffer.append("', isDefined=");

    if (stringValue == null)
    {
      buffer.append("false");
    }
    else
    {
      buffer.append("true, stringValue='");
      buffer.append(stringValue);
      buffer.append('\'');
    }

    buffer.append(", expirationTime='");
    buffer.append(StaticUtils.encodeGeneralizedTime(expirationTimeMillis));
    buffer.append("')");
  }
}
