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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure for providing information about the data
 * presented in an attribute in a Directory Server monitor entry.  It includes
 * a human-readable display name, a human-readable description, a class that
 * represents the data type for the values, and the set of values.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MonitorAttribute
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7931725606171964572L;



  // The data type for the values of this monitor attribute.
  @NotNull private final Class<?> dataType;

  // The set of values for this monitor attribute.
  @NotNull private final Object[] values;

  // The description for this monitor attribute.
  @Nullable private final String description;

  // The display name for this monitor attribute.
  @NotNull private final String displayName;

  // The name used to identify this monitor attribute.
  @NotNull private final String name;



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single Boolean value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  value        The {@code Boolean} value for this monitor attribute.
   *                      It must not be {@code null}.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Boolean value)
  {
    this(name, displayName, description, Boolean.class, new Object[] { value });

    Validator.ensureNotNull(value);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single Date value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  value        The {@code Date} value for this monitor attribute.  It
   *                      must not be {@code null}.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Date value)
  {
    this(name, displayName, description, Date.class, new Object[] { value });

    Validator.ensureNotNull(value);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have one or more Date values.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  values       The set of {@code Date} values for this monitor
   *                      attribute.  It must not be {@code null} or empty.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Date[] values)
  {
    this(name, displayName, description, Date.class, values);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single Double value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  value        The {@code Double} value for this monitor attribute.
   *                      It must not be {@code null}.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Double value)
  {
    this(name, displayName, description, Double.class, new Object[] { value });

    Validator.ensureNotNull(value);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have one or more Double values.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  values       The set of {@code Double} values for this monitor
   *                      attribute.  It must not be {@code null} or empty.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Double[] values)
  {
    this(name, displayName, description, Double.class, values);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single Long value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  value        The {@code Integer} value for this monitor attribute.
   *                      It must not be {@code null}.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Integer value)
  {
    this(name, displayName, description, Integer.class, new Object[] { value });

    Validator.ensureNotNull(value);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single Long value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  values       The set of {@code Integer} values for this monitor
   *                      attribute.  It must not be {@code null} or empty.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Integer[] values)
  {
    this(name, displayName, description, Integer.class, values);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single Long value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  value        The {@code Long} value for this monitor attribute.  It
   *                      must not be {@code null}.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Long value)
  {
    this(name, displayName, description, Long.class, new Object[] { value });

    Validator.ensureNotNull(value);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have one or more Long values.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  values       The set of {@code Long} values for this monitor
   *                      attribute.  It must not be {@code null} or empty.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final Long[] values)
  {
    this(name, displayName, description, Long.class, values);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have a single String value.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  value        The {@code String} value for this monitor attribute.
   *                      It must not be {@code null}.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final String value)
  {
    this(name, displayName, description, String.class, new Object[] { value });

    Validator.ensureNotNull(value);
  }



  /**
   * Creates a new monitor attribute with the provided information.  It will
   * have one or more String values.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  values       The set of {@code String} values for this monitor
   *                      attribute.  It must not be {@code null} or empty.
   */
  public MonitorAttribute(@NotNull final String name,
                          @NotNull final String displayName,
                          @Nullable final String description,
                          @NotNull final String[] values)
  {
    this(name, displayName, description, String.class, values);
  }



  /**
   * Creates a new monitor attribute with the provided information.
   *
   * @param  name         The name used to identify this monitor attribute.  It
   *                      must not be {@code null}.
   * @param  displayName  The human-readable display name for this monitor
   *                      attribute.  It must not be {@code null}.
   * @param  description  A human-readable description for this monitor
   *                      attribute.  It may be {@code null} if no description
   *                      is available.
   * @param  dataType     The data type for this monitor attribute.  It may be
   *                      one of the following classes:  Boolean, Date, Double,
   *                      Long, and String.  It must not be {@code null}.
   * @param  values       The set of values for this monitor attribute.  The
   *                      data type for the values must correspond to the value
   *                      of the {@code dataType} attribute.  It must not be
   *                      {@code null} or empty.
   */
  private MonitorAttribute(@NotNull final String name,
                           @NotNull final String displayName,
                           @Nullable final String description,
                           @NotNull final Class<?> dataType,
                           @NotNull final Object[] values)
  {
    Validator.ensureNotNull(name, displayName, dataType, values);
    Validator.ensureFalse(values.length == 0,
         "MonitorAttribute.values must not be empty.");

    this.name        = name;
    this.displayName = displayName;
    this.description = description;
    this.dataType    = dataType;
    this.values      = values;
  }



  /**
   * Retrieves the name used to identify this monitor attribute.  It is not
   * necessarily human-readable, but it should be used as the key for this
   * monitor attribute in the map returned by the
   * {@code MonitorEntry.getMonitorAttributes} method.
   *
   * @return  The name used to identify this monitor attribute.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the human-readable display name for this monitor attribute.
   *
   * @return  The human-readable display name for this monitor attribute.
   */
  @NotNull()
  public String getDisplayName()
  {
    return displayName;
  }



  /**
   * Retrieves the human-readable description for this monitor attribute, if
   * available.
   *
   * @return  The human-readable description for this monitor attribute, or
   *          {@code null} if none is available.
   */
  @Nullable()
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the class representing the data type for this monitor attribute.
   * It will be one of the following class types:  Boolean, Date, Double, Long,
   * or String.
   *
   * @return  The class representing the data type for this monitor attribute.
   */
  @NotNull()
  public Class<?> getDataType()
  {
    return dataType;
  }



  /**
   * Indicates whether this monitor attribute has multiple values.
   *
   * @return  {@code true} if this monitor attribute has more than one value, or
   *          {@code false} if not.
   */
  public boolean hasMultipleValues()
  {
    return (values.length > 1);
  }



  /**
   * Retrieves the value for this monitor attribute as an {@code Object}.  If it
   * has multiple values, then the first will be returned.
   *
   * @return  The value for this monitor attribute as an {@code Object}.
   */
  @NotNull()
  public Object getValue()
  {
    return values[0];
  }



  /**
   * Retrieves the set of values for this monitor attribute as a list of
   * {@code Object}s.
   *
   * @return  The set of values for this monitor attribute as a list of
   *          {@code Object}s.
   */
  @NotNull()
  public List<Object> getValues()
  {
    return Collections.unmodifiableList(Arrays.asList(values));
  }



  /**
   * Retrieves the value for this monitor attribute as a {@code Boolean} object.
   *
   * @return  The value for this monitor attribute as a {@code Boolean} object.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Boolean}.
   */
  @NotNull()
  public Boolean getBooleanValue()
         throws ClassCastException
  {
    return (Boolean) values[0];
  }



  /**
   * Retrieves the value for this monitor attribute as a {@code Date} object.
   *
   * @return  The value for this monitor attribute as a {@code Date} object.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Date}.
   */
  @NotNull()
  public Date getDateValue()
         throws ClassCastException
  {
    return (Date) values[0];
  }



  /**
   * Retrieves the values for this monitor attribute as a list of {@code Date}
   * objects.
   *
   * @return  The values for this monitor attribute as a list of {@code Date}
   *          objects.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Date}.
   */
  @NotNull()
  public List<Date> getDateValues()
         throws ClassCastException
  {
    return Collections.unmodifiableList(Arrays.asList((Date[]) values));
  }



  /**
   * Retrieves the value for this monitor attribute as a {@code Double} object.
   *
   * @return  The value for this monitor attribute as a {@code Double} object.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Double}.
   */
  @NotNull()
  public Double getDoubleValue()
         throws ClassCastException
  {
    return (Double) values[0];
  }



  /**
   * Retrieves the values for this monitor attribute as a list of {@code Double}
   * objects.
   *
   * @return  The values for this monitor attribute as a list of {@code Double}
   *          objects.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Double}.
   */
  @NotNull()
  public List<Double> getDoubleValues()
         throws ClassCastException
  {
    return Collections.unmodifiableList(Arrays.asList((Double[]) values));
  }



  /**
   * Retrieves the value for this monitor attribute as an {@code Integer}
   * object.
   *
   * @return  The value for this monitor attribute as an {@code Integer} object.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Integer}.
   */
  @NotNull()
  public Integer getIntegerValue()
         throws ClassCastException
  {
    return (Integer) values[0];
  }



  /**
   * Retrieves the values for this monitor attribute as a list of
   * {@code Integer} objects.
   *
   * @return  The values for this monitor attribute as a list of {@code Integer}
   *          objects.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Integer}.
   */
  @NotNull()
  public List<Integer> getIntegerValues()
         throws ClassCastException
  {
    return Collections.unmodifiableList(Arrays.asList((Integer[]) values));
  }



  /**
   * Retrieves the value for this monitor attribute as a {@code Long} object.
   *
   * @return  The value for this monitor attribute as a {@code Long} object.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Long}.
   */
  @NotNull()
  public Long getLongValue()
         throws ClassCastException
  {
    return (Long) values[0];
  }



  /**
   * Retrieves the values for this monitor attribute as a list of {@code Long}
   * objects.
   *
   * @return  The values for this monitor attribute as a list of {@code Long}
   *          objects.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code Long}.
   */
  @NotNull()
  public List<Long> getLongValues()
         throws ClassCastException
  {
    return Collections.unmodifiableList(Arrays.asList((Long[]) values));
  }



  /**
   * Retrieves the value for this monitor attribute as a {@code String} object.
   *
   * @return  The value for this monitor attribute as a {@code String} object.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code String}.
   */
  @NotNull()
  public String getStringValue()
         throws ClassCastException
  {
    return (String) values[0];
  }



  /**
   * Retrieves the values for this monitor attribute as a list of {@code String}
   * objects.
   *
   * @return  The values for this monitor attribute as a list of {@code String}
   *          objects.
   *
   * @throws  ClassCastException  If the data type for this monitor attribute is
   *                              not {@code String}.
   */
  @NotNull()
  public List<String> getStringValues()
         throws ClassCastException
  {
    return Collections.unmodifiableList(Arrays.asList((String[]) values));
  }



  /**
   * Retrieves a string representation of this monitor attribute.
   *
   * @return  A string representation of this monitor attribute.
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
   * Appends a string representation of this monitor attribute to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MonitorAttribute(name='");
    buffer.append(name);
    buffer.append("', values={");

    for (int i=0; i < values.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }

      buffer.append('\'');
      buffer.append(String.valueOf(values[i]));
      buffer.append('\'');
    }

    buffer.append("})");
  }
}
