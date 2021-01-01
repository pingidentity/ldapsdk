/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.jsonfilter.JFMessages.*;



/**
 * This class provides an implementation of a JSON object filter that can be
 * used to identify JSON objects that have a specified field whose value matches
 * one of specified set of values.
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
 * <BR>
 * The fields that are required to be included in an "equals any" filter are:
 * <UL>
 *   <LI>
 *     {@code field} -- A field path specifier for the JSON field for which to
 *     make the determination.  This may be either a single string or an array
 *     of strings as described in the "Targeting Fields in JSON Objects" section
 *     of the class-level documentation for {@link JSONObjectFilter}.
 *   </LI>
 *   <LI>
 *     {@code values} -- The set of values that should be used to match.  This
 *     should be an array, but the elements of the array may be of any type.  In
 *     order for a JSON object ot match this "equals any" filter, either the
 *     value of the target field must have the same type and value as one of the
 *     values in this array, or the value of the target field must be an array
 *     containing at least one element with the same type and value as one of
 *     the values in this array.
 *   </LI>
 * </UL>
 * The fields that may optionally be included in an "equals" filter are:
 * <UL>
 *   <LI>
 *     {@code caseSensitive} -- Indicates whether string values should be
 *     treated in a case-sensitive manner.  If present, this field must have a
 *     Boolean value of either {@code true} or {@code false}.  If it is not
 *     provided, then a default value of {@code false} will be assumed so that
 *     strings are treated in a case-insensitive manner.
 *   </LI>
 * </UL>
 * <H2>Example</H2>
 * The following is an example of an "equals any" filter that will match any
 * JSON object that includes a top-level field of "userType" with a value of
 * either "employee", "partner", or "contractor":
 * value:
 * <PRE>
 *   { "filterType" : "equalsAny",
 *     "field" : "userType",
 *     "values" : [  "employee", "partner", "contractor" ] }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   EqualsAnyJSONObjectFilter filter = new EqualsAnyJSONObjectFilter(
 *        "userType", "employee", "partner", "contractor");
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EqualsAnyJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents an "equals any" filter.
   */
  @NotNull public static final String FILTER_TYPE = "equalsAny";



  /**
   * The name of the JSON field that is used to specify the field in the target
   * JSON object for which to make the determination.
   */
  @NotNull public static final String FIELD_FIELD_PATH = "field";



  /**
   * The name of the JSON field that is used to specify the values to use for
   * the matching.
   */
  @NotNull public static final String FIELD_VALUES = "values";



  /**
   * The name of the JSON field that is used to indicate whether string matching
   * should be case-sensitive.
   */
  @NotNull public static final String FIELD_CASE_SENSITIVE = "caseSensitive";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(FIELD_FIELD_PATH, FIELD_VALUES)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_CASE_SENSITIVE)));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7441807169198186996L;



  // Indicates whether string matching should be case-sensitive.
  private volatile boolean caseSensitive;

  // The set of expected values for the target field.
  @NotNull private volatile List<JSONValue> values;

  // The field path specifier for the target field.
  @NotNull private volatile List<String> field;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "equals any" filters.  It cannot be used as a regular
   * "equals any" filter.
   */
  EqualsAnyJSONObjectFilter()
  {
    field = null;
    values = null;
    caseSensitive = false;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field          The field path specifier for the target field.
   * @param  values         The set of expected values for the target field.
   * @param  caseSensitive  Indicates whether string matching should be
   *                        case sensitive.
   */
  private EqualsAnyJSONObjectFilter(@NotNull final List<String> field,
                                    @NotNull final List<JSONValue> values,
                                    final boolean caseSensitive)
  {
    this.field = field;
    this.values = values;
    this.caseSensitive = caseSensitive;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field   The name of the top-level field to target with this filter.
   *                 It must not be {@code null} .  See the class-level
   *                 documentation for the {@link JSONObjectFilter} class for
   *                 information about field path specifiers.
   * @param  values  The set of expected string values for the target field.
   *                 This filter will match an object in which the target field
   *                 has the same type and value as any of the values in this
   *                 set, or in which the target field is an array containing an
   *                 element with the same type and value as any of the values
   *                 in this set.  It must not be {@code null} or empty.
   */
  public EqualsAnyJSONObjectFilter(@NotNull final String field,
                                   @NotNull final String... values)
  {
    this(Collections.singletonList(field), toJSONValues(values));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field   The name of the top-level field to target with this filter.
   *                 It must not be {@code null} .  See the class-level
   *                 documentation for the {@link JSONObjectFilter} class for
   *                 information about field path specifiers.
   * @param  values  The set of expected string values for the target field.
   *                 This filter will match an object in which the target field
   *                 has the same type and value as any of the values in this
   *                 set, or in which the target field is an array containing an
   *                 element with the same type and value as any of the values
   *                 in this set.  It must not be {@code null} or empty.
   */
  public EqualsAnyJSONObjectFilter(@NotNull final String field,
                                   @NotNull final JSONValue... values)
  {
    this(Collections.singletonList(field), StaticUtils.toList(values));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field   The name of the top-level field to target with this filter.
   *                 It must not be {@code null} .  See the class-level
   *                 documentation for the {@link JSONObjectFilter} class for
   *                 information about field path specifiers.
   * @param  values  The set of expected string values for the target field.
   *                 This filter will match an object in which the target field
   *                 has the same type and value as any of the values in this
   *                 set, or in which the target field is an array containing an
   *                 element with the same type and value as any of the values
   *                 in this set.  It must not be {@code null} or empty.
   */
  public EqualsAnyJSONObjectFilter(@NotNull final String field,
                                   @NotNull final Collection<JSONValue> values)
  {
    this(Collections.singletonList(field), values);
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field   The field path specifier for this filter.  It must not be
   *                 {@code null} or empty.  See the class-level documentation
   *                 for the {@link JSONObjectFilter} class for information
   *                 about field path specifiers.
   * @param  values  The set of expected string values for the target field.
   *                 This filter will match an object in which the target field
   *                 has the same type and value as any of the values in this
   *                 set, or in which the target field is an array containing an
   *                 element with the same type and value as any of the values
   *                 in this set.  It must not be {@code null} or empty.
   */
  public EqualsAnyJSONObjectFilter(@NotNull final List<String> field,
                                   @NotNull final Collection<JSONValue> values)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    Validator.ensureNotNull(values);
    Validator.ensureFalse(values.isEmpty());

    this.field= Collections.unmodifiableList(new ArrayList<>(field));
    this.values =
         Collections.unmodifiableList(new ArrayList<>(values));

    caseSensitive = false;
  }



  /**
   * Retrieves the field path specifier for this filter.
   *
   * @return  The field path specifier for this filter.
   */
  @NotNull()
  public List<String> getField()
  {
    return field;
  }



  /**
   * Sets the field path specifier for this filter.
   *
   * @param  field  The field path specifier for this filter.  It must not be
   *                {@code null} or empty.  See the class-level documentation
   *                for the {@link JSONObjectFilter} class for information about
   *                field path specifiers.
   */
  public void setField(@NotNull final String... field)
  {
    setField(StaticUtils.toList(field));
  }



  /**
   * Sets the field path specifier for this filter.
   *
   * @param  field  The field path specifier for this filter.  It must not be
   *                {@code null} or empty.  See the class-level documentation
   *                for the {@link JSONObjectFilter} class for information about
   *                field path specifiers.
   */
  public void setField(@NotNull final List<String> field)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    this.field = Collections.unmodifiableList(new ArrayList<>(field));
  }



  /**
   * Retrieves the set of target values for this filter.  A JSON object will
   * only match this filter if it includes the target field with a value
   * contained in this set.
   *
   * @return  The set of target values for this filter.
   */
  @NotNull()
  public List<JSONValue> getValues()
  {
    return values;
  }



  /**
   * Specifies the set of target values for this filter.
   *
   * @param  values  The set of target string values for this filter.  It must
   *                 not be {@code null} or empty.
   */
  public void setValues(@NotNull final String... values)
  {
    setValues(toJSONValues(values));
  }



  /**
   * Specifies the set of target values for this filter.
   *
   * @param  values  The set of target values for this filter.  It must not be
   *                 {@code null} or empty.
   */
  public void setValues(@NotNull final JSONValue... values)
  {
    setValues(StaticUtils.toList(values));
  }



  /**
   * Specifies the set of target values for this filter.
   *
   * @param  values  The set of target values for this filter.  It must not be
   *                 {@code null} or empty.
   */
  public void setValues(@NotNull final Collection<JSONValue> values)
  {
    Validator.ensureNotNull(values);
    Validator.ensureFalse(values.isEmpty());

    this.values =
         Collections.unmodifiableList(new ArrayList<>(values));
  }



  /**
   * Converts the provided set of string values to a list of {@code JSONString}
   * values.
   *
   * @param  values  The string values to be converted.
   *
   * @return  The corresponding list of {@code JSONString} values.
   */
  @NotNull()
  private static List<JSONValue> toJSONValues(@NotNull final String... values)
  {
    final ArrayList<JSONValue> valueList = new ArrayList<>(values.length);
    for (final String s : values)
    {
      valueList.add(new JSONString(s));
    }
    return valueList;
  }



  /**
   * Indicates whether string matching should be performed in a case-sensitive
   * manner.
   *
   * @return  {@code true} if string matching should be case sensitive, or
   *          {@code false} if not.
   */
  public boolean caseSensitive()
  {
    return caseSensitive;
  }



  /**
   * Specifies whether string matching should be performed in a case-sensitive
   * manner.
   *
   * @param  caseSensitive  Indicates whether string matching should be
   *                        case sensitive.
   */
  public void setCaseSensitive(final boolean caseSensitive)
  {
    this.caseSensitive = caseSensitive;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getFilterType()
  {
    return FILTER_TYPE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected Set<String> getRequiredFieldNames()
  {
    return REQUIRED_FIELD_NAMES;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected Set<String> getOptionalFieldNames()
  {
    return OPTIONAL_FIELD_NAMES;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesJSONObject(@NotNull final JSONObject o)
  {
    final List<JSONValue> candidates = getValues(o, field);
    if (candidates.isEmpty())
    {
      return false;
    }

    for (final JSONValue objectValue : candidates)
    {
      for (final JSONValue filterValue : values)
      {
        if (filterValue.equals(objectValue, false, (! caseSensitive), false))
        {
          return true;
        }
      }

      if (objectValue instanceof JSONArray)
      {
        final JSONArray a = (JSONArray) objectValue;
        for (final JSONValue filterValue : values)
        {
          if (a.contains(filterValue, false, (!caseSensitive), false, false))
          {
            return true;
          }
        }
      }
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONObject()
  {
    final LinkedHashMap<String,JSONValue> fields =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(4));

    fields.put(FIELD_FILTER_TYPE, new JSONString(FILTER_TYPE));

    if (field.size() == 1)
    {
      fields.put(FIELD_FIELD_PATH, new JSONString(field.get(0)));
    }
    else
    {
      final ArrayList<JSONValue> fieldNameValues =
           new ArrayList<>(field.size());
      for (final String s : field)
      {
        fieldNameValues.add(new JSONString(s));
      }
      fields.put(FIELD_FIELD_PATH, new JSONArray(fieldNameValues));
    }

    fields.put(FIELD_VALUES, new JSONArray(values));

    if (caseSensitive)
    {
      fields.put(FIELD_CASE_SENSITIVE, JSONBoolean.TRUE);
    }

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected EqualsAnyJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final List<String> fieldPath =
         getStrings(filterObject, FIELD_FIELD_PATH, false, null);

    final boolean isCaseSensitive = getBoolean(filterObject,
         FIELD_CASE_SENSITIVE, false);

    final JSONValue arrayValue = filterObject.getField(FIELD_VALUES);
    if (arrayValue instanceof JSONArray)
    {
      return new EqualsAnyJSONObjectFilter(fieldPath,
           ((JSONArray) arrayValue).getValues(), isCaseSensitive);
    }
    else
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_ARRAY.get(
           String.valueOf(filterObject), FILTER_TYPE, FIELD_VALUES));
    }
  }
}
