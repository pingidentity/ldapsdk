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
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides an implementation of a JSON object filter that can be
 * used to identify JSON objects that have a particular value for a specified
 * field.
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
 * The fields that are required to be included in an "equals" filter are:
 * <UL>
 *   <LI>
 *     {@code fieldName} -- A field path specifier for the JSON field for which
 *     to make the determination.  This may be either a single string or an
 *     array of strings as described in the "Targeting Fields in JSON Objects"
 *     section of the class-level documentation for {@link JSONObjectFilter}.
 *   </LI>
 *   <LI>
 *     {@code value} -- The value to match.  This value may be of any type.  In
 *     order for a JSON object to match the equals filter, the value of the
 *     target field must either have the same type value as this value, or the
 *     value of the target field must be an array containing at least one
 *     element with the same type and value.  If the provided value is an array,
 *     then the order, types, and values of the array must match an array
 *     contained in the target field.  If the provided value is a JSON object,
 *     then the target field must contain a JSON object with exactly the same
 *     set of fields and values.
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
 * <H2>Examples</H2>
 * The following is an example of an "equals" filter that will match any JSON
 * object with a top-level field named "firstName" with a value of "John":
 * <PRE>
 *   { "filterType" : "equals",
 *     "field" : "firstName",
 *     "value" : "John" }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   EqualsJSONObjectFilter filter =
 *        new EqualsJSONObjectFilter("firstName", "John");
 * </PRE>
 * The following is an example of an "equals" filter that will match a JSON
 * object with a top-level field named "contact" whose value is a JSON object
 * (or an array containing one or more JSON objects) with a field named "type"
 * and a value of "home":
 * <PRE>
 *   { "filterType" : "equals",
 *     "field" : [ "contact", "type" ],
 *     "value" : "home" }
 * </PRE>
 * That filter can be created with the code:
 * <PRE>
 *   EqualsJSONObjectFilter filter =
 *        new EqualsJSONObjectFilter(Arrays.asList("contact", "type"), "Home");
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class EqualsJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents an "equals" filter.
   */
  @NotNull public static final String FILTER_TYPE = "equals";



  /**
   * The name of the JSON field that is used to specify the field in the target
   * JSON object for which to make the determination.
   */
  @NotNull public static final String FIELD_FIELD_PATH = "field";



  /**
   * The name of the JSON field that is used to specify the value to use for
   * the matching.
   */
  @NotNull public static final String FIELD_VALUE = "value";



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
            Arrays.asList(FIELD_FIELD_PATH, FIELD_VALUE)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_CASE_SENSITIVE)));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4622567662624840125L;



  // Indicates whether string matching should be case-sensitive.
  private volatile boolean caseSensitive;

  // The expected value for the target field.
  @NotNull private volatile JSONValue value;

  // The path name specifier for the target field.
  @NotNull private volatile List<String> field;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "equals" filters.  It cannot be used as a regular "equals"
   * filter.
   */
  EqualsJSONObjectFilter()
  {
    field = null;
    value = null;
    caseSensitive = false;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field          The path name specifier for the target field.
   * @param  value          The expected value for the target field.
   * @param  caseSensitive  Indicates whether string matching should be
   *                        case sensitive.
   */
  private EqualsJSONObjectFilter(@NotNull final List<String> field,
                                 @NotNull final JSONValue value,
                                 final boolean caseSensitive)
  {
    this.field = field;
    this.value = value;
    this.caseSensitive = caseSensitive;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The name of the top-level field to target with this filter.
   *                It must not be {@code null} .  See the class-level
   *                documentation for the {@link JSONObjectFilter} class for
   *                information about field path specifiers.
   * @param  value  The target string value for this filter.  It must not be
   *                {@code null}.
   */
  public EqualsJSONObjectFilter(@NotNull final String field,
                                @NotNull final String value)
  {
    this(Collections.singletonList(field), new JSONString(value));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The name of the top-level field to target with this filter.
   *                It must not be {@code null} .  See the class-level
   *                documentation for the {@link JSONObjectFilter} class for
   *                information about field path specifiers.
   * @param  value  The target boolean value for this filter.
   */
  public EqualsJSONObjectFilter(@NotNull final String field,
                                final boolean value)
  {
    this(Collections.singletonList(field),
         (value ? JSONBoolean.TRUE : JSONBoolean.FALSE));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The name of the top-level field to target with this filter.
   *                It must not be {@code null} .  See the class-level
   *                documentation for the {@link JSONObjectFilter} class for
   *                information about field path specifiers.
   * @param  value  The target numeric value for this filter.
   */
  public EqualsJSONObjectFilter(@NotNull final String field, final long value)
  {
    this(Collections.singletonList(field), new JSONNumber(value));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The name of the top-level field to target with this filter.
   *                It must not be {@code null} .  See the class-level
   *                documentation for the {@link JSONObjectFilter} class for
   *                information about field path specifiers.
   * @param  value  The target numeric value for this filter.  It must not be
   *                {@code null}.
   */
  public EqualsJSONObjectFilter(@NotNull final String field,
                                final double value)
  {
    this(Collections.singletonList(field), new JSONNumber(value));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The name of the top-level field to target with this filter.
   *                It must not be {@code null} .  See the class-level
   *                documentation for the {@link JSONObjectFilter} class for
   *                information about field path specifiers.
   * @param  value  The target value for this filter.  It must not be
   *                {@code null}.
   */
  public EqualsJSONObjectFilter(@NotNull final String field,
                                @NotNull final JSONValue value)
  {
    this(Collections.singletonList(field), value);
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The field path specifier for this filter.  It must not be
   *                {@code null} or empty.  See the class-level documentation
   *                for the {@link JSONObjectFilter} class for information about
   *                field path specifiers.
   * @param  value  The target value for this filter.  It must not be
   *                {@code null} (although it may be a {@code JSONNull}).
   */
  public EqualsJSONObjectFilter(@NotNull final List<String> field,
                                @NotNull final JSONValue value)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    Validator.ensureNotNull(value);

    this.field = Collections.unmodifiableList(new ArrayList<>(field));
    this.value = value;

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
   * Retrieves the target value for this filter.
   *
   * @return  The target value for this filter.
   */
  @NotNull()
  public JSONValue getValue()
  {
    return value;
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target string value for this filter.  It must not be
   *                {@code null}.
   */
  public void setValue(@NotNull final String value)
  {
    Validator.ensureNotNull(value);

    this.value = new JSONString(value);
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target Boolean value for this filter.
   */
  public void setValue(final boolean value)
  {
    this.value = (value ? JSONBoolean.TRUE : JSONBoolean.FALSE);
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target numeric value for this filter.
   */
  public void setValue(final long value)
  {
    this.value = new JSONNumber(value);
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target numeric value for this filter.
   */
  public void setValue(final double value)
  {
    this.value = new JSONNumber(value);
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target value for this filter.  It must not be
   *                {@code null} (although it may be a {@code JSONNull}).
   */
  public void setValue(@NotNull final JSONValue value)
  {
    Validator.ensureNotNull(value);

    this.value = value;
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

    for (final JSONValue v : candidates)
    {
      if (value.equals(v, false, (! caseSensitive), false))
      {
        return true;
      }

      if (v instanceof JSONArray)
      {
        final JSONArray a = (JSONArray) v;
        if (a.contains(value, false, (! caseSensitive), false, false))
        {
          return true;
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

    fields.put(FIELD_VALUE, value);

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
  protected EqualsJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final List<String> fieldPath =
         getStrings(filterObject, FIELD_FIELD_PATH, false, null);

    final boolean isCaseSensitive = getBoolean(filterObject,
         FIELD_CASE_SENSITIVE, false);

    return new EqualsJSONObjectFilter(fieldPath,
         filterObject.getField(FIELD_VALUE), isCaseSensitive);
  }
}
