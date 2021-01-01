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



import java.math.BigDecimal;
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
 * used to identify JSON objects that have at least one value for a specified
 * field that is greater than a given value.
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
 * The fields that are required to be included in a "greater than" filter are:
 * <UL>
 *   <LI>
 *     {@code field} -- A field path specifier for the JSON field for which to
 *     make the determination.  This may be either a single string or an array
 *     of strings as described in the "Targeting Fields in JSON Objects" section
 *     of the class-level documentation for {@link JSONObjectFilter}.
 *   </LI>
 *   <LI>
 *     {@code value} -- The value to use in the matching.  It must be either a
 *     string (which will be compared against other strings using lexicographic
 *     comparison) or a number.
 *   </LI>
 * </UL>
 * The fields that may optionally be included in a "greater than" filter are:
 * <UL>
 *   <LI>
 *     {@code allowEquals} -- Indicates whether to match JSON objects that have
 *     a value for the specified field that matches the provided value.  If
 *     present, this field must have a Boolean value of either {@code true} (to
 *     indicate that it should be a "greater-than or equal to" filter) or
 *     {@code false} (to indicate that it should be a strict "greater-than"
 *     filter).  If this is not specified, then the default behavior will be to
 *     perform a strict "greater-than" evaluation.
 *   </LI>
 *   <LI>
 *     {@code matchAllElements} -- Indicates whether all elements of an array
 *     must be greater than (or possibly equal to) the specified value.  If
 *     present, this field must have a Boolean value of {@code true} (to
 *     indicate that all elements of the array must match the criteria for this
 *     filter) or {@code false} (to indicate that at least one element of the
 *     array must match the criteria for this filter).  If this is not
 *     specified, then the default behavior will be to require only at least
 *     one matching element.  This field will be ignored for JSON objects in
 *     which the specified field has a value that is not an array.
 *   </LI>
 *   <LI>
 *     {@code caseSensitive} -- Indicates whether string values should be
 *     treated in a case-sensitive manner.  If present, this field must have a
 *     Boolean value of either {@code true} or {@code false}.  If it is not
 *     provided, then a default value of {@code false} will be assumed so that
 *     strings are treated in a case-insensitive manner.
 *   </LI>
 * </UL>
 * <H2>Example</H2>
 * The following is an example of a "greater than" filter that will match any
 * JSON object with a top-level field named "salary" with a value that is
 * greater than or equal to 50000:
 * <PRE>
 *   { "filterType" : "greaterThan",
 *     "field" : "salary",
 *     "value" : 50000,
 *     "allowEquals" : true }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   GreaterThanJSONObjectFilter filter =
 *        new GreaterThanJSONObjectFilter("salary", 50000);
 *   filter.setAllowEquals(true);
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GreaterThanJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents a "greater than" filter.
   */
  @NotNull public static final String FILTER_TYPE = "greaterThan";



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
   * The name of the JSON field that is used to indicate whether to match JSON
   * objects with a value that is considered equal to the provided value.
   */
  @NotNull public static final String FIELD_ALLOW_EQUALS = "allowEquals";



  /**
   * The name of the JSON field that is used to indicate whether to match all
   * elements of an array rather than just one or more.
   */
  @NotNull public static final String FIELD_MATCH_ALL_ELEMENTS =
       "matchAllElements";



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
            Arrays.asList(FIELD_ALLOW_EQUALS, FIELD_MATCH_ALL_ELEMENTS,
                 FIELD_CASE_SENSITIVE)));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8397741931424599570L;



  // Indicates whether to match equivalent values in addition to those that are
  // strictly greater than the target value.
  private volatile boolean allowEquals;

  // Indicates whether string matching should be case-sensitive.
  private volatile boolean caseSensitive;

  // Indicates whether to match all elements of an array rather than just one or
  // more.
  private volatile boolean matchAllElements;

  // The expected value for the target field.
  @NotNull private volatile JSONValue value;

  // The field path specifier for the target field.
  @NotNull private volatile List<String> field;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "greater than" filters.  It cannot be used as a regular
   * "greater than" filter.
   */
  GreaterThanJSONObjectFilter()
  {
    field = null;
    value = null;
    allowEquals = false;
    matchAllElements = false;
    caseSensitive = false;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field             The field path specifier for the target field.
   * @param  value             The expected value for the target field.
   * @param  allowEquals       Indicates whether to match values that are equal
   *                           to the provided value in addition to those that
   *                           are strictly greater than that value.
   * @param  matchAllElements  Indicates whether, if the value of the target
   *                           field is an array, all elements of that array
   *                           will be required to match the criteria of this
   *                           filter.
   * @param  caseSensitive     Indicates whether string matching should be
   *                           case sensitive.
   */
  private GreaterThanJSONObjectFilter(@NotNull final List<String> field,
                                      @NotNull final JSONValue value,
                                      final boolean allowEquals,
                                      final boolean matchAllElements,
                                      final boolean caseSensitive)
  {
    this.field = field;
    this.value = value;
    this.allowEquals = allowEquals;
    this.matchAllElements = matchAllElements;
    this.caseSensitive = caseSensitive;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field  The name of the top-level field to target with this filter.
   *                It must not be {@code null} .  See the class-level
   *                documentation for the {@link JSONObjectFilter} class for
   *                information about field path specifiers.
   * @param  value  The target value for this filter.
   */
  public GreaterThanJSONObjectFilter(@NotNull final String field,
                                     final long value)
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
   * @param  value  The target value for this filter.
   */
  public GreaterThanJSONObjectFilter(@NotNull final String field,
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
  public GreaterThanJSONObjectFilter(@NotNull final String field,
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
   * @param  value  The target value for this filter.  It must not be
   *                {@code null}, and it must be either a {@link JSONNumber} or
   *                a {@link JSONString}.
   */
  public GreaterThanJSONObjectFilter(@NotNull final String field,
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
   *                {@code null}, and it must be either a {@link JSONNumber} or
   *                a {@link JSONString}.
   */
  public GreaterThanJSONObjectFilter(@NotNull final List<String> field,
                                     @NotNull final JSONValue value)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    Validator.ensureNotNull(value);
    Validator.ensureTrue((value instanceof JSONNumber) ||
         (value instanceof JSONString));

    this.field = Collections.unmodifiableList(new ArrayList<>(field));
    this.value = value;

    allowEquals = false;
    matchAllElements = false;
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
   * @param  value  The target value for this filter.
   */
  public void setValue(final long value)
  {
    setValue(new JSONNumber(value));
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target value for this filter.
   */
  public void setValue(final double value)
  {
    setValue(new JSONNumber(value));
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target value for this filter.  It must not be
   *                {@code null}.
   */
  public void setValue(@NotNull final String value)
  {
    Validator.ensureNotNull(value);

    setValue(new JSONString(value));
  }



  /**
   * Specifies the target value for this filter.
   *
   * @param  value  The target value for this filter.  It must not be
   *                {@code null}, and it must be either a {@link JSONNumber} or
   *                a {@link JSONString}.
   */
  public void setValue(@NotNull final JSONValue value)
  {
    Validator.ensureNotNull(value);
    Validator.ensureTrue((value instanceof JSONNumber) ||
         (value instanceof JSONString));

    this.value = value;
  }



  /**
   * Indicates whether this filter will match values that are considered equal
   * to the provided value in addition to those that are strictly greater than
   * that value.
   *
   * @return  {@code true} if this filter should behave like a "greater than or
   *          equal to" filter, or {@code false} if it should behave strictly
   *          like a "greater than" filter.
   */
  public boolean allowEquals()
  {
    return allowEquals;
  }



  /**
   * Specifies whether this filter should match values that are considered equal
   * to the provided value in addition to those that are strictly greater than
   * that value.
   *
   * @param  allowEquals  Indicates whether this filter should match values that
   *                      are considered equal to the provided value in addition
   *                      to those that are strictly greater than this value.
   */
  public void setAllowEquals(final boolean allowEquals)
  {
    this.allowEquals = allowEquals;
  }



  /**
   * Indicates whether, if the specified field has a value that is an array, to
   * require all elements of that array to match the criteria for this filter
   * rather than merely requiring at least one value to match.
   *
   * @return  {@code true} if the criteria contained in this filter will be
   *          required to match all elements of an array, or {@code false} if
   *          merely one or more values will be required to match.
   */
  public boolean matchAllElements()
  {
    return matchAllElements;
  }



  /**
   * Specifies whether, if the value of the target field is an array, all
   * elements of that array will be required to match the criteria of this
   * filter.  This will be ignored if the value of the target field is not an
   * array.
   *
   * @param  matchAllElements  {@code true} to indicate that all elements of an
   *                           array will be required to match the criteria of
   *                           this filter, or {@code false} to indicate that
   *                           merely one or more values will be required to
   *                           match.
   */
  public void setMatchAllElements(final boolean matchAllElements)
  {
    this.matchAllElements = matchAllElements;
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
      if (v instanceof JSONArray)
      {
        boolean matchOne = false;
        boolean matchAll = true;
        for (final JSONValue arrayValue : ((JSONArray) v).getValues())
        {
          if (matches(arrayValue))
          {
            if (! matchAllElements)
            {
              return true;
            }
            matchOne = true;
          }
          else
          {
            matchAll = false;
            if (matchAllElements)
            {
              break;
            }
          }
        }

        if (matchAllElements && matchOne && matchAll)
        {
          return true;
        }
      }
      else if (matches(v))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether the provided value matches the criteria of this filter.
   *
   * @param  v  The value for which to make the determination.
   *
   * @return  {@code true} if the provided value matches the criteria of this
   *          filter, or {@code false} if not.
   */
  private boolean matches(@NotNull final JSONValue v)
  {
    if ((v instanceof JSONNumber) && (value instanceof JSONNumber))
    {
      final BigDecimal targetValue = ((JSONNumber) value).getValue();
      final BigDecimal objectValue = ((JSONNumber) v).getValue();
      if (allowEquals)
      {
        return (objectValue.compareTo(targetValue) >= 0);
      }
      else
      {
        return (objectValue.compareTo(targetValue) > 0);
      }
    }
    else if ((v instanceof JSONString) && (value instanceof JSONString))
    {
      final String targetValue = ((JSONString) value).stringValue();
      final String objectValue = ((JSONString) v).stringValue();
      if (allowEquals)
      {
        if (caseSensitive)
        {
          return (objectValue.compareTo(targetValue) >= 0);
        }
        else
        {
          return (objectValue.compareToIgnoreCase(targetValue) >= 0);
        }
      }
      else
      {
        if (caseSensitive)
        {
          return (objectValue.compareTo(targetValue) > 0);
        }
        else
        {
          return (objectValue.compareToIgnoreCase(targetValue) > 0);
        }
      }
    }
    else
    {
      return false;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONObject()
  {
    final LinkedHashMap<String,JSONValue> fields =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(6));

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

    if (allowEquals)
    {
      fields.put(FIELD_ALLOW_EQUALS, JSONBoolean.TRUE);
    }

    if (matchAllElements)
    {
      fields.put(FIELD_MATCH_ALL_ELEMENTS, JSONBoolean.TRUE);
    }

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
  protected GreaterThanJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final List<String> fieldPath =
         getStrings(filterObject, FIELD_FIELD_PATH, false, null);

    final boolean isAllowEquals = getBoolean(filterObject,
         FIELD_ALLOW_EQUALS, false);

    final boolean isMatchAllElements = getBoolean(filterObject,
         FIELD_MATCH_ALL_ELEMENTS, false);

    final boolean isCaseSensitive = getBoolean(filterObject,
         FIELD_CASE_SENSITIVE, false);

    return new GreaterThanJSONObjectFilter(fieldPath,
         filterObject.getField(FIELD_VALUE), isAllowEquals, isMatchAllElements,
         isCaseSensitive);
  }
}
