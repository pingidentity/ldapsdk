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
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.jsonfilter.JFMessages.*;



/**
 * This class provides an implementation of a JSON object filter that can be
 * used to identify JSON objects containing a specified field, optionally
 * restricting it by the data type of the value.
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
 * The fields that are required to be included in a "contains field" filter are:
 * <UL>
 *   <LI>
 *     {@code field} -- A field path specifier for the JSON field for which to
 *     make the determination.  This may be either a single string or an
 *     array of strings as described in the "Targeting Fields in JSON Objects"
 *     section of the class-level documentation for {@link JSONObjectFilter}.
 *   </LI>
 * </UL>
 * The fields that may optionally be included in a "contains field" filter are:
 * <UL>
 *   <LI>
 *     {@code expectedType} -- Specifies the expected data type for the value of
 *     the target field.  If this is not specified, then any data type will be
 *     permitted.  If this is specified, then the filter will only match a JSON
 *     object that contains the specified {@code fieldName} if its value has the
 *     expected data type.  The value of the {@code expectedType} field must be
 *     either a single string or an array of strings, and the only values
 *     allowed will be:
 *     <UL>
 *       <LI>
 *         {@code boolean} -- Indicates that the value may be a Boolean value of
 *         {@code true} or {@code false}.
 *       </LI>
 *       <LI>
 *         {@code empty-array} -- Indicates that the value may be an empty
 *         array.
 *       </LI>
 *       <LI>
 *         {@code non-empty-array} -- Indicates that the value may be an array
 *         that contains at least one element.  There will not be any
 *         constraints placed on the values inside of the array.
 *       </LI>
 *       <LI>
 *         {@code null} -- Indicates that the value may be {@code null}.
 *       </LI>
 *       <LI>
 *         {@code number} -- Indicates that the value may be a number.
 *       </LI>
 *       <LI>
 *         {@code object} -- Indicates that the value may be a JSON object.
 *       </LI>
 *       <LI>
 *         {@code string} -- Indicates that the value may be a string.
 *       </LI>
 *     </UL>
 *   </LI>
 * </UL>
 * <H2>Examples</H2>
 * The following is an example of a "contains field" filter that will match any
 * JSON object that includes a top-level field of "department" with any kind of
 * value:
 * <PRE>
 *   { "filterType" : "containsField",
 *     "field" : "department" }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   ContainsFieldJSONObjectFilter filter =
 *        new ContainsFieldJSONObjectFilter("department");
 * </PRE>
 * <BR><BR>
 * The following is an example of a "contains field" filter that will match any
 * JSON object with a top-level field of "first" whose value is a JSON object
 * (or an array containing a JSON object) with a field named "second" whose
 * value is a Boolean of either {@code true} or {@code false}.
 * <PRE>
 *   { "filterType" : "containsField",
 *     "field" : [ "first", "second" ],
 *     "expectedType" : "boolean" }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   ContainsFieldJSONObjectFilter filter = new ContainsFieldJSONObjectFilter(
 *        Arrays.asList("first", "second"),
 *        EnumSet.of(ExpectedValueType.BOOLEAN));
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ContainsFieldJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents a "contains field" filter.
   */
  @NotNull public static final String FILTER_TYPE = "containsField";



  /**
   * The name of the JSON field that is used to specify the field in the target
   * JSON object for which to make the determination.
   */
  @NotNull public static final String FIELD_FIELD_PATH = "field";



  /**
   * The name of the JSON field that is used to specify the expected data type
   * for the target field.
   */
  @NotNull public static final String FIELD_EXPECTED_TYPE = "expectedType";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_FIELD_PATH)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_EXPECTED_TYPE)));



  /**
   * A pre-allocated set containing all expected value type values.
   */
  @NotNull private static final Set<ExpectedValueType>
       ALL_EXPECTED_VALUE_TYPES =
       Collections.unmodifiableSet(EnumSet.allOf(ExpectedValueType.class));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2922149221350606755L;



  // The field path specifier for the target field.
  @NotNull private volatile List<String> field;

  // The expected value types for the target field.
  @NotNull private volatile Set<ExpectedValueType> expectedValueTypes;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "contains field" filters.  It cannot be used as a regular
   * "contains field" filter.
   */
  ContainsFieldJSONObjectFilter()
  {
    field = null;
    expectedValueTypes = null;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field               The field path specifier for the target field.
   * @param  expectedValueTypes  The expected value types for the target field.
   */
  private ContainsFieldJSONObjectFilter(@NotNull final List<String> field,
               @NotNull final Set<ExpectedValueType> expectedValueTypes)
  {
    this.field = field;
    this.expectedValueTypes = expectedValueTypes;
  }



  /**
   * Creates a new "contains field" filter that targets the specified field.
   *
   * @param  field  The field path specifier for this filter.  It must not be
   *                {@code null} or empty.  See the class-level documentation
   *                for the {@link JSONObjectFilter} class for information about
   *                field path specifiers.
   */
  public ContainsFieldJSONObjectFilter(@NotNull final String... field)
  {
    this(StaticUtils.toList(field));
  }



  /**
   * Creates a new "contains field" filter that targets the specified field.
   *
   * @param  field  The field path specifier for this filter.  It must not be
   *                {@code null} or empty.  See the class-level documentation
   *                for the {@link JSONObjectFilter} class for information about
   *                field path specifiers.
   */
  public ContainsFieldJSONObjectFilter(@NotNull final List<String> field)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    this.field = Collections.unmodifiableList(new ArrayList<>(field));

    expectedValueTypes = ALL_EXPECTED_VALUE_TYPES;
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
   * Retrieves the set of acceptable value types for the specified field.
   *
   * @return  The set of acceptable value types for the specified field.
   */
  @NotNull()
  public Set<ExpectedValueType> getExpectedType()
  {
    return expectedValueTypes;
  }



  /**
   * Specifies the set of acceptable value types for the specified field.
   *
   * @param  expectedTypes  The set of acceptable value types for the specified
   *                        field.  It may be {@code null} or empty if the field
   *                        may have a value of any type.
   */
  public void setExpectedType(
                   @Nullable final ExpectedValueType... expectedTypes)
  {
    setExpectedType(StaticUtils.toList(expectedTypes));
  }



  /**
   * Specifies the set of acceptable value types for the specified field.
   *
   * @param  expectedTypes  The set of acceptable value types for the specified
   *                        field.  It may be {@code null} or empty if the field
   *                        may have a value of any type.
   */
  public void setExpectedType(
                   @Nullable final Collection<ExpectedValueType> expectedTypes)
  {
    if ((expectedTypes == null) || expectedTypes.isEmpty())
    {
      expectedValueTypes = ALL_EXPECTED_VALUE_TYPES;
    }
    else
    {
      final EnumSet<ExpectedValueType> s =
           EnumSet.noneOf(ExpectedValueType.class);
      s.addAll(expectedTypes);
      expectedValueTypes = Collections.unmodifiableSet(s);
    }
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
        final JSONArray a = (JSONArray) v;
        if (a.isEmpty())
        {
          if (expectedValueTypes.contains(ExpectedValueType.EMPTY_ARRAY))
          {
            return true;
          }
        }
        else
        {
          if (expectedValueTypes.contains(ExpectedValueType.NON_EMPTY_ARRAY))
          {
            return true;
          }
        }
      }
      else if (v instanceof JSONBoolean)
      {
        if (expectedValueTypes.contains(ExpectedValueType.BOOLEAN))
        {
          return true;
        }
      }
      else if (v instanceof JSONNull)
      {
        if (expectedValueTypes.contains(ExpectedValueType.NULL))
        {
          return true;
        }
      }
      else if (v instanceof JSONNumber)
      {
        if (expectedValueTypes.contains(ExpectedValueType.NUMBER))
        {
          return true;
        }
      }
      else if (v instanceof JSONObject)
      {
        if (expectedValueTypes.contains(ExpectedValueType.OBJECT))
        {
          return true;
        }
      }
      else if (v instanceof JSONString)
      {
        if (expectedValueTypes.contains(ExpectedValueType.STRING))
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
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));

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

    if (! expectedValueTypes.equals(ALL_EXPECTED_VALUE_TYPES))
    {
      if (expectedValueTypes.size() == 1)
      {
        fields.put(FIELD_EXPECTED_TYPE, new
             JSONString(expectedValueTypes.iterator().next().toString()));
      }
      else
      {
        final ArrayList<JSONValue> expectedTypeValues =
             new ArrayList<>(expectedValueTypes.size());
        for (final ExpectedValueType t : expectedValueTypes)
        {
          expectedTypeValues.add(new JSONString(t.toString()));
        }
        fields.put(FIELD_EXPECTED_TYPE, new JSONArray(expectedTypeValues));
      }
    }

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected ContainsFieldJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final List<String> fieldPath =
         getStrings(filterObject, FIELD_FIELD_PATH, false, null);

    final Set<ExpectedValueType> expectedTypes;
    final List<String> valueTypeNames = getStrings(filterObject,
         FIELD_EXPECTED_TYPE, false, Collections.<String>emptyList());
    if (valueTypeNames.isEmpty())
    {
      expectedTypes = ALL_EXPECTED_VALUE_TYPES;
    }
    else
    {
      final EnumSet<ExpectedValueType> valueTypes =
           EnumSet.noneOf(ExpectedValueType.class);
      for (final String s : valueTypeNames)
      {
        final ExpectedValueType t = ExpectedValueType.forName(s);
        if (t == null)
        {
          throw new JSONException(
               ERR_CONTAINS_FIELD_FILTER_UNRECOGNIZED_EXPECTED_TYPE.get(
                    String.valueOf(filterObject), FILTER_TYPE, s,
                    FIELD_EXPECTED_TYPE));
        }
        else
        {
          valueTypes.add(t);
        }
      }
      expectedTypes = valueTypes;
    }

    return new ContainsFieldJSONObjectFilter(fieldPath, expectedTypes);
  }
}
