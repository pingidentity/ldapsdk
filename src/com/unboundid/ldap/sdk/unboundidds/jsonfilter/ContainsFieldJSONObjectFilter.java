/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
  public static final String FILTER_TYPE = "containsField";



  /**
   * The name of the JSON field that is used to specify the field in the target
   * JSON object for which to make the determination.
   */
  public static final String FIELD_FIELD_PATH = "field";



  /**
   * The name of the JSON field that is used to specify the expected data type
   * for the target field.
   */
  public static final String FIELD_EXPECTED_TYPE = "expectedType";



  /**
   * The pre-allocated set of required field names.
   */
  private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<String>(
            Collections.singletonList(FIELD_FIELD_PATH)));



  /**
   * The pre-allocated set of optional field names.
   */
  private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<String>(
            Collections.singletonList(FIELD_EXPECTED_TYPE)));



  /**
   * A pre-allocated set containing all expected value type values.
   */
  private static final Set<ExpectedValueType> ALL_EXPECTED_VALUE_TYPES =
       Collections.unmodifiableSet(EnumSet.allOf(ExpectedValueType.class));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2922149221350606755L;



  // The field path specifier for the target field.
  private volatile List<String> field;

  // The expected value types for the target field.
  private volatile Set<ExpectedValueType> expectedValueTypes;



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
  private ContainsFieldJSONObjectFilter(final List<String> field,
               final Set<ExpectedValueType> expectedValueTypes)
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
  public ContainsFieldJSONObjectFilter(final String... field)
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
  public ContainsFieldJSONObjectFilter(final List<String> field)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    this.field = Collections.unmodifiableList(new ArrayList<String>(field));

    expectedValueTypes = ALL_EXPECTED_VALUE_TYPES;
  }



  /**
   * Retrieves the field path specifier for this filter.
   *
   * @return  The field path specifier for this filter.
   */
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
  public void setField(final String... field)
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
  public void setField(final List<String> field)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    this.field = Collections.unmodifiableList(new ArrayList<String>(field));
  }



  /**
   * Retrieves the set of acceptable value types for the specified field.
   *
   * @return  The set of acceptable value types for the specified field.
   */
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
  public void setExpectedType(final ExpectedValueType... expectedTypes)
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
  public void setExpectedType(final Collection<ExpectedValueType> expectedTypes)
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
  public String getFilterType()
  {
    return FILTER_TYPE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected Set<String> getRequiredFieldNames()
  {
    return REQUIRED_FIELD_NAMES;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected Set<String> getOptionalFieldNames()
  {
    return OPTIONAL_FIELD_NAMES;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesJSONObject(final JSONObject o)
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
  public JSONObject toJSONObject()
  {
    final LinkedHashMap<String,JSONValue> fields =
         new LinkedHashMap<String,JSONValue>(3);

    fields.put(FIELD_FILTER_TYPE, new JSONString(FILTER_TYPE));

    if (field.size() == 1)
    {
      fields.put(FIELD_FIELD_PATH, new JSONString(field.get(0)));
    }
    else
    {
      final ArrayList<JSONValue> fieldNameValues =
           new ArrayList<JSONValue>(field.size());
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
             new ArrayList<JSONValue>(expectedValueTypes.size());
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
  protected ContainsFieldJSONObjectFilter decodeFilter(
                                               final JSONObject filterObject)
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
