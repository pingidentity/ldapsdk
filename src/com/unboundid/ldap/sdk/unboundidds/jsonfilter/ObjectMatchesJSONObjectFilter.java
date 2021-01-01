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

import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.jsonfilter.JFMessages.*;



/**
 * This class provides an implementation of a JSON object filter that can be
 * used to identify JSON objects that have a field whose value is a JSON object
 * that matches a provided JSON object filter, or a field whose value is an
 * array that contains at least one JSON object that matches the provided
 * filter.
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
 * The fields that are required to be included in an "object matches" filter
 * are:
 * <UL>
 *   <LI>
 *     {@code field} -- A field path specifier for the JSON field for which to
 *     make the determination.  This may be either a single string or an array
 *     of strings as described in the "Targeting Fields in JSON Objects" section
 *     of the class-level documentation for {@link JSONObjectFilter}.  The value
 *     of the target field is expected to either be a JSON object or an array
 *     that contains one or more JSON objects.
 *   </LI>
 *   <LI>
 *     {@code filter} -- A JSON object that represents a valid JSON object
 *     filter to match against any JSON object(s) in the value of the target
 *     field.  Note that field name references in this filter should be
 *     relative to the object in the value of the target field, not to the
 *     other JSON object that contains that field.
 *   </LI>
 * </UL>
 * <H2>Example</H2>
 * The following is an example of an "object matches" filter that will match
 * any JSON object with a top-level field named "contact" whose value is a JSON
 * object (or an array containing one or more JSON objects) with a "type" field
 * with a value of "home" and a "email" field with any value:
 * <PRE>
 *   { "filterType" : "objectMatches",
 *     "field" : "contact",
 *     "filter" : {
 *       "filterType" : "and",
 *       "andFilters" : [
 *         { "filterType" : "equals",
 *           "field" : "type",
 *           "value" : "home" },
 *         { "filterType" : "containsField",
 *           "field" : "email" } ] } }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   ObjectMatchesJSONObjectFilter filter = new ObjectMatchesJSONObjectFilter(
 *        "contact",
 *        new ANDJSONObjectFilter(
 *             new EqualsJSONObjectFilter("type", "home"),
 *             new ContainsFieldJSONObjectFilter("email")));
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ObjectMatchesJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents an "object matches" filter.
   */
  @NotNull public static final String FILTER_TYPE = "objectMatches";



  /**
   * The name of the JSON field that is used to specify the field in the target
   * JSON object for which to make the determination.
   */
  @NotNull public static final String FIELD_FIELD_PATH = "field";



  /**
   * The name of the JSON field that is used to specify the filter to match
   * against the object in the target field.
   */
  @NotNull public static final String FIELD_FILTER = "filter";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(FIELD_FIELD_PATH, FIELD_FILTER)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.emptySet();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7138078723547160420L;



  // The filter to match against the object(s) in the target field.
  @NotNull private volatile JSONObjectFilter filter;

  // The field path specifier for the target field.
  @NotNull private volatile List<String> field;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "object matches" filters.  It cannot be used as a regular
   * "object matches" filter.
   */
  ObjectMatchesJSONObjectFilter()
  {
    field = null;
    filter = null;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field   The name of the top-level field to target with this filter.
   *                 It must not be {@code null} .  See the class-level
   *                 documentation for the {@link JSONObjectFilter} class for
   *                 information about field path specifiers.
   * @param  filter  The filter that will be matched against JSON objects
   *                 contained in the specified field.
   */
  public ObjectMatchesJSONObjectFilter(@NotNull final String field,
                                       @NotNull final JSONObjectFilter filter)
  {
    this(Collections.singletonList(field), filter);
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field   The field path specifier for this filter.  It must not be
   *                 {@code null} or empty.  See the class-level documentation
   *                 for the {@link JSONObjectFilter} class for information
   *                 about field path specifiers.
   * @param  filter  The filter that will be matched against JSON objects
   *                 contained in the specified field.
   */
  public ObjectMatchesJSONObjectFilter(@NotNull final List<String> field,
                                       @NotNull final JSONObjectFilter filter)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    Validator.ensureNotNull(filter);

    this.field = Collections.unmodifiableList(new ArrayList<>(field));
    this.filter = filter;
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
   * Retrieves the filter that will be matched against any JSON objects
   * contained in the value of the specified field.
   *
   * @return  The filter that will be matched against any JSON objects contained
   *          in the value of the specified field.
   */
  @NotNull()
  public JSONObjectFilter getFilter()
  {
    return filter;
  }



  /**
   * Specifies the filter that will be matched against any JSON objects
   * contained in the value of the specified field.
   *
   * @param  filter  The filter that will be matched against any JSON objects
   *                 contained in the value of the specified field.  It must
   *                 not be {@code null}.
   */
  public void setFilter(@NotNull final JSONObjectFilter filter)
  {
    Validator.ensureNotNull(filter);

    this.filter = filter;
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
      if (v instanceof JSONObject)
      {
        if (filter.matchesJSONObject((JSONObject) v))
        {
          return true;
        }
      }
      else if (v instanceof JSONArray)
      {
        for (final JSONValue arrayValue : ((JSONArray) v).getValues())
        {
          if ((arrayValue instanceof JSONObject) &&
              filter.matchesJSONObject((JSONObject) arrayValue))
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

    fields.put(FIELD_FILTER, filter.toJSONObject());

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected ObjectMatchesJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final List<String> fieldPath =
         getStrings(filterObject, FIELD_FIELD_PATH, false, null);

    final JSONValue v = filterObject.getField(FIELD_FILTER);
    if (v == null)
    {
      throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
           String.valueOf(filterObject), FILTER_TYPE, FIELD_FILTER));
    }

    if (! (v instanceof JSONObject))
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_OBJECT.get(
           String.valueOf(filterObject), FILTER_TYPE, FIELD_FILTER));
    }

    try
    {
      return new ObjectMatchesJSONObjectFilter(fieldPath,
           JSONObjectFilter.decode((JSONObject) v));
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new JSONException(
           ERR_OBJECT_FILTER_VALUE_NOT_FILTER.get(String.valueOf(filterObject),
                FILTER_TYPE, FIELD_FILTER, e.getMessage()),
           e);
    }
  }
}
