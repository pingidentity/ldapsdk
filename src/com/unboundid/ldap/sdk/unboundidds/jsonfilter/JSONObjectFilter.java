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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.jsonfilter.JFMessages.*;



/**
 * This class defines the base class for all JSON object filter types, which are
 * used to perform matching against JSON objects stored in a Ping Identity,
 * UnboundID, or Nokia/Alcatel-Lucent 8661 Directory Server via the
 * jsonObjectFilterExtensibleMatch matching rule.  The
 * {@link #toLDAPFilter(String)} method can be used to easily create an LDAP
 * filter from a JSON object filter.  This filter will have an attribute type
 * that is the name of an attribute with the JSON object syntax, a matching rule
 * ID of "jsonObjectFilterExtensibleMatch", and an assertion value that is the
 * string representation of the JSON object that comprises the filter.
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
 * For example, given the JSON object filter:
 * <PRE>
 *   { "filterType" : "equals", "field" : "firstName", "value" : "John" }
 * </PRE>
 * the resulting LDAP filter targeting attribute "jsonAttr" would have a string
 * representation as follows (without the line break that has been added for
 * formatting purposes):
 * <PRE>
 *   (jsonAttr:jsonObjectFilterExtensibleMatch:={ "filterType" : "equals",
 *   "field" : "firstName", "value" : "John" })
 * </PRE>
 * <BR><BR>
 * JSON object filters are themselves expressed in the form of JSON objects.
 * All filters must have a "filterType" field that indicates what type of filter
 * the object represents, and the filter type determines what other fields may
 * be required or optional for that type of filter.
 * <BR><BR>
 * <H2>Types of JSON Object Filters</H2>
 * This implementation supports a number of different types of filters to use
 * when matching JSON objects.  Supported JSON object filter types are as
 * follows:
 * <H3>Contains Field</H3>
 * This filter can be used to determine whether a JSON object has a specified
 * field, optionally with a given type of value.  For example, the following can
 * be used to determine whether a JSON object contains a top-level field named
 * "department" that has any kind of value:
 * <PRE>
 *   { "filterType" : "containsField",
 *     "field" : "department" }
 * </PRE>
 * <BR>
 * <H3>Equals</H3>
 * This filter can be used to determine whether a JSON object has a specific
 * value for a given field.  For example, the following can be used to determine
 * whether a JSON object has a top-level field named "firstName" with a value of
 * "John":
 * <PRE>
 *   { "filterType" : "equals",
 *     "field" : "firstName",
 *     "value" : "John" }
 * </PRE>
 * <BR>
 * <H3>Equals Any</H3>
 * This filter can be used to determine whether a JSON object has any of a
 * number of specified values for a given field.  For example, the following can
 * be used to determine whether a JSON object has a top-level field named
 * "userType" with a value that is either "employee", "partner", or
 * "contractor":
 * <PRE>
 *   { "filterType" : "equalsAny",
 *     "field" : "userType",
 *     "values" : [  "employee", "partner", "contractor" ] }
 * </PRE>
 * <BR>
 * <H3>Greater Than</H3>
 * This filter can be used to determine whether a JSON object has a specified
 * field with a value that is greater than (or optionally greater than or equal
 * to) a given numeric or string value.  For example, the following filter would
 * match any JSON object with a top-level field named "salary" with a numeric
 * value that is greater than or equal to 50000:
 * <PRE>
 *   { "filterType" : "greaterThan",
 *     "field" : "salary",
 *     "value" : 50000,
 *     "allowEquals" : true }
 * </PRE>
 * <BR>
 * <H3>Less Than</H3>
 * This filter can be used to determine whether a JSON object has a specified
 * field with a value that is less than (or optionally less than or equal to) a
 * given numeric or string value.  For example, the following filter will match
 * any JSON object with a "loginFailureCount" field with a numeric value that is
 * less than or equal to 3.
 * <PRE>
 *   { "filterType" : "lessThan",
 *     "field" : "loginFailureCount",
 *     "value" : 3,
 *     "allowEquals" : true }
 * </PRE>
 * <BR>
 * <H3>Substring</H3>
 * This filter can be used to determine whether a JSON object has a specified
 * field with a string value that starts with, ends with, and/or contains a
 * particular substring.  For example, the following filter will match any JSON
 * object with an "email" field containing a value that ends with
 * "@example.com":
 * <PRE>
 *   { "filterType" : "substring",
 *     "field" : "email",
 *     "endsWith" : "@example.com" }
 * </PRE>
 * <BR>
 * <H3>Regular Expression</H3>
 * This filter can be used to determine whether a JSON object has a specified
 * field with a string value that matches a given regular expression.  For
 * example, the following filter can be used to determine whether a JSON object
 * has a "userID" value that starts with an ASCII letter and contains only
 * ASCII letters and numeric digits:
 * <PRE>
 *   { "filterType" : "regularExpression",
 *     "field" : "userID",
 *     "regularExpression" : "^[a-zA-Z][a-zA-Z0-9]*$" }
 * </PRE>
 * <BR>
 * <H3>Object Matches</H3>
 * This filter can be used to determine whether a JSON object has a specified
 * field with a value that is itself a JSON object that matches a given JSON
 * object filter.  For example, the following filter can be used to determine
 * whether a JSON object has a "contact" field with a value that is a JSON
 * object with a "type" value of "home" and an "email" field with any kind of
 * value:
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
 * <BR>
 * <H3>AND</H3>
 * This filter can be used to perform a logical AND across a number of filters,
 * so that the AND filter will only match a JSON object if each of the
 * encapsulated filters matches that object.  For example, the following filter
 * could be used to match any JSON object with both a "firstName" field with a
 * value of "John" and a "lastName" field with a value of "Doe":
 * <PRE>
 *   { "filterType" : "and",
 *     "andFilters" : [
 *       { "filterType" : "equals",
 *          "field" : "firstName",
 *          "value" : "John" },
 *       { "filterType" : "equals",
 *          "field" : "lastName",
 *          "value" : "Doe" } ] }
 * </PRE>
 * <BR>
 * <H3>OR</H3>
 * This filter can be used to perform a logical OR (or optionally, a logical
 * exclusive OR) across a number of filters so that the filter will only match
 * a JSON object if at least one of the encapsulated filters matches that
 * object.  For example, the following filter could be used to match a JSON
 * object that has either or both of the "homePhone" or "workPhone" field with
 * any kind of value:
 * <PRE>
 *   { "filterType" : "or",
 *     "orFilters" : [
 *       { "filterType" : "containsField",
 *          "field" : "homePhone" },
 *       { "filterType" : "containsField",
 *          "field" : "workPhone" } ] }
 * </PRE>
 * <BR>
 * <H3>Negate</H3>
 * This filter can be used to negate the result of an encapsulated filter, so
 * that it will only match a JSON object that the encapsulated filter does not
 * match.  For example, the following filter will only match JSON objects that
 * do not have a "userType" field with a value of "employee":
 * <PRE>
 *   { "filterType" : "negate",
 *     "negateFilter" : {
 *       "filterType" : "equals",
 *       "field" : "userType",
 *       "value" : "employee" } }
 * </PRE>
 * <BR><BR>
 * <H2>Targeting Fields in JSON Objects</H2>
 * Many JSON object filter types need to specify a particular field in the JSON
 * object that is to be used for the matching.  Unless otherwise specified in
 * the Javadoc documentation for a particular filter type, the target field
 * should be specified either as a single string (to target a top-level field in
 * the object) or a non-empty array of strings (to provide the complete path to
 * the target field).  In the case the target field is specified in an array,
 * the first (leftmost in the string representation) element of the array will
 * specify a top-level field in the JSON object.  If the array contains a second
 * element, then that indicates that one of the following should be true:
 * <UL>
 *   <LI>
 *     The top-level field specified by the first element should have a value
 *     that is itself a JSON object, and the second element specifies the name
 *     of a field in that JSON object.
 *   </LI>
 *   <LI>
 *     The top-level field specified by the first element should have a value
 *     that is an array, and at least one element of the array is a JSON object
 *     with a field whose name matches the second element of the field path
 *     array.
 *   </LI>
 * </UL>
 * Each additional element of the field path array specifies an additional level
 * of hierarchy in the JSON object.  For example, consider the following JSON
 * object:
 * <PRE>
 *   { "field1" : "valueA",
 *     "field2" : {
 *       "field3" : "valueB",
 *       "field4" : {
 *         "field5" : "valueC" } } }
 * </PRE>
 * In the above example, the field whose value is {@code "valueA"} can be
 * targeted using either {@code "field1"} or {@code [ "field1" ]}.  The field
 * whose value is {@code "valueB"} can be targeted as
 * {@code [ "field2", "field3" ]}.  The field whose value is {@code "valueC"}
 * can be targeted as {@code [ "field2", "field4", "field5" ]}.
 * <BR><BR>
 * Note that the mechanism outlined here cannot always be used to uniquely
 * identify each field in a JSON object.  In particular, if an array contains
 * multiple JSON objects, then it is possible that some of those JSON objects
 * could have field names in common, and therefore the same field path reference
 * could apply to multiple fields.  For example, in the JSON object:
 * <PRE>
 *   {
 *     "contact" : [
 *       { "type" : "Home",
 *         "email" : "jdoe@example.net",
 *         "phone" : "123-456-7890" },
 *       { "type" : "Work",
 *         "email" : "john.doe@example.com",
 *         "phone" : "789-456-0123" } ] }
 * </PRE>
 * The field specifier {@code [ "contact", "type" ]} can reference either the
 * field whose value is {@code "Home"} or the field whose value is
 * {@code "Work"}.  The field specifier {@code [ "contact", "email" ]} can
 * reference the field whose value is {@code "jdoe@example.net"} or the field
 * whose value is {@code "john.doe@example.com"}.  And the field specifier
 * {@code [ "contact", "phone" ]} can reference the field with value
 * {@code "123-456-7890"} or the field with value {@code "789-456-0123"}.  This
 * ambiguity is intentional for values in arrays because it makes it possible
 * to target array elements without needing to know the order of elements in the
 * array.
 * <BR><BR>
 * <H2>Thread Safety of JSON Object Filters</H2>
 * JSON object filters are not guaranteed to be threadsafe.  Because some filter
 * types support a number of configurable options, it is more convenient and
 * future-proof to provide minimal constructors to specify values for the
 * required fields and setter methods for the optional fields.  These filters
 * will be mutable, and any filter that may be altered should not be accessed
 * concurrently by multiple threads.  However, if a JSON object filter is not
 * expected to be altered, then it may safely be shared across multiple threads.
 * Further, LDAP filters created using the {@link #toLDAPFilter} method and
 * JSON objects created using the {@link #toJSONObject} method will be
 * threadsafe under all circumstances.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class JSONObjectFilter
       implements Serializable
{
  /**
   * The name of the matching rule that may be used to determine whether an
   * attribute value matches a JSON object filter.
   */
  @NotNull public static final String JSON_OBJECT_FILTER_MATCHING_RULE_NAME =
       "jsonObjectFilterExtensibleMatch";



  /**
   * The numeric OID of the matching rule that may be used to determine whether
   * an attribute value matches a JSON object filter.
   */
  @NotNull public static final String JSON_OBJECT_FILTER_MATCHING_RULE_OID =
       "1.3.6.1.4.1.30221.2.4.13";



  /**
   * The name of the JSON field that is used to specify the filter type for
   * the JSON object filter.
   */
  @NotNull public static final String FIELD_FILTER_TYPE = "filterType";



  /**
   * A map of filter type names to instances that can be used for decoding JSON
   * objects to filters of that type.
   */
  @NotNull private static final ConcurrentHashMap<String,JSONObjectFilter>
       FILTER_TYPES =
            new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(10));
  static
  {
    registerFilterType(
         new ContainsFieldJSONObjectFilter(),
         new EqualsJSONObjectFilter(),
         new EqualsAnyJSONObjectFilter(),
         new ObjectMatchesJSONObjectFilter(),
         new SubstringJSONObjectFilter(),
         new GreaterThanJSONObjectFilter(),
         new LessThanJSONObjectFilter(),
         new RegularExpressionJSONObjectFilter(),
         new ANDJSONObjectFilter(),
         new ORJSONObjectFilter(),
         new NegateJSONObjectFilter());
  }



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -551616596693584562L;



  /**
   * Retrieves the value that must appear in the {@code filterType} field for
   * this filter.
   *
   * @return  The value that must appear in the {@code filterType} field for
   *          this filter.
   */
  @NotNull()
  public abstract String getFilterType();



  /**
   * Retrieves the names of all fields (excluding the {@code filterType} field)
   * that must be present in the JSON object representing a filter of this type.
   *
   * @return  The names of all fields (excluding the {@code filterType} field)
   *          that must be present in the JSON object representing a filter of
   *          this type.
   */
  @NotNull()
  protected abstract Set<String> getRequiredFieldNames();



  /**
   * Retrieves the names of all fields that may optionally be present but are
   * not required in the JSON object representing a filter of this type.
   *
   * @return  The names of all fields that may optionally be present but are not
   *          required in the JSON object representing a filter of this type.
   */
  @NotNull()
  protected abstract Set<String> getOptionalFieldNames();



  /**
   * Indicates whether this JSON object filter matches the provided JSON object.
   *
   * @param  o  The JSON object for which to make the determination.
   *
   * @return  {@code true} if this JSON object filter matches the provided JSON
   *          object, or {@code false} if not.
   */
  public abstract boolean matchesJSONObject(@NotNull JSONObject o);



  /**
   * Retrieves a JSON object that represents this filter.
   *
   * @return  A JSON object that represents this filter.
   */
  @NotNull()
  public abstract JSONObject toJSONObject();



  /**
   * Retrieves the value of the specified field from the provided JSON object as
   * a list of strings.  The specified field must be a top-level field in the
   * JSON object, and it must have a value that is a single string or an array
   * of strings.
   *
   * @param  o              The JSON object to examine.  It must not be
   *                        {@code null}.
   * @param  fieldName      The name of a top-level field in the JSON object
   *                        that is expected to have a value that is a string
   *                        or an array of strings.  It must not be
   *                        {@code null}.  It will be treated in a
   *                        case-sensitive manner.
   * @param  allowEmpty     Indicates whether the value is allowed to be an
   *                        empty array.
   * @param  defaultValues  The list of default values to return if the field
   *                        is not present.  If this is {@code null}, then a
   *                        {@code JSONException} will be thrown if the
   *                        specified field is not present.
   *
   * @return  The list of strings retrieved from the JSON object, or the
   *          default list if the field is not present in the object.
   *
   * @throws  JSONException  If the object doesn't have the specified field and
   *                         no set of default values was provided, or if the
   *                         value of the specified field was not a string or
   *                         an array of strings.
   */
  @NotNull()
  protected List<String> getStrings(@NotNull final JSONObject o,
                                    @NotNull final String fieldName,
                                    final boolean allowEmpty,
                                    @Nullable final List<String> defaultValues)
            throws JSONException
  {
    final JSONValue v = o.getField(fieldName);
    if (v == null)
    {
      if (defaultValues == null)
      {
        throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
             String.valueOf(o), getFilterType(), fieldName));
      }
      else
      {
        return defaultValues;
      }
    }

    if (v instanceof JSONString)
    {
      return Collections.singletonList(((JSONString) v).stringValue());
    }
    else if (v instanceof JSONArray)
    {
      final List<JSONValue> values = ((JSONArray) v).getValues();
      if (values.isEmpty())
      {
        if (allowEmpty)
        {
          return Collections.emptyList();
        }
        else
        {
          throw new JSONException(ERR_OBJECT_FILTER_VALUE_EMPTY_ARRAY.get(
               String.valueOf(o), getFilterType(), fieldName));
        }
      }

      final ArrayList<String> valueList = new ArrayList<>(values.size());
      for (final JSONValue av : values)
      {
        if (av instanceof JSONString)
        {
          valueList.add(((JSONString) av).stringValue());
        }
        else
        {
          throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_STRINGS.get(
               String.valueOf(o), getFilterType(), fieldName));
        }
      }
      return valueList;
    }
    else
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_STRINGS.get(
           String.valueOf(o), getFilterType(), fieldName));
    }
  }



  /**
   * Retrieves the value of the specified field from the provided JSON object as
   * a strings.  The specified field must be a top-level field in the JSON
   * object, and it must have a value that is a single string.
   *
   * @param  o             The JSON object to examine.  It must not be
   *                       {@code null}.
   * @param  fieldName     The name of a top-level field in the JSON object
   *                       that is expected to have a value that is a string.
   *                       It must not be {@code null}.  It will be treated in a
   *                       case-sensitive manner.
   * @param  defaultValue  The default values to return if the field is not
   *                       present.  If this is {@code null} and
   *                       {@code required} is {@code true}, then a
   *                       {@code JSONException} will be thrown if the specified
   *                       field is not present.
   * @param  required      Indicates whether the field is required to be present
   *                       in the object.
   *
   * @return  The string retrieved from the JSON object, or the default value if
   *          the field is not present in the object.
   *
   * @throws  JSONException  If the object doesn't have the specified field, the
   *                         field is required, and no default value was
   *                         provided, or if the value of the specified field
   *                         was not a string.
   */
  @Nullable()
  protected String getString(@NotNull final JSONObject o,
                             @NotNull final String fieldName,
                             @Nullable final String defaultValue,
                             final boolean required)
            throws JSONException
  {
    final JSONValue v = o.getField(fieldName);
    if (v == null)
    {
      if (required && (defaultValue == null))
      {
        throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
             String.valueOf(o), getFilterType(), fieldName));
      }
      else
      {
        return defaultValue;
      }
    }

    if (v instanceof JSONString)
    {
      return ((JSONString) v).stringValue();
    }
    else
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_STRING.get(
           String.valueOf(o), getFilterType(), fieldName));
    }
  }



  /**
   * Retrieves the value of the specified field from the provided JSON object as
   * a {@code boolean}.  The specified field must be a top-level field in the
   * JSON object, and it must have a value that is either {@code true} or
   * {@code false}.
   *
   * @param  o             The JSON object to examine.  It must not be
   *                       {@code null}.
   * @param  fieldName     The name of a top-level field in the JSON object that
   *                       that is expected to have a value that is either
   *                       {@code true} or {@code false}.
   * @param  defaultValue  The default value to return if the specified field
   *                       is not present in the JSON object.  If this is
   *                       {@code null}, then a {@code JSONException} will be
   *                       thrown if the specified field is not present.
   *
   * @return  The value retrieved from the JSON object, or the default value if
   *          the field is not present in the object.
   *
   * @throws  JSONException  If the object doesn't have the specified field and
   *                         no default value was provided, or if the value of
   *                         the specified field was neither {@code true} nor
   *                         {@code false}.
   */
  protected boolean getBoolean(@NotNull final JSONObject o,
                               @NotNull final String fieldName,
                               @Nullable final Boolean defaultValue)
            throws JSONException
  {
    final JSONValue v = o.getField(fieldName);
    if (v == null)
    {
      if (defaultValue == null)
      {
        throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
             String.valueOf(o), getFilterType(), fieldName));
      }
      else
      {
        return defaultValue;
      }
    }

    if (v instanceof JSONBoolean)
    {
      return ((JSONBoolean) v).booleanValue();
    }
    else
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_BOOLEAN.get(
           String.valueOf(o), getFilterType(), fieldName));
    }
  }



  /**
   * Retrieves the value of the specified field from the provided JSON object as
   * a list of JSON object filters.  The specified field must be a top-level
   * field in the JSON object and it must have a value that is an array of
   * JSON objects that represent valid JSON object filters.
   *
   * @param  o          The JSON object to examine.  It must not be
   *                    {@code null}.
   * @param  fieldName  The name of a top-level field in the JSON object that is
   *                    expected to have a value that is an array of JSON
   *                    objects that represent valid JSON object filters.  It
   *                    must not be {@code null}.
   *
   * @return  The list of JSON object filters retrieved from the JSON object.
   *
   * @throws  JSONException  If the object doesn't have the specified field, or
   *                         if the value of that field is not an array of
   *                         JSON objects that represent valid JSON object
   *                         filters.
   */
  @NotNull()
  protected List<JSONObjectFilter> getFilters(@NotNull final JSONObject o,
                                              @NotNull final String fieldName)
            throws JSONException
  {
    final JSONValue value = o.getField(fieldName);
    if (value == null)
    {
      throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
           String.valueOf(o), getFilterType(), fieldName));
    }

    if (! (value instanceof JSONArray))
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_ARRAY.get(
           String.valueOf(o), getFilterType(), fieldName));
    }

    final List<JSONValue> values = ((JSONArray) value).getValues();
    final ArrayList<JSONObjectFilter> filterList =
         new ArrayList<>(values.size());
    for (final JSONValue arrayValue : values)
    {
      if (! (arrayValue instanceof JSONObject))
      {
        throw new JSONException(ERR_OBJECT_FILTER_ARRAY_ELEMENT_NOT_OBJECT.get(
             String.valueOf(o), getFilterType(), fieldName));
      }

      final JSONObject filterObject = (JSONObject) arrayValue;
      try
      {
        filterList.add(decode(filterObject));
      }
      catch (final JSONException e)
      {
        Debug.debugException(e);
        throw new JSONException(
             ERR_OBJECT_FILTER_ARRAY_ELEMENT_NOT_FILTER.get(String.valueOf(o),
                  getFilterType(), String.valueOf(filterObject), fieldName,
                  e.getMessage()),
             e);
      }
    }

    return filterList;
  }



  /**
   * Retrieves the set of values that match the provided field name specifier.
   *
   * @param  o          The JSON object to examine.
   * @param  fieldName  The field name specifier for the values to retrieve.
   *
   * @return  The set of values that match the provided field name specifier, or
   *          an empty list if the provided JSON object does not have any fields
   *          matching the provided specifier.
   */
  @NotNull()
  protected static List<JSONValue> getValues(@NotNull final JSONObject o,
                                        @NotNull final List<String> fieldName)
  {
    final ArrayList<JSONValue> values = new ArrayList<>(10);
    getValues(o, fieldName, 0, values);
    return values;
  }



  /**
   * Retrieves the set of values that match the provided field name specifier.
   *
   * @param  o               The JSON object to examine.
   * @param  fieldName       The field name specifier for the values to
   *                         retrieve.
   * @param  fieldNameIndex  The current index into the field name specifier.
   * @param  values          The list into which matching values should be
   *                         added.
   */
  private static void getValues(@NotNull final JSONObject o,
                                @NotNull final List<String> fieldName,
                                final int fieldNameIndex,
                                @NotNull final List<JSONValue> values)
  {
    final JSONValue v = o.getField(fieldName.get(fieldNameIndex));
    if (v == null)
    {
      return;
    }

    final int nextIndex = fieldNameIndex + 1;
    if (nextIndex < fieldName.size())
    {
      // This indicates that there are more elements in the field name
      // specifier.  The value must either be a JSON object that we can look
      // further into, or it must be an array containing one or more JSON
      // objects.
      if (v instanceof JSONObject)
      {
        getValues((JSONObject) v, fieldName, nextIndex, values);
      }
      else if (v instanceof JSONArray)
      {
        getValuesFromArray((JSONArray) v, fieldName, nextIndex, values);
      }

      return;
    }

    // If we've gotten here, then there is no more of the field specifier, so
    // the value we retrieved matches the specifier.  Add it to the list of
    // values.
    values.add(v);
  }



  /**
   * Calls {@code getValues} for any elements of the provided array that are
   * JSON objects, recursively descending into any nested arrays.
   *
   * @param  a               The array to process.
   * @param  fieldName       The field name specifier for the values to
   *                         retrieve.
   * @param  fieldNameIndex  The current index into the field name specifier.
   * @param  values          The list into which matching values should be
   *                         added.
   */
  private static void getValuesFromArray(@NotNull final JSONArray a,
                                         @NotNull final List<String> fieldName,
                                         final int fieldNameIndex,
                                         @NotNull final List<JSONValue> values)
  {
    for (final JSONValue v : a.getValues())
    {
      if (v instanceof JSONObject)
      {
        getValues((JSONObject) v, fieldName, fieldNameIndex, values);
      }
      else if (v instanceof JSONArray)
      {
        getValuesFromArray((JSONArray) v, fieldName, fieldNameIndex, values);
      }
    }
  }



  /**
   * Decodes the provided JSON object as a JSON object filter.
   *
   * @param  o  The JSON object to be decoded as a JSON object filter.
   *
   * @return  The JSON object filter decoded from the provided JSON object.
   *
   * @throws  JSONException  If the provided JSON object cannot be decoded as a
   *                         JSON object filter.
   */
  @NotNull()
  public static JSONObjectFilter decode(@NotNull final JSONObject o)
         throws JSONException
  {
    // Get the value of the filter type field for the object and use it to get
    // a filter instance we can use to decode filters of that type.
    final JSONValue filterTypeValue = o.getField(FIELD_FILTER_TYPE);
    if (filterTypeValue == null)
    {
      throw new JSONException(ERR_OBJECT_FILTER_MISSING_FILTER_TYPE.get(
           String.valueOf(o), FIELD_FILTER_TYPE));
    }

    if (! (filterTypeValue instanceof JSONString))
    {
      throw new JSONException(ERR_OBJECT_FILTER_INVALID_FILTER_TYPE.get(
           String.valueOf(o), FIELD_FILTER_TYPE));
    }

    final String filterType =
         StaticUtils.toLowerCase(((JSONString) filterTypeValue).stringValue());
    final JSONObjectFilter decoder = FILTER_TYPES.get(filterType);
    if (decoder == null)
    {
      throw new JSONException(ERR_OBJECT_FILTER_INVALID_FILTER_TYPE.get(
           String.valueOf(o), FIELD_FILTER_TYPE));
    }


    // Validate the set of fields contained in the provided object to ensure
    // that all required fields were provided and that no disallowed fields were
    // included.
    final HashSet<String> objectFields = new HashSet<>(o.getFields().keySet());
    objectFields.remove(FIELD_FILTER_TYPE);
    for (final String requiredField : decoder.getRequiredFieldNames())
    {
      if (! objectFields.remove(requiredField))
      {
        throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
             String.valueOf(o), decoder.getFilterType(), requiredField));
      }
    }

    for (final String remainingField : objectFields)
    {
      if (! decoder.getOptionalFieldNames().contains(remainingField))
      {
        throw new JSONException(ERR_OBJECT_FILTER_UNRECOGNIZED_FIELD.get(
             String.valueOf(o), decoder.getFilterType(), remainingField));
      }
    }

    return decoder.decodeFilter(o);
  }



  /**
   * Decodes the provided JSON object as a filter of this type.
   *
   * @param  o  The JSON object to be decoded.  The caller will have already
   *            validated that all required fields are present, and that it
   *            does not have any fields that are neither required nor optional.
   *
   * @return  The decoded JSON object filter.
   *
   * @throws  JSONException  If the provided JSON object cannot be decoded as a
   *                         valid filter of this type.
   */
  @NotNull()
  protected abstract JSONObjectFilter decodeFilter(@NotNull JSONObject o)
            throws JSONException;



  /**
   * Registers the provided filter type(s) so that this class can decode filters
   * of that type.
   *
   * @param  impl  The filter type implementation(s) to register.
   */
  protected static void registerFilterType(
                             @NotNull final JSONObjectFilter... impl)
  {
    for (final JSONObjectFilter f : impl)
    {
      final String filterTypeName = StaticUtils.toLowerCase(f.getFilterType());
      FILTER_TYPES.put(filterTypeName, f);
    }
  }



  /**
   * Constructs an LDAP extensible matching filter that may be used to identify
   * entries with one or more values for a specified attribute that represent
   * JSON objects matching this JSON object filter.
   *
   * @param  attributeDescription  The attribute description (i.e., the
   *                               attribute name or numeric OID plus zero or
   *                               more attribute options) for the LDAP
   *                               attribute to target with this filter.  It
   *                               must not be {@code null}.
   *
   * @return  The constructed LDAP extensible matching filter.
   */
  @NotNull()
  public final Filter toLDAPFilter(@NotNull final String attributeDescription)
  {
    return Filter.createExtensibleMatchFilter(attributeDescription,
         JSON_OBJECT_FILTER_MATCHING_RULE_NAME, false, toString());
  }



  /**
   * Creates a string representation of the provided field path.  The path will
   * be constructed by using the JSON value representations of the field paths
   * (with each path element surrounded by quotation marks and including any
   * appropriate escaping) and using the period as a delimiter between each
   * path element.
   *
   * @param  fieldPath  The field path to process.
   *
   * @return  A string representation of the provided field path.
   */
  @NotNull()
  static String fieldPathToName(@NotNull final List<String> fieldPath)
  {
    if (fieldPath == null)
    {
      return "null";
    }
    else if (fieldPath.isEmpty())
    {
      return "";
    }
    else if (fieldPath.size() == 1)
    {
      return new JSONString(fieldPath.get(0)).toString();
    }
    else
    {
      final StringBuilder buffer = new StringBuilder();
      for (final String pathElement : fieldPath)
      {
        if (buffer.length() > 0)
        {
          buffer.append('.');
        }

        new JSONString(pathElement).toString(buffer);
      }

      return buffer.toString();
    }
  }



  /**
   * Retrieves a hash code for this JSON object filter.
   *
   * @return  A hash code for this JSON object filter.
   */
  @Override()
  public final int hashCode()
  {
    return toJSONObject().hashCode();
  }



  /**
   * Indicates whether the provided object is considered equal to this JSON
   * object filter.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          JSON object filter, or {@code false} if not.
   */
  @Override()
  public final boolean equals(@Nullable final Object o)
  {
    if (o == this)
    {
      return true;
    }

    if (o instanceof JSONObjectFilter)
    {
      final JSONObjectFilter f = (JSONObjectFilter) o;
      return toJSONObject().equals(f.toJSONObject());
    }

    return false;
  }



  /**
   * Retrieves a string representation of the JSON object that represents this
   * filter.
   *
   * @return  A string representation of the JSON object that represents this
   *          filter.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    return toJSONObject().toString();
  }



  /**
   * Appends a string representation of the JSON object that represents this
   * filter to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public final void toString(@NotNull final StringBuilder buffer)
  {
    toJSONObject().toString(buffer);
  }
}
