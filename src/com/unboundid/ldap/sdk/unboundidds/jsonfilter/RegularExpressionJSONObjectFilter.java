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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.unboundid.util.Debug;
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
 * The fields that are required to be included in a "regular expression" filter
 * are:
 * <UL>
 *   <LI>
 *     {@code field} -- A field path specifier for the JSON field for which to
 *     make the determination.  This may be either a single string or an array
 *     of strings as described in the "Targeting Fields in JSON Objects" section
 *     of the class-level documentation for {@link JSONObjectFilter}.
 *   </LI>
 *   <LI>
 *     {@code regularExpression} -- The regular expression to use to identify
 *     matching values.  It must be compatible for use with the Java
 *     {@code java.util.regex.Pattern} class.
 *   </LI>
 * </UL>
 * The fields that may optionally be included in a "regular expression" filter
 * are:
 * <UL>
 *   <LI>
 *     {@code matchAllElements} -- Indicates whether all elements of an array
 *     must match the provided regular expression.  If present, this field must
 *     have a Boolean value of {@code true} (to indicate that all elements of
 *     the array must match the regular expression) or {@code false} (to
 *     indicate that at least one element of the array must match the regular
 *     expression).  If this is not specified, then the default behavior will be
 *     to require only at least one matching element.  This field will be
 *     ignored for JSON objects in which the specified field has a value that is
 *     not an array.
 *   </LI>
 * </UL>
 * <H2>Example</H2>
 * The following is an example of a "regular expression" filter that will match
 * any JSON object with a top-level field named "userID" with a value that
 * starts with an ASCII letter and contains only ASCII letters and numeric
 * digits:
 * <PRE>
 *   { "filterType" : "regularExpression",
 *     "field" : "userID",
 *     "regularExpression" : "^[a-zA-Z][a-zA-Z0-9]*$" }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   RegularExpressionJSONObjectFilter filter =
          new RegularExpressionJSONObjectFilter("userID",
               "^[a-zA-Z][a-zA-Z0-9]*$");
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class RegularExpressionJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents a "regular expression" filter.
   */
  @NotNull public static final String FILTER_TYPE = "regularExpression";



  /**
   * The name of the JSON field that is used to specify the field in the target
   * JSON object for which to make the determination.
   */
  @NotNull public static final String FIELD_FIELD_PATH = "field";



  /**
   * The name of the JSON field that is used to specify the regular expression
   * that values should match.
   */
  @NotNull public static final String FIELD_REGULAR_EXPRESSION =
       "regularExpression";



  /**
   * The name of the JSON field that is used to indicate whether all values of
   * an array should be required to match the provided regular expression.
   */
  @NotNull public static final String FIELD_MATCH_ALL_ELEMENTS =
       "matchAllElements";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(FIELD_FIELD_PATH, FIELD_REGULAR_EXPRESSION)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_MATCH_ALL_ELEMENTS)));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7678844742777504519L;



  // Indicates whether to require all elements of an array to match the
  // regular expression
  private volatile boolean matchAllElements;

  // The field path specifier for the target field.
  @NotNull private volatile List<String> field;

  // The regular expression to match.
  @NotNull private volatile Pattern regularExpression;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "regular expression" filters.  It cannot be used as a
   * regular "regular expression" filter.
   */
  RegularExpressionJSONObjectFilter()
  {
    field = null;
    regularExpression = null;
    matchAllElements = false;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field              The field path specifier for the target field.
   * @param  regularExpression  The regular expression pattern to match.
   * @param  matchAllElements   Indicates whether all elements of an array are
   *                            required to match the regular expression rather
   *                            than merely at least one element.
   */
  private RegularExpressionJSONObjectFilter(
               @NotNull final List<String> field,
               @NotNull final Pattern regularExpression,
               final boolean matchAllElements)
  {
    this.field = field;
    this.regularExpression = regularExpression;
    this.matchAllElements = matchAllElements;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field              The name of the top-level field to target with
   *                            this filter.  It must not be {@code null} .  See
   *                            the class-level documentation for the
   *                            {@link JSONObjectFilter} class for information
   *                            about field path specifiers.
   * @param  regularExpression  The regular expression to match.  It must not
   *                            be {@code null}, and it must be compatible for
   *                            use with the {@code java.util.regex.Pattern}
   *                            class.
   *
   * @throws  JSONException  If the provided string cannot be parsed as a valid
   *                         regular expression.
   */
  public RegularExpressionJSONObjectFilter(@NotNull final String field,
              @NotNull final String regularExpression)
         throws JSONException
  {
    this(Collections.singletonList(field), regularExpression);
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field              The name of the top-level field to target with
   *                            this filter.  It must not be {@code null} .  See
   *                            the class-level documentation for the
   *                            {@link JSONObjectFilter} class for information
   *                            about field path specifiers.
   * @param  regularExpression  The regular expression pattern to match.  It
   *                            must not be {@code null}.
   */
  public RegularExpressionJSONObjectFilter(@NotNull final String field,
              @NotNull final Pattern regularExpression)
  {
    this(Collections.singletonList(field), regularExpression);
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field              The field path specifier for this filter.  It
   *                            must not be {@code null} or empty.  See the
   *                            class-level documentation for the
   *                            {@link JSONObjectFilter} class for information
   *                            about field path specifiers.
   * @param  regularExpression  The regular expression to match.  It must not
   *                            be {@code null}, and it must be compatible for
   *                            use with the {@code java.util.regex.Pattern}
   *                            class.
   *
   * @throws  JSONException  If the provided string cannot be parsed as a valid
   *                         regular expression.
   */
  public RegularExpressionJSONObjectFilter(@NotNull final List<String> field,
              @NotNull final String regularExpression)
         throws JSONException
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    Validator.ensureNotNull(regularExpression);

    this.field = Collections.unmodifiableList(new ArrayList<>(field));

    try
    {
      this.regularExpression = Pattern.compile(regularExpression);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new JSONException(
           ERR_REGEX_FILTER_INVALID_REGEX.get(regularExpression,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    matchAllElements = false;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  field              The field path specifier for this filter.  It
   *                            must not be {@code null} or empty.  See the
   *                            class-level documentation for the
   *                            {@link JSONObjectFilter} class for information
   *                            about field path specifiers.
   * @param  regularExpression  The regular expression pattern to match.  It
   *                            must not be {@code null}.
   */
  public RegularExpressionJSONObjectFilter(@NotNull final List<String> field,
              @NotNull final Pattern regularExpression)
  {
    Validator.ensureNotNull(field);
    Validator.ensureFalse(field.isEmpty());

    Validator.ensureNotNull(regularExpression);

    this.field = Collections.unmodifiableList(new ArrayList<>(field));
    this.regularExpression = regularExpression;

    matchAllElements = false;
  }



  /**
   * Retrieves the field path specifier for this filter.
   *
   * @return The field path specifier for this filter.
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

    this.field= Collections.unmodifiableList(new ArrayList<>(field));
  }



  /**
   * Retrieves the regular expression pattern for this filter.
   *
   * @return  The regular expression pattern for this filter.
   */
  @NotNull()
  public Pattern getRegularExpression()
  {
    return regularExpression;
  }



  /**
   * Specifies the regular expression for this filter.
   *
   * @param  regularExpression  The regular expression to match.  It must not
   *                            be {@code null}, and it must be compatible for
   *                            use with the {@code java.util.regex.Pattern}
   *                            class.
   *
   * @throws  JSONException  If the provided string cannot be parsed as a valid
   *                         regular expression.
   */
  public void setRegularExpression(@NotNull final String regularExpression)
         throws JSONException
  {
    Validator.ensureNotNull(regularExpression);

    try
    {
      this.regularExpression = Pattern.compile(regularExpression);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new JSONException(
           ERR_REGEX_FILTER_INVALID_REGEX.get(regularExpression,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Specifies the regular expression for this filter.
   *
   * @param  regularExpression  The regular expression pattern to match.  It
   *                            must not be {@code null}.
   */
  public void setRegularExpression(@NotNull final Pattern regularExpression)
  {
    Validator.ensureNotNull(regularExpression);

    this.regularExpression = regularExpression;
  }



  /**
   * Indicates whether, if the target field is an array of values, the regular
   * expression will be required to match all elements in the array rather than
   * at least one element.
   *
   * @return  {@code true} if the regular expression will be required to match
   *          all elements of an array, or {@code false} if it will only be
   *          required to match at least one element.
   */
  public boolean matchAllElements()
  {
    return matchAllElements;
  }



  /**
   * Specifies whether the regular expression will be required to match all
   * elements of an array rather than at least one element.
   *
   * @param  matchAllElements  Indicates whether the regular expression will be
   *                           required to match all elements of an array rather
   *                           than at least one element.
   */
  public void setMatchAllElements(final boolean matchAllElements)
  {
    this.matchAllElements = matchAllElements;
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
      if (v instanceof JSONString)
      {
        final Matcher matcher =
             regularExpression.matcher(((JSONString) v).stringValue());
        if (matcher.matches())
        {
          return true;
        }
      }
      else if (v instanceof JSONArray)
      {
        boolean matchOne = false;
        boolean matchAll = true;
        for (final JSONValue arrayValue : ((JSONArray) v).getValues())
        {
          if (! (arrayValue instanceof JSONString))
          {
            matchAll = false;
            if (matchAllElements)
            {
              break;
            }
          }

          final Matcher matcher = regularExpression.matcher(
               ((JSONString) arrayValue).stringValue());
          if (matcher.matches())
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

        if (matchOne && matchAll)
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

    fields.put(FIELD_REGULAR_EXPRESSION,
         new JSONString(regularExpression.toString()));

    if (matchAllElements)
    {
      fields.put(FIELD_MATCH_ALL_ELEMENTS, JSONBoolean.TRUE);
    }

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected RegularExpressionJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final List<String> fieldPath =
         getStrings(filterObject, FIELD_FIELD_PATH, false, null);

    final String regex = getString(filterObject, FIELD_REGULAR_EXPRESSION,
         null, true);

    final Pattern pattern;
    try
    {
      pattern = Pattern.compile(regex);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new JSONException(
           ERR_REGEX_FILTER_DECODE_INVALID_REGEX.get(
                String.valueOf(filterObject), FIELD_REGULAR_EXPRESSION,
                fieldPathToName(fieldPath), StaticUtils.getExceptionMessage(e)),
           e);
    }

    final boolean matchAll =
         getBoolean(filterObject, FIELD_MATCH_ALL_ELEMENTS, false);

    return new RegularExpressionJSONObjectFilter(fieldPath, pattern, matchAll);
  }
}
