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



import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;

import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.jsonfilter.JFMessages.*;



/**
 * This class provides an implementation of a JSON object filter that can
 * negate the result of a provided filter.  If the embedded filter matches a
 * given JSON object, then this negate filter will not match that object.  If
 * the embedded filter does not match a JSON object, then this negate filter
 * will match that object.
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
 * The fields that are required to be included in a "negate" filter are:
 * <UL>
 *   <LI>
 *     {@code negateFilter} -- The JSON object filter whose match result should
 *     be negated.
 *   </LI>
 * </UL>
 * <H2>Example</H2>
 * The following is an example of a "negate" filter that will match any JSON
 * object that does not have a top-level field named "userType" with a value of
 * "employee":
 * <PRE>
 *   { "filterType" : "negate",
 *     "negateFilter" : {
 *       "filterType" : "equals",
 *       "field" : "userType",
 *       "value" : "employee" } }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   NegateJSONObjectFilter filter = new NegateJSONObjectFilter(
 *        new EqualsJSONObjectFilter("userType", "employee"));
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class NegateJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents a "negate" filter.
   */
  @NotNull public static final String FILTER_TYPE = "negate";



  /**
   * The name of the JSON field that is used to specify the filter to negate.
   */
  @NotNull public static final String FIELD_NEGATE_FILTER = "negateFilter";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_NEGATE_FILTER)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.emptySet();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9067967834329526711L;



  // The embedded filter whose result will be negated.
  @NotNull private volatile JSONObjectFilter negateFilter;



  /**
   * Creates an instance of this filter type that can only be used for decoding
   * JSON objects as "negate" filters.  It cannot be used as a regular "negate"
   * filter.
   */
  NegateJSONObjectFilter()
  {
    negateFilter = null;
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  negateFilter  The JSON object filter whose match result should be
   *                       negated.  It must not be {@code null}.
   */
  public NegateJSONObjectFilter(@NotNull final JSONObjectFilter negateFilter)
  {
    Validator.ensureNotNull(negateFilter);

    this.negateFilter = negateFilter;
  }



  /**
   * Retrieves the JSON object filter whose match result will be negated.
   *
   * @return  The JSON object filter whose match result will be negated.
   */
  @NotNull()
  public JSONObjectFilter getNegateFilter()
  {
    return negateFilter;
  }



  /**
   * Specifies the JSON object filter whose match result should be negated.
   *
   * @param  negateFilter  The JSON object filter whose match result should be
   *                       negated.
   */
  public void setNegateFilter(@NotNull final JSONObjectFilter negateFilter)
  {
    Validator.ensureNotNull(negateFilter);

    this.negateFilter = negateFilter;
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
    return (! negateFilter.matchesJSONObject(o));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public JSONObject toJSONObject()
  {
    final LinkedHashMap<String,JSONValue> fields =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));

    fields.put(FIELD_FILTER_TYPE, new JSONString(FILTER_TYPE));
    fields.put(FIELD_NEGATE_FILTER, negateFilter.toJSONObject());

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected NegateJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final JSONValue v = filterObject.getField(FIELD_NEGATE_FILTER);
    if (v == null)
    {
      throw new JSONException(ERR_OBJECT_FILTER_MISSING_REQUIRED_FIELD.get(
           String.valueOf(filterObject), FILTER_TYPE, FIELD_NEGATE_FILTER));
    }

    if (! (v instanceof JSONObject))
    {
      throw new JSONException(ERR_OBJECT_FILTER_VALUE_NOT_OBJECT.get(
           String.valueOf(filterObject), FILTER_TYPE, FIELD_NEGATE_FILTER));
    }

    try
    {
      return new NegateJSONObjectFilter(
           JSONObjectFilter.decode((JSONObject) v));
    }
    catch (final JSONException e)
    {
      Debug.debugException(e);
      throw new JSONException(
           ERR_OBJECT_FILTER_VALUE_NOT_FILTER.get(String.valueOf(filterObject),
                FILTER_TYPE, FIELD_NEGATE_FILTER, e.getMessage()),
           e);
    }
  }
}
