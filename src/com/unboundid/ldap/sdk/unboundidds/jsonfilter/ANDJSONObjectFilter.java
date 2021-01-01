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
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides an implementation of a JSON object filter that can
 * perform a logical AND across the result obtained from a number of filters.
 * The AND filter will match an object only if all of the filters contained in
 * it match that object.  An AND filter with an empty set of embedded filters
 * will match any object.
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
 * The fields that are required to be included in an "AND" filter are:
 * <UL>
 *   <LI>
 *     {@code andFilters} -- An array of JSON objects, each of which is a valid
 *     JSON object filter.  Each of these filters must match a JSON object in
 *     order for the AND filter to match.  If this is an empty array, then the
 *     filter will match any object.
 *   </LI>
 * </UL>
 * <BR><BR>
 * <H2>Examples</H2>
 * The following is an example of an AND filter that will match any JSON object:
 * <PRE>
 *   { "filterType" : "and",
 *     "andFilters" : [ ] }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   ANDJSONObjectFilter filter = new ANDJSONObjectFilter();
 * </PRE>
 * <BR><BR>
 * The following is an example of an AND filter that will match any JSON object
 * in which there is a top-level field named "firstName" with a String value of
 * "John" and top-level field named "lastName" with a String value of "Doe":
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
 * The above filter can be created with the code:
 * <PRE>
 *   ANDJSONObjectFilter filter = new ANDJSONObjectFilter(
 *        new EqualsJSONObjectFilter("firstName", "John"),
 *        new EqualsJSONObjectFilter("firstName", "Doe"));
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ANDJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents an "AND" filter.
   */
  @NotNull public static final String FILTER_TYPE = "and";



  /**
   * The name of the JSON field that is used to specify the set of filters to
   * include in this AND filter.
   */
  @NotNull public static final String FIELD_AND_FILTERS = "andFilters";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_AND_FILTERS)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.emptySet();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6616759665873968672L;



  // The set of embedded filters for this AND filter.
  @NotNull private volatile List<JSONObjectFilter> andFilters;



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  andFilters  The set of filters that must each match a JSON object
   *                     in order for this AND filter to match.  If this is
   *                     {@code null} or empty, then this AND filter will match
   *                     any JSON object.
   */
  public ANDJSONObjectFilter(@Nullable final JSONObjectFilter... andFilters)
  {
    this(StaticUtils.toList(andFilters));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  andFilters  The set of filters that must each match a JSON object
   *                     in order for this AND filter to match.  If this is
   *                     {@code null} or empty, then this AND filter will match
   *                     any JSON object.
   */
  public ANDJSONObjectFilter(
              @Nullable final Collection<JSONObjectFilter> andFilters)
  {
    setANDFilters(andFilters);
  }



  /**
   * Retrieves the set of filters that must each match a JSON object in order
   * for this AND filter to match.
   *
   * @return  The set of filters that must each match a JSON object in order for
   *          this AND filter to match, or an empty list if this AND filter
   *          should match any JSON object.
   */
  @NotNull()
  public List<JSONObjectFilter> getANDFilters()
  {
    return andFilters;
  }



  /**
   * Specifies the set of AND filters that must each match a JSON object in
   * order for this AND filter to match.
   *
   * @param  andFilters  The set of filters that must each match a JSON object
   *                     in order for this AND filter to match.  If this is
   *                     {@code null} or empty, then this AND filter will match
   *                     any JSON object.
   */
  public void setANDFilters(@Nullable final JSONObjectFilter... andFilters)
  {
    setANDFilters(StaticUtils.toList(andFilters));
  }



  /**
   * Specifies the set of AND filters that must each match a JSON object in
   * order for this AND filter to match.
   *
   * @param  andFilters  The set of filters that must each match a JSON object
   *                     in order for this AND filter to match.  If this is
   *                     {@code null} or empty, then this AND filter will match
   *                     any JSON object.
   */
  public void setANDFilters(
                   @Nullable final Collection<JSONObjectFilter> andFilters)
  {
    if ((andFilters == null) || andFilters.isEmpty())
    {
      this.andFilters = Collections.emptyList();
    }
    else
    {
      this.andFilters =
           Collections.unmodifiableList(new ArrayList<>(andFilters));
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
    for (final JSONObjectFilter f : andFilters)
    {
      if (! f.matchesJSONObject(o))
      {
        return false;
      }
    }

    return true;
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

    final ArrayList<JSONValue> filterValues =
         new ArrayList<>(andFilters.size());
    for (final JSONObjectFilter f : andFilters)
    {
      filterValues.add(f.toJSONObject());
    }
    fields.put(FIELD_AND_FILTERS, new JSONArray(filterValues));

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected ANDJSONObjectFilter decodeFilter(
                                     @NotNull final JSONObject filterObject)
            throws JSONException
  {
    return new ANDJSONObjectFilter(getFilters(filterObject, FIELD_AND_FILTERS));
  }
}
