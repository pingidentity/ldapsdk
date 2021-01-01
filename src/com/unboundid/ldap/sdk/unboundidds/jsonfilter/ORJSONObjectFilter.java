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
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONException;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



/**
 * This class provides an implementation of a JSON object filter that can
 * perform a logical OR across the result obtained from a number of filters.
 * The OR filter will match an object only if at least one (and optionally,
 * exactly one) of the filters contained in it matches that object.  An OR
 * filter with an empty set of embedded filters will never match any object.
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
 * The fields that are required to be included in an "OR" filter are:
 * <UL>
 *   <LI>
 *     {@code orFilters} -- An array of JSON objects, each of which is a valid
 *     JSON object filter.  At least one of these filters must match a JSON
 *     object in order for the OR filter to match.  If this is an empty array,
 *     then the filter will not match any object.
 *   </LI>
 * </UL>
 * The fields that may optionally be included in an "OR" filter are:
 * <UL>
 *   <LI>
 *     {@code exclusive} -- Indicates whether this should be treated as an
 *     exclusive OR.  If this is present, then it must have a Boolean value of
 *     either {@code true} (to indicate that this OR filter will only match a
 *     JSON object if exactly one of the embedded filters matches that object),
 *     or {@code false} (to indicate that it is a non-exclusive OR and will
 *     match a JSON object as long as at least one of the filters matches that
 *     object).  If this is not specified, then a non-exclusive OR will be
 *     performed.
 *   </LI>
 * </UL>
 * <H2>Examples</H2>
 * The following is an example of an OR filter that will never match any JSON
 * object:
 * <PRE>
 *   { "filterType" : "or",
 *     "orFilters" : [ ] }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   ORJSONObjectFilter filter = new ORJSONObjectFilter();
 * </PRE>
 * <BR><BR>
 * The following is an example of an OR filter that will match any JSON object
 * that contains either a top-level field named "homePhone" or a top-level
 * field named "workPhone":
 * <PRE>
 *   { "filterType" : "or",
 *     "orFilters" : [
 *       { "filterType" : "containsField",
 *          "field" : "homePhone" },
 *       { "filterType" : "containsField",
 *          "field" : "workPhone" } ] }
 * </PRE>
 * The above filter can be created with the code:
 * <PRE>
 *   ORJSONObjectFilter filter = new ORJSONObjectFilter(
 *        new ContainsFieldJSONObjectFilter("homePhone"),
 *        new EqualsJSONObjectFilter("workPhone"));
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ORJSONObjectFilter
       extends JSONObjectFilter
{
  /**
   * The value that should be used for the filterType element of the JSON object
   * that represents an "OR" filter.
   */
  @NotNull public static final String FILTER_TYPE = "or";



  /**
   * The name of the JSON field that is used to specify the set of filters to
   * include in this OR filter.
   */
  @NotNull public static final String FIELD_OR_FILTERS = "orFilters";



  /**
   * The name of the JSON field that is used to indicate whether this should be
   * an exclusive OR.
   */
  @NotNull public static final String FIELD_EXCLUSIVE = "exclusive";



  /**
   * The pre-allocated set of required field names.
   */
  @NotNull private static final Set<String> REQUIRED_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_OR_FILTERS)));



  /**
   * The pre-allocated set of optional field names.
   */
  @NotNull private static final Set<String> OPTIONAL_FIELD_NAMES =
       Collections.unmodifiableSet(new HashSet<>(
            Collections.singletonList(FIELD_EXCLUSIVE)));



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7821418213623654386L;



  // Indicates whether to process this filter as an exclusive OR.
  private volatile boolean exclusive;

  // The set of embedded filters for this OR filter.
  @NotNull private volatile List<JSONObjectFilter> orFilters;



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  orFilters  The set of filters for this OR filter.  At least one
   *                    of these filters must match a JSON object in order for
   *                    this OR filter to match that object.  If this is
   *                    {@code null} or empty, then this OR filter will never
   *                    match any JSON object.
   */
  public ORJSONObjectFilter(@Nullable final JSONObjectFilter... orFilters)
  {
    this(StaticUtils.toList(orFilters));
  }



  /**
   * Creates a new instance of this filter type with the provided information.
   *
   * @param  orFilters  The set of filters for this OR filter.  At least one
   *                    of these filters must match a JSON object in order for
   *                    this OR filter to match that object.  If this is
   *                    {@code null} or empty, then this OR filter will never
   *                    match any JSON object.
   */
  public ORJSONObjectFilter(
              @Nullable final Collection<JSONObjectFilter> orFilters)
  {
    setORFilters(orFilters);

    exclusive = false;
  }



  /**
   * Retrieves the set of filters for this OR filter.  At least one of these
   * filters must match a JSON object in order fro this OR filter to match that
   * object.
   *
   * @return  The set of filters for this OR filter.
   */
  @NotNull()
  public List<JSONObjectFilter> getORFilters()
  {
    return orFilters;
  }



  /**
   * Specifies the set of filters for this OR filter.  At least one of these
   * filters must match a JSON object in order for this OR filter to match that
   * object.
   *
   * @param  orFilters  The set of filters for this OR filter.  At least one
   *                    of these filters must match a JSON object in order for
   *                    this OR filter to match that object.  If this is
   *                    {@code null} or empty, then this OR filter will never
   *                    match any JSON object.
   */
  public void setORFilters(@Nullable final JSONObjectFilter... orFilters)
  {
    setORFilters(StaticUtils.toList(orFilters));
  }



  /**
   * Specifies the set of filters for this OR filter.  At least one of these
   * filters must match a JSON object in order for this OR filter to match that
   * object.
   *
   * @param  orFilters  The set of filters for this OR filter.  At least one
   *                    of these filters must match a JSON object in order for
   *                    this OR filter to match that object.  If this is
   *                    {@code null} or empty, then this OR filter will never
   *                    match any JSON object.
   */
  public void setORFilters(
                   @Nullable final Collection<JSONObjectFilter> orFilters)
  {
    if ((orFilters == null) || orFilters.isEmpty())
    {
      this.orFilters = Collections.emptyList();
    }
    else
    {
      this.orFilters = Collections.unmodifiableList(new ArrayList<>(orFilters));
    }
  }



  /**
   * Indicates whether this filter should be treated as an exclusive OR, in
   * which it will only match a JSON object if exactly one of the embedded
   * filters matches that object.
   *
   * @return  {@code true} if this filter should be treated as an exclusive OR
   *          and will only match a JSON object if exactly one of the embedded
   *          filters matches that object, or {@code false} if this filter will
   *          be non-exclusive and will match a JSON object as long as at least
   *          one of the embedded filters matches that object.
   */
  public boolean exclusive()
  {
    return exclusive;
  }



  /**
   * Specifies whether this filter should be treated as an exclusive OR, in
   * which it will only match a JSON object if exactly one of the embedded
   * filters matches that object.
   *
   * @param  exclusive  Indicates whether this filter should be treated as an
   *                    exclusive OR.
   */
  public void setExclusive(final boolean exclusive)
  {
    this.exclusive = exclusive;
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
    boolean matchFound = false;
    for (final JSONObjectFilter f : orFilters)
    {
      if (f.matchesJSONObject(o))
      {
        if (exclusive)
        {
          if (matchFound)
          {
            return false;
          }
          else
          {
            matchFound = true;
          }
        }
        else
        {
          return true;
        }
      }
    }

    return matchFound;
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

    final ArrayList<JSONValue> filterValues = new ArrayList<>(orFilters.size());
    for (final JSONObjectFilter f : orFilters)
    {
      filterValues.add(f.toJSONObject());
    }
    fields.put(FIELD_OR_FILTERS, new JSONArray(filterValues));

    if (exclusive)
    {
      fields.put(FIELD_EXCLUSIVE, JSONBoolean.TRUE);
    }

    return new JSONObject(fields);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected ORJSONObjectFilter decodeFilter(
                 @NotNull final JSONObject filterObject)
            throws JSONException
  {
    final ORJSONObjectFilter orFilter =
         new ORJSONObjectFilter(getFilters(filterObject, FIELD_OR_FILTERS));
    orFilter.exclusive = getBoolean(filterObject, FIELD_EXCLUSIVE, false);
    return orFilter;
  }
}
