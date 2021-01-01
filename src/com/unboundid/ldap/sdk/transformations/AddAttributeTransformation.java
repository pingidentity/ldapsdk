/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an entry transformation that will
 * add a specified attribute with a given set of values to any entry that does
 * not already contain that attribute and matches a specified set of criteria.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AddAttributeTransformation
       implements EntryTransformation
{
  // The attribute to add if appropriate.
  @NotNull private final Attribute attributeToAdd;

  // Indicates whether we need to check entries against the filter.
  private final boolean examineFilter;

  // Indicates whether we need to check entries against the scope.
  private final boolean examineScope;

  // Indicates whether to only add the attribute to entries that do not already
  // have any values for the associated attribute type.
  private final boolean onlyIfMissing;

  // The base DN to use to identify entries to which to add the attribute.
  @NotNull private final DN baseDN;

  // The filter to use to identify entries to which to add the attribute.
  @NotNull private final Filter filter;

  // The schema to use when processing.
  @Nullable private final Schema schema;

  // The scope to use to identify entries to which to add the attribute.
  @NotNull private final SearchScope scope;

  // The names that can be used to reference the target attribute.
  @NotNull private final Set<String> names;



  /**
   * Creates a new add attribute transformation with the provided information.
   *
   * @param  schema          The schema to use in processing.  It may be
   *                         {@code null} if a default standard schema should be
   *                         used.
   * @param  baseDN          The base DN to use to identify which entries to
   *                         update.  If this is {@code null}, it will be
   *                         assumed to be the null DN.
   * @param  scope           The scope to use to identify which entries to
   *                         update.  If this is {@code null}, it will be
   *                         assumed to be {@link SearchScope#SUB}.
   * @param  filter          An optional filter to use to identify which entries
   *                         to update.  If this is {@code null}, then a default
   *                         LDAP true filter (which will match any entry) will
   *                         be used.
   * @param  attributeToAdd  The attribute to add to entries that match the
   *                         criteria and do not already contain any values for
   *                         the specified attribute.  It must not be
   *                         {@code null}.
   * @param  onlyIfMissing   Indicates whether the attribute should only be
   *                         added to entries that do not already contain it.
   *                         If this is {@code false} and an entry that matches
   *                         the base, scope, and filter criteria and already
   *                         has one or more values for the target attribute
   *                         will be updated to include the new values in
   *                         addition to the existing values.
   */
  public AddAttributeTransformation(@Nullable final Schema schema,
                                    @Nullable final DN baseDN,
                                    @Nullable final SearchScope scope,
                                    @Nullable final Filter filter,
                                    @NotNull final Attribute attributeToAdd,
                                    final boolean onlyIfMissing)
  {
    this.attributeToAdd = attributeToAdd;
    this.onlyIfMissing = onlyIfMissing;


    // If a schema was provided, then use it.  Otherwise, use the default
    // standard schema.
    Schema s = schema;
    if (s == null)
    {
      try
      {
        s = Schema.getDefaultStandardSchema();
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
      }
    }
    this.schema = s;


    // Identify all of the names that can be used to reference the specified
    // attribute.
    final HashSet<String> attrNames =
         new HashSet<>(StaticUtils.computeMapCapacity(5));
    final String baseName =
         StaticUtils.toLowerCase(attributeToAdd.getBaseName());
    attrNames.add(baseName);
    if (s != null)
    {
      final AttributeTypeDefinition at = s.getAttributeType(baseName);
      if (at != null)
      {
        attrNames.add(StaticUtils.toLowerCase(at.getOID()));
        for (final String name : at.getNames())
        {
          attrNames.add(StaticUtils.toLowerCase(name));
        }
      }
    }
    names = Collections.unmodifiableSet(attrNames);


    // If a base DN was provided, then use it.  Otherwise, use the null DN.
    if (baseDN == null)
    {
      this.baseDN = DN.NULL_DN;
    }
    else
    {
      this.baseDN = baseDN;
    }


    // If a scope was provided, then use it.  Otherwise, use a subtree scope.
    if (scope == null)
    {
      this.scope = SearchScope.SUB;
    }
    else
    {
      this.scope = scope;
    }


    // If a filter was provided, then use it.  Otherwise, use an LDAP true
    // filter.
    if (filter == null)
    {
      this.filter = Filter.createANDFilter();
      examineFilter = false;
    }
    else
    {
      this.filter = filter;
      if (filter.getFilterType() == Filter.FILTER_TYPE_AND)
      {
        examineFilter = (filter.getComponents().length > 0);
      }
      else
      {
        examineFilter = true;
      }
    }


    examineScope =
         (! (this.baseDN.isNullDN() && this.scope == SearchScope.SUB));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry transformEntry(@NotNull final Entry e)
  {
    if (e == null)
    {
      return null;
    }


    // If we should only add the attribute to entries that don't already contain
    // any values for that type, then determine whether the target attribute
    // already exists in the entry.  If so, then just return the original entry.
    if (onlyIfMissing)
    {
      for (final String name : names)
      {
        if (e.hasAttribute(name))
        {
          return e;
        }
      }
    }


    // Determine whether the entry is within the scope of the inclusion
    // criteria.  If not, then return the original entry.
    try
    {
      if (examineScope && (! e.matchesBaseAndScope(baseDN, scope)))
      {
        return e;
      }
    }
    catch (final Exception ex)
    {
      // This should only happen if the entry has a malformed DN.  In that case,
      // we'll assume it isn't within the scope and return the provided entry.
      Debug.debugException(ex);
      return e;
    }


    // Determine whether the entry matches the suppression filter.  If not, then
    // return the original entry.
    try
    {
      if (examineFilter && (! filter.matchesEntry(e, schema)))
      {
        return e;
      }
    }
    catch (final Exception ex)
    {
      // If we can't verify whether the entry matches the filter, then assume
      // it doesn't and return the provided entry.
      Debug.debugException(ex);
      return e;
    }


    // If we've gotten here, then we should add the attribute to the entry.
    final Entry copy = e.duplicate();
    final Attribute existingAttribute =
         copy.getAttribute(attributeToAdd.getName(), schema);
    if (existingAttribute == null)
    {
      copy.addAttribute(attributeToAdd);
    }
    else
    {
      copy.addAttribute(existingAttribute.getName(),
           attributeToAdd.getValueByteArrays());
    }
    return copy;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translate(@NotNull final Entry original,
                         final long firstLineNumber)
  {
    return transformEntry(original);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry translateEntryToWrite(@NotNull final Entry original)
  {
    return transformEntry(original);
  }
}
