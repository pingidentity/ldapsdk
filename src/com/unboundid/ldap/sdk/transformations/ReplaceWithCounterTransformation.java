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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.RDN;
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
 * replace the existing set of values for a given attribute with a value that
 * contains a numeric counter (optionally along with additional static text)
 * that increments for each entry that contains the target attribute.  The
 * resulting attribute will only have a single value, even if it originally had
 * multiple values.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplaceWithCounterTransformation
       implements EntryTransformation
{
  // The counter to use to obtain the values.
  @NotNull private final AtomicLong counter;

  // Indicates whether to update the DN of the target entry if its RDN includes
  // the target attribute.
  private final boolean replaceInRDN;

  // The amount by which to increment the counter for each entry.
  private final long incrementAmount;

  // The schema to use when processing.
  @Nullable private final Schema schema;

  // The names that may be used to reference the attribute to replace.
  @NotNull private final Set<String> names;

  // The static text that will appear after the number in generated values.
  @Nullable private final String afterText;

  // The static text that will appear before the number in generated values.
  @Nullable private final String beforeText;



  /**
   * Creates a new replace with counter transformation using the provided
   * information.
   *
   * @param  schema           The schema to use to identify alternate names for
   *                          the target attribute.  This may be {@code null} if
   *                          a default standard schema should be used.
   * @param  attributeName    The name of the attribute that should be replaced
   *                          with the generated value.
   * @param  initialValue     The initial value to use for the counter.
   * @param  incrementAmount  The amount by which the counter should be
   *                          incremented for each entry containing the target
   *                          attribute.
   * @param  beforeText       An optional string that should appear before the
   *                          counter in generated values.  It may be
   *                          {@code null} if no before text should be used.
   * @param  afterText        An optional string that should appear after the
   *                          counter in generated values.  It may be
   *                          {@code null} if no after text should be used.
   * @param  replaceInRDN     Indicates whether to update the DN of the target
   *                          entry if its RDN includes the target attribute.
   */
  public ReplaceWithCounterTransformation(@Nullable final Schema schema,
                                          @NotNull final String attributeName,
                                          final long initialValue,
                                          final long incrementAmount,
                                          @Nullable final String beforeText,
                                          @Nullable final String afterText,
                                          final boolean replaceInRDN)
  {
    this.incrementAmount = incrementAmount;
    this.replaceInRDN = replaceInRDN;

    counter = new AtomicLong(initialValue);

    if (beforeText == null)
    {
      this.beforeText = "";
    }
    else
    {
      this.beforeText = beforeText;
    }

    if (afterText == null)
    {
      this.afterText = "";
    }
    else
    {
      this.afterText = afterText;
    }


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


    // Get all names that can be used to reference the target attribute.
    final HashSet<String> nameSet =
         new HashSet<>(StaticUtils.computeMapCapacity(5));
    final String baseName =
         StaticUtils.toLowerCase(Attribute.getBaseName(attributeName));
    nameSet.add(baseName);
    if (s != null)
    {
      final AttributeTypeDefinition at = s.getAttributeType(baseName);
      if (at != null)
      {
        nameSet.add(StaticUtils.toLowerCase(at.getOID()));
        for (final String name : at.getNames())
        {
          nameSet.add(StaticUtils.toLowerCase(name));
        }
      }
    }
    names = Collections.unmodifiableSet(nameSet);
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


    // See if the DN contains the target attribute in the RDN.  If so, then
    // replace its value.
    String dn = e.getDN();
    String newValue = null;
    if (replaceInRDN)
    {
      try
      {
        final DN parsedDN = new DN(dn);
        final RDN rdn = parsedDN.getRDN();
        for (final String name : names)
        {
          if (rdn.hasAttribute(name))
          {
            newValue =
                 beforeText + counter.getAndAdd(incrementAmount) + afterText;
            break;
          }
        }

        if (newValue != null)
        {
          if (rdn.isMultiValued())
          {
            final String[] attrNames = rdn.getAttributeNames();
            final byte[][] originalValues = rdn.getByteArrayAttributeValues();
            final byte[][] newValues = new byte[originalValues.length][];
            for (int i=0; i < attrNames.length; i++)
            {
              if (names.contains(StaticUtils.toLowerCase(attrNames[i])))
              {
                newValues[i] = StaticUtils.getBytes(newValue);
              }
              else
              {
                newValues[i] = originalValues[i];
              }
            }
            dn = new DN(new RDN(attrNames, newValues, schema),
                 parsedDN.getParent()).toString();
          }
          else
          {
            dn = new DN(new RDN(rdn.getAttributeNames()[0], newValue, schema),
                 parsedDN.getParent()).toString();
          }
        }
      }
      catch (final Exception ex)
      {
        Debug.debugException(ex);
      }
    }


    // If the RDN doesn't contain the target attribute, then see if the entry
    // contains the target attribute.  If not, then just return the provided
    // entry.
    if (newValue == null)
    {
      boolean hasAttribute = false;
      for (final String name : names)
      {
        if (e.hasAttribute(name))
        {
          hasAttribute = true;
          break;
        }
      }

      if (! hasAttribute)
      {
        return e;
      }
    }


    // If we haven't computed the new value for this entry, then do so now.
    if (newValue == null)
    {
      newValue = beforeText + counter.getAndAdd(incrementAmount) + afterText;
    }


    // Iterate through the attributes in the entry and make the appropriate
    // updates.
    final Collection<Attribute> originalAttributes = e.getAttributes();
    final ArrayList<Attribute> updatedAttributes =
         new ArrayList<>(originalAttributes.size());
    for (final Attribute a : originalAttributes)
    {
      if (names.contains(StaticUtils.toLowerCase(a.getBaseName())))
      {
        updatedAttributes.add(new Attribute(a.getName(), schema, newValue));
      }
      else
      {
        updatedAttributes.add(a);
      }
    }


    // Return the updated entry.
    return new Entry(dn, schema, updatedAttributes);
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
