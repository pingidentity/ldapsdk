/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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
import java.util.HashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an entry transformation that can be
 * used to replace existing attributes in entries with a default set of values.
 * The default attributes will not be added to entries that do not have existing
 * values for the target attributes.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplaceAttributeTransformation
       implements EntryTransformation
{
  // The schema to use when processing.
  private final Schema schema;

  // The set of attributes to replace in entries.
  private final Map<String,Attribute> attributes;



  /**
   * Creates a new replace attribute transformation that will replace existing
   * values of the specified attribute with the provided set of default values.
   *
   * @param  schema         The schema to use to identify alternate names that
   *                        may be used to reference the attributes to replace.
   *                        It may be {@code null} to use a default standard
   *                        schema.
   * @param  attributeName  The name of the attribute for which to replace
   *                        existing values.  It must not be {@code null}.
   * @param  newValues      The new values to use in place of the existing
   *                        values for the specified attribute.
   */
  public ReplaceAttributeTransformation(final Schema schema,
                                        final String attributeName,
                                        final String... newValues)
  {
    this(schema, new Attribute(attributeName, schema, newValues));
  }



  /**
   * Creates a new replace attribute transformation that will replace existing
   * values of the specified attribute with the provided set of default values.
   *
   * @param  schema         The schema to use to identify alternate names that
   *                        may be used to reference the attributes to replace.
   *                        It may be {@code null} to use a default standard
   *                        schema.
   * @param  attributeName  The name of the attribute for which to replace
   *                        existing values.  It must not be {@code null}.
   * @param  newValues      The new values to use in place of the existing
   *                        values for the specified attribute.
   */
  public ReplaceAttributeTransformation(final Schema schema,
                                        final String attributeName,
                                        final Collection<String> newValues)
  {
    this(schema, new Attribute(attributeName, schema, newValues));
  }



  /**
   * Creates a new replace attribute transformation that will replace existing
   * copies of the specified attributes with the provided versions.
   *
   * @param  schema      The schema to use to identify alternate names that may
   *                     be used to reference the attributes to replace.  It may
   *                     be {@code null} to use a default standard schema.
   * @param  attributes  The attributes to be used in place of existing
   *                     attributes of the same type.  It must not be
   *                     {@code null} or empty.
   */
  public ReplaceAttributeTransformation(final Schema schema,
                                        final Attribute... attributes)
  {
    this(schema, StaticUtils.toList(attributes));
  }



  /**
   * Creates a new replace attribute transformation that will replace existing
   * copies of the specified attributes with the provided versions.
   *
   * @param  schema      The schema to use to identify alternate names that may
   *                     be used to reference the attributes to replace.  It may
   *                     be {@code null} to use a default standard schema.
   * @param  attributes  The attributes to be used in place of existing
   *                     attributes of the same type.  It must not be
   *                     {@code null} or empty.
   */
  public ReplaceAttributeTransformation(final Schema schema,
                                        final Collection<Attribute> attributes)
  {
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


    // Identify all of the names that may be used to reference the attributes
    // to replace.
    final HashMap<String,Attribute> attrMap = new HashMap<String,Attribute>(10);
    for (final Attribute a : attributes)
    {
      final String baseName = StaticUtils.toLowerCase(a.getBaseName());
      attrMap.put(baseName, a);

      if (s != null)
      {
        final AttributeTypeDefinition at = s.getAttributeType(baseName);
        if (at != null)
        {
          attrMap.put(StaticUtils.toLowerCase(at.getOID()),
               new Attribute(at.getOID(), s, a.getValues()));
          for (final String name : at.getNames())
          {
            final String lowerName = StaticUtils.toLowerCase(name);
            if (! attrMap.containsKey(lowerName))
            {
              attrMap.put(lowerName, new Attribute(name, s, a.getValues()));
            }
          }
        }
      }
    }
    this.attributes = Collections.unmodifiableMap(attrMap);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry transformEntry(final Entry e)
  {
    if (e == null)
    {
      return null;
    }


    // First, see if the entry has any of the target attributes.  If not, we can
    // just return the provided entry.
    boolean hasAttributeToReplace = false;
    final Collection<Attribute> originalAttributes = e.getAttributes();
    for (final Attribute a : originalAttributes)
    {
      if (attributes.containsKey(StaticUtils.toLowerCase(a.getBaseName())))
      {
        hasAttributeToReplace = true;
        break;
      }
    }

    if (! hasAttributeToReplace)
    {
      return e;
    }


    // Create a copy of the entry with all appropriate attributes replaced with
    // the appropriate default versions.
    final ArrayList<Attribute> newAttributes =
         new ArrayList<Attribute>(originalAttributes.size());
    for (final Attribute a : originalAttributes)
    {
      final Attribute replacement =
           attributes.get(StaticUtils.toLowerCase(a.getBaseName()));
      if (replacement == null)
      {
        newAttributes.add(a);
      }
      else
      {
        if (a.hasOptions())
        {
          newAttributes.add(new Attribute(a.getName(), schema,
               replacement.getRawValues()));
        }
        else
        {
          newAttributes.add(replacement);
        }
      }
    }

    return new Entry(e.getDN(), schema, newAttributes);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translate(final Entry original, final long firstLineNumber)
  {
    return transformEntry(original);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Entry translateEntryToWrite(final Entry original)
  {
    return transformEntry(original);
  }
}
