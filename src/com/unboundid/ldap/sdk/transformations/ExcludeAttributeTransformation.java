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

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an entry and LDIF change record
 * transformation that will remove a specified set of attributes from entries
 * or change records.  Note that this transformation will not alter entry DNs,
 * so if an attribute to exclude is included in an entry's DN, that value will
 * still be visible in the DN even if it is removed from the set of attributes
 * in the entry.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExcludeAttributeTransformation
       implements EntryTransformation, LDIFChangeRecordTransformation
{
  // The schema to use when processing.
  @Nullable private final Schema schema;

  // The set of attributes to exclude from entries.
  @NotNull private final Set<String> attributes;



  /**
   * Creates a new exclude attribute transformation that will strip the
   * specified attributes out of entries and change records.
   *
   * @param  schema      The scheme to use to identify alternate names that
   *                     may be used to reference the attributes to exclude from
   *                     entries.  It may be {@code null} to use a default
   *                     standard schema.
   * @param  attributes  The names of the attributes to strip from entries and
   *                     change records.  It must not be {@code null} or empty.
   */
  public ExcludeAttributeTransformation(@Nullable final Schema schema,
                                        @NotNull final String... attributes)
  {
    this(schema, StaticUtils.toList(attributes));
  }



  /**
   * Creates a new exclude attribute transformation that will strip the
   * specified attributes out of entries and change records.
   *
   * @param  schema      The scheme to use to identify alternate names that
   *                     may be used to reference the attributes to exclude from
   *                     entries.  It may be {@code null} to use a default
   *                     standard schema.
   * @param  attributes  The names of the attributes to strip from entries and
   *                     change records.  It must not be {@code null} or empty.
   */
  public ExcludeAttributeTransformation(@Nullable final Schema schema,
              @NotNull final Collection<String> attributes)
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
    // to suppress.
    final HashSet<String> attrNames =
         new HashSet<>(StaticUtils.computeMapCapacity(3*attributes.size()));
    for (final String attrName : attributes)
    {
      final String baseName =
           Attribute.getBaseName(StaticUtils.toLowerCase(attrName));
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
    }
    this.attributes = Collections.unmodifiableSet(attrNames);
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


    // First, see if the entry has any of the target attributes.  If not, we can
    // just return the provided entry.
    boolean hasAttributeToRemove = false;
    final Collection<Attribute> originalAttributes = e.getAttributes();
    for (final Attribute a : originalAttributes)
    {
      if (attributes.contains(StaticUtils.toLowerCase(a.getBaseName())))
      {
        hasAttributeToRemove = true;
        break;
      }
    }

    if (! hasAttributeToRemove)
    {
      return e;
    }


    // Create a copy of the entry with all appropriate attributes removed.
    final ArrayList<Attribute> attributesToKeep =
         new ArrayList<>(originalAttributes.size());
    for (final Attribute a : originalAttributes)
    {
      if (! attributes.contains(StaticUtils.toLowerCase(a.getBaseName())))
      {
        attributesToKeep.add(a);
      }
    }

    return new Entry(e.getDN(), schema, attributesToKeep);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDIFChangeRecord transformChangeRecord(
                               @NotNull final LDIFChangeRecord r)
  {
    if (r == null)
    {
      return null;
    }


    // If it's an add change record, then just use the same processing as for an
    // entry, except we will suppress the entire change record if all of the
    // attributes end up getting suppressed.
    if (r instanceof LDIFAddChangeRecord)
    {
      final LDIFAddChangeRecord addRecord = (LDIFAddChangeRecord) r;
      final Entry updatedEntry = transformEntry(addRecord.getEntryToAdd());
      if (updatedEntry.getAttributes().isEmpty())
      {
        return null;
      }

      return new LDIFAddChangeRecord(updatedEntry, addRecord.getControls());
    }


    // If it's a modify change record, then suppress all modifications targeting
    // any of the appropriate attributes.  If there are no more modifications
    // left, then suppress the entire change record.
    if (r instanceof LDIFModifyChangeRecord)
    {
      final LDIFModifyChangeRecord modifyRecord = (LDIFModifyChangeRecord) r;

      final Modification[] originalMods = modifyRecord.getModifications();
      final ArrayList<Modification> modsToKeep =
           new ArrayList<>(originalMods.length);
      for (final Modification m : originalMods)
      {
        final String attrName = StaticUtils.toLowerCase(
             Attribute.getBaseName(m.getAttributeName()));
        if (! attributes.contains(attrName))
        {
          modsToKeep.add(m);
        }
      }

      if (modsToKeep.isEmpty())
      {
        return null;
      }

      return new LDIFModifyChangeRecord(modifyRecord.getDN(), modsToKeep,
           modifyRecord.getControls());
    }


    // If it's some other type of change record (which should just be delete or
    // modify DN), then don't do anything.
    return r;
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
  public LDIFChangeRecord translate(@NotNull final LDIFChangeRecord original,
                                    final long firstLineNumber)
  {
    return transformChangeRecord(original);
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



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public LDIFChangeRecord translateChangeRecordToWrite(
                               @NotNull final LDIFChangeRecord original)
  {
    return transformChangeRecord(original);
  }
}
