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

import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an entry and LDIF change record
 * translator that will rename a specified attribute so that it uses a different
 * name.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RenameAttributeTransformation
       implements EntryTransformation, LDIFChangeRecordTransformation
{
  // Indicates whether to rename attributes in entry DNs.
  private final boolean renameInDNs;

  // The schema that will be used in processing.
  @Nullable private final Schema schema;

  // The names that will be replaced with the target name.
  @NotNull private final Set<String> baseSourceNames;

  // The target name that will be used in place of the source name.
  @NotNull private final String baseTargetName;



  /**
   * Creates a new rename attribute transformation with the provided
   * information.
   *
   * @param  schema           The schema to use in processing.  If this is
   *                          {@code null}, a default standard schema will be
   *                          used.
   * @param  sourceAttribute  The name of the source attribute to be replaced
   *                          with the name of the target attribute.  It must
   *                          not be {@code null}.
   * @param  targetAttribute  The name of the target attribute to use in place
   *                          of the source attribute.  It must not be
   *                          {@code null}.
   * @param  renameInDNs      Indicates whether to rename attributes contained
   *                          in DNs.  This includes both in the DN of an entry
   *                          to be transformed, but also in the values of
   *                          attributes with a DN syntax.
   */
  public RenameAttributeTransformation(@Nullable final Schema schema,
                                       @NotNull final String sourceAttribute,
                                       @NotNull final String targetAttribute,
                                       final boolean renameInDNs)
  {
    this.renameInDNs = renameInDNs;


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


    final HashSet<String> sourceNames =
         new HashSet<>(StaticUtils.computeMapCapacity(5));
    final String baseSourceName =
         StaticUtils.toLowerCase(Attribute.getBaseName(sourceAttribute));
    sourceNames.add(baseSourceName);

    if (s != null)
    {
      final AttributeTypeDefinition at = s.getAttributeType(baseSourceName);
      if (at != null)
      {
        sourceNames.add(StaticUtils.toLowerCase(at.getOID()));
        for (final String name : at.getNames())
        {
          sourceNames.add(StaticUtils.toLowerCase(name));
        }
      }
    }
    baseSourceNames = Collections.unmodifiableSet(sourceNames);


    baseTargetName = Attribute.getBaseName(targetAttribute);
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


    final String newDN;
    if (renameInDNs)
    {
      newDN = replaceDN(e.getDN());
    }
    else
    {
      newDN = e.getDN();
    }


    // Iterate through the attributes in the entry and make any appropriate name
    // replacements.
    final Collection<Attribute> originalAttributes = e.getAttributes();
    final ArrayList<Attribute> newAttributes =
         new ArrayList<>(originalAttributes.size());
    for (final Attribute a : originalAttributes)
    {
      // Determine if we we should rename this attribute.
      final String newName;
      final String baseName = StaticUtils.toLowerCase(a.getBaseName());
      if (baseSourceNames.contains(baseName))
      {
        if (a.hasOptions())
        {
          final StringBuilder buffer = new StringBuilder();
          buffer.append(baseTargetName);
          for (final String option : a.getOptions())
          {
            buffer.append(';');
            buffer.append(option);
          }
          newName = buffer.toString();
        }
        else
        {
          newName = baseTargetName;
        }
      }
      else
      {
        newName = a.getName();
      }


      // If we should rename attributes in entry DNs, then see if this
      // attribute has a DN syntax and if so then process its values.
      final String[] newValues;
      if (renameInDNs && (schema != null) &&
           (MatchingRule.selectEqualityMatchingRule(baseName, schema)
                instanceof DistinguishedNameMatchingRule))
      {
        final String[] originalValues = a.getValues();
        newValues = new String[originalValues.length];
        for (int i=0; i < originalValues.length; i++)
        {
          newValues[i] = replaceDN(originalValues[i]);
        }
      }
      else
      {
        newValues = a.getValues();
      }

      newAttributes.add(new Attribute(newName, schema, newValues));
    }

    return new Entry(newDN, newAttributes);
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


    if (r instanceof LDIFAddChangeRecord)
    {
      // Just use the same processing as for an entry.
      final LDIFAddChangeRecord addRecord = (LDIFAddChangeRecord) r;
      return new LDIFAddChangeRecord(transformEntry(
           addRecord.getEntryToAdd()), addRecord.getControls());
    }
    if (r instanceof LDIFDeleteChangeRecord)
    {
      if (renameInDNs)
      {
        return new LDIFDeleteChangeRecord(replaceDN(r.getDN()),
             r.getControls());
      }
      else
      {
        return r;
      }
    }
    else if (r instanceof LDIFModifyChangeRecord)
    {
      // Determine the new DN for the change record.
      final String newDN;
      final LDIFModifyChangeRecord modRecord = (LDIFModifyChangeRecord) r;
      if (renameInDNs)
      {
        newDN = replaceDN(modRecord.getDN());
      }
      else
      {
        newDN = modRecord.getDN();
      }


      // Iterate through the attributes and perform the appropriate rename
      // processing
      final Modification[] originalMods = modRecord.getModifications();
      final Modification[] newMods = new Modification[originalMods.length];
      for (int i=0; i < originalMods.length; i++)
      {
        final String newName;
        final Modification m = originalMods[i];
        final String baseName = StaticUtils.toLowerCase(
             Attribute.getBaseName(m.getAttributeName()));
        if (baseSourceNames.contains(baseName))
        {
          final Set<String> options =
               Attribute.getOptions(m.getAttributeName());
          if (options.isEmpty())
          {
            newName = baseTargetName;
          }
          else
          {
            final StringBuilder buffer = new StringBuilder();
            buffer.append(baseTargetName);
            for (final String option : options)
            {
              buffer.append(';');
              buffer.append(option);
            }
            newName = buffer.toString();
          }
        }
        else
        {
          newName = m.getAttributeName();
        }

        final String[] newValues;
        if (renameInDNs && (schema != null) &&
             (MatchingRule.selectEqualityMatchingRule(baseName, schema)
                  instanceof DistinguishedNameMatchingRule))
        {
          final String[] originalValues = m.getValues();
          newValues = new String[originalValues.length];
          for (int j=0; j < originalValues.length; j++)
          {
            newValues[j] = replaceDN(originalValues[j]);
          }
        }
        else
        {
          newValues = m.getValues();
        }

        newMods[i] = new Modification(m.getModificationType(), newName,
             newValues);
      }

      return new LDIFModifyChangeRecord(newDN, newMods,
           modRecord.getControls());
    }
    else if (r instanceof LDIFModifyDNChangeRecord)
    {
      if (renameInDNs)
      {
        final LDIFModifyDNChangeRecord modDNRecord =
             (LDIFModifyDNChangeRecord) r;
        return new LDIFModifyDNChangeRecord(replaceDN(modDNRecord.getDN()),
             replaceDN(modDNRecord.getNewRDN()), modDNRecord.deleteOldRDN(),
             replaceDN(modDNRecord.getNewSuperiorDN()),
             modDNRecord.getControls());
      }
      else
      {
        return r;
      }
    }
    else
    {
      // This should never happen.
      return r;
    }
  }



  /**
   * Makes any appropriate attribute replacements in the provided DN.
   *
   * @param  dn  The DN to process.
   *
   * @return  The DN with any appropriate replacements.
   */
  @NotNull()
  private String replaceDN(@NotNull final String dn)
  {
    try
    {
      final DN parsedDN = new DN(dn);
      final RDN[] originalRDNs = parsedDN.getRDNs();
      final RDN[] newRDNs = new RDN[originalRDNs.length];
      for (int i=0; i < originalRDNs.length; i++)
      {
        final String[] originalNames = originalRDNs[i].getAttributeNames();
        final String[] newNames = new String[originalNames.length];
        for (int j=0; j < originalNames.length; j++)
        {
          if (baseSourceNames.contains(
               StaticUtils.toLowerCase(originalNames[j])))
          {
            newNames[j] = baseTargetName;
          }
          else
          {
            newNames[j] = originalNames[j];
          }
        }
        newRDNs[i] =
             new RDN(newNames, originalRDNs[i].getByteArrayAttributeValues());
      }

      return new DN(newRDNs).toString();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return dn;
    }
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
