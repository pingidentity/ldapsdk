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

import com.unboundid.asn1.ASN1OctetString;
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
 * transformation that will redact the values of a specified set of attributes
 * so that it will be possible to determine whether the attribute had been
 * present in an entry or change record, but not what the values were for that
 * attribute.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RedactAttributeTransformation
       implements EntryTransformation, LDIFChangeRecordTransformation
{
  // Indicates whether to preserve the number of values in redacted attributes.
  private final boolean preserveValueCount;

  // Indicates whether to redact
  private final boolean redactDNAttributes;

  // The schema to use when processing.
  @Nullable private final Schema schema;

  // The set of attributes to strip from entries.
  @NotNull private final Set<String> attributes;



  /**
   * Creates a new redact attribute transformation that will redact the values
   * of the specified attributes.
   *
   * @param  schema              The schema to use to identify alternate names
   *                             that may be used to reference the attributes to
   *                             redact.  It may be {@code null} to use a
   *                             default standard schema.
   * @param  redactDNAttributes  Indicates whether to redact values of the
   *                             target attributes that appear in DNs.  This
   *                             includes the DNs of the entries to process as
   *                             well as the values of attributes with a DN
   *                             syntax.
   * @param  preserveValueCount  Indicates whether to preserve the number of
   *                             values in redacted attributes.  If this is
   *                             {@code true}, then multivalued attributes that
   *                             are redacted will have the same number of
   *                             values but each value will be replaced with
   *                             "***REDACTED{num}***" where "{num}" is a
   *                             counter that increments for each value.  If
   *                             this is {@code false}, then the set of values
   *                             will always be replaced with a single value of
   *                             "***REDACTED***" regardless of whether the
   *                             original attribute had one or multiple values.
   * @param  attributes          The names of the attributes whose values should
   *                             be redacted.  It must must not be {@code null}
   *                             or empty.
   */
  public RedactAttributeTransformation(@Nullable final Schema schema,
                                       final boolean redactDNAttributes,
                                       final boolean preserveValueCount,
                                       @NotNull final String... attributes)
  {
    this(schema, redactDNAttributes, preserveValueCount,
         StaticUtils.toList(attributes));
  }



  /**
   * Creates a new redact attribute transformation that will redact the values
   * of the specified attributes.
   *
   * @param  schema              The schema to use to identify alternate names
   *                             that may be used to reference the attributes to
   *                             redact.  It may be {@code null} to use a
   *                             default standard schema.
   * @param  redactDNAttributes  Indicates whether to redact values of the
   *                             target attributes that appear in DNs.  This
   *                             includes the DNs of the entries to process as
   *                             well as the values of attributes with a DN
   *                             syntax.
   * @param  preserveValueCount  Indicates whether to preserve the number of
   *                             values in redacted attributes.  If this is
   *                             {@code true}, then multivalued attributes that
   *                             are redacted will have the same number of
   *                             values but each value will be replaced with
   *                             "***REDACTED{num}***" where "{num}" is a
   *                             counter that increments for each value.  If
   *                             this is {@code false}, then the set of values
   *                             will always be replaced with a single value of
   *                             "***REDACTED***" regardless of whether the
   *                             original attribute had one or multiple values.
   * @param  attributes          The names of the attributes whose values should
   *                             be redacted.  It must must not be {@code null}
   *                             or empty.
   */
  public RedactAttributeTransformation(@Nullable final Schema schema,
              final boolean redactDNAttributes,
              final boolean preserveValueCount,
              @NotNull  final Collection<String> attributes)
  {
    this.redactDNAttributes = redactDNAttributes;
    this.preserveValueCount = preserveValueCount;

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
    // to redact.
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


    // If we should process entry DNs, then see if the DN contains any of the
    // target attributes.
    final String newDN;
    if (redactDNAttributes)
    {
      newDN = redactDN(e.getDN());
    }
    else
    {
      newDN = e.getDN();
    }


    // Create a copy of the entry with all appropriate attributes redacted.
    final Collection<Attribute> originalAttributes = e.getAttributes();
    final ArrayList<Attribute> newAttributes =
         new ArrayList<>(originalAttributes.size());
    for (final Attribute a : originalAttributes)
    {
      final String baseName = StaticUtils.toLowerCase(a.getBaseName());
      if (attributes.contains(baseName))
      {
        if (preserveValueCount && (a.size() > 1))
        {
          final ASN1OctetString[] values = new ASN1OctetString[a.size()];
          for (int i=0; i < values.length; i++)
          {
            values[i] = new ASN1OctetString("***REDACTED" + (i+1) + "***");
          }
          newAttributes.add(new Attribute(a.getName(), values));
        }
        else
        {
          newAttributes.add(new Attribute(a.getName(), "***REDACTED***"));
        }
      }
      else if (redactDNAttributes && (schema != null) &&
           (MatchingRule.selectEqualityMatchingRule(baseName, schema)
                instanceof DistinguishedNameMatchingRule))
      {

        final String[] originalValues = a.getValues();
        final String[] newValues = new String[originalValues.length];
        for (int i=0; i < originalValues.length; i++)
        {
          newValues[i] = redactDN(originalValues[i]);
        }
        newAttributes.add(new Attribute(a.getName(), schema, newValues));
      }
      else
      {
        newAttributes.add(a);
      }
    }

    return new Entry(newDN, schema, newAttributes);
  }



  /**
   * Applies any appropriate redaction to the provided DN.
   *
   * @param  dn  The DN for which to apply any appropriate redaction.
   *
   * @return  The DN with any appropriate redaction applied.
   */
  @Nullable()
  private String redactDN(@Nullable final String dn)
  {
    if (dn == null)
    {
      return null;
    }

    try
    {
      boolean changeApplied = false;
      final RDN[] originalRDNs = new DN(dn).getRDNs();
      final RDN[] newRDNs = new RDN[originalRDNs.length];
      for (int i=0; i < originalRDNs.length; i++)
      {
        final String[] names = originalRDNs[i].getAttributeNames();
        final String[] originalValues = originalRDNs[i].getAttributeValues();
        final String[] newValues = new String[originalValues.length];
        for (int j=0; j < names.length; j++)
        {
          if (attributes.contains(StaticUtils.toLowerCase(names[j])))
          {
            changeApplied = true;
            newValues[j] = "***REDACTED***";
          }
          else
          {
            newValues[j] = originalValues[j];
          }
        }
        newRDNs[i] = new RDN(names, newValues, schema);
      }

      if (changeApplied)
      {
        return new DN(newRDNs).toString();
      }
      else
      {
        return dn;
      }
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
  public LDIFChangeRecord transformChangeRecord(
                               @NotNull final LDIFChangeRecord r)
  {
    if (r == null)
    {
      return null;
    }


    // If it's an add change record, then just use the same processing as for an
    // entry.
    if (r instanceof LDIFAddChangeRecord)
    {
      final LDIFAddChangeRecord addRecord = (LDIFAddChangeRecord) r;
      return new LDIFAddChangeRecord(transformEntry(addRecord.getEntryToAdd()),
           addRecord.getControls());
    }


    // If it's a delete change record, then see if the DN contains anything
    // that we might need to redact.
    if (r instanceof LDIFDeleteChangeRecord)
    {
      if (redactDNAttributes)
      {
        final LDIFDeleteChangeRecord deleteRecord = (LDIFDeleteChangeRecord) r;
        return new LDIFDeleteChangeRecord(redactDN(deleteRecord.getDN()),
             deleteRecord.getControls());
      }
      else
      {
        return r;
      }
    }


    // If it's a modify change record, then redact all appropriate values.
    if (r instanceof LDIFModifyChangeRecord)
    {
      final LDIFModifyChangeRecord modifyRecord = (LDIFModifyChangeRecord) r;

      final String newDN;
      if (redactDNAttributes)
      {
        newDN = redactDN(modifyRecord.getDN());
      }
      else
      {
        newDN = modifyRecord.getDN();
      }

      final Modification[] originalMods = modifyRecord.getModifications();
      final Modification[] newMods = new Modification[originalMods.length];

      for (int i=0; i < originalMods.length; i++)
      {
        // If the modification doesn't have any values, then just use the
        // original modification.
        final Modification m = originalMods[i];
        if (! m.hasValue())
        {
          newMods[i] = m;
          continue;
        }


        // See if the modification targets an attribute that we should redact.
        // If not, then see if the attribute has a DN syntax.
        final String attrName = StaticUtils.toLowerCase(
             Attribute.getBaseName(m.getAttributeName()));
        if (! attributes.contains(attrName))
        {
          if (redactDNAttributes && (schema != null) &&
               (MatchingRule.selectEqualityMatchingRule(attrName, schema)
                instanceof DistinguishedNameMatchingRule))
          {
            final String[] originalValues = m.getValues();
            final String[] newValues = new String[originalValues.length];
            for (int j=0; j < originalValues.length; j++)
            {
              newValues[j] = redactDN(originalValues[j]);
            }
            newMods[i] = new Modification(m.getModificationType(),
                 m.getAttributeName(), newValues);
          }
          else
          {
            newMods[i] = m;
          }
          continue;
        }


        // Get the original values.  If there's only one of them, or if we
        // shouldn't preserve the original number of values, then just create a
        // modification with a single value.  Otherwise, create a modification
        // with the appropriate number of values.
        final ASN1OctetString[] originalValues = m.getRawValues();
        if (preserveValueCount && (originalValues.length > 1))
        {
          final ASN1OctetString[] newValues =
               new ASN1OctetString[originalValues.length];
          for (int j=0; j < originalValues.length; j++)
          {
            newValues[j] = new ASN1OctetString("***REDACTED" + (j+1) + "***");
          }
          newMods[i] = new Modification(m.getModificationType(),
               m.getAttributeName(), newValues);
        }
        else
        {
          newMods[i] = new Modification(m.getModificationType(),
               m.getAttributeName(), "***REDACTED***");
        }
      }

      return new LDIFModifyChangeRecord(newDN, newMods,
           modifyRecord.getControls());
    }


    // If it's a modify DN change record, then see if the DN, new RDN, or new
    // superior DN contain anything that we might need to redact.
    if (r instanceof LDIFModifyDNChangeRecord)
    {
      if (redactDNAttributes)
      {
        final LDIFModifyDNChangeRecord modDNRecord =
             (LDIFModifyDNChangeRecord) r;
        return new LDIFModifyDNChangeRecord(redactDN(modDNRecord.getDN()),
             redactDN(modDNRecord.getNewRDN()), modDNRecord.deleteOldRDN(),
             redactDN(modDNRecord.getNewSuperiorDN()),
             modDNRecord.getControls());
      }
      else
      {
        return r;
      }
    }


    // We should never get here.
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
