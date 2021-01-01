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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an entry transformation that will
 * alter DNs below a specified base DN to ensure that they are exactly one level
 * below the specified base DN.  This can be useful when migrating data
 * containing a large number of branches into a flat DIT with all of the entries
 * below a common parent.
 * <BR><BR>
 * Only entries that were previously more than one level below the base DN will
 * be renamed.  The DN of the base entry itself will be unchanged, as well as
 * the DNs of entries outside of the specified base DN.
 * <BR><BR>
 * For any entries that were originally more than one level below the specified
 * base DN, any RDNs that were omitted may optionally be added as
 * attributes to the updated entry.  For example, if the flatten base DN is
 * "ou=People,dc=example,dc=com" and an entry is encountered with a DN of
 * "uid=john.doe,ou=East,ou=People,dc=example,dc=com", the resulting DN would
 * be "uid=john.doe,ou=People,dc=example,dc=com" and the entry may optionally be
 * updated to include an "ou" attribute with a value of "East".
 * <BR><BR>
 * Alternately, the attribute-value pairs from any omitted RDNs may be added to
 * the resulting entry's RDN, making it a multivalued RDN if necessary.  Using
 * the example above, this means that the resulting DN could be
 * "uid=john.doe+ou=East,ou=People,dc=example,dc=com".  This can help avoid the
 * potential for naming conflicts if entries exist with the same RDN in
 * different branches.
 * <BR><BR>
 * This transformation will also be applied to DNs used as attribute values in
 * the entries to be processed.  All attributes in all entries (regardless of
 * location in the DIT) will be examined, and any value that is a DN will have
 * the same flattening transformation described above applied to it.  The
 * processing will be applied to any entry anywhere in the DIT, but will only
 * affect values that represent DNs below the flatten base DN.
 * <BR><BR>
 * In many cases, when flattening a DIT with a large number of branches, the
 * non-leaf entries below the flatten base DN are often simple container entries
 * like organizationalUnit entries without any real attributes.  In those cases,
 * those container entries may no longer be necessary in the flattened DIT, and
 * it may be desirable to eliminate them.  To address that, it is possible to
 * provide a filter that can be used to identify these entries so that they can
 * be excluded from the resulting LDIF output.  Note that only entries below the
 * flatten base DN may be excluded by this transformation.  Any entry at or
 * outside the specified base DN that matches the filter will be preserved.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class FlattenSubtreeTransformation
       implements EntryTransformation, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5500436195237056110L;



  // Indicates whether the attribute-value pairs from any omitted RDNs should be
  // added to any entries that are updated.
  private final boolean addOmittedRDNAttributesToEntry;

  // Indicates whether the RDN of the attribute-value pairs from any omitted
  // RDNs should be added into the RDN for any entries that are updated.
  private final boolean addOmittedRDNAttributesToRDN;

  // The base DN below which to flatten the DIT.
  @NotNull  private final DN flattenBaseDN;

  // A filter that can be used to identify which entries to exclude.
  @Nullable private final Filter excludeFilter;

  // The RDNs that comprise the flatten base DN.
  @NotNull private final RDN[] flattenBaseRDNs;

  // The schema to use when processing.
  @Nullable private final Schema schema;



  /**
   * Creates a new instance of this transformation with the provided
   * information.
   *
   * @param  schema                          The schema to use in processing.
   *                                         It may be {@code null} if a default
   *                                         standard schema should be used.
   * @param  flattenBaseDN                   The base DN below which any
   *                                         flattening will be performed.  In
   *                                         the transformed data, all entries
   *                                         below this base DN will be exactly
   *                                         one level below this base DN.  It
   *                                         must not be {@code null}.
   * @param  addOmittedRDNAttributesToEntry  Indicates whether to add the
   *                                         attribute-value pairs of any RDNs
   *                                         stripped out of DNs during the
   *                                         course of flattening the DIT should
   *                                         be added as attribute values in the
   *                                         target entry.
   * @param  addOmittedRDNAttributesToRDN    Indicates whether to add the
   *                                         attribute-value pairs of any RDNs
   *                                         stripped out of DNs during the
   *                                         course of flattening the DIT should
   *                                         be added as additional values in
   *                                         the RDN of the target entry (so the
   *                                         resulting DN will have a
   *                                         multivalued RDN with all of the
   *                                         attribute-value pairs of the
   *                                         original RDN, plus all
   *                                         attribute-value pairs from any
   *                                         omitted RDNs).
   * @param  excludeFilter                   An optional filter that may be used
   *                                         to exclude entries during the
   *                                         flattening process.  If this is
   *                                         non-{@code null}, then any entry
   *                                         below the flatten base DN that
   *                                         matches this filter will be
   *                                         excluded from the results rather
   *                                         than flattened.  This can be used
   *                                         to strip out "container" entries
   *                                         that were simply used to add levels
   *                                         of hierarchy in the previous
   *                                         branched DN that are no longer
   *                                         needed in the flattened
   *                                         representation of the DIT.
   */
  public FlattenSubtreeTransformation(@Nullable final Schema schema,
              @NotNull final DN flattenBaseDN,
              final boolean addOmittedRDNAttributesToEntry,
              final boolean addOmittedRDNAttributesToRDN,
              @Nullable final Filter excludeFilter)
  {
    this.flattenBaseDN                  = flattenBaseDN;
    this.addOmittedRDNAttributesToEntry = addOmittedRDNAttributesToEntry;
    this.addOmittedRDNAttributesToRDN   = addOmittedRDNAttributesToRDN;
    this.excludeFilter                  = excludeFilter;

    flattenBaseRDNs = flattenBaseDN.getRDNs();


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
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public Entry transformEntry(@NotNull final Entry e)
  {
    // If the provided entry was null, then just return null.
    if (e == null)
    {
      return null;
    }


    // Get a parsed representation of the entry's DN.  If we can't parse the DN
    // for some reason, then leave it unaltered.  If we can parse it, then
    // perform any appropriate transformation.
    DN newDN = null;
    LinkedHashSet<ObjectPair<String,String>> omittedRDNValues = null;
    try
    {
      final DN dn = e.getParsedDN();

      if (dn.isDescendantOf(flattenBaseDN, false))
      {
        // If the entry matches the exclude filter, then return null to indicate
        // that the entry should be omitted from the results.
        try
        {
          if ((excludeFilter != null) && excludeFilter.matchesEntry(e))
          {
            return null;
          }
        }
        catch (final Exception ex)
        {
          Debug.debugException(ex);
        }


        // If appropriate allocate a set to hold omitted RDN values.
        if (addOmittedRDNAttributesToEntry || addOmittedRDNAttributesToRDN)
        {
          omittedRDNValues =
               new LinkedHashSet<>(StaticUtils.computeMapCapacity(5));
        }


        // Transform the parsed DN.
        newDN = transformDN(dn, omittedRDNValues);
      }
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);
      return e;
    }


    // Iterate through the attributes and apply any appropriate transformations.
    // If the resulting RDN should reflect any omitted RDNs, then create a
    // temporary set to use to hold the RDN values omitted from attribute
    // values.
    final Collection<Attribute> originalAttributes = e.getAttributes();
    final ArrayList<Attribute> newAttributes =
         new ArrayList<>(originalAttributes.size());

    final LinkedHashSet<ObjectPair<String,String>> tempOmittedRDNValues;
    if (addOmittedRDNAttributesToRDN)
    {
      tempOmittedRDNValues =
           new LinkedHashSet<>(StaticUtils.computeMapCapacity(5));
    }
    else
    {
      tempOmittedRDNValues = null;
    }

    for (final Attribute a : originalAttributes)
    {
      newAttributes.add(transformAttribute(a, tempOmittedRDNValues));
    }


    // Create the new entry.
    final Entry newEntry;
    if (newDN == null)
    {
      newEntry = new Entry(e.getDN(), schema, newAttributes);
    }
    else
    {
      newEntry = new Entry(newDN, schema, newAttributes);
    }


    // If we should add omitted RDN name-value pairs to the entry, then add them
    // now.
    if (addOmittedRDNAttributesToEntry && (omittedRDNValues != null))
    {
      for (final ObjectPair<String,String> p : omittedRDNValues)
      {
        newEntry.addAttribute(
             new Attribute(p.getFirst(), schema, p.getSecond()));
      }
    }


    return newEntry;
  }



  /**
   * Applies the appropriate transformation to the provided DN.
   *
   * @param  dn                The DN to transform.  It must not be
   *                           {@code null}.
   * @param  omittedRDNValues  A set into which any omitted RDN values should be
   *                           added.  It may be {@code null} if we don't need
   *                           to collect the set of omitted RDNs.
   *
   * @return  The transformed DN, or the original DN if no alteration is
   *          necessary.
   */
  @NotNull()
  private DN transformDN(@NotNull final DN dn,
       @Nullable final Set<ObjectPair<String,String>> omittedRDNValues)
  {
    // Get the number of RDNs to omit.  If we shouldn't omit any, then return
    // the provided DN without alterations.
    final RDN[] originalRDNs = dn.getRDNs();
    final int numRDNsToOmit = originalRDNs.length - flattenBaseRDNs.length - 1;
    if (numRDNsToOmit == 0)
    {
      return dn;
    }


    // Construct an array of the new RDNs to use for the entry.
    final RDN[] newRDNs = new RDN[flattenBaseRDNs.length + 1];
    System.arraycopy(flattenBaseRDNs, 0, newRDNs, 1, flattenBaseRDNs.length);


    // If necessary, get the name-value pairs for the omitted RDNs and construct
    // the new RDN.  Otherwise, just preserve the original RDN.
    if (omittedRDNValues == null)
    {
      newRDNs[0] = originalRDNs[0];
    }
    else
    {
      for (int i=1; i <= numRDNsToOmit; i++)
      {
        final String[] names  = originalRDNs[i].getAttributeNames();
        final String[] values = originalRDNs[i].getAttributeValues();
        for (int j=0; j < names.length; j++)
        {
          omittedRDNValues.add(new ObjectPair<>(names[j], values[j]));
        }
      }

      // Just in case the entry's original RDN has one or more name-value pairs
      // as some of the omitted RDNs, remove those values from the set.
      final String[] origNames  = originalRDNs[0].getAttributeNames();
      final String[] origValues = originalRDNs[0].getAttributeValues();
      for (int i=0; i < origNames.length; i++)
      {
        omittedRDNValues.remove(new ObjectPair<>(origNames[i], origValues[i]));
      }

      // If we should include omitted RDN values in the new RDN, then construct
      // a new RDN for the entry.  Otherwise, preserve the original RDN.
      if (addOmittedRDNAttributesToRDN)
      {
        final String[] originalRDNNames  = originalRDNs[0].getAttributeNames();
        final String[] originalRDNValues = originalRDNs[0].getAttributeValues();

        final String[] newRDNNames =
             new String[originalRDNNames.length + omittedRDNValues.size()];
        final String[] newRDNValues = new String[newRDNNames.length];

        int i=0;
        for (int j=0; j < originalRDNNames.length; j++)
        {
          newRDNNames[i]  = originalRDNNames[i];
          newRDNValues[i] = originalRDNValues[i];
          i++;
        }

        for (final ObjectPair<String,String> p : omittedRDNValues)
        {
          newRDNNames[i]  = p.getFirst();
          newRDNValues[i] = p.getSecond();
          i++;
        }

        newRDNs[0] = new RDN(newRDNNames, newRDNValues, schema);
      }
      else
      {
        newRDNs[0] = originalRDNs[0];
      }
    }

    return new DN(newRDNs);
  }



  /**
   * Applies the appropriate transformation to any values of the provided
   * attribute that represent DNs.
   *
   * @param  a                 The attribute to transform.  It must not be
   *                           {@code null}.
   * @param  omittedRDNValues  A set into which any omitted RDN values should be
   *                           added.  It may be {@code null} if we don't need
   *                           to collect the set of omitted RDNs.
   *
   * @return  The transformed attribute, or the original attribute if no
   *          alteration is necessary.
   */
  @NotNull()
  private Attribute transformAttribute(@NotNull final Attribute a,
       @Nullable final Set<ObjectPair<String,String>> omittedRDNValues)
  {
    // Assume that the attribute doesn't have any values that are DNs, and that
    // we won't need to create a new attribute.  This should be the common case.
    // Also, even if the attribute has one or more DNs, we don't need to do
    // anything for values that aren't below the flatten base DN.
    boolean hasTransformableDN = false;
    final String[] values = a.getValues();
    for (final String value : values)
    {
      try
      {
        final DN dn = new DN(value);
        if (dn.isDescendantOf(flattenBaseDN, false))
        {
          hasTransformableDN = true;
          break;
        }
      }
      catch (final Exception e)
      {
        // This is the common case.  We shouldn't even debug this.
      }
    }

    if (! hasTransformableDN)
    {
      return a;
    }


    // If we've gotten here, then we know that the attribute has at least one
    // value to be transformed.
    final String[] newValues = new String[values.length];
    for (int i=0; i < values.length; i++)
    {
      try
      {
        final DN dn = new DN(values[i]);
        if (dn.isDescendantOf(flattenBaseDN, false))
        {
          if (omittedRDNValues != null)
          {
            omittedRDNValues.clear();
          }
          newValues[i] = transformDN(dn, omittedRDNValues).toString();
        }
        else
        {
          newValues[i] = values[i];
        }
      }
      catch (final Exception e)
      {
        // Even if some values are DNs, there may be values that aren't.  Don't
        // worry about this.  Just use the existing value without alteration.
        newValues[i] = values[i];
      }
    }

    return new Attribute(a.getName(), schema, newValues);
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
