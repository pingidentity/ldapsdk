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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.security.MessageDigest;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an implementation of an LDIF reader entry translator that
 * can be used to determine the set into which an entry should be placed by
 * computing a modulus from a digest of a specified attribute.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class SplitLDIFAttributeHashTranslator
      extends SplitLDIFTranslator
{
  // Indicates whether to use all values for the specified attribute in the
  // course of selecting the appropriate set.
  private final boolean useAllValues;

  // The map used to cache decisions made by this translator.
  @Nullable private final ConcurrentHashMap<String,Set<String>> rdnCache;

  // A map of the names that will be used for each of the sets.
  @NotNull private final Map<Integer,Set<String>> setNames;

  // The sets in which entries outside the split base should be placed.
  @NotNull private final Set<String> outsideSplitBaseSetNames;

  // The sets in which the split base entry should be placed.
  @NotNull private final Set<String> splitBaseEntrySetNames;

  // The name of the attribute for which to compute the digest.
  @NotNull private final String attributeName;



  /**
   * Creates a new instance of this translator with the provided information.
   *
   * @param  splitBaseDN                           The base DN below which to
   *                                               split entries.
   * @param  numSets                               The number of sets into which
   *                                               entries should be split.
   * @param  attributeName                         The name of the attribute for
   *                                               which to compute the hash.
   * @param  useAllValues                          Indicates whether to use all
   *                                               values for the target
   *                                               attribute rather than just
   *                                               the first.
   * @param  assumeFlatDIT                         Indicates whether to assume
   *                                               that the DIT is flat, and
   *                                               there aren't any entries more
   *                                               than one level below the
   *                                               split base DN.  If this is
   *                                               {@code true}, then any
   *                                               entries more than one level
   *                                               below the split base DN will
   *                                               be considered an error.
   * @param  addEntriesOutsideSplitToAllSets       Indicates whether entries
   *                                               outside the split should be
   *                                               added to all sets.
   * @param  addEntriesOutsideSplitToDedicatedSet  Indicates whether entries
   *                                               outside the split should be
   *                                               added to all sets.
   */
  SplitLDIFAttributeHashTranslator(@NotNull final DN splitBaseDN,
       final int numSets,
       @NotNull final String attributeName,
       final boolean useAllValues,
       final boolean assumeFlatDIT,
       final boolean addEntriesOutsideSplitToAllSets,
       final boolean addEntriesOutsideSplitToDedicatedSet)
  {
    super(splitBaseDN);

    this.attributeName = attributeName;
    this.useAllValues = useAllValues;

    if (assumeFlatDIT)
    {
      rdnCache = null;
    }
    else
    {
      rdnCache = new ConcurrentHashMap<>(StaticUtils.computeMapCapacity(100));
    }

    outsideSplitBaseSetNames =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(numSets+1));
    splitBaseEntrySetNames =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(numSets));

    if (addEntriesOutsideSplitToDedicatedSet)
    {
      outsideSplitBaseSetNames.add(SplitLDIFEntry.SET_NAME_OUTSIDE_SPLIT);
    }

    setNames = new LinkedHashMap<>(StaticUtils.computeMapCapacity(numSets));
    for (int i=0; i < numSets; i++)
    {
      final String setName = ".set" + (i+1);

      setNames.put(i, Collections.singleton(setName));
      splitBaseEntrySetNames.add(setName);

      if (addEntriesOutsideSplitToAllSets)
      {
        outsideSplitBaseSetNames.add(setName);
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SplitLDIFEntry translate(@NotNull final Entry original,
                                  final long firstLineNumber)
         throws LDIFException
  {
    // Get the parsed DN for the entry.  If we can't, that's an error and we
    // should only include it in the error set.
    final DN dn;
    try
    {
      dn = original.getParsedDN();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return createEntry(original,
           ERR_SPLIT_LDIF_ATTR_HASH_TRANSLATOR_CANNOT_PARSE_DN.get(
                le.getMessage()),
           getErrorSetNames());
    }


    // If the parsed DN is outside the split base DN, then return the
    // appropriate sets for that.
    if (! dn.isDescendantOf(getSplitBaseDN(), true))
    {
      return createEntry(original, outsideSplitBaseSetNames);
    }


    // If the parsed DN matches the split base DN, then it will always go into
    // all of the split sets.
    if (dn.equals(getSplitBaseDN()))
    {
      return createEntry(original, splitBaseEntrySetNames);
    }


    // Determine which RDN component is immediately below the split base DN and
    // get its normalized string representation.
    final RDN[] rdns = dn.getRDNs();
    final int targetRDNIndex = rdns.length - getSplitBaseRDNs().length - 1;
    final String normalizedRDNString =
         rdns[targetRDNIndex].toNormalizedString();


    // If the target RDN component is not the first component of the DN, then
    // we'll use the cache to send this entry to the same set as its parent.
    if (targetRDNIndex > 0)
    {
      // If we aren't maintaining an RDN cache (which should only happen if
      // the --assumeFlatDIT argument was provided), then this is an error.
      if (rdnCache == null)
      {
        return createEntry(original,
             ERR_SPLIT_LDIF_ATTR_HASH_TRANSLATOR_NON_FLAT_DIT.get(
                  getSplitBaseDN().toString()),
             getErrorSetNames());
      }

      // Note that even if we are maintaining an RDN cache, it may not contain
      // the information that we need to determine which set should hold this
      // entry.  There are two reasons for this:
      //
      // - The LDIF file contains an entry below the split base DN without
      //   including the parent for that entry, (or includes a child entry
      //   before its parent).
      //
      // - We are processing multiple entries in parallel, and the parent entry
      //   is currently being processed in another thread and that thread hasn't
      //   yet made the determination as to which set should be used for that
      //   parent entry.
      //
      // In either case, use null for the target set names.  If we are in the
      // parallel processing phase, then we will re-invoke this method later
      // at a point in which we can be confident that the caching should have
      // been performed  If we still get null the second time through, then
      // the caller will consider that an error and handle it appropriately.
      return createEntry(original, rdnCache.get(normalizedRDNString));
    }


    // At this point, we know that the entry is exactly one level below the
    // split base DN, and we're going to need to generate an MD5 digest of
    // something (preferably one or more values for the target attribute, but
    // if not then the normalized RDN).  Get an MD5 digest generator.
    final MessageDigest md5Digest;
    try
    {
      md5Digest = getMD5();
      md5Digest.reset();
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      return createEntry(original,
           ERR_SPLIT_LDIF_TRANSLATOR_CANNOT_GET_MD5.get(
                StaticUtils.getExceptionMessage(e)),
           getErrorSetNames());
    }


    // Try to compute the digest based on the target attribute.  If we can't
    // do that for some reason, then fall back to computing it based on the
    // normalized RDN.
    byte[] md5Bytes = null;
    final Attribute a = original.getAttribute(attributeName);
    if (a != null)
    {
      // We want to use the normalized representation of the attribute values,
      // so get the appropriate matching rule.
      MatchingRule mr = a.getMatchingRule();
      if (mr == null)
      {
        mr = CaseIgnoreStringMatchingRule.getInstance();
      }

      // If there are multiple values and we should use all of them, then we'll
      // need to sort the values to ensure that the order in which they appear
      // in the entry won't affect the checksum.
      if (useAllValues && (a.size() > 1))
      {
        try
        {
          final TreeSet<String> sortedValues = new TreeSet<>();
          for (final ASN1OctetString value : a.getRawValues())
          {
            sortedValues.add(mr.normalize(value).stringValue());
          }

          for (final String value : sortedValues)
          {
            md5Digest.update(StaticUtils.getBytes(value));
          }

          md5Bytes = md5Digest.digest();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
      else if (a.size() != 0)
      {
        try
        {
          md5Bytes =
               md5Digest.digest(mr.normalize(a.getRawValues()[0]).getValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    if (md5Bytes == null)
    {
      md5Bytes = md5Digest.digest(StaticUtils.getBytes(normalizedRDNString));
    }


    // Use the first four bytes of the MD5 digest to compute an integer checksum
    // (but don't use the most significant bit of the first byte to avoid the
    // possibility of a negative number).  Then use a modulus operation to
    // convert that checksum into a value that we can use to get the
    // corresponding set names.
    final int checksum =
         ((md5Bytes[0] & 0x7F) << 24) |
         ((md5Bytes[1] & 0xFF) << 16) |
         ((md5Bytes[2] & 0xFF) << 8) |
         (md5Bytes[3] & 0xFF);
    final int setNumber = checksum % setNames.size();


    // Get the appropriate set, update the RDN cache if appropriate, and return
    // the transformed entry.
    final Set<String> sets = setNames.get(setNumber);
    if (rdnCache != null)
    {
      rdnCache.put(normalizedRDNString, sets);
    }

    return createEntry(original, sets);
  }
}
