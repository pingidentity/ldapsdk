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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.Debug;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an implementation of an LDIF reader entry translator that
 * can be used to determine the set into which an entry should be placed by
 * computing a modulus from a digest of the RDN.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
final class SplitLDIFRDNHashTranslator
      extends SplitLDIFTranslator
{
  // A map of the names that will be used for each of the sets.
  private final Map<Integer,Set<String>> setNames;

  // The sets in which entries outside the split base should be placed.
  private final Set<String> outsideSplitBaseSetNames;

  // The sets in which the split base entry should be placed.
  private final Set<String> splitBaseEntrySetNames;



  /**
   * Creates a new instance of this translator with the provided information.
   *
   * @param  splitBaseDN                           The base DN below which to
   *                                               split entries.
   * @param  numSets                               The number of sets into which
   *                                               entries should be split.
   * @param  addEntriesOutsideSplitToAllSets       Indicates whether entries
   *                                               outside the split should be
   *                                               added to all sets.
   * @param  addEntriesOutsideSplitToDedicatedSet  Indicates whether entries
   *                                               outside the split should be
   *                                               added to all sets.
   */
  SplitLDIFRDNHashTranslator(final DN splitBaseDN, final int numSets,
                             final boolean addEntriesOutsideSplitToAllSets,
                             final boolean addEntriesOutsideSplitToDedicatedSet)
  {
    super(splitBaseDN);

    outsideSplitBaseSetNames = new LinkedHashSet<String>(numSets+1);
    splitBaseEntrySetNames = new LinkedHashSet<String>(numSets);

    if (addEntriesOutsideSplitToDedicatedSet)
    {
      outsideSplitBaseSetNames.add(SplitLDIFEntry.SET_NAME_OUTSIDE_SPLIT);
    }

    setNames = new LinkedHashMap<Integer,Set<String>>(numSets);
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
  public SplitLDIFEntry translate(final Entry original,
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
           ERR_SPLIT_LDIF_RDN_HASH_TRANSLATOR_CANNOT_PARSE_DN.get(
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
    // all of the split sets.  Otherwise, figure out where to send it based on
    // the RDN component immediately below the split base DN.
    if (dn.equals(getSplitBaseDN()))
    {
      return createEntry(original, splitBaseEntrySetNames);
    }
    else
    {
      return createFromRDNHash(original, dn, setNames);
    }
  }
}
