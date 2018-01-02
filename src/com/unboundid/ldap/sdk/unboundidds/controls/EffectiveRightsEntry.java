/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.DebugType;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class provides a mechanism for extracting the effective rights
 * information from an entry returned for a search request that included the
 * get effective rights request control.  In particular, it provides the ability
 * to parse the values of the aclRights attributes in order to determine what
 * rights the specified user may have when interacting with the entry.
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
 * <BR>
 * See the {@link GetEffectiveRightsRequestControl} for an example that
 * demonstrates the use of the get effective rights request control and this
 * entry.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EffectiveRightsEntry
       extends ReadOnlyEntry
{
  /**
   * The name of the attribute that includes the rights information.
   */
  private static final String ATTR_ACL_RIGHTS = "aclRights";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3203127456449579174L;



  // The set of entry-level rights parsed from the entry.
  private final Set<EntryRight> entryRights;

  // The set of attribute-level rights parsed from the entry, mapped from the
  // name of the attribute to the set of the corresponding attribute rights.
  private final Map<String,Set<AttributeRight>> attributeRights;



  /**
   * Creates a new get effective rights entry from the provided entry.
   *
   * @param  entry  The entry to use to create this get effective rights entry.
   *                It must not be {@code null}.
   */
  public EffectiveRightsEntry(final Entry entry)
  {
    super(entry);

    final HashSet<String> options = new HashSet<String>(1);
    options.add("entryLevel");

    List<Attribute> attrList =
         getAttributesWithOptions(ATTR_ACL_RIGHTS, options);
    if ((attrList == null) || attrList.isEmpty())
    {
      if (debugEnabled(DebugType.LDAP))
      {
        debug(Level.WARNING, DebugType.LDAP,
              "No entry-level aclRights information contained in entry " +
              entry.getDN());
      }

      entryRights = null;
    }
    else
    {
      entryRights = Collections.unmodifiableSet(parseEntryRights(attrList));
    }

    options.clear();
    options.add("attributeLevel");
    attrList = getAttributesWithOptions(ATTR_ACL_RIGHTS, options);
    if ((attrList == null) || attrList.isEmpty())
    {
      if (debugEnabled(DebugType.LDAP))
      {
        debug(Level.WARNING, DebugType.LDAP,
              "No attribute-level aclRights information contained in entry " +
              entry.getDN());
      }

      attributeRights = null;
    }
    else
    {
      final HashMap<String,Set<AttributeRight>> attrRightsMap =
           new HashMap<String,Set<AttributeRight>>(attrList.size());
      for (final Attribute a : attrList)
      {
        final Set<String> attrOptions = a.getOptions();
        String attrName = null;
        for (final String s : attrOptions)
        {
          if (! s.equalsIgnoreCase("attributeLevel"))
          {
            attrName = s;
          }
        }

        if (attrName == null)
        {
          if (debugEnabled(DebugType.LDAP))
          {
            debug(Level.WARNING, DebugType.LDAP,
                  "Unable to determine the target attribute name from " +
                  a.getName());
          }
        }
        else
        {
          final String lowerName = toLowerCase(attrName);
          final Set<AttributeRight> rights = parseAttributeRights(a);
          attrRightsMap.put(lowerName, rights);
        }
      }

      attributeRights = Collections.unmodifiableMap(attrRightsMap);
    }
  }



  /**
   * Parses the entry rights information from the entry.
   *
   * @param  attrList  The list of attributes to be parsed.
   *
   * @return  The set of entry rights parsed from the entry.
   */
  private static Set<EntryRight> parseEntryRights(
                                      final List<Attribute> attrList)
  {
    final EnumSet<EntryRight> entryRightsSet = EnumSet.noneOf(EntryRight.class);
    for (final Attribute a : attrList)
    {
      for (final String value : a.getValues())
      {
        final StringTokenizer tokenizer = new StringTokenizer(value, ", ");
        while (tokenizer.hasMoreTokens())
        {
          final String token = tokenizer.nextToken();
          if (token.endsWith(":1"))
          {
            final String rightName = token.substring(0, token.length()-2);
            final EntryRight r = EntryRight.forName(rightName);
            if (r == null)
            {
              if (debugEnabled(DebugType.LDAP))
              {
                debug(Level.WARNING, DebugType.LDAP,
                      "Unrecognized entry right " + rightName);
              }
            }
            else
            {
              entryRightsSet.add(r);
            }
          }
        }
      }
    }

    return entryRightsSet;
  }



  /**
   * Parses the attribute rights information from the provided attribute.
   *
   * @param  a  The attribute to be parsed.
   *
   * @return  The set of attribute rights parsed from the provided attribute.
   */
  private static Set<AttributeRight> parseAttributeRights(final Attribute a)
  {
    final EnumSet<AttributeRight> rightsSet =
         EnumSet.noneOf(AttributeRight.class);

    for (final String value : a.getValues())
    {
      final StringTokenizer tokenizer = new StringTokenizer(value, ", ");
      while (tokenizer.hasMoreTokens())
      {
        final String token = tokenizer.nextToken();
        if (token.endsWith(":1"))
        {
          final String rightName = token.substring(0, token.length()-2);
          final AttributeRight r = AttributeRight.forName(rightName);
          if (r == null)
          {
            if (debugEnabled(DebugType.LDAP))
            {
              debug(Level.WARNING, DebugType.LDAP,
                    "Unrecognized attribute right " + rightName);
            }
          }
          else
          {
            rightsSet.add(r);
          }
        }
      }
    }

    return rightsSet;
  }



  /**
   * Indicates whether any access control rights information was contained in
   * the entry.
   *
   * @return  {@code true} if access control rights information was contained in
   *          the entry, or {@code false} if not.
   */
  public boolean rightsInformationAvailable()
  {
    return ((entryRights != null) || (attributeRights != null));
  }



  /**
   * Retrieves the set of entry-level rights parsed from the entry.
   *
   * @return  The set of entry-level rights parsed from the entry, or
   *          {@code null} if the entry did not have any entry-level rights
   *          information.
   */
  public Set<EntryRight> getEntryRights()
  {
    return entryRights;
  }



  /**
   * Indicates whether the specified entry right is granted for this entry.
   *
   * @param  entryRight  The entry right for which to make the determination.
   *                     It must not be {@code null}.
   *
   * @return  {@code true} if the entry included entry-level rights information
   *          and the specified entry right is granted, or {@code false} if not.
   */
  public boolean hasEntryRight(final EntryRight entryRight)
  {
    ensureNotNull(entryRight);

    return ((entryRights != null) && entryRights.contains(entryRight));
  }



  /**
   * Retrieves the set of attribute-level rights parsed from the entry, mapped
   * from attribute name (in all lowercase characters) to the set of
   * attribute-level rights for that attribute.
   *
   * @return  The set of attribute-level rights parsed from the entry, or
   *          {@code null} if the entry did not have any attribute-level rights
   *          information.
   */
  public Map<String,Set<AttributeRight>> getAttributeRights()
  {
    return attributeRights;
  }



  /**
   * Retrieves the set of attribute-level rights parsed from the entry for the
   * specified attribute.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        attribute-level rights.  It must not be
   *                        {@code null}.
   *
   * @return  The set of attribute-level rights for the specified attribute, or
   *          {@code null} if the entry did not include any attribute-level
   *          rights information for the specified attribute.
   */
  public Set<AttributeRight> getAttributeRights(final String attributeName)
  {
    ensureNotNull(attributeName);

    if (attributeRights == null)
    {
      return null;
    }

    return attributeRights.get(toLowerCase(attributeName));
  }



  /**
   * Indicates whether the specified attribute right is granted for the
   * specified attribute in this entry.
   *
   * @param  attributeRight  The attribute right for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   *
   * @return  {@code true} if the entry included attribute-level rights
   *          information for the specified attribute and the indicated right is
   *          granted, or {@code false} if not.
   */
  public boolean hasAttributeRight(final AttributeRight attributeRight,
                                   final String attributeName)
  {
    ensureNotNull(attributeName, attributeRight);

    final Set<AttributeRight> attrRights = getAttributeRights(attributeName);
    return ((attrRights != null) && attrRights.contains(attributeRight));
  }
}
