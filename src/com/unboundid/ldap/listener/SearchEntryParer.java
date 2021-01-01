/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides support methods for paring search result entries based
 * on a given set of requested attributes.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchEntryParer
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3249960583816464391L;



  // Indicates whether to include all operational attributes.
  private final boolean allOperationalAttributes;

  // Indicates whether to include all user attributes.
  private final boolean allUserAttributes;

  // The list of requested attributes for use when paring entries.
  @NotNull private final List<String> requestedAttributes;

  // A map of specific attribute types to be returned.  The keys of the map will
  // be the lowercase OIDs and names of each attribute types, and the values
  // will be a list of option sets for the associated attribute type.
  @NotNull private final Map<String,List<List<String>>> attributeTypesToReturn;

  // The schema to use in processing.
  @Nullable private final Schema schema;



  /**
   * Creates a new search entry parer for the provided set of requested
   * attributes.
   *
   * @param  requestedAttributes  The list of requested attributes for use when
   *                              paring entries.  It must not be {@code null},
   *                              but may be empty.
   * @param  schema               The schema to use when paring entries.  It may
   *                              be {@code null} if no schema is available.
   */
  public SearchEntryParer(@NotNull final List<String> requestedAttributes,
                          @Nullable final Schema schema)
  {
    this.schema = schema;
    this.requestedAttributes =
         Collections.unmodifiableList(new ArrayList<>(requestedAttributes));

    if (requestedAttributes.isEmpty())
    {
      allUserAttributes = true;
      allOperationalAttributes = false;
      attributeTypesToReturn = Collections.emptyMap();
      return;
    }

    boolean allUserAttrs = false;
    boolean allOpAttrs = false;
    final Map<String,List<List<String>>> m = new HashMap<>(
         StaticUtils.computeMapCapacity(requestedAttributes.size()));
    for (final String s : requestedAttributes)
    {
      if (s.equals("*"))
      {
        allUserAttrs = true;
      }
      else if (s.equals("+"))
      {
        allOpAttrs = true;
      }
      else if (s.startsWith("@"))
      {
        // Return attributes by object class.  This can only be supported if a
        // schema has been defined.
        if (schema != null)
        {
          final String ocName = s.substring(1);
          final ObjectClassDefinition oc = schema.getObjectClass(ocName);
          if (oc != null)
          {
            for (final AttributeTypeDefinition at :
                 oc.getRequiredAttributes(schema, true))
            {
              addAttributeOIDAndNames(at, m, Collections.<String>emptyList(),
                   schema);
            }
            for (final AttributeTypeDefinition at :
                 oc.getOptionalAttributes(schema, true))
            {
              addAttributeOIDAndNames(at, m, Collections.<String>emptyList(),
                   schema);
            }
          }
        }
      }
      else
      {
        final ObjectPair<String,List<String>> nameWithOptions =
             getNameWithOptions(s);
        if (nameWithOptions == null)
        {
          continue;
        }

        final String name = nameWithOptions.getFirst();
        final List<String> options = nameWithOptions.getSecond();

        if (schema == null)
        {
          // Just use the name as provided.
          List<List<String>> optionLists = m.get(name);
          if (optionLists == null)
          {
            optionLists = new ArrayList<>(1);
            m.put(name, optionLists);
          }
          optionLists.add(options);
        }
        else
        {
          // If the attribute type is defined in the schema, then use it to get
          // all names and the OID.  Otherwise, just use the name as provided.
          final AttributeTypeDefinition at = schema.getAttributeType(name);
          if (at == null)
          {
            List<List<String>> optionLists = m.get(name);
            if (optionLists == null)
            {
              optionLists = new ArrayList<>(1);
              m.put(name, optionLists);
            }
            optionLists.add(options);
          }
          else
          {
            addAttributeOIDAndNames(at, m, options, schema);
          }
        }
      }
    }

    allUserAttributes = allUserAttrs;
    allOperationalAttributes = allOpAttrs;
    attributeTypesToReturn = Collections.unmodifiableMap(m);
  }



  /**
   * Parses the provided string into an attribute type and set of options.
   *
   * @param  s  The string to be parsed.
   *
   * @return  An {@code ObjectPair} in which the first element is the attribute
   *          type name and the second is the list of options (or an empty
   *          list if there are no options).  Alternately, a value of
   *          {@code null} may be returned if the provided string does not
   *          represent a valid attribute type description.
   */
  @NotNull()
  private static ObjectPair<String,List<String>> getNameWithOptions(
                                                      @NotNull final String s)
  {
    if (! Attribute.nameIsValid(s, true))
    {
      return null;
    }

    final String l = StaticUtils.toLowerCase(s);

    int semicolonPos = l.indexOf(';');
    if (semicolonPos < 0)
    {
      return new ObjectPair<>(l, Collections.<String>emptyList());
    }

    final String name = l.substring(0, semicolonPos);
    final ArrayList<String> optionList = new ArrayList<>(1);
    while (true)
    {
      final int nextSemicolonPos = l.indexOf(';', semicolonPos+1);
      if (nextSemicolonPos < 0)
      {
        optionList.add(l.substring(semicolonPos+1));
        break;
      }
      else
      {
        optionList.add(l.substring(semicolonPos+1, nextSemicolonPos));
        semicolonPos = nextSemicolonPos;
      }
    }

    return new ObjectPair<String,List<String>>(name, optionList);
  }



  /**
   * Adds all-lowercase versions of the OID and all names for the provided
   * attribute type definition to the given map with the given options.
   *
   * @param  d  The attribute type definition to process.
   * @param  m  The map to which the OID and names should be added.
   * @param  o  The array of attribute options to use in the map.  It should be
   *            empty if no options are needed, and must not be {@code null}.
   * @param  s  The schema to use when processing.
   */
  private static void addAttributeOIDAndNames(
                           @Nullable final AttributeTypeDefinition d,
                           @NotNull final Map<String,List<List<String>>> m,
                           @NotNull final List<String> o,
                           @Nullable final Schema s)
  {
    if (d == null)
    {
      return;
    }

    final String lowerOID = StaticUtils.toLowerCase(d.getOID());
    if (lowerOID != null)
    {
      List<List<String>> l = m.get(lowerOID);
      if (l == null)
      {
        l = new ArrayList<>(1);
        m.put(lowerOID, l);
      }

      l.add(o);
    }

    for (final String name : d.getNames())
    {
      final String lowerName = StaticUtils.toLowerCase(name);
      List<List<String>> l = m.get(lowerName);
      if (l == null)
      {
        l = new ArrayList<>(1);
        m.put(lowerName, l);
      }

      l.add(o);
    }

    // If a schema is available, then see if the attribute type has any
    // subordinate types.  If so, then add them.
    if (s != null)
    {
      for (final AttributeTypeDefinition subordinateType :
           s.getSubordinateAttributeTypes(d))
      {
        addAttributeOIDAndNames(subordinateType, m, o, s);
      }
    }
  }



  /**
   * Retrieves the set of requested attributes used to create this search entry
   * parer.
   *
   * @return  The set of requested attributes used to create this search entry
   *          parer.
   */
  @NotNull()
  public List<String> getRequestedAttributes()
  {
    return requestedAttributes;
  }



  /**
   * Retrieves a copy of the provided entry that includes only the appropriate
   * set of requested attributes.
   *
   * @param  entry  The entry to be pared.
   *
   * @return  A copy of the provided entry that includes only the appropriate
   *          set of requested attributes.
   */
  @NotNull()
  public Entry pareEntry(@NotNull final Entry entry)
  {
    // See if we can return the entry without paring it down.
    if (allUserAttributes)
    {
      if (allOperationalAttributes || (schema == null))
      {
        return entry.duplicate();
      }
    }


    // If we've gotten here, then we may only need to return a partial entry.
    final Entry copy = new Entry(entry.getDN(), schema);

    for (final Attribute a : entry.getAttributes())
    {
      final ObjectPair<String,List<String>> nameWithOptions =
           getNameWithOptions(a.getName());
      final String name = nameWithOptions.getFirst();
      final List<String> options = nameWithOptions.getSecond();

      // If there is a schema, then see if it is an operational attribute, since
      // that needs to be handled in a manner different from user attributes
      if (schema != null)
      {
        final AttributeTypeDefinition at = schema.getAttributeType(name);
        if ((at != null) && at.isOperational())
        {
          if (allOperationalAttributes)
          {
            copy.addAttribute(a);
            continue;
          }

          final List<List<String>> optionLists =
               attributeTypesToReturn.get(name);
          if (optionLists == null)
          {
            continue;
          }

          for (final List<String> optionList : optionLists)
          {
            boolean matchAll = true;
            for (final String option : optionList)
            {
              if (! options.contains(option))
              {
                matchAll = false;
                break;
              }
            }

            if (matchAll)
            {
              copy.addAttribute(a);
              break;
            }
          }
          continue;
        }
      }

      // We'll assume that it's a user attribute, and we'll look for an exact
      // match on the base name.
      if (allUserAttributes)
      {
        copy.addAttribute(a);
        continue;
      }

      final List<List<String>> optionLists = attributeTypesToReturn.get(name);
      if (optionLists == null)
      {
        continue;
      }

      for (final List<String> optionList : optionLists)
      {
        boolean matchAll = true;
        for (final String option : optionList)
        {
          if (! options.contains(option))
          {
            matchAll = false;
            break;
          }
        }

        if (matchAll)
        {
          copy.addAttribute(a);
          break;
        }
      }
    }

    return copy;
  }
}
