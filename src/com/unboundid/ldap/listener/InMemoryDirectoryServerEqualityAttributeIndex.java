/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a data structure for maintaining an equality index for a
 * specified attribute.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class InMemoryDirectoryServerEqualityAttributeIndex
{
  // The attribute type with which this index is associated.
  @NotNull private final AttributeTypeDefinition attributeType;

  // A map from normalized values to the DNs of entries with those values.
  @NotNull private final Map<ASN1OctetString,TreeSet<DN>> indexMap;

  // The matching rule used to normalize values.
  @NotNull private final MatchingRule matchingRule;

  // The schema for the server.
  @NotNull private final Schema schema;



  /**
   * Creates a new equality attribute index for the specified attribute type.
   *
   * @param  attributeType  The name or OID of the attribute type with which
   *                        this index is associated.  It must be defined in the
   *                        schema.
   * @param  schema         The schema for the server.  It must not be
   *                        {@code null}.
   *
   * @throws  LDAPException  If the specified attribute type is not defined in
   *                         the schema.
   */
  InMemoryDirectoryServerEqualityAttributeIndex(
       @NotNull final String attributeType, @NotNull final Schema schema)
       throws LDAPException
  {
    this.schema = schema;
    if (schema == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_DS_EQ_INDEX_NO_SCHEMA.get(attributeType));
    }

    this.attributeType = schema.getAttributeType(attributeType);
    if (this.attributeType == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_DS_EQ_INDEX_UNDEFINED_ATTRIBUTE_TYPE.get(attributeType));
    }

    matchingRule = MatchingRule.selectEqualityMatchingRule(attributeType,
         schema);

    indexMap = new HashMap<>(StaticUtils.computeMapCapacity(100));
  }



  /**
   * Retrieves the attribute type definition for this index.
   *
   * @return  The attribute type definition for this index.
   */
  @NotNull()
  AttributeTypeDefinition getAttributeType()
  {
    return attributeType;
  }



  /**
   * Clears all index data for the associated attribute.
   */
  synchronized void clear()
  {
    indexMap.clear();
  }



  /**
   * Obtains a copy of the internal map used by this index.  This is only
   * intended for internal use for testing purposes.
   *
   * @return  A copy of the internal map used by this index.
   */
  @InternalUseOnly()
  @NotNull()
  synchronized Map<ASN1OctetString,TreeSet<DN>> copyMap()
  {
    final HashMap<ASN1OctetString,TreeSet<DN>> m =
         new HashMap<>(StaticUtils.computeMapCapacity(indexMap.size()));
    for (final Map.Entry<ASN1OctetString,TreeSet<DN>> e : indexMap.entrySet())
    {
      m.put(e.getKey(), new TreeSet<>(e.getValue()));
    }

    return Collections.unmodifiableMap(m);
  }



  /**
   * Retrieves the DNs of the entries that have the specified value for the
   * associated attribute.
   *
   * @param  value  The value for which to retrieve the corresponding entry DNs.
   *
   * @return  A set containing the DNs of the entries that have the provided
   *          value, or an empty set if there are none.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         make the determination (e.g., if the given value is
   *                         not acceptable for the associated attribute type).
   */
  @NotNull()
  synchronized Set<DN> getMatchingEntries(@NotNull final ASN1OctetString value)
               throws LDAPException
  {
    final TreeSet<DN> dnSet = indexMap.get(matchingRule.normalize(value));
    if (dnSet == null)
    {
      return Collections.emptySet();
    }
    else
    {
      return Collections.unmodifiableSet(dnSet);
    }
  }



  /**
   * Performs the necessary processing for adding the given entry.
   *
   * @param  entry  The entry to be added.
   *
   * @throws  LDAPException  If a problem is encountered (e.g., the entry has
   *                         one or more values that are not acceptable for the
   *                         associated attribute type).
   */
  synchronized void processAdd(@NotNull final Entry entry)
               throws LDAPException
  {
    final Attribute a =
         entry.getAttribute(attributeType.getNameOrOID(), schema);
    if (a != null)
    {
      final DN dn = entry.getParsedDN();

      final ASN1OctetString[] rawValues = a.getRawValues();
      final ASN1OctetString[] normalizedValues =
           new ASN1OctetString[rawValues.length];
      for (int i=0; i < rawValues.length; i++)
      {
        normalizedValues[i] = matchingRule.normalize(rawValues[i]);
      }

      for (final ASN1OctetString v : normalizedValues)
      {
        TreeSet<DN> dnSet = indexMap.get(v);
        if (dnSet == null)
        {
          dnSet = new TreeSet<>();
          indexMap.put(v, dnSet);
        }
        dnSet.add(dn);
      }
    }
  }



  /**
   * Performs the necessary processing for deleting the given entry.
   *
   * @param  entry  The entry to be deleted.
   *
   * @throws  LDAPException  If a problem is encountered (e.g., the entry has
   *                         one or more values that are not acceptable for the
   *                         associated attribute type).
   */
  synchronized void processDelete(@NotNull final Entry entry)
               throws LDAPException
  {
    final Attribute a =
         entry.getAttribute(attributeType.getNameOrOID(), schema);
    if (a != null)
    {
      final DN dn = entry.getParsedDN();

      final ASN1OctetString[] rawValues = a.getRawValues();
      final ASN1OctetString[] normalizedValues =
           new ASN1OctetString[rawValues.length];
      for (int i=0; i < rawValues.length; i++)
      {
        normalizedValues[i] = matchingRule.normalize(rawValues[i]);
      }

      for (final ASN1OctetString v : normalizedValues)
      {
        final TreeSet<DN> dnSet = indexMap.get(v);
        if (dnSet != null)
        {
          dnSet.remove(dn);
          if (dnSet.isEmpty())
          {
            indexMap.remove(v);
          }
        }
      }
    }
  }
}
