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
package com.unboundid.util;



import java.io.InputStream;
import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.schema.AttributeSyntaxDefinition;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.MatchingRuleDefinition;
import com.unboundid.ldap.sdk.schema.NameFormDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class represents a data structure with information about a variety of
 * object identifiers (OIDs) used in LDAP-related contexts.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OIDRegistry
       implements Serializable
{
  /**
   * A reference to the default instance of this OID registry.
   */
  @NotNull private static final AtomicReference<OIDRegistry> DEFAULT_INSTANCE =
       new AtomicReference<>();



  /**
   * The name of the resource that holds the data for the default OID registry.
   */
  @NotNull private static final String OID_REGISTRY_JSON_RESOURCE_NAME =
       "com/unboundid/util/oid-registry.json";



  /**
   * The name of the X-ORIGIN extension that schema elements may use to specify
   * their origin.
   */
  @NotNull private static final String X_ORIGIN_EXTENSION_NAME = "X-ORIGIN";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 867525903925430865L;



  // A map of the items contained in the OID registry, indexed by
  @NotNull private final Map<OID,OIDRegistryItem> items;



  /**
   * Creates an OID registry instance with the provided set of items.
   *
   * @param  items  The map of items to include in the OID registry.
   */
  private OIDRegistry(@NotNull final Map<OID,OIDRegistryItem> items)
  {
    this.items = items;
  }



  /**
   * Retrieves the default instance of this OID registry.
   *
   * @return  The default instance of this OID registry.
   */
  @NotNull()
  public static OIDRegistry getDefault()
  {
    OIDRegistry oidRegistry = DEFAULT_INSTANCE.get();
    if (oidRegistry == null)
    {
      synchronized (DEFAULT_INSTANCE)
      {
        oidRegistry = DEFAULT_INSTANCE.get();
        if (oidRegistry == null)
        {
          final Map<OID,OIDRegistryItem> items = new TreeMap<>();
          try (InputStream inputStream =
                    OIDRegistry.class.getClassLoader().getResourceAsStream(
                         OID_REGISTRY_JSON_RESOURCE_NAME);
               JSONObjectReader jsonObjectReader =
                    new JSONObjectReader(inputStream))
          {
            while (true)
            {
              final JSONObject o = jsonObjectReader.readObject();
              if (o == null)
              {
                break;
              }

              try
              {
                final OIDRegistryItem item = new OIDRegistryItem(o);
                items.put(new OID(item.getOID()), item);
              }
              catch (final Exception e)
              {
                Debug.debugException(e);
              }
            }
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }

          oidRegistry = new OIDRegistry(Collections.unmodifiableMap(items));
          DEFAULT_INSTANCE.set(oidRegistry);
        }
      }
    }

    return oidRegistry;
  }



  /**
   * Retrieves a copy of this OID registry that has been augmented with
   * information from the provided schema.
   *
   * @param  schema  The schema that may be used to augment the information in
   *                 this OID registry.  It must not be {@code null}.
   *
   * @return  A copy of this OID registry that has been augmented with
   *          information from the provided schema.
   */
  @NotNull()
  public OIDRegistry withSchema(@NotNull final Schema schema)
  {
    final TreeMap<OID,OIDRegistryItem> newItems = new TreeMap<>(items);
    for (final AttributeSyntaxDefinition syntax : schema.getAttributeSyntaxes())
    {
      final String oidString = syntax.getOID();
      final OID oid = new OID(syntax.getOID());
      if (newItems.containsKey(oid))
      {
        continue;
      }

      String name = syntax.getDescription();
      if (name == null)
      {
        name = oidString;
      }

      newItems.put(oid,
           new OIDRegistryItem(syntax.getOID(), name, "Attribute Syntax",
                getOrigin(syntax.getExtensions()), null));
    }

    for (final MatchingRuleDefinition matchingRule : schema.getMatchingRules())
    {
      final String oidString = matchingRule.getOID();
      final OID oid = new OID(matchingRule.getOID());
      if (newItems.containsKey(oid))
      {
        continue;
      }

      newItems.put(oid,
           new OIDRegistryItem(matchingRule.getOID(),
                matchingRule.getNameOrOID(), "Matching Rule",
                getOrigin(matchingRule.getExtensions()), null));
    }

    for (final AttributeTypeDefinition attributeType :
         schema.getAttributeTypes())
    {
      final String oidString = attributeType.getOID();
      final OID oid = new OID(attributeType.getOID());
      if (newItems.containsKey(oid))
      {
        continue;
      }

      newItems.put(oid,
           new OIDRegistryItem(attributeType.getOID(),
                attributeType.getNameOrOID(), "Attribute Type",
                getOrigin(attributeType.getExtensions()), null));
    }

    for (final ObjectClassDefinition objectClass :
         schema.getObjectClasses())
    {
      final String oidString = objectClass.getOID();
      final OID oid = new OID(objectClass.getOID());
      if (newItems.containsKey(oid))
      {
        continue;
      }

      newItems.put(oid,
           new OIDRegistryItem(objectClass.getOID(),
                objectClass.getNameOrOID(), "Object Class",
                getOrigin(objectClass.getExtensions()), null));
    }

    for (final NameFormDefinition nameForm : schema.getNameForms())
    {
      final String oidString = nameForm.getOID();
      final OID oid = new OID(nameForm.getOID());
      if (newItems.containsKey(oid))
      {
        continue;
      }

      newItems.put(oid,
           new OIDRegistryItem(nameForm.getOID(),
                nameForm.getNameOrOID(), "Name Form",
                getOrigin(nameForm.getExtensions()), null));
    }

    return new OIDRegistry(Collections.unmodifiableMap(newItems));
  }



  /**
   * Retrieves the value for the X-ORIGIN extension from the provided map, if
   * available.
   *
   * @param  extensions  The map of extensions for the associated schema
   *                     element.
   *
   * @return  The value for the X-ORIGIN extension from the provided map, or
   *          {@code null} if there is no such extension.
   */
  @Nullable()
  private static String getOrigin(
               @NotNull final Map<String,String[]> extensions)
  {
    final String[] values = extensions.get(X_ORIGIN_EXTENSION_NAME);
    if ((values != null) && (values.length > 0))
    {
      return values[0];
    }

    return null;
  }



  /**
   * Retrieves an unmodifiable map of all items in the OID registry, indexed by
   * OID.
   *
   * @return  An unmodifiable map of all items in the OID registry, indexed by
   *          OID.
   */
  @NotNull()
  public Map<OID,OIDRegistryItem> getItems()
  {
    return items;
  }



  /**
   * Retrieves the OID registry item for the specified OID, if available.
   *
   * @param  oid  The OID for the item to retrieve.
   *
   * @return  The OID registry item for the specified OID, or {@code null} if
   *          this registry does not have any information about the specified
   *          OID.
   */
  @Nullable()
  public OIDRegistryItem get(@NotNull final String oid)
  {
    return get(new OID(oid));
  }



  /**
   * Retrieves the OID registry item for the specified OID, if available.
   *
   * @param  oid  The OID for the item to retrieve.
   *
   * @return  The OID registry item for the specified OID, or {@code null} if
   *          this registry does not have any information about the specified
   *          OID.
   */
  @Nullable()
  public OIDRegistryItem get(@NotNull final OID oid)
  {
    return items.get(oid);
  }
}
