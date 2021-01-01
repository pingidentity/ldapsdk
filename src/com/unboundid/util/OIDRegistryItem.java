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



import java.io.Serializable;
import java.util.LinkedHashMap;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class defines a data structure that represents an item in the OID
 * registry.
 *
 * @see  OIDRegistry
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OIDRegistryItem
       implements Serializable
{
  /**
   * The name of the JSON field that holds the name for the item.
   */
  @NotNull private static final String FIELD_NAME = "name";



  /**
   * The name of the JSON field that holds the OID for the item.
   */
  @NotNull private static final String FIELD_OID = "oid";



  /**
   * The name of the JSON field that holds the origin for the item.
   */
  @NotNull private static final String FIELD_ORIGIN = "origin";



  /**
   * The name of the JSON field that holds the type for the item.
   */
  @NotNull private static final String FIELD_TYPE = "type";



  /**
   * The name of the JSON field that holds the URL for the item.
   */
  @NotNull private static final String FIELD_URL = "url";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4342220623592884938L;



  // A JSON object representation of this item.
  @NotNull private final JSONObject jsonObject;

  // The name for the item.
  @NotNull private final String name;

  // The OID for the item.
  @NotNull private final String oid;

  // The origin for the item.
  @Nullable private final String origin;

  // The type for the item.
  @NotNull private final String type;

  // A URL with more information about the item.
  @Nullable private final String url;



  /**
   * Creates an OID registry item with the provided information.
   *
   * @param  oid     The OID for the item.
   * @param  name    The name for the item.
   * @param  type    The type for the item.
   * @param  origin  The origin for the item, if any.
   * @param  url     The URL for the item, if any.
   */
  OIDRegistryItem(@NotNull final String oid,
                  @NotNull final String name,
                  @NotNull final String type,
                  @Nullable final String origin,
                  @Nullable final String url)
  {
    this.oid = oid;
    this.name = name;
    this.type = type;
    this.origin = origin;
    this.url = url;

    final LinkedHashMap<String,JSONValue> jsonFields = new LinkedHashMap<>();
    jsonFields.put(FIELD_OID, new JSONString(oid));
    jsonFields.put(FIELD_NAME, new JSONString(name));
    jsonFields.put(FIELD_TYPE, new JSONString(type));

    if (origin != null)
    {
      jsonFields.put(FIELD_ORIGIN, new JSONString(origin));
    }

    if (url != null)
    {
      jsonFields.put(FIELD_URL, new JSONString(url));
    }

    jsonObject = new JSONObject(jsonFields);
  }



  /**
   * Creates an OID registry item that is decoded from the provided JSON object.
   *
   * @param  jsonObject  The JSON object to decode as an OID registry item.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid OID registry item.
   */
  OIDRegistryItem(@NotNull final JSONObject jsonObject)
       throws LDAPException
  {
    this.jsonObject = jsonObject;

    oid = jsonObject.getFieldAsString(FIELD_OID);
    if (oid == null)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_OID_REGISTRY_ITEM_OBJECT_MISSING_FIELD.get(
                jsonObject.toSingleLineString(), FIELD_OID));
    }

    name = jsonObject.getFieldAsString(FIELD_NAME);
    if (name == null)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_OID_REGISTRY_ITEM_OBJECT_MISSING_FIELD.get(
                jsonObject.toSingleLineString(), FIELD_NAME));
    }

    type = jsonObject.getFieldAsString(FIELD_TYPE);
    if (type == null)
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_OID_REGISTRY_ITEM_OBJECT_MISSING_FIELD.get(
                jsonObject.toSingleLineString(), FIELD_TYPE));
    }

    origin = jsonObject.getFieldAsString(FIELD_ORIGIN);
    url = jsonObject.getFieldAsString(FIELD_URL);
  }



  /**
   * Retrieves a string representation of the OID for this OID registry item.
   *
   * @return  A string representation of the OID for this OID registry item.
   */
  @NotNull()
  public String getOID()
  {
    return oid;
  }



  /**
   * Retrieves the name for this OID registry item.
   *
   * @return  The name for this OID registry item.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the type for this OID registry item.
   *
   * @return  The type for this OID registry item.
   */
  @NotNull()
  public String getType()
  {
    return type;
  }



  /**
   * Retrieves a string with information about the origin of this OID registry
   * item, if available.
   *
   * @return  A string with information about the origin of this OID registry
   *          item, or {@code null} if none is available.
   */
  @Nullable()
  public String getOrigin()
  {
    return origin;
  }



  /**
   * Retrieves a URL with more information about this OID registry item, if
   * available.
   *
   * @return  A URL with more information about this OID registry item, or
   *          {@code null} if none is available.
   */
  @Nullable()
  public String getURL()
  {
    return url;
  }



  /**
   * Retrieves a representation of this OID registry item as a JSON object.
   *
   * @return  A representation of this OID registry item as a JSON object.
   */
  @NotNull()
  public JSONObject asJSONObject()
  {
    return jsonObject;
  }



  /**
   * Retrieves a string representation of this OID registry item.
   *
   * @return  A string representation of this OID registry item.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return jsonObject.toSingleLineString();
  }
}
