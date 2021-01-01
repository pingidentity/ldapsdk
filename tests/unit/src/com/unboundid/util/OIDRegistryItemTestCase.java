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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the {@code OIdRegistryItem}
 * class.
 */
public final class OIDRegistryItemTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an item created with values for all fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithAllFields()
         throws Exception
  {
    OIDRegistryItem item = new OIDRegistryItem("1.2.3.4", "test-name",
         "test-type", "test-origin", "https://test.example.com/");

    item = new OIDRegistryItem(item.asJSONObject());

    assertNotNull(item.getOID());
    assertEquals(item.getOID(), "1.2.3.4");

    assertNotNull(item.getName());
    assertEquals(item.getName(), "test-name");

    assertNotNull(item.getType());
    assertEquals(item.getType(), "test-type");

    assertNotNull(item.getOrigin());
    assertEquals(item.getOrigin(), "test-origin");

    assertNotNull(item.getURL());
    assertEquals(item.getURL(), "https://test.example.com/");

    assertNotNull(item.toString());
    assertEquals(item.toString(), item.asJSONObject().toSingleLineString());
  }



  /**
   * Tests the behavior for an item created with values for the minimum set of
   * required fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithMinimalFields()
         throws Exception
  {
    OIDRegistryItem item = new OIDRegistryItem("1.2.3.5", "another-name",
         "another-type", null, null);

    item = new OIDRegistryItem(item.asJSONObject());

    assertNotNull(item.getOID());
    assertEquals(item.getOID(), "1.2.3.5");

    assertNotNull(item.getName());
    assertEquals(item.getName(), "another-name");

    assertNotNull(item.getType());
    assertEquals(item.getType(), "another-type");

    assertNull(item.getOrigin());

    assertNull(item.getURL());

    assertNotNull(item.toString());
    assertEquals(item.toString(), item.asJSONObject().toSingleLineString());
  }



  /**
   * Tests the behavior when trying to decode a JSON object that does not
   * include an OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutOID()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("name", "test-name"),
         new JSONField("type", "test-type"),
         new JSONField("origin", "test-origin"),
         new JSONField("url", "https://test.example.com/"));
    new OIDRegistryItem(o);
  }



  /**
   * Tests the behavior when trying to decode a JSON object that does not
   * include a name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutName()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("type", "test-type"),
         new JSONField("origin", "test-origin"),
         new JSONField("url", "https://test.example.com/"));
    new OIDRegistryItem(o);
  }



  /**
   * Tests the behavior when trying to decode a JSON object that does not
   * include a type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeObjectWithoutType()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("oid", "1.2.3.4"),
         new JSONField("name", "test-name"),
         new JSONField("origin", "test-origin"),
         new JSONField("url", "https://test.example.com/"));
    new OIDRegistryItem(o);
  }
}
