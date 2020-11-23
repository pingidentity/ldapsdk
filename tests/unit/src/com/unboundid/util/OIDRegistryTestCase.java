/*
 * Copyright 2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020 Ping Identity Corporation
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
 * Copyright (C) 2020 Ping Identity Corporation
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



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the {@code OIdRegistry} class.
 */
public final class OIDRegistryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when using the default registry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultRegistry()
         throws Exception
  {
    final OIDRegistry registry = OIDRegistry.getDefault();
    assertNotNull(registry);

    assertNotNull(registry.getItems());
    assertFalse(registry.getItems().isEmpty());

    assertNotNull(registry.get("2.5.4.3"));
    assertEquals(registry.get("2.5.4.3").getOID(), "2.5.4.3");
    assertEquals(registry.get("2.5.4.3").getName(), "cn");
    assertEquals(registry.get("2.5.4.3").getName(), "cn");
    assertEquals(registry.get("2.5.4.3").getType(), "Attribute Type");
    assertEquals(registry.get("2.5.4.3").getOrigin(), "RFC 4519");

    assertNull(registry.get("1.2.3.4"));
  }



  /**
   * Tests the behavior when attempting to augment the default registry with
   * an additional schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRegistryWithSchema()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.2.3.4.1 DESC 'test-syntax' " +
              "X-ORIGIN 'test-origin' )",
         "matchingRules: ( 1.2.3.4.2 NAME 'testMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.4.3 NAME 'test-attr' " +
              "EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-ORIGIN 'another-origin' )",
         "objectClasses: ( 1.2.3.4.4 NAME 'test-oc' SUP top STRUCTURAL " +
              "MUST cn )",
         "nameForms: ( 1.2.3.4.5 NAME 'test-nf' OC person MUST uid )");

    final Schema schema = Schema.getSchema(schemaFile);
    assertNotNull(schema);


    OIDRegistry registry = OIDRegistry.getDefault();
    assertNotNull(registry);

    assertNotNull(registry.getItems());
    assertFalse(registry.getItems().isEmpty());

    assertNull(registry.get("1.2.3.4.1"));
    assertNull(registry.get("1.2.3.4.2"));
    assertNull(registry.get("1.2.3.4.3"));
    assertNull(registry.get("1.2.3.4.4"));
    assertNull(registry.get("1.2.3.4.5"));

    registry = registry.withSchema(schema);
    assertNotNull(registry);

    assertNotNull(registry.get("1.2.3.4.1"));
    assertEquals(registry.get("1.2.3.4.1").getOID(), "1.2.3.4.1");
    assertEquals(registry.get("1.2.3.4.1").getName(), "test-syntax");
    assertEquals(registry.get("1.2.3.4.1").getType(), "Attribute Syntax");
    assertEquals(registry.get("1.2.3.4.1").getOrigin(), "test-origin");
    assertNull(registry.get("1.2.3.4.1").getURL());

    assertNotNull(registry.get("1.2.3.4.2"));
    assertEquals(registry.get("1.2.3.4.2").getOID(), "1.2.3.4.2");
    assertEquals(registry.get("1.2.3.4.2").getName(), "testMatch");
    assertEquals(registry.get("1.2.3.4.2").getType(), "Matching Rule");
    assertNull(registry.get("1.2.3.4.2").getOrigin());
    assertNull(registry.get("1.2.3.4.2").getURL());

    assertNotNull(registry.get("1.2.3.4.3"));
    assertEquals(registry.get("1.2.3.4.3").getOID(), "1.2.3.4.3");
    assertEquals(registry.get("1.2.3.4.3").getName(), "test-attr");
    assertEquals(registry.get("1.2.3.4.3").getType(), "Attribute Type");
    assertEquals(registry.get("1.2.3.4.3").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.3").getURL());

    assertNotNull(registry.get("1.2.3.4.4"));
    assertEquals(registry.get("1.2.3.4.4").getOID(), "1.2.3.4.4");
    assertEquals(registry.get("1.2.3.4.4").getName(), "test-oc");
    assertEquals(registry.get("1.2.3.4.4").getType(), "Object Class");
    assertNull(registry.get("1.2.3.4.4").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.4").getURL());

    assertNotNull(registry.get("1.2.3.4.5"));
    assertEquals(registry.get("1.2.3.4.5").getOID(), "1.2.3.4.5");
    assertEquals(registry.get("1.2.3.4.5").getName(), "test-nf");
    assertEquals(registry.get("1.2.3.4.5").getType(), "Name Form");
    assertNull(registry.get("1.2.3.4.5").getOrigin());
    assertNull(registry.get("1.2.3.4.5").getURL());

    registry = registry.withSchema(schema);
    assertNotNull(registry);

    assertNotNull(registry.get("1.2.3.4.1"));
    assertEquals(registry.get("1.2.3.4.1").getOID(), "1.2.3.4.1");
    assertEquals(registry.get("1.2.3.4.1").getName(), "test-syntax");
    assertEquals(registry.get("1.2.3.4.1").getType(), "Attribute Syntax");
    assertEquals(registry.get("1.2.3.4.1").getOrigin(), "test-origin");
    assertNull(registry.get("1.2.3.4.1").getURL());

    assertNotNull(registry.get("1.2.3.4.2"));
    assertEquals(registry.get("1.2.3.4.2").getOID(), "1.2.3.4.2");
    assertEquals(registry.get("1.2.3.4.2").getName(), "testMatch");
    assertEquals(registry.get("1.2.3.4.2").getType(), "Matching Rule");
    assertNull(registry.get("1.2.3.4.2").getOrigin());
    assertNull(registry.get("1.2.3.4.2").getURL());

    assertNotNull(registry.get("1.2.3.4.3"));
    assertEquals(registry.get("1.2.3.4.3").getOID(), "1.2.3.4.3");
    assertEquals(registry.get("1.2.3.4.3").getName(), "test-attr");
    assertEquals(registry.get("1.2.3.4.3").getType(), "Attribute Type");
    assertEquals(registry.get("1.2.3.4.3").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.3").getURL());

    assertNotNull(registry.get("1.2.3.4.4"));
    assertEquals(registry.get("1.2.3.4.4").getOID(), "1.2.3.4.4");
    assertEquals(registry.get("1.2.3.4.4").getName(), "test-oc");
    assertEquals(registry.get("1.2.3.4.4").getType(), "Object Class");
    assertNull(registry.get("1.2.3.4.4").getOrigin(), "another-origin");
    assertNull(registry.get("1.2.3.4.4").getURL());

    assertNotNull(registry.get("1.2.3.4.5"));
    assertEquals(registry.get("1.2.3.4.5").getOID(), "1.2.3.4.5");
    assertEquals(registry.get("1.2.3.4.5").getName(), "test-nf");
    assertEquals(registry.get("1.2.3.4.5").getType(), "Name Form");
    assertNull(registry.get("1.2.3.4.5").getOrigin());
    assertNull(registry.get("1.2.3.4.5").getURL());
  }
}
