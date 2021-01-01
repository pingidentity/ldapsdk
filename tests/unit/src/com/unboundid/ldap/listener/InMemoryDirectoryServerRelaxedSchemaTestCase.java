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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the methods that allow relaxing
 * schema compliance.
 */
public final class InMemoryDirectoryServerRelaxedSchemaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Ensures that values which do not conform with their associated attribute
   * syntax will be rejected when the server is configured to do so.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireAttributeSyntaxCompliance()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    assertTrue(cfg.enforceAttributeSyntaxCompliance());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.add(
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    try
    {
      ds.add(
           "dn: cn=Add Invalid,ou=Groups,dc=example,dc=com",
           "objectClass: top",
           "objectClass: groupOfNames",
           "cn: Add Invalid",
           "member: invalid");
      fail("Expected an exception when trying to add a group with an invalid " +
           "member value");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.OBJECT_CLASS_VIOLATION);
    }

    ds.add(
         "dn: cn=Modify Invalid,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Modify Invalid",
         "member: uid=valid,ou=People,dc=example,dc=com");

    try
    {
      ds.modify(
           "dn: cn=Modify Invalid,ou=Groups,dc=example,dc=com",
           "changetype: modify",
           "add: member",
           "member: invalid");
      fail("Expected an exception when trying to modify a group to add an " +
           "invalid member value");
    }
    catch (final LDAPException le)
    {
      // This was expected
      assertResultCodeEquals(le, ResultCode.OBJECT_CLASS_VIOLATION);
    }
  }



  /**
   * Ensures that the server can be configured to allow values which violate
   * the associated attribute syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowDisablingAttributeSyntaxCompliance()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    assertTrue(cfg.enforceAttributeSyntaxCompliance());

    cfg.setEnforceAttributeSyntaxCompliance(false);
    assertFalse(cfg.enforceAttributeSyntaxCompliance());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.add(
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.add(
         "dn: cn=Add Invalid,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Add Invalid",
         "member: invalid");

    ds.add(
         "dn: cn=Modify Invalid,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Modify Invalid",
         "member: uid=valid,ou=People,dc=example,dc=com");

    ds.modify(
         "dn: cn=Modify Invalid,ou=Groups,dc=example,dc=com",
         "changetype: modify",
         "add: member",
         "member: invalid");
  }



  /**
   * Ensures that entries which do not have exactly one structural object class
   * will be rejected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireSingleStructuralObjectClassCompliance()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    assertTrue(cfg.enforceSingleStructuralObjectClass());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    try
    {
      ds.add(
           "dn: ou=No Structural Class,dc=example,dc=com",
           "objectClass: top",
           "objectClass: extensibleObject",
           "ou: No Structural Class");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.OBJECT_CLASS_VIOLATION);
    }

    try
    {
      ds.add(
           "dn: ou=Multiple Structural Classes,dc=example,dc=com",
           "objectClass: top",
           "objectClass: groupOfNames",
           "objectClass: organizationalUnit",
           "ou: Multiple Structural Classes",
           "cn: Test",
           "member: uid=test,ou=People,dc=example,dc=com");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.OBJECT_CLASS_VIOLATION);
    }
  }



  /**
   * Ensures that the server can be configured to allow entries which do not
   * have exactly one structural object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowDisablingSingleStructuralObjectClassCompliance()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    assertTrue(cfg.enforceSingleStructuralObjectClass());

    cfg.setEnforceSingleStructuralObjectClass(false);
    assertFalse(cfg.enforceSingleStructuralObjectClass());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.add(
         "dn: ou=No Structural Class,dc=example,dc=com",
         "objectClass: top",
         "objectClass: extensibleObject",
         "ou: No Structural Class");

    ds.add(
         "dn: ou=Multiple Structural Classes,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "objectClass: organizationalUnit",
         "ou: Multiple Structural Classes",
         "cn: Test",
         "member: uid=test,ou=People,dc=example,dc=com");
  }
}
