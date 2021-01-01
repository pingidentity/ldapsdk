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



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the test methods provided in the
 * in-memory directory server.
 */
public final class InMemoryDirectoryTestMethodsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the methods used to determine whether entries
   * exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryExistence()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(generateDomainEntry("example", "dc=com"));
    ds.add(generateOrgUnitEntry("People", "dc=example,dc=com"));
    ds.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
         "Test", "User", "password"));


    // entryExists(conn, dn)
    assertTrue(ds.entryExists("dc=example,dc=com"));

    assertFalse(ds.entryExists("dc=missing,dc=com"));

    try
    {
      ds.entryExists("malformed-dn");
      fail("Expected an exception from entryExists with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryExists(conn, dn)
    ds.assertEntryExists("dc=example,dc=com");

    try
    {
      ds.assertEntryExists("dc=missing,dc=com");
      throw new Exception("Expected an assertion error from " +
           "assertEntryExists with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntryExists("malformed-dn");
      fail("Expected an LDAP exception from assertEntryExists with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // entryExists(conn, dn, filter)
    assertTrue(ds.entryExists("dc=example,dc=com", "(objectClass=top)"));

    assertFalse(ds.entryExists("dc=example,dc=com", "(objectClass=missing)"));

    assertFalse(ds.entryExists("dc=missing,dc=com", "(objectClass=top)"));

    try
    {
      ds.entryExists("dc=example,dc=com", "malformed-filter");
      fail("Expected an LDAP exception from entryExists with a malformed " +
           "filter.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryExists(conn, dn, filter)
    ds.assertEntryExists("dc=example,dc=com", "(objectClass=top)");

    try
    {
      ds.assertEntryExists("dc=example,dc=com", "(objectClass=missing)");
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with a valid target entry but filter that does not match.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntryExists("dc=missing,dc=com", "(objectClass=top)");
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with a filter and a target entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntryExists("dc=example,dc=com", "malformed-filter");
      fail("Expected an LDAP exception for assertEntryExists with a " +
           "malformed filter.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // entryExists(conn, entry)
    assertTrue(ds.entryExists(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    assertTrue(ds.entryExists(new Entry("dc=example,dc=com")));

    assertTrue(ds.entryExists(new Entry(
         "dn: dc=example,dc=com",
         "dc: example")));

    assertTrue(ds.entryExists(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: domain",
         "dc: example")));

    assertFalse(ds.entryExists(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo")));

    assertFalse(ds.entryExists(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: wrong")));

    assertFalse(ds.entryExists(new Entry(
         "dn: dc=missing,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: missing")));

    try
    {
      ds.entryExists(new Entry(
           "dn: malformed-dn",
           "objectClass: top",
           "objectClass: domain",
           "dc: malformed"));
      fail("Expected an LDAP exception from entryExists with an entry " +
           "containing a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryExists(conn, entry)
    ds.assertEntryExists(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    ds.assertEntryExists(new Entry("dc=example,dc=com"));

    ds.assertEntryExists(new Entry(
         "dn: dc=example,dc=com",
         "dc: example"));

    ds.assertEntryExists(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: domain",
         "dc: example"));

    try
    {
      ds.assertEntryExists(new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example",
           "description: foo"));
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with an entry missing an expected attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      ds.assertEntryExists(new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: wrong"));
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with an entry with the wrong value for an attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      ds.assertEntryExists(new Entry(
           "dn: dc=missing,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: missing"));
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntryExists(new Entry(
           "dn: malformed-dn",
           "objectClass: top",
           "objectClass: domain",
           "dc: malformed"));
      fail("Expected an LDAP exception from assertEntryExists with an entry " +
           "that has a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // getMissingEntryDNs(conn, dn...)
    List<String> missingDNs = ds.getMissingEntryDNs("dc=example,dc=com");
    assertNotNull(missingDNs);
    assertTrue(missingDNs.isEmpty());

    missingDNs = ds.getMissingEntryDNs(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(missingDNs);
    assertTrue(missingDNs.isEmpty());

    missingDNs = ds.getMissingEntryDNs(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=missing,ou=People,dc=example,dc=com");
    assertNotNull(missingDNs);
    assertEquals(missingDNs.size(), 1);
    assertEquals(new DN(missingDNs.get(0)),
         new DN("uid=missing,ou=People,dc=example,dc=com"));

    missingDNs = ds.getMissingEntryDNs(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=missing1,ou=People,dc=example,dc=com",
         "uid=missing2,ou=People,dc=example,dc=com");
    assertNotNull(missingDNs);
    assertEquals(missingDNs.size(), 2);
    assertEquals(new DN(missingDNs.get(0)),
         new DN("uid=missing1,ou=People,dc=example,dc=com"));
    assertEquals(new DN(missingDNs.get(1)),
         new DN("uid=missing2,ou=People,dc=example,dc=com"));

    try
    {
      ds.getMissingEntryDNs(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "malformed-dn");
      fail("Expected an exception from getMissingEntryDNs with a malformed DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // getMissingEntryDNs(conn, Collection<dn>)
    missingDNs = ds.getMissingEntryDNs(Arrays.asList("dc=example,dc=com"));
    assertNotNull(missingDNs);
    assertTrue(missingDNs.isEmpty());

    missingDNs = ds.getMissingEntryDNs(Arrays.asList(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(missingDNs);
    assertTrue(missingDNs.isEmpty());

    missingDNs = ds.getMissingEntryDNs(Arrays.asList(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=missing,ou=People,dc=example,dc=com"));
    assertNotNull(missingDNs);
    assertEquals(missingDNs.size(), 1);
    assertEquals(new DN(missingDNs.get(0)),
         new DN("uid=missing,ou=People,dc=example,dc=com"));

    missingDNs = ds.getMissingEntryDNs(Arrays.asList(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=missing1,ou=People,dc=example,dc=com",
         "uid=missing2,ou=People,dc=example,dc=com"));
    assertNotNull(missingDNs);
    assertEquals(missingDNs.size(), 2);
    assertEquals(new DN(missingDNs.get(0)),
         new DN("uid=missing1,ou=People,dc=example,dc=com"));
    assertEquals(new DN(missingDNs.get(1)),
         new DN("uid=missing2,ou=People,dc=example,dc=com"));

    try
    {
      ds.getMissingEntryDNs(Arrays.asList(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "malformed-dn"));
      fail("Expected an exception from getMissingEntryDNs with a malformed DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntriesExist(conn, dn...)
    ds.assertEntriesExist("dc=example,dc=com");

    ds.assertEntriesExist(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");

    try
    {
      ds.assertEntriesExist(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=missing,ou=People,dc=example,dc=com");
      throw new Exception("Expected an assertion error in assertEntriesExist " +
           "with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntriesExist(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=missing1,ou=People,dc=example,dc=com",
           "uid=missing2,ou=People,dc=example,dc=com");
      throw new Exception("Expected an assertion error in assertEntriesExist " +
           "with multiple missing entries.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntriesExist(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "malformed-dn");
      fail("Expected an LDAP exception in assertEntriesExist with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntriesExist(conn, Collection<dn>)
    ds.assertEntriesExist(Arrays.asList("dc=example,dc=com"));

    ds.assertEntriesExist(Arrays.asList(
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com"));

    try
    {
      ds.assertEntriesExist(Arrays.asList(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=missing,ou=People,dc=example,dc=com"));
      throw new Exception("Expected an assertion error in assertEntriesExist " +
           "with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntriesExist(Arrays.asList(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=missing1,ou=People,dc=example,dc=com",
           "uid=missing2,ou=People,dc=example,dc=com"));
      throw new Exception("Expected an assertion error in assertEntriesExist " +
           "with multiple missing entries.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntriesExist(Arrays.asList(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "malformed-dn"));
      fail("Expected an LDAP exception in assertEntriesExist with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // getMissingAttributes(conn, dn, name...)
    List<String> missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", "objectClass");
    assertNotNull(missingAttrNames);
    assertTrue(missingAttrNames.isEmpty());

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", "objectClass", "dc");
    assertNotNull(missingAttrNames);
    assertTrue(missingAttrNames.isEmpty());

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", "description");
    assertNotNull(missingAttrNames);
    assertEquals(missingAttrNames.size(), 1);
    assertEquals(missingAttrNames.get(0), "description");

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", "objectClass", "dc", "description", "o");
    assertNotNull(missingAttrNames);
    assertEquals(missingAttrNames.size(), 2);
    assertEquals(missingAttrNames.get(0), "description");
    assertEquals(missingAttrNames.get(1), "o");

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=missing,dc=com", "objectClass");
    assertNull(missingAttrNames);

    try
    {
      ds.getMissingAttributeNames("malformed-dn",
           "objectClass");
      fail("Expected an LDAP exception from getMissingAttributeNames with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }



    // getMissingAttributes(conn, dn, Collection<name>)
    missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", Arrays.asList("objectClass"));
    assertNotNull(missingAttrNames);
    assertTrue(missingAttrNames.isEmpty());

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", Arrays.asList("objectClass", "dc"));
    assertNotNull(missingAttrNames);
    assertTrue(missingAttrNames.isEmpty());

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=example,dc=com", Arrays.asList("description"));
    assertNotNull(missingAttrNames);
    assertEquals(missingAttrNames.size(), 1);
    assertEquals(missingAttrNames.get(0), "description");

    missingAttrNames = ds.getMissingAttributeNames("dc=example,dc=com",
         Arrays.asList("objectClass", "dc", "description", "o"));
    assertNotNull(missingAttrNames);
    assertEquals(missingAttrNames.size(), 2);
    assertEquals(missingAttrNames.get(0), "description");
    assertEquals(missingAttrNames.get(1), "o");

    missingAttrNames = ds.getMissingAttributeNames(
         "dc=missing,dc=com", "objectClass");
    assertNull(missingAttrNames);

    try
    {
      ds.getMissingAttributeNames("malformed-dn",
           Arrays.asList("objectClass"));
      fail("Expected an LDAP exception from getMissingAttributeNames with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }



    // assertAttributeExists(conn, dn, name...)
    ds.assertAttributeExists("dc=example,dc=com", "objectClass");

    ds.assertAttributeExists("dc=example,dc=com", "objectClass", "dc");

    try
    {
      ds.assertAttributeExists("dc=example,dc=com", "missingAttr");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeExits with a missing attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeExists("dc=missing,dc=com", "objectClass");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeExits with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeExists("malformed-dn", "objectClass");
      fail("Expected an LDAP exception from assertAttributeExits with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertAttributeExists(conn, dn, Collection<name>)
    ds.assertAttributeExists("dc=example,dc=com", Arrays.asList("objectClass"));

    ds.assertAttributeExists("dc=example,dc=com",
         Arrays.asList("objectClass", "dc"));

    try
    {
      ds.assertAttributeExists("dc=example,dc=com",
           Arrays.asList("missingAttr"));
      throw new Exception("Expected an assertion error from " +
           "assertAttributeExits with a missing attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeExists("dc=missing,dc=com",
           Arrays.asList("objectClass"));
      throw new Exception("Expected an assertion error from " +
           "assertAttributeExits with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeExists("malformed-dn", Arrays.asList("objectClass"));
      fail("Expected an LDAP exception from assertAttributeExits with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // getMissingAttributeValues(conn, dn, name, value...)
    List<String> missingValues = ds.getMissingAttributeValues(
         "dc=example,dc=com", "objectClass", "top");
    assertNotNull(missingValues);
    assertTrue(missingValues.isEmpty());

    missingValues = ds.getMissingAttributeValues("dc=example,dc=com",
         "objectClass", "top", "domain");
    assertNotNull(missingValues);
    assertTrue(missingValues.isEmpty());

    missingValues = ds.getMissingAttributeValues("dc=example,dc=com",
         "objectClass", "top", "domain", "extensibleObject");
    assertNotNull(missingValues);
    assertEquals(missingValues.size(), 1);
    assertEquals(missingValues.get(0), "extensibleObject");

    missingValues = ds.getMissingAttributeValues("dc=missing,dc=com",
         "objectClass", "top");
    assertNull(missingValues);

    try
    {
      ds.getMissingAttributeValues("malformed-dn", "objectClass", "top");
      fail("Expected an LDAP exception from getMissingAttributeValues with " +
           "a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // getMissingAttributeValues(conn, dn, name, Collection<value>)
    missingValues = ds.getMissingAttributeValues(
         "dc=example,dc=com", "objectClass", Arrays.asList("top"));
    assertNotNull(missingValues);
    assertTrue(missingValues.isEmpty());

    missingValues = ds.getMissingAttributeValues("dc=example,dc=com",
         "objectClass", Arrays.asList("top", "domain"));
    assertNotNull(missingValues);
    assertTrue(missingValues.isEmpty());

    missingValues = ds.getMissingAttributeValues("dc=example,dc=com",
         "objectClass", Arrays.asList("top", "domain", "extensibleObject"));
    assertNotNull(missingValues);
    assertEquals(missingValues.size(), 1);
    assertEquals(missingValues.get(0), "extensibleObject");

    missingValues = ds.getMissingAttributeValues("dc=missing,dc=com",
         "objectClass", "top");
    assertNull(missingValues);

    try
    {
      ds.getMissingAttributeValues("malformed-dn", "objectClass",
           Arrays.asList("top"));
      fail("Expected an LDAP exception from getMissingAttributeValues with " +
           "a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertValueExists(conn, dn, name, value...)
    ds.assertValueExists("dc=example,dc=com", "objectClass", "top");

    ds.assertValueExists("dc=example,dc=com", "objectClass", "top", "domain");

    try
    {
      ds.assertValueExists("dc=example,dc=com", "objectClass", "top",
           "domain", "extensibleObject");
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing value.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueExists("dc=example,dc=com", "description", "foo",
           "domain", "extensibleObject");
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueExists("dc=missing,dc=com", "objectClass", "top");
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing target entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueExists("malformed-dn", "objectClass", "top");
      fail("Expected an LDAP exception from assertValueExists with a " +
           "malformed target DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertValueExists(conn, dn, name, Collection<value>)
    ds.assertValueExists("dc=example,dc=com", "objectClass",
         Arrays.asList("top"));

    ds.assertValueExists("dc=example,dc=com", "objectClass",
         Arrays.asList("top", "domain"));

    try
    {
      ds.assertValueExists("dc=example,dc=com", "objectClass",
           Arrays.asList("top", "domain", "extensibleObject"));
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing value.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueExists("dc=example,dc=com", "description",
           Arrays.asList("foo", "domain", "extensibleObject"));
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueExists("dc=missing,dc=com", "objectClass",
           Arrays.asList("top"));
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing target entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueExists("malformed-dn", "objectClass",
           Arrays.asList("top"));
      fail("Expected an LDAP exception from assertValueExists with a " +
           "malformed target DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryMissing(conn, dn)
    ds.assertEntryMissing("dc=missing,dc=com");

    try
    {
      ds.assertEntryMissing("dc=example,dc=com");
      throw new Exception("Expected an assertion error from " +
           "assertEntryMissing with an existing DN.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertEntryMissing("malformed-dn");
      fail("Expected an LDAP exception from assertEntryMissing with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertAttributeMissing(conn, dn, name...)
    ds.assertAttributeMissing("dc=example,dc=com", "description");

    ds.assertAttributeMissing("dc=example,dc=com", "description", "o");

    try
    {
      ds.assertAttributeMissing("dc=example,dc=com", "objectClass");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeMissing for an attribute that exists.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeMissing("dc=missing,dc=com", "description");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeMissing for an entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeMissing("malformed-dn", "description");
      fail("Expected an LDAP exception from assertAttributeMissing for a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertAttributeMissing(conn, dn, Collection<name>)
    ds.assertAttributeMissing("dc=example,dc=com",
         Arrays.asList("description"));

    ds.assertAttributeMissing("dc=example,dc=com",
         Arrays.asList("description", "o"));

    try
    {
      ds.assertAttributeMissing("dc=example,dc=com",
           Arrays.asList("objectClass"));
      throw new Exception("Expected an assertion error from " +
           "assertAttributeMissing for an attribute that exists.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeMissing("dc=missing,dc=com",
           Arrays.asList("description"));
      throw new Exception("Expected an assertion error from " +
           "assertAttributeMissing for an entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertAttributeMissing("malformed-dn", Arrays.asList("description"));
      fail("Expected an LDAP exception from assertAttributeMissing for a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertValueMissing(conn, dn, name, value...)
    ds.assertValueMissing("dc=example,dc=com", "objectClass",
         "extensibleObject");

    ds.assertValueMissing("dc=example,dc=com", "description", "foo");

    try
    {
      ds.assertValueMissing("dc=example,dc=com", "objectClass", "top");
      throw new Exception("Expected an assertion error in assertValueMissing " +
           "for a value that exists");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueMissing("dc=missing,dc=com", "description", "foo");
      throw new Exception("Expected an assertion error in assertValueMissing " +
           "for an entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueMissing("malformed-dn", "description", "foo");
      fail("Expected an LDAP exception in assertValueMissing for a malformed " +
           "DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertValueMissing(conn, dn, name, Collection<value>)
    ds.assertValueMissing("dc=example,dc=com", "objectClass",
         Arrays.asList("extensibleObject"));

    ds.assertValueMissing("dc=example,dc=com", "description",
         Arrays.asList("foo"));

    try
    {
      ds.assertValueMissing("dc=example,dc=com", "objectClass",
           Arrays.asList("top"));
      throw new Exception("Expected an assertion error in assertValueMissing " +
           "for a value that exists");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueMissing("dc=missing,dc=com", "description",
           Arrays.asList("foo"));
      throw new Exception("Expected an assertion error in assertValueMissing " +
           "for an entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      ds.assertValueMissing("malformed-dn", "description",
           Arrays.asList("foo"));
      fail("Expected an LDAP exception in assertValueMissing for a malformed " +
           "DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }
}
