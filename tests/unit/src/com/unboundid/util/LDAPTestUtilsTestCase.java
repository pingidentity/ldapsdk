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
package com.unboundid.util;



import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.TestSearchResultListener;



/**
 * This class provides test coverage for the {@code LDAPTestUtils} class.
 */
public final class LDAPTestUtilsTestCase
       extends UtilTestCase
{
  /**
   * Provides test coverage for the generateDomainEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateDomainEntry()
         throws Exception
  {
    Entry e = generateDomainEntry("com", null);
    assertEquals(e, new Entry(
         "dn: dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: com"));

    e = generateDomainEntry("com", "");
    assertEquals(e, new Entry(
         "dn: dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: com"));

    e = generateDomainEntry("example", "dc=com");
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    e = generateDomainEntry("example", "dc=com",
         new Attribute("description", "foo"));
    assertEquals(e, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo"));
  }



  /**
   * Provides test coverage for the generateOrgEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateOrgEntry()
         throws Exception
  {
    Entry e = generateOrgEntry("example.com", null);
    assertEquals(e, new Entry(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com"));

    e = generateOrgEntry("example.com", "");
    assertEquals(e, new Entry(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com"));

    e = generateOrgEntry("example.com", "cn=test");
    assertEquals(e, new Entry(
         "dn: o=example.com,cn=test",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com"));

    e = generateOrgEntry("example.com", "cn=test",
         new Attribute("description", "foo"));
    assertEquals(e, new Entry(
         "dn: o=example.com,cn=test",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com",
         "description: foo"));
  }



  /**
   * Provides test coverage for the generateOrgUnitEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateOrgUnitEntry()
         throws Exception
  {
    Entry e = generateOrgUnitEntry("People", null);
    assertEquals(e, new Entry(
         "dn: ou=People",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People"));

    e = generateOrgUnitEntry("People", "");
    assertEquals(e, new Entry(
         "dn: ou=People",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People"));

    e = generateOrgUnitEntry("People", "dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People"));

    e = generateOrgUnitEntry("People", "dc=example,dc=com",
         new Attribute("description", "foo"));
    assertEquals(e, new Entry(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo"));
  }



  /**
   * Provides test coverage for the generateCountryEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateCountryEntry()
         throws Exception
  {
    Entry e = generateCountryEntry("US", null);
    assertEquals(e, new Entry(
         "dn: c=US",
         "objectClass: top",
         "objectClass: country",
         "c: US"));

    e = generateCountryEntry("US", "");
    assertEquals(e, new Entry(
         "dn: c=US",
         "objectClass: top",
         "objectClass: country",
         "c: US"));

    e = generateCountryEntry("US", "dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: c=US,dc=example,dc=com",
         "objectClass: top",
         "objectClass: country",
         "c: US"));

    e = generateCountryEntry("US", "dc=example,dc=com",
         new Attribute("description", "foo"));
    assertEquals(e, new Entry(
         "dn: c=US,dc=example,dc=com",
         "objectClass: top",
         "objectClass: country",
         "c: US",
         "description: foo"));
  }



  /**
   * Provides test coverage for the generateUserEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateUserEntry()
         throws Exception
  {
    Entry e = generateUserEntry("test.user",
         "ou=People,dc=example,dc=com", "Test", "User", "password");
    assertEquals(e, new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password"));

    e = generateUserEntry("test.user",
         "ou=People,dc=example,dc=com", "Test", "User", null);
    assertEquals(e, new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User"));

    e = generateUserEntry("test.user",
         "ou=People,dc=example,dc=com", "Test", "User", "password",
         new Attribute("description", "foo"),
         new Attribute("mail", "test.user@example.com"));
    assertEquals(e, new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: foo",
         "mail: test.user@example.com"));

    e = generateUserEntry("test.user",
         "ou=People,dc=example,dc=com", "Test", "User", null,
         new Attribute("description", "foo"),
         new Attribute("mail", "test.user@example.com"));
    assertEquals(e, new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "description: foo",
         "mail: test.user@example.com"));
  }



  /**
   * Provides test coverage for the generateGroupOfNamesEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateGroupOfNamesEntry()
         throws Exception
  {
    Entry e = generateGroupOfNamesEntry("test", null,
         "uid=user.1,ou=People,dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: cn=test",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: test",
         "member: uid=user.1,ou=People,dc=example,dc=com"));

    e = generateGroupOfNamesEntry("test", "",
         "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: cn=test",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: test",
         "member: uid=user.1,ou=People,dc=example,dc=com",
         "member: uid=user.2,ou=People,dc=example,dc=com"));

    e = generateGroupOfNamesEntry("test", "ou=Groups,dc=example,dc=com",
         "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com",
         "uid=user.3,ou=People,dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: cn=test,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: test",
         "member: uid=user.1,ou=People,dc=example,dc=com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: uid=user.3,ou=People,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the generateGroupOfUniqueNamesEntry method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateGroupOfUniqueNamesEntry()
         throws Exception
  {
    Entry e = generateGroupOfUniqueNamesEntry("test", null,
         "uid=user.1,ou=People,dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: cn=test",
         "objectClass: top",
         "objectClass: groupOfUniqueNames",
         "cn: test",
         "uniqueMember: uid=user.1,ou=People,dc=example,dc=com"));

    e = generateGroupOfUniqueNamesEntry("test", "",
         "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: cn=test",
         "objectClass: top",
         "objectClass: groupOfUniqueNames",
         "cn: test",
         "uniqueMember: uid=user.1,ou=People,dc=example,dc=com",
         "uniqueMember: uid=user.2,ou=People,dc=example,dc=com"));

    e = generateGroupOfUniqueNamesEntry("test", "ou=Groups,dc=example,dc=com",
         "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com",
         "uid=user.3,ou=People,dc=example,dc=com");
    assertEquals(e, new Entry(
         "dn: cn=test,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfUniqueNames",
         "cn: test",
         "uniqueMember: uid=user.1,ou=People,dc=example,dc=com",
         "uniqueMember: uid=user.2,ou=People,dc=example,dc=com",
         "uniqueMember: uid=user.3,ou=People,dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the methods used to determine whether entries
   * exist.
   *
   * @param  conn  The interface to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testInterfaces")
  public void testEntryExistence(final LDAPInterface conn)
         throws Exception
  {
    // entryExists(conn, dn)
    assertTrue(entryExists(conn, "dc=example,dc=com"));

    assertFalse(entryExists(conn, "dc=missing,dc=com"));

    try
    {
      entryExists(conn, "malformed-dn");
      fail("Expected an exception from entryExists with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryExists(conn, dn)
    assertEntryExists(conn, "dc=example,dc=com");

    try
    {
      assertEntryExists(conn, "dc=missing,dc=com");
      throw new Exception("Expected an assertion error from " +
           "assertEntryExists with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryExists(conn, "malformed-dn");
      fail("Expected an LDAP exception from assertEntryExists with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // entryExists(conn, dn, filter)
    assertTrue(entryExists(conn, "dc=example,dc=com",
         "(objectClass=top)"));

    assertFalse(entryExists(conn, "dc=example,dc=com",
         "(objectClass=missing)"));

    assertFalse(entryExists(conn, "dc=missing,dc=com",
         "(objectClass=top)"));

    try
    {
      entryExists(conn, "dc=example,dc=com", "malformed-filter");
      fail("Expected an LDAP exception from entryExists with a malformed " +
           "filter.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryExists(conn, dn, filter)
    assertEntryExists(conn, "dc=example,dc=com",
         "(objectClass=top)");

    try
    {
      assertEntryExists(conn, "dc=example,dc=com",
           "(objectClass=missing)");
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with a valid target entry but filter that does not match.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryExists(conn, "dc=missing,dc=com",
           "(objectClass=top)");
      throw new Exception("Expected an assertion error for assertEntryExists " +
           "with a filter and a target entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryExists(conn, "dc=example,dc=com",
           "malformed-filter");
      fail("Expected an LDAP exception for assertEntryExists with a " +
           "malformed filter.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // entryExists(conn, entry)
    assertTrue(entryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    assertTrue(entryExists(conn, new Entry("dc=example,dc=com")));

    assertTrue(entryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "dc: example")));

    assertTrue(entryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: domain",
         "dc: example")));

    assertFalse(entryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo")));

    assertFalse(entryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: wrong")));

    assertFalse(entryExists(conn, new Entry(
         "dn: dc=missing,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: missing")));

    try
    {
      entryExists(conn, new Entry(
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
    assertEntryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertEntryExists(conn, new Entry("dc=example,dc=com"));

    assertEntryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "dc: example"));

    assertEntryExists(conn, new Entry(
         "dn: dc=example,dc=com",
         "objectClass: domain",
         "dc: example"));

    try
    {
      assertEntryExists(conn, new Entry(
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
      assertEntryExists(conn, new Entry(
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
      assertEntryExists(conn, new Entry(
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
      assertEntryExists(conn, new Entry(
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
    List<String> missingDNs = getMissingEntryDNs(conn,
         "dc=example,dc=com");
    assertNotNull(missingDNs);
    assertTrue(missingDNs.isEmpty());

    missingDNs = getMissingEntryDNs(conn,
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(missingDNs);
    assertTrue(missingDNs.isEmpty());

    missingDNs = getMissingEntryDNs(conn,
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=missing,ou=People,dc=example,dc=com");
    assertNotNull(missingDNs);
    assertEquals(missingDNs.size(), 1);
    assertEquals(new DN(missingDNs.get(0)),
         new DN("uid=missing,ou=People,dc=example,dc=com"));

    missingDNs = getMissingEntryDNs(conn,
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
      getMissingEntryDNs(conn,
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "malformed-dn");
      fail("Expected an exception from getMissingEntryDNs with a malformed DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntriesExist(conn, dn...)
    assertEntriesExist(conn,
         "dc=example,dc=com");

    assertEntriesExist(conn,
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");

    try
    {
      assertEntriesExist(conn,
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
      assertEntriesExist(conn,
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
      assertEntriesExist(conn,
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



    // getMissingAttributes(conn, dn, name...)
    List<String> missingAttrNames = getMissingAttributeNames(conn,
         "dc=example,dc=com", "objectClass");
    assertNotNull(missingAttrNames);
    assertTrue(missingAttrNames.isEmpty());

    missingAttrNames = getMissingAttributeNames(conn,
         "dc=example,dc=com", "objectClass", "dc");
    assertNotNull(missingAttrNames);
    assertTrue(missingAttrNames.isEmpty());

    missingAttrNames = getMissingAttributeNames(conn,
         "dc=example,dc=com", "description");
    assertNotNull(missingAttrNames);
    assertEquals(missingAttrNames.size(), 1);
    assertEquals(missingAttrNames.get(0), "description");

    missingAttrNames = getMissingAttributeNames(conn,
         "dc=example,dc=com", "objectClass", "dc", "description", "o");
    assertNotNull(missingAttrNames);
    assertEquals(missingAttrNames.size(), 2);
    assertEquals(missingAttrNames.get(0), "description");
    assertEquals(missingAttrNames.get(1), "o");

    missingAttrNames = getMissingAttributeNames(conn,
         "dc=missing,dc=com", "objectClass");
    assertNull(missingAttrNames);

    try
    {
      getMissingAttributeNames(conn, "malformed-dn",
           "objectClass");
      fail("Expected an LDAP exception from getMissingAttributeNames with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }



    // assertAttributeExists(conn, dn, name...)
    assertAttributeExists(conn, "dc=example,dc=com", "objectClass");

    assertAttributeExists(conn, "dc=example,dc=com", "objectClass", "dc");

    try
    {
      assertAttributeExists(conn, "dc=example,dc=com", "missingAttr");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeExits with a missing attribute.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertAttributeExists(conn, "dc=missing,dc=com", "objectClass");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeExits with a missing entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertAttributeExists(conn, "malformed-dn", "objectClass");
      fail("Expected an LDAP exception from assertAttributeExits with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // getMissingAttributeValues(conn, dn, name, value...)
    List<String> missingValues = getMissingAttributeValues(conn,
         "dc=example,dc=com", "objectClass", "top");
    assertNotNull(missingValues);
    assertTrue(missingValues.isEmpty());

    missingValues = getMissingAttributeValues(conn, "dc=example,dc=com",
         "objectClass", "top", "domain");
    assertNotNull(missingValues);
    assertTrue(missingValues.isEmpty());

    missingValues = getMissingAttributeValues(conn, "dc=example,dc=com",
         "objectClass", "top", "domain", "extensibleObject");
    assertNotNull(missingValues);
    assertEquals(missingValues.size(), 1);
    assertEquals(missingValues.get(0), "extensibleObject");

    missingValues = getMissingAttributeValues(conn, "dc=missing,dc=com",
         "objectClass", "top");
    assertNull(missingValues);

    try
    {
      getMissingAttributeValues(conn, "malformed-dn", "objectClass", "top");
      fail("Expected an LDAP exception from getMissingAttributeValues with " +
           "a malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertValueExists(conn, dn, name, value...)
    assertValueExists(conn, "dc=example,dc=com", "objectClass", "top");

    assertValueExists(conn, "dc=example,dc=com", "objectClass", "top",
         "domain");

    try
    {
      assertValueExists(conn, "dc=example,dc=com", "objectClass", "top",
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
      assertValueExists(conn, "dc=example,dc=com", "description", "foo",
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
      assertValueExists(conn, "dc=missing,dc=com", "objectClass", "top");
      throw new Exception("Expected an assertion error from " +
           "assertValueExists with a missing target entry.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertValueExists(conn, "malformed-dn", "objectClass", "top");
      fail("Expected an LDAP exception from assertValueExists with a " +
           "malformed target DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertEntryMissing(conn, dn)
    assertEntryMissing(conn, "dc=missing,dc=com");

    try
    {
      assertEntryMissing(conn, "dc=example,dc=com");
      throw new Exception("Expected an assertion error from " +
           "assertEntryMissing with an existing DN.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryMissing(conn, "malformed-dn");
      fail("Expected an LDAP exception from assertEntryMissing with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertAttributeMissing(conn, dn, name...)
    assertAttributeMissing(conn, "dc=example,dc=com", "description");

    assertAttributeMissing(conn, "dc=example,dc=com", "description", "o");

    try
    {
      assertAttributeMissing(conn, "dc=example,dc=com", "objectClass");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeMissing for an attribute that exists.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertAttributeMissing(conn, "dc=missing,dc=com", "description");
      throw new Exception("Expected an assertion error from " +
           "assertAttributeMissing for an entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertAttributeMissing(conn, "malformed-dn", "description");
      fail("Expected an LDAP exception from assertAttributeMissing for a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    // assertValueMissing(conn, dn, name, value...)
    assertValueMissing(conn, "dc=example,dc=com", "objectClass",
         "extensibleObject");

    assertValueMissing(conn, "dc=example,dc=com", "description", "foo");

    try
    {
      assertValueMissing(conn, "dc=example,dc=com", "objectClass", "top");
      throw new Exception("Expected an assertion error in assertValueMissing " +
           "for a value that exists");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertValueMissing(conn, "dc=missing,dc=com", "description", "foo");
      throw new Exception("Expected an assertion error in assertValueMissing " +
           "for an entry that does not exist.");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertValueMissing(conn, "malformed-dn", "description", "foo");
      fail("Expected an LDAP exception in assertValueMissing for a malformed " +
           "DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }



    if (conn instanceof LDAPConnection)
    {
      ((LDAPConnection) conn).close();
    }
    else if (conn instanceof LDAPConnectionPool)
    {
      ((LDAPConnectionPool) conn).close();
    }
  }



  /**
   * Retrieves a set of interfaces that may be used to communicate with the
   * server.
   *
   * @return  A set of interfaces that may be used to communicate with the
   *          server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testInterfaces")
  public Object[][] getTestInterfaces()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    return new Object[][]
    {
      new Object[] { ds.getConnection() },
      new Object[] { ds.getConnectionPool(1) },
    };
  }



  /**
   * Provides test coverage for methods pertaining to result codes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testResultCodeMethods()
         throws Exception
  {
    // Test the assertResultCodeEquals method with a result.
    LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS);

    assertResultCodeEquals(result, ResultCode.SUCCESS);
    assertResultCodeEquals(result, ResultCode.SUCCESS, ResultCode.COMPARE_TRUE);
    assertResultCodeEquals(result, ResultCode.COMPARE_TRUE, ResultCode.SUCCESS);

    try
    {
      assertResultCodeEquals(result, ResultCode.NO_SUCH_OBJECT);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeEquals(result, ResultCode.NO_SUCH_OBJECT,
           ResultCode.OTHER);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertResultCodeEquals method with an exception.
    LDAPException exception = new LDAPException(result);

    assertResultCodeEquals(exception, ResultCode.SUCCESS);
    assertResultCodeEquals(exception, ResultCode.SUCCESS,
         ResultCode.COMPARE_TRUE);
    assertResultCodeEquals(exception, ResultCode.COMPARE_TRUE,
         ResultCode.SUCCESS);

    try
    {
      assertResultCodeEquals(exception, ResultCode.NO_SUCH_OBJECT);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeEquals(exception, ResultCode.NO_SUCH_OBJECT,
           ResultCode.OTHER);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertResultCodeEquals method with a request.
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();
    final LDAPConnection badConn = ds.getConnection();
    badConn.close();

    result = assertResultCodeEquals(conn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.SUCCESS);
    assertNotNull(result);

    result = assertResultCodeEquals(conn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.SUCCESS, ResultCode.COMPARE_TRUE);
    assertNotNull(result);

    result = assertResultCodeEquals(conn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.COMPARE_TRUE, ResultCode.SUCCESS);
    assertNotNull(result);

    result = assertResultCodeEquals(conn,
         new SearchRequest("cn=missing", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.NO_SUCH_OBJECT);
    assertNotNull(result);

    result = assertResultCodeEquals(conn,
         new SearchRequest("cn=missing", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.NO_SUCH_OBJECT, ResultCode.COMPARE_TRUE);
    assertNotNull(result);

    result = assertResultCodeEquals(conn,
         new SearchRequest("cn=missing", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.COMPARE_TRUE, ResultCode.NO_SUCH_OBJECT);
    assertNotNull(result);

    result = assertResultCodeEquals(badConn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.CONNECT_ERROR, ResultCode.SERVER_DOWN);
    assertNotNull(result);

    try
    {
      assertResultCodeEquals(conn,
           new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
           ResultCode.NO_SUCH_OBJECT);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeEquals(conn,
           new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
           ResultCode.NO_SUCH_OBJECT, ResultCode.OTHER);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeEquals(conn,
           new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
           ResultCode.OTHER, ResultCode.NO_SUCH_OBJECT);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertResultCodeNot method with a result.
    result = new LDAPResult(1, ResultCode.SUCCESS);

    assertResultCodeNot(result, ResultCode.NO_SUCH_OBJECT);
    assertResultCodeNot(result, ResultCode.NO_SUCH_OBJECT, ResultCode.OTHER);

    try
    {
      assertResultCodeNot(result, ResultCode.SUCCESS);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeNot(result, ResultCode.SUCCESS, ResultCode.OTHER);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeNot(result, ResultCode.OTHER, ResultCode.SUCCESS);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertResultCodeEquals method with an exception.
    exception = new LDAPException(result);

    assertResultCodeNot(exception, ResultCode.NO_SUCH_OBJECT);
    assertResultCodeNot(exception, ResultCode.NO_SUCH_OBJECT, ResultCode.OTHER);

    try
    {
      assertResultCodeNot(exception, ResultCode.SUCCESS);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeNot(exception, ResultCode.SUCCESS, ResultCode.OTHER);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeNot(exception, ResultCode.OTHER, ResultCode.SUCCESS);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertResultCodeNot method with a request.
    result = assertResultCodeNot(conn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.NO_SUCH_OBJECT);
    assertNotNull(result);

    result = assertResultCodeNot(conn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.NO_SUCH_OBJECT, ResultCode.COMPARE_TRUE);
    assertNotNull(result);

    result = assertResultCodeNot(conn,
         new SearchRequest("cn=missing", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.SUCCESS);
    assertNotNull(result);

    result = assertResultCodeNot(conn,
         new SearchRequest("cn=missing", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.SUCCESS, ResultCode.COMPARE_TRUE);
    assertNotNull(result);

    result = assertResultCodeNot(badConn,
         new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
         ResultCode.SUCCESS, ResultCode.COMPARE_TRUE);
    assertNotNull(result);

    try
    {
      assertResultCodeNot(conn,
           new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
           ResultCode.SUCCESS);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeNot(conn,
           new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
           ResultCode.SUCCESS, ResultCode.OTHER);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertResultCodeNot(conn,
           new SearchRequest("", SearchScope.BASE, "(objectClass=*)"),
           ResultCode.OTHER, ResultCode.SUCCESS);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    conn.close();
  }



  /**
   * Provides test coverage for the methods related to the matched DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMatchedDN()
         throws Exception
  {
    // Test the assertContainsMatchedDN method with a result.
    final LDAPResult resultWithMatchedDN = new LDAPResult(1,
         ResultCode.NO_SUCH_OBJECT, "foo", "dc=example,dc=com",
         (String[]) null, (Control[]) null);
    final LDAPResult resultWithoutMatchedDN = new LDAPResult(1,
         ResultCode.SUCCESS);

    assertContainsMatchedDN(resultWithMatchedDN);

    try
    {
      assertContainsMatchedDN(resultWithoutMatchedDN);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertContainsMatchedDN method with an exception.
    final LDAPException exceptionWithMatchedDN =
         new LDAPException(resultWithMatchedDN);
    final LDAPException exceptionWithoutMatchedDN =
         new LDAPException(resultWithoutMatchedDN);

    assertContainsMatchedDN(exceptionWithMatchedDN);

    try
    {
      assertContainsMatchedDN(exceptionWithoutMatchedDN);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingMatchedDN method with a result.
    assertMissingMatchedDN(resultWithoutMatchedDN);

    try
    {
      assertMissingMatchedDN(resultWithMatchedDN);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingMatchedDN method with an exception.
    assertMissingMatchedDN(exceptionWithoutMatchedDN);

    try
    {
      assertMissingMatchedDN(exceptionWithMatchedDN);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMatchedDNEquals method with a result.
    assertMatchedDNEquals(resultWithMatchedDN,  "dc=example,dc=com");

    try
    {
      assertMatchedDNEquals(resultWithoutMatchedDN, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      assertMatchedDNEquals(resultWithMatchedDN, "dc=wrong,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }


    // Test the assertMatchedDNEquals method with an exception.
    assertMatchedDNEquals(exceptionWithMatchedDN,  "dc=example,dc=com");

    try
    {
      assertMatchedDNEquals(exceptionWithoutMatchedDN, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      assertMatchedDNEquals(exceptionWithMatchedDN, "dc=wrong,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the methods related to the diagnostic message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiagnosticMessage()
         throws Exception
  {
    // Test the assertContainsDiagnosticMessage method with a result.
    final LDAPResult resultWithDiagnosticMessage = new LDAPResult(1,
         ResultCode.NO_SUCH_OBJECT, "foo", "dc=example,dc=com",
         (String[]) null, (Control[]) null);
    final LDAPResult resultWithoutDiagnosticMessage = new LDAPResult(1,
         ResultCode.SUCCESS);

    assertContainsDiagnosticMessage(resultWithDiagnosticMessage);

    try
    {
      assertContainsDiagnosticMessage(resultWithoutDiagnosticMessage);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertContainsDiagnosticMessage method with an exception.
    final LDAPException exceptionWithDiagnosticMessage =
         new LDAPException(resultWithDiagnosticMessage);
    final LDAPException exceptionWithoutDiagnosticMessage =
         new LDAPException(resultWithoutDiagnosticMessage);

    assertContainsDiagnosticMessage(exceptionWithDiagnosticMessage);

    try
    {
      assertContainsDiagnosticMessage(exceptionWithoutDiagnosticMessage);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingDiagnosticMessage method with a result.
    assertMissingDiagnosticMessage(resultWithoutDiagnosticMessage);

    try
    {
      assertMissingDiagnosticMessage(resultWithDiagnosticMessage);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingDiagnosticMessage method with an exception.
    assertMissingDiagnosticMessage(exceptionWithoutDiagnosticMessage);

    try
    {
      assertMissingDiagnosticMessage(exceptionWithDiagnosticMessage);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertDiagnosticMessageEquals method with a result.
    assertDiagnosticMessageEquals(resultWithDiagnosticMessage,  "foo");

    try
    {
      assertDiagnosticMessageEquals(resultWithoutDiagnosticMessage, "foo");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      assertDiagnosticMessageEquals(resultWithDiagnosticMessage, "bar");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }


    // Test the assertDiagnosticMessageEquals method with an exception.
    assertDiagnosticMessageEquals(exceptionWithDiagnosticMessage,  "foo");

    try
    {
      assertDiagnosticMessageEquals(exceptionWithoutDiagnosticMessage, "foo");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      assertDiagnosticMessageEquals(exceptionWithDiagnosticMessage, "bar");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the methods related to referrals.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferral()
         throws Exception
  {
    // Test the assertHasReferral method with a result.
    final String[] singleRef =
    {
      "ldap://server.example.com:389/dc=example,dc=com"
    };

    final String[] multipleRefs =
    {
      "ldap://server1.example.com:389/dc=example,dc=com",
      "ldap://server2.example.com:389/dc=example,dc=com"
    };

    final LDAPResult resultWithoutRef = new LDAPResult(1, ResultCode.SUCCESS);
    final LDAPResult resultWithOneRef = new LDAPResult(1, ResultCode.REFERRAL,
         "foo", null, singleRef, null);
    final LDAPResult resultWithMultipleRefs = new LDAPResult(1,
         ResultCode.REFERRAL, "foo", null, multipleRefs, null);

    assertHasReferral(resultWithOneRef);

    assertHasReferral(resultWithMultipleRefs);

    try
    {
      assertHasReferral(resultWithoutRef);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertHasReferral method with an exception.
    final LDAPException exceptionWithoutRef =
         new LDAPException(resultWithoutRef);
    final LDAPException exceptionWithOneRef =
         new LDAPException(resultWithOneRef);
    final LDAPException exceptionWithMultipleRefs =
         new LDAPException(resultWithMultipleRefs);

    assertHasReferral(exceptionWithOneRef);

    assertHasReferral(exceptionWithMultipleRefs);

    try
    {
      assertHasReferral(exceptionWithoutRef);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingReferral method with a result.
    assertMissingReferral(resultWithoutRef);

    try
    {
      assertMissingReferral(resultWithOneRef);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingReferral(resultWithMultipleRefs);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingReferral method with an exception.
    assertMissingReferral(exceptionWithoutRef);

    try
    {
      assertMissingReferral(exceptionWithOneRef);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingReferral(exceptionWithMultipleRefs);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the methods related to controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControl()
         throws Exception
  {
    // Test the assertHasControl method with a result.
    final Control[] singleControl =
    {
      new Control("1.2.3.4")
    };

    final Control[] multipleControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    final LDAPResult resultWithoutControl = new LDAPResult(1,
         ResultCode.SUCCESS);
    final LDAPResult resultWithOneControl = new LDAPResult(1,
         ResultCode.SUCCESS, null, null, null, singleControl);
    final LDAPResult resultWithMultipleControls = new LDAPResult(1,
         ResultCode.SUCCESS, null, null, null, multipleControls);

    Control c = assertHasControl(resultWithOneControl, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(resultWithMultipleControls, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(resultWithMultipleControls, "1.2.3.5");
    assertNotNull(c);

    try
    {
      assertHasControl(resultWithoutControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(resultWithOneControl, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(resultWithMultipleControls, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertHasControl method with an exception.
    final LDAPException exceptionWithoutControl =
         new LDAPException(resultWithoutControl);
    final LDAPException exceptionWithOneControl =
         new LDAPException(resultWithOneControl);
    final LDAPException exceptionWithMultipleControls =
         new LDAPException(resultWithMultipleControls);

    c = assertHasControl(exceptionWithOneControl, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(exceptionWithMultipleControls, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(exceptionWithMultipleControls, "1.2.3.5");
    assertNotNull(c);

    try
    {
      assertHasControl(exceptionWithoutControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(exceptionWithOneControl, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(exceptionWithMultipleControls, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertHasControl method with a search result entry.
    final SearchResultEntry entryWithoutControl = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    final SearchResultEntry entryWithOneControl = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         singleControl);

    final SearchResultEntry entryWithMultipleControls = new SearchResultEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         multipleControls);

    c = assertHasControl(entryWithOneControl, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(entryWithMultipleControls, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(entryWithMultipleControls, "1.2.3.5");
    assertNotNull(c);

    try
    {
      assertHasControl(entryWithoutControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(entryWithOneControl, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(entryWithMultipleControls, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertHasControl method with a search result reference.
    final String[] refs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    final SearchResultReference refWithoutControl =
         new SearchResultReference(refs, new Control[0]);

    final SearchResultReference refWithOneControl =
         new SearchResultReference(refs, singleControl);

    final SearchResultReference refWithMultipleControls =
         new SearchResultReference(refs, multipleControls);

    c = assertHasControl(refWithOneControl, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(refWithMultipleControls, "1.2.3.4");
    assertNotNull(c);

    c = assertHasControl(refWithMultipleControls, "1.2.3.5");
    assertNotNull(c);

    try
    {
      assertHasControl(refWithoutControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(refWithOneControl, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertHasControl(refWithMultipleControls, "1.2.3.6");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingControl method with a result.
    assertMissingControl(resultWithoutControl, "1.2.3.6");

    assertMissingControl(resultWithOneControl, "1.2.3.6");

    assertMissingControl(resultWithMultipleControls, "1.2.3.6");

    try
    {
      assertMissingControl(resultWithOneControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(resultWithMultipleControls, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(resultWithMultipleControls, "1.2.3.5");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingControl method with an exception.
    assertMissingControl(exceptionWithoutControl, "1.2.3.6");

    assertMissingControl(exceptionWithOneControl, "1.2.3.6");

    assertMissingControl(exceptionWithMultipleControls, "1.2.3.6");

    try
    {
      assertMissingControl(exceptionWithOneControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(exceptionWithMultipleControls, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(exceptionWithMultipleControls, "1.2.3.5");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingControl method with a search result entry.
    assertMissingControl(entryWithoutControl, "1.2.3.6");

    assertMissingControl(entryWithOneControl, "1.2.3.6");

    assertMissingControl(entryWithMultipleControls, "1.2.3.6");

    try
    {
      assertMissingControl(entryWithOneControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(entryWithMultipleControls, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(entryWithMultipleControls, "1.2.3.5");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertMissingControl method with a search result reference.
    assertMissingControl(refWithoutControl, "1.2.3.6");

    assertMissingControl(refWithOneControl, "1.2.3.6");

    assertMissingControl(refWithMultipleControls, "1.2.3.6");

    try
    {
      assertMissingControl(refWithOneControl, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(refWithMultipleControls, "1.2.3.4");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertMissingControl(refWithMultipleControls, "1.2.3.5");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the methods related to search result entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultEntry()
         throws Exception
  {
    // Test the assertEntryReturned method with a result.
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final SearchResult resultWithoutEntries = conn.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=missing)");

    final SearchResult resultWithOneEntry = conn.search("dc=example,dc=com",
         SearchScope.BASE, "(objectClass=*)");

    final SearchResult resultWithThreeEntries = conn.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");

    final TestSearchResultListener listener = new TestSearchResultListener();
    final SearchResult listenerResultWithoutEntries = conn.search(listener,
         "dc=example,dc=com", SearchScope.SUB, "(objectClass=missing)");

    final SearchResult listenerResultWithOneEntry = conn.search(listener,
         "dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");

    final SearchResult listenerResultWithThreeEntries = conn.search(listener,
         "dc=example,dc=com", SearchScope.SUB, "(objectClass=*)");

    assertEntryReturned(resultWithOneEntry);

    assertEntryReturned(resultWithThreeEntries);

    assertEntryReturned(listenerResultWithOneEntry);

    assertEntryReturned(listenerResultWithThreeEntries);

    try
    {
      assertEntryReturned(resultWithoutEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      assertEntryReturned(listenerResultWithoutEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }


    // Test the assertEntryReturned method with an exception.
    final LDAPSearchException exceptionWithoutEntries =
         new LDAPSearchException(resultWithoutEntries);
    final LDAPSearchException exceptionWithOneEntry =
         new LDAPSearchException(resultWithOneEntry);
    final LDAPSearchException exceptionWithThreeEntries =
         new LDAPSearchException(resultWithThreeEntries);
    final LDAPSearchException listenerExceptionWithoutEntries =
         new LDAPSearchException(listenerResultWithoutEntries);
    final LDAPSearchException listenerExceptionWithOneEntry =
         new LDAPSearchException(listenerResultWithOneEntry);
    final LDAPSearchException listenerExceptionWithThreeEntries =
         new LDAPSearchException(listenerResultWithThreeEntries);

    assertEntryReturned(exceptionWithOneEntry);

    assertEntryReturned(exceptionWithThreeEntries);

    assertEntryReturned(listenerExceptionWithOneEntry);

    assertEntryReturned(listenerExceptionWithThreeEntries);

    try
    {
      assertEntryReturned(exceptionWithoutEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }

    try
    {
      assertEntryReturned(listenerExceptionWithoutEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected
    }


    // Test the assertEntryReturned method with a result and DN.
    assertEntryReturned(resultWithOneEntry, "dc=example,dc=com");

    assertEntryReturned(resultWithThreeEntries, "dc=example,dc=com");

    assertEntryReturned(resultWithThreeEntries, "ou=People,dc=example,dc=com");

    assertEntryReturned(resultWithThreeEntries,
         "uid=test.user,ou=People,dc=example,dc=com");

    try
    {
      assertEntryReturned(resultWithoutEntries, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(resultWithOneEntry, "ou=missing,dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(resultWithThreeEntries,
           "ou=missing,dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(listenerResultWithOneEntry, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(listenerResultWithThreeEntries, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertEntryReturned method with an exception and DN.
    assertEntryReturned(exceptionWithOneEntry, "dc=example,dc=com");

    assertEntryReturned(exceptionWithThreeEntries, "dc=example,dc=com");

    assertEntryReturned(exceptionWithThreeEntries,
         "ou=People,dc=example,dc=com");

    assertEntryReturned(exceptionWithThreeEntries,
         "uid=test.user,ou=People,dc=example,dc=com");

    try
    {
      assertEntryReturned(exceptionWithoutEntries, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(exceptionWithOneEntry,
           "ou=missing,dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(exceptionWithThreeEntries,
           "ou=missing,dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(listenerExceptionWithOneEntry, "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntryReturned(listenerExceptionWithThreeEntries,
           "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertNoEntriesReturned method with a result.
    assertNoEntriesReturned(resultWithoutEntries);

    assertNoEntriesReturned(listenerResultWithoutEntries);

    try
    {
      assertNoEntriesReturned(resultWithOneEntry);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoEntriesReturned(resultWithThreeEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoEntriesReturned(listenerResultWithOneEntry);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoEntriesReturned(listenerResultWithThreeEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertNoEntriesReturned method with an exception.
    assertNoEntriesReturned(exceptionWithoutEntries);

    assertNoEntriesReturned(listenerExceptionWithoutEntries);

    try
    {
      assertNoEntriesReturned(exceptionWithOneEntry);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoEntriesReturned(exceptionWithThreeEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoEntriesReturned(listenerExceptionWithOneEntry);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoEntriesReturned(listenerExceptionWithThreeEntries);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertEntriesReturnedEquals method with a result.
    assertEntriesReturnedEquals(resultWithoutEntries, 0);

    assertEntriesReturnedEquals(resultWithOneEntry, 1);

    assertEntriesReturnedEquals(resultWithThreeEntries, 3);

    assertEntriesReturnedEquals(listenerResultWithoutEntries, 0);

    assertEntriesReturnedEquals(listenerResultWithOneEntry, 1);

    assertEntriesReturnedEquals(listenerResultWithThreeEntries, 3);

    try
    {
      assertEntriesReturnedEquals(resultWithoutEntries, 1);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntriesReturnedEquals(resultWithOneEntry, 0);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntriesReturnedEquals(listenerResultWithoutEntries, 1);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntriesReturnedEquals(listenerResultWithOneEntry, 0);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertEntriesReturnedEquals method with an exception.
    assertEntriesReturnedEquals(exceptionWithoutEntries, 0);

    assertEntriesReturnedEquals(exceptionWithOneEntry, 1);

    assertEntriesReturnedEquals(exceptionWithThreeEntries, 3);

    assertEntriesReturnedEquals(listenerExceptionWithoutEntries, 0);

    assertEntriesReturnedEquals(listenerExceptionWithOneEntry, 1);

    assertEntriesReturnedEquals(listenerExceptionWithThreeEntries, 3);

    try
    {
      assertEntriesReturnedEquals(exceptionWithoutEntries, 1);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntriesReturnedEquals(exceptionWithOneEntry, 0);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntriesReturnedEquals(listenerExceptionWithoutEntries, 1);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertEntriesReturnedEquals(listenerExceptionWithOneEntry, 0);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    conn.close();
  }



  /**
   * Provides test coverage for the methods related to search result
   * references.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultReference()
         throws Exception
  {
    // Test the assertReferenceReturned method with a result.
    final SearchResult resultWithoutRefs = new SearchResult(1,
         ResultCode.SUCCESS, null, null, null, 0, 0, null);
    final SearchResult resultWithOneRef = new SearchResult(1,
         ResultCode.SUCCESS, null, null, null, 0, 1, null);
    final SearchResult resultWithThreeRefs = new SearchResult(1,
         ResultCode.SUCCESS, null, null, null, 0, 3, null);

    assertReferenceReturned(resultWithOneRef);

    assertReferenceReturned(resultWithThreeRefs);

    try
    {
      assertReferenceReturned(resultWithoutRefs);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertReferenceReturned method with an exception.
    final LDAPSearchException exceptionWithoutRefs =
         new LDAPSearchException(resultWithoutRefs);
    final LDAPSearchException exceptionWithOneRef =
         new LDAPSearchException(resultWithOneRef);
    final LDAPSearchException exceptionWithThreeRefs =
         new LDAPSearchException(resultWithThreeRefs);

    assertReferenceReturned(exceptionWithOneRef);

    assertReferenceReturned(exceptionWithThreeRefs);

    try
    {
      assertReferenceReturned(exceptionWithoutRefs);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertNoReferencesReturned method with a result.
    assertNoReferencesReturned(resultWithoutRefs);

    try
    {
      assertNoReferencesReturned(resultWithOneRef);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoReferencesReturned(resultWithThreeRefs);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertNoReferencesReturned method with a exception.
    assertNoReferencesReturned(exceptionWithoutRefs);

    try
    {
      assertNoReferencesReturned(exceptionWithOneRef);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertNoReferencesReturned(exceptionWithThreeRefs);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertReferencesReturnedEquals method with a result.
    assertReferencesReturnedEquals(resultWithoutRefs, 0);

    assertReferencesReturnedEquals(resultWithOneRef, 1);

    assertReferencesReturnedEquals(resultWithThreeRefs, 3);

    try
    {
      assertReferencesReturnedEquals(resultWithoutRefs, 1);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertReferencesReturnedEquals(resultWithOneRef, 0);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }


    // Test the assertReferencesReturnedEquals method with an exception.
    assertReferencesReturnedEquals(exceptionWithoutRefs, 0);

    assertReferencesReturnedEquals(exceptionWithOneRef, 1);

    assertReferencesReturnedEquals(exceptionWithThreeRefs, 3);

    try
    {
      assertReferencesReturnedEquals(exceptionWithoutRefs, 1);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertReferencesReturnedEquals(exceptionWithOneRef, 0);
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code assertDNsEqual} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertDNsEqual()
         throws Exception
  {
    assertDNsEqual("", "");
    assertDNsEqual("dc=example,dc=com", "dc=example,dc=com");
    assertDNsEqual("dc=example,dc=com", "DC=EXAMPLE, DC=COM");

    try
    {
      assertDNsEqual("invalid", "dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertDNsEqual("dc=example,dc=com", "invalid");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertDNsEqual("invalid", "invalid");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertDNsEqual("dc=example,dc=com", "ou=People,dc=example,dc=com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }

    try
    {
      assertDNsEqual("dc=example,dc=com", "o=example.com");
      throw new Exception("Expected an assertion error");
    }
    catch (final AssertionError ae)
    {
      // This was expected.
    }
  }
}
