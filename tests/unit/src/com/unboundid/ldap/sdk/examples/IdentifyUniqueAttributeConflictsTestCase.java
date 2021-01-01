/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.examples;



import java.util.concurrent.atomic.AtomicLong;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the identify unique attribute
 * conflicts tool.
 */
public final class IdentifyUniqueAttributeConflictsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    IdentifyUniqueAttributeConflicts.main(new String[] { "--help" },
         null, null);

    final IdentifyUniqueAttributeConflicts tool =
         new IdentifyUniqueAttributeConflicts(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());

    tool.searchReferenceReturned(null);
  }



  /**
   * Tests for a simple case in which we check for a single attribute below a
   * single base DN and without using the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleAttributeSingleBaseWithoutPagedResults()
         throws Exception
  {
    // Create a directory instance with an initial set of data that doesn't have
    // any unique attribute conflicts.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    for (int i=0; i < 100; i++)
    {
      conn.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "objectClass: extensibleObject",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    // Invoke the identify-unique-attribute-conflicts tool to verify that
    // there are no conflicts.
    IdentifyUniqueAttributeConflicts tool =
         new IdentifyUniqueAttributeConflicts(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "uid");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(tool.getConflictCounts());
    assertFalse(tool.getConflictCounts().isEmpty());
    for (final AtomicLong l : tool.getConflictCounts().values())
    {
      assertEquals(l.get(), 0L);
    }


    // Add a new entry with the same uid as an existing entry.
    conn.add(
         "dn: cn=Test User,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.0",
         "givenName: Test",
         "sn: User",
         "cn: Test User");


    // Verify that the tool will now discover a conflict.  It will actually
    // appear as two conflicts, since two entries will conflict with each other.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "uid");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    assertNotNull(tool.getConflictCounts());
    assertFalse(tool.getConflictCounts().isEmpty());
    for (final AtomicLong l : tool.getConflictCounts().values())
    {
      assertEquals(l.get(), 2L);
    }


    // Invoke the tool again with a filter that will only identify conflicts in
    // entries that match "(objectClass=extensibleObject)".  We should not find
    // any conflicts with this filter in place.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--filter", "(objectClass=extensibleObject)",
         "--attribute", "uid");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(tool.getConflictCounts());
    assertFalse(tool.getConflictCounts().isEmpty());
    for (final AtomicLong l : tool.getConflictCounts().values())
    {
      assertEquals(l.get(), 0L);
    }


    // Update the newly-created entry to include the extensibleObject object
    // class.
    conn.modify(
         "dn: cn=Test User,ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: objectClass",
         "objectClass: extensibleObject");


    // Now verify that the tool will report a conflict even when using the
    // filter.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--filter", "(objectClass=extensibleObject)",
         "--attribute", "uid");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    assertNotNull(tool.getConflictCounts());
    assertFalse(tool.getConflictCounts().isEmpty());
    for (final AtomicLong l : tool.getConflictCounts().values())
    {
      assertEquals(l.get(), 2L);
    }


    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests for a case in which we check for multiple attributes below multiple
   * base DNs and in conjunction with the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleAttributesMultipleBasesWithPagedResults()
         throws Exception
  {
    // Create a directory instance with an initial set of data that doesn't have
    // any unique attribute conflicts.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    conn.add(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com");

    conn.add(
         "dn: ou=People,o=example.com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    for (int i=0; i < 100; i++)
    {
      conn.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    // Invoke the identify-unique-attribute-conflicts tool to verify that
    // there are no conflicts.
    IdentifyUniqueAttributeConflicts tool =
         new IdentifyUniqueAttributeConflicts(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(tool.getConflictCounts());
    assertFalse(tool.getConflictCounts().isEmpty());
    for (final AtomicLong l : tool.getConflictCounts().values())
    {
      assertEquals(l.get(), 0L);
    }


    // Update all of the existing entries to include a displayName value that
    // matches their cn value.
    for (int i=0; i < 100; i++)
    {
      conn.modify(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "changetype: modify",
           "add: displayName",
           "displayName: User " + i);
    }


    // Verify that there are still no conflicts within each attribute, nor when
    // we allow conflicts in the same entry, but there are when we reject
    // conflicts in the same entry.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10",
         "--multipleAttributeBehavior", "unique-within-each-attribute");
    assertEquals(resultCode, ResultCode.SUCCESS);

    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10",
         "--multipleAttributeBehavior",
              "unique-across-all-attributes-except-in-same-entry");
    assertEquals(resultCode, ResultCode.SUCCESS);

    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10",
         "--multipleAttributeBehavior",
              "unique-across-all-attributes-including-in-same-entry");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);


    // Add another set of entries in the other branch that are identical to the
    // existing user entries.
    for (int i=0; i < 100; i++)
    {
      conn.add(
           "dn: uid=user." + i + ",ou=People,o=example.com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i,
           "displayName: User " + i);
    }


    // Verify that there are now conflicts in all conflict behaviors.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10",
         "--multipleAttributeBehavior", "unique-within-each-attribute");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10",
         "--multipleAttributeBehavior",
              "unique-across-all-attributes-except-in-same-entry");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "cn",
         "--attribute", "displayName",
         "--simplePageSize", "10",
         "--multipleAttributeBehavior",
              "unique-across-all-attributes-including-in-same-entry");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);


    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests for a number of error conditions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorConditions()
         throws Exception
  {
    // Create a directory instance with an initial set of data that doesn't have
    // any unique attribute conflicts.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn.close();


    // Shut down the server and try to use the tool when it can't establish a
    // connection.
    ds.shutDown(true);

    IdentifyUniqueAttributeConflicts tool =
         new IdentifyUniqueAttributeConflicts(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "member");
    assertFalse(resultCode == ResultCode.SUCCESS);


    // Start the server and try to use the tool with invalid bind credentials.
    ds.startListening();

    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=invalid",
         "--bindPassword", "invalid",
         "--baseDN", "dc=missing,dc=com",
         "--attribute", "member");
    assertFalse(resultCode == ResultCode.SUCCESS);


    // Try to use the tool with a base DN that doesn't exist.
    ds.startListening();

    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=missing,dc=com",
         "--attribute", "member");
    assertFalse(resultCode == ResultCode.SUCCESS);


    ds.shutDown(true);
  }



  /**
   * Tests the behavior of the {@code --timeLimit} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimeLimit()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    ds.setProcessingDelayMillis(1100L);

    LDAPConnection connection = null;
    try
    {
      connection = ds.getConnection();

      ds.addEntries(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example",
           "",
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People",
           "",
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "",
           "dn: ou=Groups,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: Groups",
           "",
           "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
           "objectClass: top",
           "objectClass: groupOfNames",
           "cn: Test Group",
           "member: uid=test.user,ou=People,dc=example,dc=com");

      final IdentifyUniqueAttributeConflicts tool =
           new IdentifyUniqueAttributeConflicts(null, null);
      final ResultCode resultCode = tool.runTool(
           "--port", String.valueOf(ds.getListenPort()),
           "--baseDN", "dc=example,dc=com",
           "--attribute", "uid",
           "--timeLimitSeconds", "1");
      assertEquals(resultCode, ResultCode.TIME_LIMIT_EXCEEDED);
    }
    finally
    {
      if (connection != null)
      {
        connection.close();
      }

      ds.setProcessingDelayMillis(0L);
      ds.shutDown(true);
    }
  }



  /**
   * Tests for a case in which we check for multiple attributes in combination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleAttributesInCombination()
         throws Exception
  {
    // Create a directory instance with an initial set of data that doesn't have
    // any unique attribute conflicts.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    conn.add(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com");

    conn.add(
         "dn: ou=People,o=example.com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    for (int i=0; i < 5; i++)
    {
      conn.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    // Invoke the identify-unique-attribute-conflicts tool to verify that
    // there are no conflicts.
    IdentifyUniqueAttributeConflicts tool =
         new IdentifyUniqueAttributeConflicts(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "givenName",
         "--attribute", "sn",
         "--multipleAttributeBehavior", "unique-in-combination");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertEquals(tool.getCombinationConflictCounts(), 0L);


    // Add a new entry that introduces a conflict.
    conn.add(
         "dn: cn=User 0,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.0",
         "givenName: User",
         "sn: 0",
         "cn: User 0");


    // Invoke the tool again and verify that we identify the conflict.  There
    // will be two conflicts reported because each entry conflicts with the
    // other.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "givenName",
         "--attribute", "sn",
         "--multipleAttributeBehavior", "unique-in-combination");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    assertEquals(tool.getCombinationConflictCounts(), 2L);


    // Add another conflict, this time with multiple values for each of the
    // target attributes.
    conn.add(
         "dn: cn=User 1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "givenName: Person",
         "sn: 1",
         "sn: One",
         "cn: User 1",
         "cn: Person One");


    // Invoke the tool again and verify that we identify the new conflict.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "givenName",
         "--attribute", "sn",
         "--multipleAttributeBehavior", "unique-in-combination");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    assertEquals(tool.getCombinationConflictCounts(), 4L);


    // Invoke the tool again, this time with a nonexistent base DN.
    tool = new IdentifyUniqueAttributeConflicts(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "dc=missing,dc=com",
         "--attribute", "givenName",
         "--attribute", "sn",
         "--multipleAttributeBehavior", "unique-in-combination",
         "--filter", "(objectClass=person)");
    assertFalse(resultCode == ResultCode.SUCCESS);

    conn.close();
    ds.shutDown(true);
  }
}
