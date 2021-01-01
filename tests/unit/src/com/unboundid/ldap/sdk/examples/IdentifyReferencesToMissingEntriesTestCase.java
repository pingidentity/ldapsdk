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
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the identify references to
 * missing attributes tool.
 */
public final class IdentifyReferencesToMissingEntriesTestCase
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
    IdentifyReferencesToMissingEntries.main(new String[] { "--help" },
         null, null);

    final IdentifyReferencesToMissingEntries tool =
         new IdentifyReferencesToMissingEntries(null, null);
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
    // any missing references.
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

    conn.add(
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

    final String[] memberDNs = new String[100];
    for (int i=0; i < 100; i++)
    {
      final String dn = "uid=user." + i + ",ou=People,dc=example,dc=com";
      memberDNs[i] = dn;

      conn.add(
           "dn: " + dn,
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);

      conn.add(
           "dn: cn=Group for User " + i + ",ou=Groups,dc=example,dc=com",
           "objectClass: top",
           "objectClass: groupOfNames",
           "cn: Group for User " + i,
           "member: " + dn);
    }

    final AddRequest addRequest = new AddRequest(
         "dn: cn=All Users,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: All Users");
    addRequest.addAttribute("member", memberDNs);
    conn.add(addRequest);


    // Invoke the identify-references-to-missing-entries tool to verify that
    // there are no conflicts.
    IdentifyReferencesToMissingEntries tool =
         new IdentifyReferencesToMissingEntries(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "member");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(tool.getMissingReferenceCounts());
    assertFalse(tool.getMissingReferenceCounts().isEmpty());
    for (final AtomicLong l : tool.getMissingReferenceCounts().values())
    {
      assertEquals(l.get(), 0L);
    }


    // Add a reference to an entry that doesn't exist, and delete another
    // entry from the server.  This should create three missing references
    // (one for the new member value and two for the user that was deleted).
    conn.modify(
         "dn: cn=All Users,ou=Groups,dc=example,dc=com",
         "changetype: modify",
         "add: member",
         "member: uid=user.100,ou=People,dc=example,dc=com");
    conn.delete("uid=user.99,ou=People,dc=example,dc=com");


    // Verify that the tool will now discover references to missing entries.
    tool = new IdentifyReferencesToMissingEntries(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "member");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    assertNotNull(tool.getMissingReferenceCounts());
    assertFalse(tool.getMissingReferenceCounts().isEmpty());
    for (final AtomicLong l : tool.getMissingReferenceCounts().values())
    {
      assertEquals(l.get(), 3L);
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
    // any missing references.
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
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

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

    conn.add(
         "dn: ou=Groups,o=example.com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

    final String[] memberDNs = new String[100];
    final String[] uniqueMemberDNs = new String[100];
    for (int i=0; i < 100; i++)
    {
      final String memberDN = "uid=user." + i + ",ou=People,dc=example,dc=com";
      memberDNs[i] = memberDN;

      conn.add(
           "dn: " + memberDN,
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);

      conn.add(
           "dn: cn=Group for User " + i + ",ou=Groups,dc=example,dc=com",
           "objectClass: top",
           "objectClass: groupOfNames",
           "cn: Group for User " + i,
           "member: " + memberDN);

      final String uniqueMemberDN =
           "uid=user." + i + ",ou=People,o=example.com";
      uniqueMemberDNs[i] = memberDN;

      conn.add(
           "dn: " + uniqueMemberDN,
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);

      conn.add(
           "dn: cn=Group for User " + i + ",ou=Groups,o=example.com",
           "objectClass: top",
           "objectClass: groupOfUniqueNames",
           "cn: Group for User " + i,
           "uniqueMember: " + uniqueMemberDN);
    }

    AddRequest addRequest = new AddRequest(
         "dn: cn=All Users,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: All Users");
    addRequest.addAttribute("member", memberDNs);
    conn.add(addRequest);

    addRequest = new AddRequest(
         "dn: cn=All Users,ou=Groups,o=example.com",
         "objectClass: top",
         "objectClass: groupOfUniqueNames",
         "cn: All Users");
    addRequest.addAttribute("uniqueMember", uniqueMemberDNs);
    conn.add(addRequest);


    // Invoke the identify-references-to-missing-entries tool to verify that
    // there are no conflicts.
    IdentifyReferencesToMissingEntries tool =
         new IdentifyReferencesToMissingEntries(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "member",
         "--attribute", "uniqueMember",
         "--simplePageSize", "10");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(tool.getMissingReferenceCounts());
    assertFalse(tool.getMissingReferenceCounts().isEmpty());
    for (final AtomicLong l : tool.getMissingReferenceCounts().values())
    {
      assertEquals(l.get(), 0L);
    }


    // Add a reference to an entry that doesn't exist, and delete another
    // entry from the server.  This should create three missing references
    // (one for the new member value and two for the user that was deleted).
    conn.modify(
         "dn: cn=All Users,ou=Groups,dc=example,dc=com",
         "changetype: modify",
         "add: member",
         "member: uid=user.100,ou=People,dc=example,dc=com");
    conn.delete("uid=user.99,ou=People,dc=example,dc=com");

    conn.modify(
         "dn: cn=All Users,ou=Groups,o=example.com",
         "changetype: modify",
         "add: uniqueMember",
         "uniqueMember: uid=user.100,ou=People,dc=example,dc=com");
    conn.delete("uid=user.99,ou=People,o=example.com");


    // Verify that the tool will now discover references to missing entries.
    tool = new IdentifyReferencesToMissingEntries(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--baseDN", "o=example.com",
         "--attribute", "member",
         "--attribute", "uniqueMember",
         "--simplePageSize", "10");
    assertEquals(resultCode, ResultCode.CONSTRAINT_VIOLATION);

    assertNotNull(tool.getMissingReferenceCounts());
    assertFalse(tool.getMissingReferenceCounts().isEmpty());
    for (final AtomicLong l : tool.getMissingReferenceCounts().values())
    {
      assertEquals(l.get(), 3L);
    }


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
    // any missing references.
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

    IdentifyReferencesToMissingEntries tool =
         new IdentifyReferencesToMissingEntries(null, null);
    ResultCode resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--attribute", "member");
    assertFalse(resultCode == ResultCode.SUCCESS);


    // Start the server and try to use the tool with invalid bind credentials.
    ds.startListening();

    tool = new IdentifyReferencesToMissingEntries(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=invalid",
         "--bindPassword", "invalid",
         "--baseDN", "dc=missing,dc=com",
         "--attribute", "member");
    assertFalse(resultCode == ResultCode.SUCCESS);


    // Try to use the tool with a base DN that doesn't exist.
    ds.startListening();

    tool = new IdentifyReferencesToMissingEntries(null, null);
    resultCode = tool.runTool(
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=missing,dc=com",
         "--attribute", "member");
    assertFalse(resultCode == ResultCode.SUCCESS);


    ds.shutDown(true);
  }
}
