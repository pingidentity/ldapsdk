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

import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;



/**
 * This class provides a set of test cases for the in-memory directory server's
 * referential integrity functionality.
 */
public final class InMemoryDirectoryServerReferentialIntegrityTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for simple delete operations with referential integrity
   * disabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteWithoutReferentialIntegrity()
         throws Exception
  {
    // Create a directory server instance that is not configured for use with
    // referential integrity.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Populate the server with a set of test data.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateOrgUnitEntry("Groups", "dc=example,dc=com"),
         generateUserEntry("none", "ou=People,dc=example,dc=com",
              "No", "Memberships", "password"),
         generateUserEntry("single", "ou=People,dc=example,dc=com",
              "Single", "Membership", "password"),
         generateUserEntry("multiple", "ou=People,dc=example,dc=com",
              "Multiple", "Memberships", "password"),
         generateGroupOfNamesEntry("group1", "ou=Groups,dc=example,dc=com",
              "uid=single,ou=People,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfNamesEntry("group2", "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group3",
              "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group4",
              "ou=Groups,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"));

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entry for a user that is a member of only one group, and
    // ensure that no references are altered.
    final LDAPConnection conn = ds.getConnection();
    assertResultCodeEquals(conn,
         new DeleteRequest("uid=single,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entry for a user that is not member of any groups, and
    // ensure that no changes are made.
    assertResultCodeEquals(conn,
         new DeleteRequest("uid=none,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entry for a user that is a member of multiple groups, and
    // ensure that no changes are made.
    assertResultCodeEquals(conn,
         new DeleteRequest("uid=multiple,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Close the connection and shut down the server.
    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for simple delete operations with referential integrity
   * enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteWithReferentialIntegrity()
         throws Exception
  {
    // Create a directory server instance and configure it for use with
    // referential integrity.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setReferentialIntegrityAttributes("member", "uniqueMember");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Populate the server with a set of test data.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateOrgUnitEntry("Groups", "dc=example,dc=com"),
         generateUserEntry("none", "ou=People,dc=example,dc=com",
              "No", "Memberships", "password"),
         generateUserEntry("single", "ou=People,dc=example,dc=com",
              "Single", "Membership", "password"),
         generateUserEntry("multiple", "ou=People,dc=example,dc=com",
              "Multiple", "Memberships", "password"),
         generateGroupOfNamesEntry("group1", "ou=Groups,dc=example,dc=com",
              "uid=single,ou=People,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfNamesEntry("group2", "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group3",
              "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group4",
              "ou=Groups,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"));

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entry for a user that is a member of only one group, and
    // ensure that the reference to that user is properly cleaned up.
    final LDAPConnection conn = ds.getConnection();
    assertResultCodeEquals(conn,
         new DeleteRequest("uid=single,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entry for a user that is not member of any groups, and
    // ensure that no changes are made.
    assertResultCodeEquals(conn,
         new DeleteRequest("uid=none,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entry for a user that is a member of multiple groups, and
    // ensure that all appropriate changes are made.
    assertResultCodeEquals(conn,
         new DeleteRequest("uid=multiple,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Close the connection and shut down the server.
    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for subtree delete operations with referential integrity
   * disabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubtreeDeleteWithoutReferentialIntegrity()
         throws Exception
  {
    // Create a directory server instance that is not configured for use with
    // referential integrity.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Populate the server with a set of test data.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateOrgUnitEntry("Groups", "dc=example,dc=com"),
         generateUserEntry("none", "ou=People,dc=example,dc=com",
              "No", "Memberships", "password"),
         generateUserEntry("single", "ou=People,dc=example,dc=com",
              "Single", "Membership", "password"),
         generateUserEntry("multiple", "ou=People,dc=example,dc=com",
              "Multiple", "Memberships", "password"),
         generateGroupOfNamesEntry("group1", "ou=Groups,dc=example,dc=com",
              "uid=single,ou=People,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfNamesEntry("group2", "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group3",
              "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group4",
              "ou=Groups,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"));

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entire "ou=People" tree and verify that all appropriate
    // referential integrity changes are made.
    final LDAPConnection conn = ds.getConnection();

    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.addControl(new SubtreeDeleteRequestControl());

    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Close the connection and shut down the server.
    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for subtree delete operations with referential integrity
   * enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubtreeDeleteWithReferentialIntegrity()
         throws Exception
  {
    // Create a directory server instance and configure it for use with
    // referential integrity.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setReferentialIntegrityAttributes("member", "uniqueMember");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Populate the server with a set of test data.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateOrgUnitEntry("Groups", "dc=example,dc=com"),
         generateUserEntry("none", "ou=People,dc=example,dc=com",
              "No", "Memberships", "password"),
         generateUserEntry("single", "ou=People,dc=example,dc=com",
              "Single", "Membership", "password"),
         generateUserEntry("multiple", "ou=People,dc=example,dc=com",
              "Multiple", "Memberships", "password"),
         generateGroupOfNamesEntry("group1", "ou=Groups,dc=example,dc=com",
              "uid=single,ou=People,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfNamesEntry("group2", "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group3",
              "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group4",
              "ou=Groups,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"));

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Delete the entire "ou=People" tree and verify that all appropriate
    // referential integrity changes are made.
    final LDAPConnection conn = ds.getConnection();

    final DeleteRequest deleteRequest =
         new DeleteRequest("ou=People,dc=example,dc=com");
    deleteRequest.addControl(new SubtreeDeleteRequestControl());

    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Close the connection and shut down the server.
    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for modify DN operations with referential integrity
   * disabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNWithoutReferentialIntegrity()
         throws Exception
  {
    // Create a directory server instance that is not configured for use with
    // referential integrity.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Populate the server with a set of test data.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateOrgUnitEntry("Groups", "dc=example,dc=com"),
         generateUserEntry("none", "ou=People,dc=example,dc=com",
              "No", "Memberships", "password"),
         generateUserEntry("single", "ou=People,dc=example,dc=com",
              "Single", "Membership", "password"),
         generateUserEntry("multiple", "ou=People,dc=example,dc=com",
              "Multiple", "Memberships", "password"),
         generateGroupOfNamesEntry("group1", "ou=Groups,dc=example,dc=com",
              "uid=single,ou=People,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfNamesEntry("group2", "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group3",
              "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group4",
              "ou=Groups,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"));

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename a user that is a member of only one group, and ensure that no
    // references are altered.
    final LDAPConnection conn = ds.getConnection();

    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=single,ou=People,dc=example,dc=com",
              "uid=one", true);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename a user that is not member of any groups, and ensure that no
    // changes are made.
    modifyDNRequest.setDN("uid=none,ou=People,dc=example,dc=com");
    modifyDNRequest.setNewRDN("uid=zero");
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename a user that is a member of multiple groups, and ensure that no
    // changes are made.
    modifyDNRequest.setDN("uid=multiple,ou=People,dc=example,dc=com");
    modifyDNRequest.setNewRDN("uid=three");
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename the entire "ou=People" subtree and ensure that no references to
    // the subordinate entries are updated.
    modifyDNRequest.setDN("ou=People,dc=example,dc=com");
    modifyDNRequest.setNewRDN("ou=Users");
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=three,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Close the connection and shut down the server.
    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior for modify DN operations with referential integrity
   * enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNWithReferentialIntegrity()
         throws Exception
  {
    // Create a directory server instance and configure it for use with
    // referential integrity.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setReferentialIntegrityAttributes("member", "uniqueMember");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Populate the server with a set of test data.
    ds.addEntries(
         generateDomainEntry("example", "dc=com"),
         generateOrgUnitEntry("People", "dc=example,dc=com"),
         generateOrgUnitEntry("Groups", "dc=example,dc=com"),
         generateUserEntry("none", "ou=People,dc=example,dc=com",
              "No", "Memberships", "password"),
         generateUserEntry("single", "ou=People,dc=example,dc=com",
              "Single", "Membership", "password"),
         generateUserEntry("multiple", "ou=People,dc=example,dc=com",
              "Multiple", "Memberships", "password"),
         generateGroupOfNamesEntry("group1", "ou=Groups,dc=example,dc=com",
              "uid=single,ou=People,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfNamesEntry("group2", "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group3",
              "ou=Groups,dc=example,dc=com",
              "uid=multiple,ou=People,dc=example,dc=com"),
         generateGroupOfUniqueNamesEntry("group4",
              "ou=Groups,dc=example,dc=com",
              "uid=nonexistent,ou=People,dc=example,dc=com"));

    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename a user that is a member of only one group, and ensure that the
    // reference to it is updated.
    final LDAPConnection conn = ds.getConnection();

    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("uid=single,ou=People,dc=example,dc=com",
              "uid=one", true);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename a user that is not member of any groups, and ensure that no
    // changes are made.
    modifyDNRequest.setDN("uid=none,ou=People,dc=example,dc=com");
    modifyDNRequest.setNewRDN("uid=zero");
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename a user that is a member of multiple groups, and ensure that all
    // appropriate changes are made.
    modifyDNRequest.setDN("uid=multiple,ou=People,dc=example,dc=com");
    modifyDNRequest.setNewRDN("uid=three");
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Rename the entire "ou=People" subtree and ensure that all references to
    // the subordinate entries are updated.
    modifyDNRequest.setDN("ou=People,dc=example,dc=com");
    modifyDNRequest.setNewRDN("ou=Users");
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS);

    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=single,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=one,ou=Users,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group1,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=three,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group2,ou=Groups,dc=example,dc=com", "member",
         "uid=nonexistent,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=multiple,ou=People,dc=example,dc=com");
    ds.assertValueMissing("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=three,ou=People,dc=example,dc=com");
    ds.assertValueExists("cn=group3,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=three,ou=Users,dc=example,dc=com");
    ds.assertValueExists("cn=group4,ou=Groups,dc=example,dc=com",
         "uniqueMember",
         "uid=nonexistent,ou=People,dc=example,dc=com");


    // Close the connection and shut down the server.
    conn.close();
    ds.shutDown(true);
  }
}
