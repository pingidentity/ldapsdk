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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the auto-reconnect capability.
 * Note that auto-reconnect is a very fragile and problematic thing, so this
 * test can be somewhat unreliable.  Since the auto-reconnect feature is
 * deprecated, the test will be more permissive than it would otherwise be for
 * an essential feature and may swallow some failures.
 */
public final class AutoReconnectTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the auto-reconnect feature for an add operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testAddSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);
    assertNotNull(conn.getRootDSE());

    ds.closeAllConnections(true);

    final AddRequest addRequest = new AddRequest(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for an add operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testAddNonSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);
    assertNotNull(conn.getRootDSE());

    ds.closeAllConnections(true);

    final AddRequest addRequest = new AddRequest(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a bind operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testBindSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.addEntries(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: uid=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=test,dc=example,dc=com", "password");
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a bind operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testBindNonSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.addEntries(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: uid=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=test,dc=example,dc=com", "password");
    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a compare operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testCompareSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "dc", "example");
    assertResultCodeEquals(conn, compareRequest, ResultCode.COMPARE_TRUE,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a compare operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testCompareNonSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "dc", "example");
    assertResultCodeEquals(conn, compareRequest, ResultCode.COMPARE_TRUE,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a delete operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testDeleteSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final DeleteRequest deleteRequest = new DeleteRequest("dc=example,dc=com");
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a delete operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testDeleteNonSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final DeleteRequest deleteRequest = new DeleteRequest("dc=example,dc=com");
    assertResultCodeEquals(conn, deleteRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a modify operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testModifySynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a modify operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testModifyNonSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertResultCodeEquals(conn, modifyRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a modify DN operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testModifyDNSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.addEntries(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a modify DN operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testModifyDNNonSynchronousModeAutoReconnect()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.addEntries(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);

    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
    assertResultCodeEquals(conn, modifyDNRequest, ResultCode.SUCCESS,
         ResultCode.SERVER_DOWN);

    ds.closeAllConnections(true);

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a search operation when used in
   * synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testSearchSynchronousModeAutoReconnect()
       throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(true);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);
    assertNotNull(conn.getRootDSE());

    ds.closeAllConnections(true);

    try
    {
      assertNotNull(conn.getRootDSE());
    }
    catch (final LDAPException le)
    {
      if (le.getResultCode() != ResultCode.SERVER_DOWN)
      {
        throw le;
      }
    }

    conn.close();
    ds.shutDown(true);
  }



  /**
   * Tests the auto-reconnect feature for a search operation when used in
   * non-synchronous mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  @SuppressWarnings("deprecation")
  public void testSearchNonSynchronousModeAutoReconnect()
       throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.startListening();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUseSynchronousMode(false);
    opts.setAutoReconnect(true);

    final LDAPConnection conn = ds.getConnection(opts);
    assertNotNull(conn.getRootDSE());

    ds.closeAllConnections(true);

    try
    {
      assertNotNull(conn.getRootDSE());
    }
    catch (final LDAPException le)
    {
      if (le.getResultCode() != ResultCode.SERVER_DOWN)
      {
        throw le;
      }
    }

    conn.close();
    ds.shutDown(true);
  }
}
