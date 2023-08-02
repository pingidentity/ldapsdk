/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.cert.ManageCertificates;

import static com.unboundid.ldap.sdk.
                   PooledReferralConnectorLDAPURLSecurityType.*;



/**
 * This class provides a set of test cases for the pooled referral connector,
 * which allows connections to be reused across multiple referrals.
 */
public final class PooledReferralConnectorTestCase
       extends LDAPSDKTestCase
{
  // A pair of in-memory directory server instances that can be used for
  // testing.  They will be configured with support for both LDAP and LDAPS,
  // and StartTLS will be supported for LDAP communication.
  private InMemoryDirectoryServer ds1;
  private InMemoryDirectoryServer ds2;

  // The ports on which the in-memory directory servers are listening.
  private int ds1LDAPPort;
  private int ds1LDAPSPort;
  private int ds2LDAPPort;
  private int ds2LDAPSPort;

  // An SSL socket factory that can be used when securing connections.
  private SSLSocketFactory sslSocketFactory;



  /**
   * Generates a pair of in-memory directory server instances that are
   * configured with support for LDAP (with StartTLS) and LDAPS.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    final File keyStoreFile = createTempFile();
    assertTrue(keyStoreFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode manageCertificatesResult = ManageCertificates.main(
         null, out, out,
         "generate-self-signed-certificate",
         "--keystore", keyStoreFile.getAbsolutePath(),
         "--keystore-password", "password",
         "--alias", "server-cert",
         "--subject-dn", "CN=ds.example.com,O=Example Corp,C=US");


    final SSLUtil sslUtil = new SSLUtil(
         new KeyStoreKeyManager(keyStoreFile, "password".toCharArray()),
         new TrustAllTrustManager());
    sslSocketFactory = sslUtil.createSSLSocketFactory();
    final SSLServerSocketFactory sslServerSocketFactory =
         sslUtil.createSSLServerSocketFactory();


    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    dsCfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("ldap",
              InetAddress.getByName("127.0.0.1"), 0, sslSocketFactory),
         InMemoryListenerConfig.createLDAPSConfig("ldaps",
              InetAddress.getByName("127.0.0.1"), 0, sslServerSocketFactory,
              sslSocketFactory));

    ds1 = new InMemoryDirectoryServer(dsCfg);
    ds1.startListening();
    ds1LDAPPort = ds1.getListenPort("ldap");
    ds1LDAPSPort = ds1.getListenPort("ldaps");

    ds2 = new InMemoryDirectoryServer(dsCfg);
    ds2.startListening();
    ds2LDAPPort = ds2.getListenPort("ldap");
    ds2LDAPSPort = ds2.getListenPort("ldaps");


    // Verify that it is possible to establish LDAP and LDAPS connections to
    // each of the servers, and that we can successfully secure the LDAP
    // connections with StartTLS.
    try (LDAPConnection conn = new LDAPConnection("127.0.0.1", ds1LDAPPort))
    {
      assertNotNull(conn.getRootDSE());

      assertResultCodeEquals(conn,
           new StartTLSExtendedRequest(sslSocketFactory),
           ResultCode.SUCCESS);

      assertNotNull(conn.getRootDSE());
    }

    try (LDAPConnection conn = new LDAPConnection(sslSocketFactory, "127.0.0.1",
         ds1LDAPSPort))
    {
      assertNotNull(conn.getRootDSE());
    }

    try (LDAPConnection conn = new LDAPConnection("127.0.0.1", ds2LDAPPort))
    {
      assertNotNull(conn.getRootDSE());

      assertResultCodeEquals(conn,
           new StartTLSExtendedRequest(sslSocketFactory),
           ResultCode.SUCCESS);

      assertNotNull(conn.getRootDSE());
    }

    try (LDAPConnection conn = new LDAPConnection(sslSocketFactory, "127.0.0.1",
         ds2LDAPSPort))
    {
      assertNotNull(conn.getRootDSE());
    }
  }



  /**
   * Cleans up after testing has completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    ds1.shutDown(true);
    ds2.shutDown(true);
  }



  /**
   * Tests to ensure that the server will successfully follow referrals to
   * another server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicReferralFollowingToDifferentServer()
         throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds2LDAPPort +
              "/ou=People,dc=example,dc=com");
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds2.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
         "Test", "User", "password"));


    // First, establish connections without any referral connector at all,
    // and make sure that we get the expected referrals when attempting to
    // interact with ds1.  Also, make sure that operations that have the
    // potential to make changes don't actually result in any changes in ds2.
    try (LDAPConnection conn1 = ds1.getConnection();
         LDAPConnection conn2 = ds2.getConnection())
    {
      // An attempt to add a new entry below the referral entry should yield
      // a referral result.
      final LDAPResult addResult = assertResultCodeEquals(conn1,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.REFERRAL);
      assertHasReferral(addResult);

      assertEntryMissing(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");


      // An attempt to perform a compare operation of the referral entry
      // should yield a referral result.
      final LDAPResult compareResult = assertResultCodeEquals(conn1,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.REFERRAL);
      assertHasReferral(compareResult);


      // An attempt to delete an entry below the referral entry should yield
      // a referral result.
      final LDAPResult deleteResult = assertResultCodeEquals(conn1,
           new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
           ResultCode.REFERRAL);
      assertHasReferral(deleteResult);

      assertEntryExists(conn2, "uid=test.user,ou=People,dc=example,dc=com");


      // An attempt to modify the referral entry should yield a referral
      // result.
      final LDAPResult modifyResult = assertResultCodeEquals(conn1,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.REFERRAL);
      assertHasReferral(modifyResult);

      assertAttributeMissing(conn2, "ou=People,dc=example,dc=com",
           "description");


      // An attempt to rename an entry below the referral entry should yield
      // a referral result.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn1,
           new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                "cn=Test User", false),
           ResultCode.REFERRAL);
      assertHasReferral(modifyDNResult);

      assertEntryExists(conn2, "uid=test.user,ou=People,dc=example,dc=com");
      assertEntryMissing(conn2, "cn=Test User,ou=People,dc=example,dc=com");


      // An attempt to perform a search based at the referral entry should
      // yield a referral result.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL);
      assertHasReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 0);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and return a search result
      // reference for the referral base.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 1);
      assertReferencesReturnedEquals(searchReferenceResult, 1);
    }


    // Perform a similar set of operations, but this time, use the default
    // referral connector, which establishes a separate connection for each
    // referral.
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setFollowReferrals(true);
    try (LDAPConnection conn1 = ds1.getConnection(options);
         LDAPConnection conn2 = ds2.getConnection())
    {
      // An attempt to add a new entry below the referral entry should now
      // follow the referral and succeed.
      final LDAPResult addResult = assertResultCodeEquals(conn1,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.SUCCESS);
      assertMissingReferral(addResult);

      assertEntryExists(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");


      // An attempt to perform a compare operation of the referral entry
      // should follow the referral and process the compare in the other
      // server.
      final LDAPResult compareResult = assertResultCodeEquals(conn1,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.COMPARE_TRUE);
      assertMissingReferral(compareResult);


      // An attempt to rename an entry below the referral entry should follow
      // the referral and succeed in the other server.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn1,
           new ModifyDNRequest("uid=another.user,ou=People,dc=example,dc=com",
                "cn=Another User", false),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyDNResult);

      assertEntryMissing(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");
      assertEntryExists(conn2,
           "cn=Another User,ou=People,dc=example,dc=com");


      // An attempt to delete an entry below the referral entry should follow
      // the referral and succeed.
      final LDAPResult deleteResult = assertResultCodeEquals(conn1,
           new DeleteRequest("cn=Another User,ou=People,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertMissingReferral(deleteResult);

      assertEntryMissing(conn2,
           "cn=Another User,ou=People,dc=example,dc=com");


      // An attempt to modify the referral entry should follow the referral
      // and succeed in the other server.
      final LDAPResult modifyResult = assertResultCodeEquals(conn1,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyResult);

      assertValueExists(conn2, "ou=People,dc=example,dc=com",
           "description", "foo");


      // An attempt to perform a search based at the referral entry should
      // follow the referral and succeed.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 2);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and follow the search result
      // reference to get the entries below the referral.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 3);
      assertReferencesReturnedEquals(searchReferenceResult, 0);
    }


    // Process another set of operations using the pooled referral connector.
    PooledReferralConnector referralConnector =
         new PooledReferralConnector();
    Map<String,List<ReferralConnectionPool>> poolMap =
         referralConnector.getPoolsByHostPort();
      assertPoolAndConnectionCount(poolMap, 0, 0);
    options.setReferralConnector(referralConnector);
    try (LDAPConnection conn1 = ds1.getConnection(options);
         LDAPConnection conn2 = ds2.getConnection())
    {
      // An attempt to add a new entry below the referral entry should now
      // follow the referral and succeed.
      final LDAPResult addResult = assertResultCodeEquals(conn1,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.SUCCESS);
      assertMissingReferral(addResult);

      assertEntryExists(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a compare operation of the referral entry
      // should follow the referral and process the compare in the other
      // server.
      final LDAPResult compareResult = assertResultCodeEquals(conn1,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.COMPARE_TRUE);
      assertMissingReferral(compareResult);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to rename an entry below the referral entry should follow
      // the referral and succeed in the other server.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn1,
           new ModifyDNRequest("uid=another.user,ou=People,dc=example,dc=com",
                "cn=Another User", false),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyDNResult);

      assertEntryMissing(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");
      assertEntryExists(conn2,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to delete an entry below the referral entry should follow
      // the referral and succeed.
      final LDAPResult deleteResult = assertResultCodeEquals(conn1,
           new DeleteRequest("cn=Another User,ou=People,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertMissingReferral(deleteResult);

      assertEntryMissing(conn2,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to modify the referral entry should follow the referral
      // and succeed in the other server.
      final LDAPResult modifyResult = assertResultCodeEquals(conn1,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: bar"),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyResult);

      assertValueExists(conn2, "ou=People,dc=example,dc=com",
           "description", "bar");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based at the referral entry should
      // follow the referral and succeed.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 2);
      assertReferencesReturnedEquals(searchReferralResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and follow the search result
      // reference to get the entries below the referral.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 3);
      assertReferencesReturnedEquals(searchReferenceResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);
    }
    finally
    {
      referralConnector.close();
    }


    // Make one last attempt with the pooled referral connector, this time
    // using a connection options object that uses synchronous mode.
    options.setUseSynchronousMode(true);

    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    properties.setConnectionOptions(options);

    referralConnector = new PooledReferralConnector(properties);
    poolMap = referralConnector.getPoolsByHostPort();
      assertPoolAndConnectionCount(poolMap, 0, 0);
    options.setReferralConnector(referralConnector);
    try (LDAPConnection conn1 = ds1.getConnection(options);
         LDAPConnection conn2 = ds2.getConnection())
    {
      // An attempt to add a new entry below the referral entry should now
      // follow the referral and succeed.
      final LDAPResult addResult = assertResultCodeEquals(conn1,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.SUCCESS);
      assertMissingReferral(addResult);

      assertEntryExists(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a compare operation of the referral entry
      // should follow the referral and process the compare in the other
      // server.
      final LDAPResult compareResult = assertResultCodeEquals(conn1,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.COMPARE_TRUE);
      assertMissingReferral(compareResult);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to rename an entry below the referral entry should follow
      // the referral and succeed in the other server.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn1,
           new ModifyDNRequest("uid=another.user,ou=People,dc=example,dc=com",
                "cn=Another User", false),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyDNResult);

      assertEntryMissing(conn2,
           "uid=another.user,ou=People,dc=example,dc=com");
      assertEntryExists(conn2,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to delete an entry below the referral entry should follow
      // the referral and succeed.
      final LDAPResult deleteResult = assertResultCodeEquals(conn1,
           new DeleteRequest("cn=Another User,ou=People,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertMissingReferral(deleteResult);

      assertEntryMissing(conn2,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to modify the referral entry should follow the referral
      // and succeed in the other server.
      final LDAPResult modifyResult = assertResultCodeEquals(conn1,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: baz"),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyResult);

      assertValueExists(conn2, "ou=People,dc=example,dc=com",
           "description", "baz");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based at the referral entry should
      // follow the referral and succeed.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 2);
      assertReferencesReturnedEquals(searchReferralResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and follow the search result
      // reference to get the entries below the referral.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn1,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 3);
      assertReferencesReturnedEquals(searchReferenceResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests to ensure that the server will successfully follow referrals to a
   * different location in the same server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicReferralFollowingToDifferentLocationInSameServer()
         throws Exception
  {
    ds1.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds1LDAPPort +
              "/ou=People,dc=example,dc=com");
    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds1.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
         "Test", "User", "password"));


    // First, establish connections without any referral connector at all,
    // and make sure that we get the expected referrals when attempting to
    // interact with entries at or below "ou=Users,dc=example,dc=com".  Also,
    // make sure that operations that have the potential to make changes don't
    // actually result in any changes.
    try (LDAPConnection conn = ds1.getConnection())
    {
      // An attempt to add a new entry below the referral entry should yield
      // a referral result.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=Users,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.REFERRAL);
      assertHasReferral(addResult);

      assertEntryMissing(conn,
           "uid=another.user,ou=People,dc=example,dc=com");


      // An attempt to perform a compare operation of the referral entry
      // should yield a referral result.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=Users,dc=example,dc=com", "ou", "People"),
           ResultCode.REFERRAL);
      assertHasReferral(compareResult);


      // An attempt to delete an entry below the referral entry should yield
      // a referral result.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("uid=test.user,ou=Users,dc=example,dc=com"),
           ResultCode.REFERRAL);
      assertHasReferral(deleteResult);

      assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");


      // An attempt to modify the referral entry should yield a referral
      // result.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=Users,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.REFERRAL);
      assertHasReferral(modifyResult);

      assertAttributeMissing(conn, "ou=People,dc=example,dc=com",
           "description");


      // An attempt to rename an entry below the referral entry should yield
      // a referral result.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=test.user,ou=Users,dc=example,dc=com",
                "cn=Test User", false),
           ResultCode.REFERRAL);
      assertHasReferral(modifyDNResult);

      assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");
      assertEntryMissing(conn, "cn=Test User,ou=People,dc=example,dc=com");


      // An attempt to perform a search based at the referral entry should
      // yield a referral result.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=Users,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL);
      assertHasReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 0);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and return a search result
      // reference for the referral base.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 3);
      assertReferencesReturnedEquals(searchReferenceResult, 1);
    }


    // Perform a similar set of operations, but this time, use the default
    // referral connector, which establishes a separate connection for each
    // referral.
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setFollowReferrals(true);
    try (LDAPConnection conn = ds1.getConnection(options))
    {
      // An attempt to add a new entry below the referral entry should now
      // follow the referral and succeed.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=Users,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.SUCCESS);
      assertMissingReferral(addResult);

      assertEntryExists(conn,
           "uid=another.user,ou=People,dc=example,dc=com");


      // An attempt to perform a compare operation of the referral entry
      // should follow the referral and process the compare in the other
      // server.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=Users,dc=example,dc=com", "ou", "People"),
           ResultCode.COMPARE_TRUE);
      assertMissingReferral(compareResult);


      // An attempt to rename an entry below the referral entry should follow
      // the referral and succeed in the other server.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=another.user,ou=Users,dc=example,dc=com",
                "cn=Another User", false),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyDNResult);

      assertEntryMissing(conn,
           "uid=another.user,ou=People,dc=example,dc=com");
      assertEntryExists(conn,
           "cn=Another User,ou=People,dc=example,dc=com");


      // An attempt to delete an entry below the referral entry should follow
      // the referral and succeed.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("cn=Another User,ou=Users,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertMissingReferral(deleteResult);

      assertEntryMissing(conn,
           "cn=Another User,ou=People,dc=example,dc=com");


      // An attempt to modify the referral entry should follow the referral
      // and succeed in the other server.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=Users,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyResult);

      assertValueExists(conn, "ou=People,dc=example,dc=com",
           "description", "foo");


      // An attempt to perform a search based at the referral entry should
      // follow the referral and succeed.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=Users,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 2);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and follow the search result
      // reference to get the entries below the referral.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 5);
      assertReferencesReturnedEquals(searchReferenceResult, 0);
    }


    // Process another set of operations using the pooled referral connector.
    PooledReferralConnector referralConnector =
         new PooledReferralConnector();
    Map<String,List<ReferralConnectionPool>> poolMap =
         referralConnector.getPoolsByHostPort();
      assertPoolAndConnectionCount(poolMap, 0, 0);
    options.setReferralConnector(referralConnector);
    try (LDAPConnection conn = ds1.getConnection(options))
    {
      // An attempt to add a new entry below the referral entry should now
      // follow the referral and succeed.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=Users,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.SUCCESS);
      assertMissingReferral(addResult);

      assertEntryExists(conn,
           "uid=another.user,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a compare operation of the referral entry
      // should follow the referral and process the compare in the other
      // server.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=Users,dc=example,dc=com", "ou", "People"),
           ResultCode.COMPARE_TRUE);
      assertMissingReferral(compareResult);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to rename an entry below the referral entry should follow
      // the referral and succeed in the other server.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=another.user,ou=Users,dc=example,dc=com",
                "cn=Another User", false),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyDNResult);

      assertEntryMissing(conn,
           "uid=another.user,ou=People,dc=example,dc=com");
      assertEntryExists(conn,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to delete an entry below the referral entry should follow
      // the referral and succeed.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("cn=Another User,ou=Users,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertMissingReferral(deleteResult);

      assertEntryMissing(conn,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to modify the referral entry should follow the referral
      // and succeed in the other server.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=Users,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: bar"),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyResult);

      assertValueExists(conn, "ou=People,dc=example,dc=com",
           "description", "bar");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based at the referral entry should
      // follow the referral and succeed.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=Users,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 2);
      assertReferencesReturnedEquals(searchReferralResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and follow the search result
      // reference to get the entries below the referral.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 5);
      assertReferencesReturnedEquals(searchReferenceResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);
    }
    finally
    {
      referralConnector.close();
    }


    // Make one last attempt with the pooled referral connector, this time
    // using a connection options object that uses synchronous mode.
    options.setUseSynchronousMode(true);

    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    properties.setConnectionOptions(options);

    referralConnector = new PooledReferralConnector(properties);
    poolMap = referralConnector.getPoolsByHostPort();
      assertPoolAndConnectionCount(poolMap, 0, 0);
    options.setReferralConnector(referralConnector);
    try (LDAPConnection conn = ds1.getConnection(options))
    {
      // An attempt to add a new entry below the referral entry should now
      // follow the referral and succeed.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=Users,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.SUCCESS);
      assertMissingReferral(addResult);

      assertEntryExists(conn,
           "uid=another.user,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a compare operation of the referral entry
      // should follow the referral and process the compare in the other
      // server.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=Users,dc=example,dc=com", "ou", "People"),
           ResultCode.COMPARE_TRUE);
      assertMissingReferral(compareResult);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to rename an entry below the referral entry should follow
      // the referral and succeed in the other server.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=another.user,ou=Users,dc=example,dc=com",
                "cn=Another User", false),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyDNResult);

      assertEntryMissing(conn,
           "uid=another.user,ou=People,dc=example,dc=com");
      assertEntryExists(conn,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to delete an entry below the referral entry should follow
      // the referral and succeed.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("cn=Another User,ou=Users,dc=example,dc=com"),
           ResultCode.SUCCESS);
      assertMissingReferral(deleteResult);

      assertEntryMissing(conn,
           "cn=Another User,ou=People,dc=example,dc=com");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to modify the referral entry should follow the referral
      // and succeed in the other server.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=Users,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: baz"),
           ResultCode.SUCCESS);
      assertMissingReferral(modifyResult);

      assertValueExists(conn, "ou=People,dc=example,dc=com",
           "description", "baz");

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based at the referral entry should
      // follow the referral and succeed.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=Users,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 2);
      assertReferencesReturnedEquals(searchReferralResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and follow the search result
      // reference to get the entries below the referral.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 5);
      assertReferencesReturnedEquals(searchReferenceResult, 0);

      assertPoolAndConnectionCount(poolMap, 1, 1);
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests referral behavior for the case in which a referral is received for a
   * password modify extended operation.  Although the in-memory directory
   * server has some support for the password modify extended operation, it
   * doesn't support encountering referrals in the course of identifying the
   * target user.  To work around that, we'll simulate that by just directly
   * calling the ReferralHelper.handleReferral method for the operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralsInPasswordModify()
         throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final String referralURL =
         "ldap://127.0.0.1:" + ds2LDAPPort + "/ou=People,dc=example,dc=com";
    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: " + referralURL);
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds2.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
         "Test", "User", "password"));


    final PasswordModifyExtendedResult referralResult =
         new PasswordModifyExtendedResult(1, ResultCode.REFERRAL,
              "Follow the referral", null, new String[] { referralURL }, null,
              null);


    // Test with a connection using the default referral connector.
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    connectionOptions.setFollowReferrals(true);

    try (LDAPConnection conn = ds1.getConnection(connectionOptions))
    {
      conn.bind("cn=Directory Manager", "password");

      final PasswordModifyExtendedRequest passwordModifyRequest =
           new PasswordModifyExtendedRequest(
                "uid=test.user,ou=People,dc=example,dc=com", null,
                "newPassword1");

      final PasswordModifyExtendedResult passwordModifyResult =
           ReferralHelper.handleReferral(passwordModifyRequest, referralResult,
                conn);
      assertResultCodeEquals(passwordModifyResult, ResultCode.SUCCESS);
      assertMissingReferral(passwordModifyResult);
    }


    // Test with the pooled referral connector.
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector();

    connectionOptions.setReferralConnector(referralConnector);

    try (LDAPConnection conn = ds1.getConnection(connectionOptions))
    {
      conn.bind("cn=Directory Manager", "password");

      final PasswordModifyExtendedRequest passwordModifyRequest =
           new PasswordModifyExtendedRequest(
                "uid=test.user,ou=People,dc=example,dc=com", null,
                "newPassword2");

      final PasswordModifyExtendedResult passwordModifyResult =
           ReferralHelper.handleReferral(passwordModifyRequest, referralResult,
                conn);
      assertResultCodeEquals(passwordModifyResult, ResultCode.SUCCESS);
      assertMissingReferral(passwordModifyResult);
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests the behavior when following referrals on authenticated connections.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralsOnAuthenticatedConnections()
         throws Exception
  {
    // Use separate servers for this because the second server needs to be
    // configured to require authentication.
    final InMemoryDirectoryServerConfig ds1Cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1Cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(ds1Cfg);

    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds2Cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    ds2Cfg.setAuthenticationRequiredOperationTypes(
         EnumSet.allOf(OperationType.class));
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Cfg);

    try
    {
      ds1.startListening();
      ds2.startListening();

      ds1.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      ds2.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      ds1.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: referral",
           "objectClass: extensibleObject",
           "ref: ldap://127.0.0.1:" + ds2.getListenPort() +
                "/ou=People,dc=example,dc=com");
      ds2.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");

      ds2.add(generateUserEntry("test.user", "ou=People,dc=example,dc=com",
           "Test", "User", "password"));


      // Ensure that we can't successfully issue a search against DS2 unless
      // we authenticate.
      try (LDAPConnection conn = ds2.getConnection())
      {
        assertResultCodeEquals(conn,
             new SearchRequest("ou=People,dc=example,dc=com", SearchScope.BASE,
                  Filter.present("objectClass")),
             ResultCode.INSUFFICIENT_ACCESS_RIGHTS);

        assertResultCodeEquals(conn,
             new SimpleBindRequest("cn=Directory Manager", "password"),
             ResultCode.SUCCESS);

        assertResultCodeEquals(conn,
             new SearchRequest("ou=People,dc=example,dc=com", SearchScope.BASE,
                  Filter.present("objectClass")),
             ResultCode.SUCCESS);
      }



      // Test with a pooled referral connector that does not have an
      // explicitly configured bind request.
      final PooledReferralConnectorProperties properties =
           new PooledReferralConnectorProperties();

      PooledReferralConnector referralConnector =
           new PooledReferralConnector(properties);

      final LDAPConnectionOptions options = new LDAPConnectionOptions();
      options.setFollowReferrals(true);
      options.setReferralConnector(referralConnector);

      try (LDAPConnection conn = ds1.getConnection(options))
      {
        // Since DS2 is configured to require authentication, make sure that
        // we can't follow a referral on an unauthenticated connection when
        // the referral connector isn't configured with a bind request.
        SearchResult searchResult = (SearchResult) assertResultCodeEquals(conn,
             new SearchRequest("ou=People,dc=example,dc=com",
                  SearchScope.BASE, Filter.present("objectClass")),
             ResultCode.REFERRAL);
        assertHasReferral(searchResult);


        // Authenticate the connection.
        assertResultCodeEquals(conn,
             new SimpleBindRequest("cn=Directory Manager", "password"),
             ResultCode.SUCCESS);


        // Make sure that we can now successfully follow the referral.
        searchResult = (SearchResult) assertResultCodeEquals(conn,
             new SearchRequest("ou=People,dc=example,dc=com",
                  SearchScope.BASE, Filter.present("objectClass")),
             ResultCode.SUCCESS);
        assertMissingReferral(searchResult);
      }
      finally
      {
        referralConnector.close();
      }


      // Test with another pooled referral connector that has an explicitly
      // configured bind request.  Also, configure a health check just to get
      // some coverage for that.
      properties.setBindRequest(new SimpleBindRequest("cn=Directory Manager",
           "password"));
      properties.setHealthCheck(new GetEntryLDAPConnectionPoolHealthCheck(
           "", 1000L, true, true, true, true, true, true));
      referralConnector = new PooledReferralConnector(properties);

      try (LDAPConnection conn = ds1.getConnection(options))
      {
        // Test on an unauthenticated connection.  Since the referral connector
        // now has an explicitly configured bind request, we should be able to
        // successfully follow the referral even over an unauthenticated
        // connection.
        final SearchResult searchResult = (SearchResult) assertResultCodeEquals(
             conn,
             new SearchRequest("ou=People,dc=example,dc=com",
                  SearchScope.BASE, Filter.present("objectClass")),
             ResultCode.REFERRAL);
        assertHasReferral(searchResult);
      }
      finally
      {
        referralConnector.close();
      }
    }
    finally
    {
      ds1.shutDown(true);
      ds2.shutDown(true);
    }
  }



  /**
   * Tests the behavior with a variety of security types.
   *
   * @param  securityType  The security type to use for this test.
   * @param  referralURL   The referral URL to use for this test.
   * @param  useLDAPS      Indicates whether to establish an LDAPS connection to
   *                       the initial server.
   * @param  useStartTLS   Indicates whether to secure the LDAP connection to
   *                       the initial server with StartTLS.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "ldapURLSecurityTypesTestData")
  public void testLDAPURLSecurityTypes(
       final PooledReferralConnectorLDAPURLSecurityType securityType,
       final String referralURL,
       final boolean useLDAPS,
       final boolean useStartTLS)
       throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: " + referralURL);
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    final SocketFactory socketFactory;
    if (useLDAPS)
    {
      socketFactory = sslSocketFactory;
    }
    else
    {
      socketFactory = null;
    }

    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    properties.setLDAPURLSecurityType(securityType);
    properties.setSSLSocketFactory(sslSocketFactory);
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector(properties);

    try
    {
      final LDAPConnectionOptions connectionOptions =
           new LDAPConnectionOptions();
      connectionOptions.setFollowReferrals(true);
      connectionOptions.setReferralConnector(referralConnector);

      int connectPort;
      if (useLDAPS)
      {
        connectPort = ds1LDAPSPort;
      }
      else
      {
        connectPort = ds1LDAPPort;
      }

      try (LDAPConnection conn = new LDAPConnection(socketFactory,
                connectionOptions, "127.0.0.1", connectPort))
      {
        if (useStartTLS)
        {
          assertResultCodeEquals(conn,
               new StartTLSExtendedRequest(sslSocketFactory),
               ResultCode.SUCCESS);
        }

        final SearchResult searchResult = (SearchResult) assertResultCodeEquals(
             conn,
             new SearchRequest("ou=People,dc=example,dc=com", SearchScope.BASE,
                  Filter.present("objectClass")),
             ResultCode.SUCCESS);
        assertMissingReferral(searchResult);
      }

      final Map<String,List<ReferralConnectionPool>> poolMap =
           referralConnector.getPoolsByHostPort();
      assertEquals(poolMap.size(), 1);

      for (final List<ReferralConnectionPool> poolList : poolMap.values())
      {
        assertEquals(poolList.size(), 1);

        for (final ReferralConnectionPool pool : poolList)
        {
          assertEquals(
               pool.getConnectionPool().getCurrentAvailableConnections(), 1);
        }
      }
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * This retrieves a set of data to use for testing LDAP URL security types.
   *
   * @return  A set of data to use for testing LDAP URL security types.
   */
  @DataProvider(name = "ldapURLSecurityTypesTestData")
  public Iterator<Object[]> getLDAPURLSecurityTypesTestData()
  {
    // Define constant values that clarify whether to use LDAP or LDAPS, and
    // whether to use StartTLS with LDAP.
    final boolean useLDAP = false;
    final boolean useLDAPS = true;
    final boolean useStartTLS = true;
    final boolean doNotUseStartTLS = false;


    // Define the various referral URLs that will be used for testing.
    final String ldapReferralURLToLDAPPort = "ldap://127.0.0.1:" + ds2LDAPPort +
         "/ou=People,dc=example,dc=com";
    final String ldapReferralURLToLDAPSPort = "ldap://127.0.0.1:" +
         ds2LDAPSPort + "/ou=People,dc=example,dc=com";
    final String ldapsReferralURL = "ldaps://127.0.0.1:" + ds2LDAPSPort +
         "/ou=People,dc=example,dc=com";


    // For a referral URL with a scheme of "ldaps", it doesn't matter what
    // security type we use.
    final List<Object[]> argumentSetList = new ArrayList<>();
    for (final PooledReferralConnectorLDAPURLSecurityType securityType :
         PooledReferralConnectorLDAPURLSecurityType.values())
    {
      // It also doesn't matter how we connect to the initial server instance,
      // so test with LDAP, LDAP+StartTLS, and LDAPS.
      argumentSetList.add(new Object[]
           {
             securityType,
             ldapsReferralURL,
             useLDAP,
             doNotUseStartTLS
           });
      argumentSetList.add(new Object[]
           {
             securityType,
             ldapsReferralURL,
             useLDAP,
             useStartTLS
           });
      argumentSetList.add(new Object[]
           {
             securityType,
             ldapsReferralURL,
             useLDAPS,
             doNotUseStartTLS
           });
    }


    // For the ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS type, we must use the
    // LDAP port.  It doesn't matter how we connect to the initial server.
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_NEVER_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAPS,
           doNotUseStartTLS
         });


    // For the ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS type, we must use the
    // LDAP port.  It doesn't matter how we connect to the initial server.
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_ALWAYS_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAPS,
           doNotUseStartTLS
         });


    // For the ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS type, we must use
    // the LDAP port.  How we connect to the initial server will indicate
    // whether we use StartTLS when following the referral, but we should be
    // able to follow the referral regardless of how we connect to the initial
    // server.
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAPS,
           doNotUseStartTLS
         });


    // For the CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS type, we need to
    // use the LDAPS port for connections established over LDAPS, and the LDAP
    // port for connections established over LDAP regardless of whether they're
    // using StartTLS.
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_NEVER_USE_START_TLS,
           ldapReferralURLToLDAPSPort,
           useLDAPS,
           doNotUseStartTLS
         });


    // For the CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS type, we need to
    // use the LDAPS port for connections established over LDAPS, and the LDAP
    // port for connections established over LDAP regardless of whether they're
    // using StartTLS.
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_ALWAYS_USE_START_TLS,
           ldapReferralURLToLDAPSPort,
           useLDAPS,
           doNotUseStartTLS
         });


    // For the CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS type, we
    // need to use the LDAPS port for connections established over LDAPS, and
    // the LDAP port for connections established over LDAP regardless of whether
    // they're using StartTLS.
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,
           ldapReferralURLToLDAPPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           CONDITIONALLY_USE_LDAP_AND_CONDITIONALLY_USE_START_TLS,
           ldapReferralURLToLDAPSPort,
           useLDAPS,
           doNotUseStartTLS
         });


    // For the ALWAYS_USE_LDAPS type, we need to use the LDAPS port for all
    // connections established over LDAPS, and it doesn't matter how we connect
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAPS,
           ldapReferralURLToLDAPSPort,
           useLDAP,
           doNotUseStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAPS,
           ldapReferralURLToLDAPSPort,
           useLDAP,
           useStartTLS
         });
    argumentSetList.add(new Object[]
         {
           ALWAYS_USE_LDAPS,
           ldapReferralURLToLDAPSPort,
           useLDAPS,
           doNotUseStartTLS
         });


    return argumentSetList.iterator();
  }



  /**
   * Tests to ensure that connection pools are automatically closed after they
   * have been around for longer than the configured maximum age.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPoolCleanupViaMaxPoolAge()
         throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds2LDAPPort +
              "/ou=People,dc=example,dc=com");
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Create a referral connector with a relatively short (but not so short
    // that we're likely to encounter a timeout when we don't expect it) maximum
    // pool age.
    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    properties.setMaximumPoolAgeMillis(1000L);
    properties.setBackgroundThreadCheckIntervalMillis(100L);
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector(properties);

    try
    {
      final LDAPConnectionOptions connectionOptions =
           new LDAPConnectionOptions();
      connectionOptions.setFollowReferrals(true);
      connectionOptions.setReferralConnector(referralConnector);


      // Establish a connection and issue a search that should have to follow a
      // referral.
      try (LDAPConnection conn = new LDAPConnection(connectionOptions,
                "127.0.0.1", ds1LDAPPort))
      {
        final SearchResult searchResult = (SearchResult) assertResultCodeEquals(
             conn,
             new SearchRequest("ou=People,dc=example,dc=com", SearchScope.BASE,
                  Filter.present("objectClass")),
             ResultCode.SUCCESS);
        assertMissingReferral(searchResult);
      }


      // Make sure that a referral connection pool was created and a connection
      // established in it.
      final Map<String,List<ReferralConnectionPool>> poolMap =
           referralConnector.getPoolsByHostPort();
      assertEquals(poolMap.size(), 1);

      for (final List<ReferralConnectionPool> poolList : poolMap.values())
      {
        assertEquals(poolList.size(), 1);

        for (final ReferralConnectionPool pool : poolList)
        {
          assertEquals(
               pool.getConnectionPool().getCurrentAvailableConnections(), 1);
        }
      }


      // Sleep for more than enough time to ensure that the pool has been around
      // for longer than the maximum age and that it should have been disposed
      // of by the background thread.
      Thread.sleep(1500L);


      // Make sure that the connection pool is no longer active.
      assertEquals(poolMap.size(), 1);

      for (final List<ReferralConnectionPool> poolList : poolMap.values())
      {
        assertEquals(poolList.size(), 0);
      }
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests to ensure that connection pools are automatically closed after they
   * have been idle for longer than the configured maximum duration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPoolCleanupViaMaxPoolIdleDuration()
         throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds2LDAPPort +
              "/ou=People,dc=example,dc=com");
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Create a referral connector with a relatively short (but not so short
    // that we're likely to encounter a timeout when we don't expect it) maximum
    // pool idle duration.
    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    properties.setMaximumPoolIdleDurationMillis(1000L);
    properties.setBackgroundThreadCheckIntervalMillis(100L);
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector(properties);

    try
    {
      final LDAPConnectionOptions connectionOptions =
           new LDAPConnectionOptions();
      connectionOptions.setFollowReferrals(true);
      connectionOptions.setReferralConnector(referralConnector);


      // Establish a connection and issue a search that should have to follow a
      // referral.
      try (LDAPConnection conn = new LDAPConnection(connectionOptions,
                "127.0.0.1", ds1LDAPPort))
      {
        final SearchResult searchResult = (SearchResult) assertResultCodeEquals(
             conn,
             new SearchRequest("ou=People,dc=example,dc=com", SearchScope.BASE,
                  Filter.present("objectClass")),
             ResultCode.SUCCESS);
        assertMissingReferral(searchResult);
      }


      // Make sure that a referral connection pool was created and a connection
      // established in it.
      final Map<String,List<ReferralConnectionPool>> poolMap =
           referralConnector.getPoolsByHostPort();
      assertEquals(poolMap.size(), 1);

      for (final List<ReferralConnectionPool> poolList : poolMap.values())
      {
        assertEquals(poolList.size(), 1);

        for (final ReferralConnectionPool pool : poolList)
        {
          assertEquals(
               pool.getConnectionPool().getCurrentAvailableConnections(), 1);
        }
      }


      // Sleep for more than enough time to ensure that the pool has been around
      // for longer than the maximum age and that it should have been disposed
      // of by the background thread.
      Thread.sleep(1500L);


      // Make sure that the connection pool is no longer active.
      assertEquals(poolMap.size(), 1);

      for (final List<ReferralConnectionPool> poolList : poolMap.values())
      {
        assertEquals(poolList.size(), 0);
      }
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests the behavior when a referral loop is encountered.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralLoop()
         throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds2LDAPPort +
              "/ou=People,dc=example,dc=com");
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds1LDAPPort +
              "/ou=People,dc=example,dc=com");


    // First, test a set of operations with the default referral connector.
    final LDAPConnectionOptions connectionOptions =
         new LDAPConnectionOptions();
    connectionOptions.setFollowReferrals(true);
    try (LDAPConnection conn = new LDAPConnection(connectionOptions,
              "127.0.0.1", ds1LDAPPort))
    {
      // An attempt to add a new entry below the referral entry should yield
      // a referral limit exceeded result.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(addResult);


      // An attempt to perform a compare operation of the referral entry
      // should yield a referral limit exceeded result.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(compareResult);


      // An attempt to delete an entry below the referral entry should yield
      // a referral limit exceeded result.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(deleteResult);


      // An attempt to modify the referral entry should yield a referral limit
      // exceeded result.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(modifyResult);


      // An attempt to rename an entry below the referral entry should yield
      // a referral limit exceeded result.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                "cn=Test User", false),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(modifyDNResult);


      // An attempt to perform a search based at the referral entry should
      // yield a referral limit exceeded result.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 0);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and return a search result
      // reference for the referral base.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 1);
      assertReferencesReturnedEquals(searchReferenceResult, 1);
    }


    // Perform the same test using the pooled referral connector.
    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector(properties);

    connectionOptions.setReferralConnector(referralConnector);
    try (LDAPConnection conn = new LDAPConnection(connectionOptions,
              "127.0.0.1", ds1LDAPPort))
    {
      // An attempt to add a new entry below the referral entry should yield
      // a referral limit exceeded result.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(addResult);


      // An attempt to perform a compare operation of the referral entry
      // should yield a referral limit exceeded result.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(compareResult);


      // An attempt to delete an entry below the referral entry should yield
      // a referral limit exceeded result.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(deleteResult);


      // An attempt to modify the referral entry should yield a referral limit
      // exceeded result.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(modifyResult);


      // An attempt to rename an entry below the referral entry should yield
      // a referral limit exceeded result.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                "cn=Test User", false),
           ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(modifyDNResult);


      // An attempt to perform a search based at the referral entry should
      // yield a referral limit exceeded result.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertHasReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 0);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and return a search result
      // reference for the referral base.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL_LIMIT_EXCEEDED);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 1);
      assertReferencesReturnedEquals(searchReferenceResult, 1);
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests the behavior when an unreachable referral URL is encountered.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnreachableReferralURL()
         throws Exception
  {
    ds2.shutDown(true);

    try
    {
      ds1.clear();

      ds1.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      ds1.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: referral",
           "objectClass: extensibleObject",
           "ref: ldap://127.0.0.1:" + ds2LDAPPort +
                "/ou=People,dc=example,dc=com");


      // First, test with the default referral connector.
      final LDAPConnectionOptions connectionOptions =
           new LDAPConnectionOptions();
      connectionOptions.setFollowReferrals(true);
      try (LDAPConnection conn = ds1.getConnection(connectionOptions))
      {
        // An attempt to add a new entry below the referral entry should yield
        // a referral result.
        final LDAPResult addResult = assertResultCodeEquals(conn,
             new AddRequest(generateUserEntry("another.user",
                  "ou=People,dc=example,dc=com", "Another", "User",
                  "password")),
             ResultCode.REFERRAL);
        assertHasReferral(addResult);


        // An attempt to perform a compare operation of the referral entry
        // should yield a referral result.
        final LDAPResult compareResult = assertResultCodeEquals(conn,
             new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
             ResultCode.REFERRAL);
        assertHasReferral(compareResult);


        // An attempt to delete an entry below the referral entry should yield
        // a referral result.
        final LDAPResult deleteResult = assertResultCodeEquals(conn,
             new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
             ResultCode.REFERRAL);
        assertHasReferral(deleteResult);


        // An attempt to modify the referral entry should yield a referral
        // result.
        final LDAPResult modifyResult = assertResultCodeEquals(conn,
             new ModifyRequest(
                  "dn: ou=People,dc=example,dc=com",
                  "changetype: modify",
                  "replace: description",
                  "description: foo"),
             ResultCode.REFERRAL);
        assertHasReferral(modifyResult);


        // An attempt to rename an entry below the referral entry should yield
        // a referral result.
        final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
             new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                  "cn=Test User", false),
             ResultCode.REFERRAL);
        assertHasReferral(modifyDNResult);


        // An attempt to perform a search based at the referral entry should
        // yield a referral result.
        final SearchResult searchReferralResult = (SearchResult)
             assertResultCodeEquals(conn,
                  new SearchRequest("ou=People,dc=example,dc=com",
                       SearchScope.SUB, Filter.present("objectClass")),
                  ResultCode.REFERRAL);
        assertHasReferral(searchReferralResult);
        assertEntriesReturnedEquals(searchReferralResult, 0);
        assertReferencesReturnedEquals(searchReferralResult, 0);


        // An attempt to perform a search based above the referral entry should
        // match entries outside the referral base and return a search result
        // reference for the referral base.
        final SearchResult searchReferenceResult = (SearchResult)
             assertResultCodeEquals(conn,
                  new SearchRequest("dc=example,dc=com",
                       SearchScope.SUB, Filter.present("objectClass")),
                  ResultCode.SUCCESS);
        assertMissingReferral(searchReferenceResult);
        assertEntriesReturnedEquals(searchReferenceResult, 1);
        assertReferencesReturnedEquals(searchReferenceResult, 1);
      }


      // Test again with the pooled referral connector.
      final PooledReferralConnectorProperties properties =
           new PooledReferralConnectorProperties();
      final PooledReferralConnector referralConnector =
           new PooledReferralConnector(properties);

      connectionOptions.setReferralConnector(referralConnector);
      try (LDAPConnection conn = ds1.getConnection(connectionOptions))
      {
        // An attempt to add a new entry below the referral entry should yield
        // a referral result.
        final LDAPResult addResult = assertResultCodeEquals(conn,
             new AddRequest(generateUserEntry("another.user",
                  "ou=People,dc=example,dc=com", "Another", "User",
                  "password")),
             ResultCode.REFERRAL);
        assertHasReferral(addResult);


        // An attempt to perform a compare operation of the referral entry
        // should yield a referral result.
        final LDAPResult compareResult = assertResultCodeEquals(conn,
             new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
             ResultCode.REFERRAL);
        assertHasReferral(compareResult);


        // An attempt to delete an entry below the referral entry should yield
        // a referral result.
        final LDAPResult deleteResult = assertResultCodeEquals(conn,
             new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
             ResultCode.REFERRAL);
        assertHasReferral(deleteResult);


        // An attempt to modify the referral entry should yield a referral
        // result.
        final LDAPResult modifyResult = assertResultCodeEquals(conn,
             new ModifyRequest(
                  "dn: ou=People,dc=example,dc=com",
                  "changetype: modify",
                  "replace: description",
                  "description: foo"),
             ResultCode.REFERRAL);
        assertHasReferral(modifyResult);


        // An attempt to rename an entry below the referral entry should yield
        // a referral result.
        final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
             new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                  "cn=Test User", false),
             ResultCode.REFERRAL);
        assertHasReferral(modifyDNResult);


        // An attempt to perform a search based at the referral entry should
        // yield a referral result.
        final SearchResult searchReferralResult = (SearchResult)
             assertResultCodeEquals(conn,
                  new SearchRequest("ou=People,dc=example,dc=com",
                       SearchScope.SUB, Filter.present("objectClass")),
                  ResultCode.REFERRAL);
        assertHasReferral(searchReferralResult);
        assertEntriesReturnedEquals(searchReferralResult, 0);
        assertReferencesReturnedEquals(searchReferralResult, 0);


        // An attempt to perform a search based above the referral entry should
        // match entries outside the referral base and return a search result
        // reference for the referral base.
        final SearchResult searchReferenceResult = (SearchResult)
             assertResultCodeEquals(conn,
                  new SearchRequest("dc=example,dc=com",
                       SearchScope.SUB, Filter.present("objectClass")),
                  ResultCode.SUCCESS);
        assertMissingReferral(searchReferenceResult);
        assertEntriesReturnedEquals(searchReferenceResult, 1);
        assertReferencesReturnedEquals(searchReferenceResult, 1);
      }
      finally
      {
        referralConnector.close();
      }
    }
    finally
    {
      ds2.startListening();
    }
  }



  /**
   * Tests the behavior when a malformed referral URL is encountered.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedReferralURL()
         throws Exception
  {
    ds1.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds2LDAPPort +
              "/malformed");


    // First, test with the default referral connector.
    final LDAPConnectionOptions connectionOptions =
         new LDAPConnectionOptions();
    connectionOptions.setFollowReferrals(true);
    try (LDAPConnection conn = ds1.getConnection(connectionOptions))
    {
      // An attempt to add a new entry below the referral entry should yield
      // a referral result.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.REFERRAL);
      assertHasReferral(addResult);


      // An attempt to perform a compare operation of the referral entry
      // should yield a referral result.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.REFERRAL);
      assertHasReferral(compareResult);


      // An attempt to delete an entry below the referral entry should yield
      // a referral result.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
           ResultCode.REFERRAL);
      assertHasReferral(deleteResult);


      // An attempt to modify the referral entry should yield a referral
      // result.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.REFERRAL);
      assertHasReferral(modifyResult);


      // An attempt to rename an entry below the referral entry should yield
      // a referral result.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                "cn=Test User", false),
           ResultCode.REFERRAL);
      assertHasReferral(modifyDNResult);


      // An attempt to perform a search based at the referral entry should
      // yield a referral result.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL);
      assertHasReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 0);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and return a search result
      // reference for the referral base.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 1);
      assertReferencesReturnedEquals(searchReferenceResult, 1);
    }


    // Test again with the pooled referral connector.
    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector(properties);

    connectionOptions.setReferralConnector(referralConnector);
    try (LDAPConnection conn = ds1.getConnection(connectionOptions))
    {
      // An attempt to add a new entry below the referral entry should yield
      // a referral result.
      final LDAPResult addResult = assertResultCodeEquals(conn,
           new AddRequest(generateUserEntry("another.user",
                "ou=People,dc=example,dc=com", "Another", "User",
                "password")),
           ResultCode.REFERRAL);
      assertHasReferral(addResult);


      // An attempt to perform a compare operation of the referral entry
      // should yield a referral result.
      final LDAPResult compareResult = assertResultCodeEquals(conn,
           new CompareRequest("ou=People,dc=example,dc=com", "ou", "People"),
           ResultCode.REFERRAL);
      assertHasReferral(compareResult);


      // An attempt to delete an entry below the referral entry should yield
      // a referral result.
      final LDAPResult deleteResult = assertResultCodeEquals(conn,
           new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com"),
           ResultCode.REFERRAL);
      assertHasReferral(deleteResult);


      // An attempt to modify the referral entry should yield a referral
      // result.
      final LDAPResult modifyResult = assertResultCodeEquals(conn,
           new ModifyRequest(
                "dn: ou=People,dc=example,dc=com",
                "changetype: modify",
                "replace: description",
                "description: foo"),
           ResultCode.REFERRAL);
      assertHasReferral(modifyResult);


      // An attempt to rename an entry below the referral entry should yield
      // a referral result.
      final LDAPResult modifyDNResult = assertResultCodeEquals(conn,
           new ModifyDNRequest("uid=test.user,ou=People,dc=example,dc=com",
                "cn=Test User", false),
           ResultCode.REFERRAL);
      assertHasReferral(modifyDNResult);


      // An attempt to perform a search based at the referral entry should
      // yield a referral result.
      final SearchResult searchReferralResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("ou=People,dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.REFERRAL);
      assertHasReferral(searchReferralResult);
      assertEntriesReturnedEquals(searchReferralResult, 0);
      assertReferencesReturnedEquals(searchReferralResult, 0);


      // An attempt to perform a search based above the referral entry should
      // match entries outside the referral base and return a search result
      // reference for the referral base.
      final SearchResult searchReferenceResult = (SearchResult)
           assertResultCodeEquals(conn,
                new SearchRequest("dc=example,dc=com",
                     SearchScope.SUB, Filter.present("objectClass")),
                ResultCode.SUCCESS);
      assertMissingReferral(searchReferenceResult);
      assertEntriesReturnedEquals(searchReferenceResult, 1);
      assertReferencesReturnedEquals(searchReferenceResult, 1);
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Tests to ensure that the {@code getReferralConnection} method works as
   * expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReferralConnection()
         throws Exception
  {
    ds1.clear();
    ds2.clear();

    ds1.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds2.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds1.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ref: ldap://127.0.0.1:" + ds2LDAPPort +
              "/ou=People,dc=example,dc=com");
    ds2.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Create a referral connector.  Just to get coverage, set it to never
    // discard pools after they've been created.
    final PooledReferralConnectorProperties properties =
         new PooledReferralConnectorProperties();
    properties.setMaximumPoolAgeMillis(0L);
    properties.setMaximumPoolIdleDurationMillis(0L);
    final PooledReferralConnector referralConnector =
         new PooledReferralConnector(properties);


    try (LDAPConnection conn = ds1.getConnection())
    {
      // Issue a search that should yield a referral result.  Since we're not
      // set up to automatically follow the referral, we should get that
      // referral result.
      final SearchRequest searchRequest = new SearchRequest(
           "ou=People,dc=example,dc=com", SearchScope.BASE,
           Filter.present("objectClass"));
      final SearchResult referralResult = (SearchResult) assertResultCodeEquals(
           conn, searchRequest, ResultCode.REFERRAL);
      assertHasReferral(referralResult);


      // Make sure that the referral result has a single referral URL and that
      // we can parse it as a valid LDAP URL.
      final String[] referralURLStrings = referralResult.getReferralURLs();
      assertNotNull(referralURLStrings);
      assertEquals(referralURLStrings.length, 1);

      final LDAPURL referralURL = new LDAPURL(referralURLStrings[0]);


      // Use the referral connector's getReferralConnection method to obtain a
      // connection based on that referral URL.
      try (LDAPConnection referralConnection =
                referralConnector.getReferralConnection(referralURL, conn))
      {
        // Issue the same search over the referral connection and verify that
        // it succeeds.
        final SearchResult searchResult = (SearchResult) assertResultCodeEquals(
             referralConnection, searchRequest, ResultCode.SUCCESS);
        assertMissingReferral(searchResult);
        assertEntriesReturnedEquals(searchResult, 1);
      }
    }
    finally
    {
      referralConnector.close();
    }
  }



  /**
   * Ensures that the provided map has the expected number of connection pools
   * and the overall expected number of connections.
   *
   * @param  poolMap                  The map of pools that have been created.
   * @param  expectedPoolCount        The expected number of pools.
   * @param  expectedConnectionCount  The expected number of connections across
   *                                  all of the pools.
   */
  private void assertPoolAndConnectionCount(
                    final Map<String,List<ReferralConnectionPool>> poolMap,
                    final int expectedPoolCount,
                    final int expectedConnectionCount)
  {
    synchronized (poolMap)
    {
      int poolCount = 0;
      int connectionCount = 0;
      for (final List<ReferralConnectionPool> poolList : poolMap.values())
      {
        for (final ReferralConnectionPool pool : poolList)
        {
          poolCount++;
          connectionCount +=
               pool.getConnectionPool().getCurrentAvailableConnections();
        }
      }

      assertEquals(poolCount, expectedPoolCount,
           "Expected poolMap " + poolMap + " to contain " + expectedPoolCount +
                " pool(s), but it had " + poolCount);
      assertEquals(connectionCount, expectedConnectionCount,
           "Expected poolMap " + poolMap + " to contain " +
                expectedConnectionCount + " active connection(s), but it had " +
                connectionCount);
    }
  }
}
