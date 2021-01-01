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



import java.io.File;
import java.util.Iterator;
import java.util.SortedSet;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.RoundRobinDNSServerSet.AddressSelectionMode;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFEntrySource;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code ANONYMOUSBindRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANONYMOUSBindRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    ANONYMOUSBindRequest bindRequest =
         new ANONYMOUSBindRequest("Demo Application");
    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // If we get here, then the bind was successful.
    }
    catch (LDAPException le)
    {
      // The bind failed for some reason.
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
  }



  /**
   * Tests the example in the {@code AsyncRequestID} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncRequestIDExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();
    final TestAsyncListener myAsyncResultListener = new TestAsyncListener();


    /* ----- BEGIN EXAMPLE CODE ----- */
    Modification mod = new Modification(ModificationType.REPLACE,
         "description", "This is the new description.");
    ModifyRequest modifyRequest =
         new ModifyRequest("dc=example,dc=com", mod);

    AsyncRequestID asyncRequestID =
         connection.asyncModify(modifyRequest, myAsyncResultListener);

    // Assume that we've waited a reasonable amount of time but the modify
    // hasn't completed yet so we'll try to abandon it.

    connection.abandon(asyncRequestID);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
  }



  /**
   * Tests the example in the {@code CompareRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: test");


    /* ----- BEGIN EXAMPLE CODE ----- */
    CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "description", "test");
    CompareResult compareResult;
    try
    {
      compareResult = connection.compare(compareRequest);

      // The compare operation didn't throw an exception, so we can try to
      // determine whether the compare matched.
      if (compareResult.compareMatched())
      {
        // The entry does have a description value of test.
      }
      else
      {
        // The entry does not have a description value of test.
      }
    }
    catch (LDAPException le)
    {
      // The compare operation failed.
      compareResult = new CompareResult(le.toLDAPResult());
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(compareResult, ResultCode.COMPARE_TRUE);
  }



  /**
   * Tests the example in the {@code CRAMMD5BindRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCRAMMD5BindRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    CRAMMD5BindRequest bindRequest =
         new CRAMMD5BindRequest("u:john.doe", "password");
    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // If we get here, then the bind was successful.
    }
    catch (LDAPException le)
    {
      // The bind failed for some reason.
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
  }



  /**
   * Tests the example in the {@code DeleteRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: cn=entry to delete,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "cn: entry to delete",
         "sn: delete");


    /* ----- BEGIN EXAMPLE CODE ----- */
    DeleteRequest deleteRequest =
         new DeleteRequest("cn=entry to delete,dc=example,dc=com");
    LDAPResult deleteResult;
    try
    {
      deleteResult = connection.delete(deleteRequest);
      // If we get here, the delete was successful.
    }
    catch (LDAPException le)
    {
      // The delete operation failed.
      deleteResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(deleteResult, ResultCode.SUCCESS);
  }



  /**
   * Tests the example in the {@code DIGESTMD5BindRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDIGESTMD5BindRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    DIGESTMD5BindRequest bindRequest =
         new DIGESTMD5BindRequest("u:john.doe", "password");
    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // If we get here, then the bind was successful.
    }
    catch (LDAPException le)
    {
      // The bind failed for some reason.
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
  }



  /**
   * Tests the example in the {@code DNEntrySource} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNEntrySourceExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=member.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: member.1",
         "givenName: Member",
         "sn: 1",
         "cn: Member 1");
    connection.add(
         "dn: uid=member.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: member.2",
         "givenName: Member",
         "sn: 2",
         "cn: Member 2");
    connection.add(
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    connection.add(
         "dn: cn=My Group,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: My Group",
         "member: uid=member.1,ou=People,dc=example,dc=com",
         "member: uid=missing,ou=People,dc=example,dc=com",
         "member: uid=member.2,ou=People,dc=example,dc=com");


    /* ----- BEGIN EXAMPLE CODE ----- */
    Entry groupEntry =
         connection.getEntry("cn=My Group,ou=Groups,dc=example,dc=com");
    String[] memberValues = groupEntry.getAttributeValues("member");
    int entriesReturned = 0;
    int exceptionsCaught = 0;

    if (memberValues != null)
    {
      DNEntrySource entrySource =
           new DNEntrySource(connection, memberValues, "cn");
      try
      {
        while (true)
        {
          Entry memberEntry;
          try
          {
            memberEntry = entrySource.nextEntry();
          }
          catch (EntrySourceException ese)
          {
            // A problem was encountered while attempting to obtain an entry.
            // We may be able to continue reading entries (e.g., if the problem
            // was that the group referenced an entry that doesn't exist), or
            // we may not (e.g., if the problem was a significant search error
            // or problem with the connection).
            exceptionsCaught++;
            if (ese.mayContinueReading())
            {
              continue;
            }
            else
            {
              break;
            }
          }

          if (memberEntry == null)
          {
            // We've retrieved all of the entries for the given set of DNs.
            break;
          }
          else
          {
            entriesReturned++;
          }
        }
      }
      finally
      {
        entrySource.close();
      }
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(entriesReturned, 2);
    assertEquals(exceptionsCaught, 1);
  }



  /**
   * Tests the example in the {@code EntrySorter} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntrySorterExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=snuffy.smith,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: snuffy.smith",
         "givenName: Snuffy",
         "sn: Smith",
         "cn: Snuffy Smith");
    connection.add(
         "dn: uid=jefferson.smith,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: jefferson.smith",
         "givenName: Jefferson",
         "sn: Smith",
         "cn: Jefferson Smith");
    connection.add(
         "dn: uid=david.smith,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: david.smith",
         "givenName: David",
         "sn: Smith",
         "cn: David Smith");
    connection.add(
         "dn: uid=ann.smith,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: ann.smith",
         "givenName: Ann",
         "sn: Smith",
         "cn: Ann Smith");


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchResult searchResult = connection.search("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("sn", "Smith"));

    EntrySorter entrySorter = new EntrySorter(false,
         new SortKey("sn"), new SortKey("givenName"));
    SortedSet<Entry> sortedEntries =
        entrySorter.sort(searchResult.getSearchEntries());
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 4);
    assertEquals(sortedEntries.size(), 4);

    final Iterator<Entry> iterator = sortedEntries.iterator();
    assertTrue(iterator.next().hasAttributeValue("givenName", "Ann"));
    assertTrue(iterator.next().hasAttributeValue("givenName", "David"));
    assertTrue(iterator.next().hasAttributeValue("givenName", "Jefferson"));
    assertTrue(iterator.next().hasAttributeValue("givenName", "Snuffy"));
    assertFalse(iterator.hasNext());
  }



  /**
   * Tests the example in the {@code EntrySource} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntrySourceExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final File ldifFile = createTempFile(
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
         "cn: Test User");
    final String ldifFilePath = ldifFile.getAbsolutePath();


    /* ----- BEGIN EXAMPLE CODE ----- */
    LDIFReader ldifReader = new LDIFReader(ldifFilePath);
    EntrySource entrySource = new LDIFEntrySource(ldifReader);

    int entriesRead = 0;
    int exceptionsCaught = 0;
    try
    {
      while (true)
      {
        try
        {
          Entry entry = entrySource.nextEntry();
          if (entry == null)
          {
            // There are no more entries to be read.
            break;
          }
          else
          {
            // Do something with the entry here.
            entriesRead++;
          }
        }
        catch (EntrySourceException e)
        {
          // Some kind of problem was encountered (e.g., a malformed entry
          // found in an LDIF file, or a referral returned from a directory).
          // See if we can continue reading entries.
          exceptionsCaught++;
          if (! e.mayContinueReading())
          {
            break;
          }
        }
      }
    }
    finally
    {
      entrySource.close();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertEquals(entriesRead, 3);
    assertEquals(exceptionsCaught, 0);
  }



  /**
   * Tests the example in the {@code EXTERNALBindRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEXTERNALBindRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    EXTERNALBindRequest bindRequest = new EXTERNALBindRequest("");
    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // If we get here, then the bind was successful.
    }
    catch (LDAPException le)
    {
      // The bind failed for some reason.
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
  }



  /**
   * Tests the first example in the {@code FailoverServerSet} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailoverServerSetExample1()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig ds1Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(ds1Config);
    ds1.startListening();

    final InMemoryDirectoryServerConfig ds2Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds2Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Config);
    ds2.startListening();

    final String server1Address = "localhost";
    final String server2Address = "localhost";
    final int server1Port = ds1.getListenPort();
    final int server2Port = ds2.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create arrays with the addresses and ports of the directory server
    // instances.
    String[] addresses =
    {
      server1Address,
      server2Address
    };
    int[] ports =
    {
      server1Port,
      server2Port
    };

    // Create the server set using the address and port arrays.
    FailoverServerSet failoverSet = new FailoverServerSet(addresses, ports);

    // Verify that we can establish a single connection using the server set.
    LDAPConnection connection = failoverSet.getConnection();
    RootDSE rootDSEFromConnection = connection.getRootDSE();
    connection.close();

    // Verify that we can establish a connection pool using the server set.
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
    LDAPConnectionPool pool =
         new LDAPConnectionPool(failoverSet, bindRequest, 10);
    RootDSE rootDSEFromPool = pool.getRootDSE();
    pool.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    ds1.shutDown(true);
    ds2.shutDown(true);

    assertNotNull(rootDSEFromConnection);
    assertNotNull(rootDSEFromPool);
  }



  /**
   * Tests the second example in the {@code FailoverServerSet} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailoverServerSetExample2()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig ds1Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(ds1Config);
    ds1.startListening();

    final InMemoryDirectoryServerConfig ds2Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds2Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Config);
    ds2.startListening();

    final InMemoryDirectoryServerConfig ds3Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds3Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds3 = new InMemoryDirectoryServer(ds3Config);
    ds3.startListening();

    final InMemoryDirectoryServerConfig ds4Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds4Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds4 = new InMemoryDirectoryServer(ds4Config);
    ds4.startListening();

    final String eastServer1Address = "localhost";
    final String eastServer2Address = "localhost";
    final String westServer1Address = "localhost";
    final String westServer2Address = "localhost";
    final int eastServer1Port = ds1.getListenPort();
    final int eastServer2Port = ds2.getListenPort();
    final int westServer1Port = ds3.getListenPort();
    final int westServer2Port = ds4.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a round-robin server set for the servers in the "east" data
    // center.
    String[] eastAddresses =
    {
      eastServer1Address,
      eastServer2Address
    };
    int[] eastPorts =
    {
      eastServer1Port,
      eastServer2Port
    };
    RoundRobinServerSet eastSet =
         new RoundRobinServerSet(eastAddresses, eastPorts);

    // Create a round-robin server set for the servers in the "west" data
    // center.
    String[] westAddresses =
    {
      westServer1Address,
      westServer2Address
    };
    int[] westPorts =
    {
      westServer1Port,
      westServer2Port
    };
    RoundRobinServerSet westSet =
         new RoundRobinServerSet(westAddresses, westPorts);

    // Create the failover server set across the east and west round-robin sets.
    FailoverServerSet failoverSet = new FailoverServerSet(eastSet, westSet);

    // Verify that we can establish a single connection using the server set.
    LDAPConnection connection = failoverSet.getConnection();
    RootDSE rootDSEFromConnection = connection.getRootDSE();
    connection.close();

    // Verify that we can establish a connection pool using the server set.
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
    LDAPConnectionPool pool =
         new LDAPConnectionPool(failoverSet, bindRequest, 10);
    RootDSE rootDSEFromPool = pool.getRootDSE();
    pool.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    ds1.shutDown(true);
    ds2.shutDown(true);
    ds3.shutDown(true);
    ds4.shutDown(true);

    assertNotNull(rootDSEFromConnection);
    assertNotNull(rootDSEFromPool);
  }



  /**
   * Tests the example in the {@code FastestConnectServerSet} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFastestConnectServerSetExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig ds1Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(ds1Config);
    ds1.startListening();

    final InMemoryDirectoryServerConfig ds2Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds2Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Config);
    ds2.startListening();

    final String server1Address = "localhost";
    final String server2Address = "localhost";
    final int server1Port = ds1.getListenPort();
    final int server2Port = ds2.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create arrays with the addresses and ports of the directory server
    // instances.
    String[] addresses =
    {
      server1Address,
      server2Address
    };
    int[] ports =
    {
      server1Port,
      server2Port
    };

    // Create the server set using the address and port arrays.
    FastestConnectServerSet fastestConnectSet =
         new FastestConnectServerSet(addresses, ports);

    // Verify that we can establish a single connection using the server set.
    LDAPConnection connection = fastestConnectSet.getConnection();
    RootDSE rootDSEFromConnection = connection.getRootDSE();
    connection.close();

    // Verify that we can establish a connection pool using the server set.
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
    LDAPConnectionPool pool =
         new LDAPConnectionPool(fastestConnectSet, bindRequest, 10);
    RootDSE rootDSEFromPool = pool.getRootDSE();
    pool.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    ds1.shutDown(true);
    ds2.shutDown(true);

    assertNotNull(rootDSEFromConnection);
    assertNotNull(rootDSEFromPool);
  }



  /**
   * Tests the example in the {@code FewestConnectionsServerSet} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFewestConnectionsServerSetExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig ds1Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(ds1Config);
    ds1.startListening();

    final InMemoryDirectoryServerConfig ds2Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds2Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Config);
    ds2.startListening();

    final String server1Address = "localhost";
    final String server2Address = "localhost";
    final int server1Port = ds1.getListenPort();
    final int server2Port = ds2.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create arrays with the addresses and ports of the directory server
    // instances.
    String[] addresses =
    {
      server1Address,
      server2Address
    };
    int[] ports =
    {
      server1Port,
      server2Port
    };

    // Create the server set using the address and port arrays.
    FewestConnectionsServerSet fewestConnectionsSet =
         new FewestConnectionsServerSet(addresses, ports);

    // Verify that we can establish a single connection using the server set.
    LDAPConnection connection = fewestConnectionsSet.getConnection();
    RootDSE rootDSEFromConnection = connection.getRootDSE();
    connection.close();

    // Verify that we can establish a connection pool using the server set.
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
    LDAPConnectionPool pool =
         new LDAPConnectionPool(fewestConnectionsSet, bindRequest, 10);
    RootDSE rootDSEFromPool = pool.getRootDSE();
    pool.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    ds1.shutDown(true);
    ds2.shutDown(true);

    assertNotNull(rootDSEFromConnection);
    assertNotNull(rootDSEFromPool);
  }



  /**
   * Tests the example in the {@code GSSAPIBindRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGSSAPIBindRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    GSSAPIBindRequestProperties gssapiProperties =
         new GSSAPIBindRequestProperties("john.doe@EXAMPLE.COM", "password");
    gssapiProperties.setKDCAddress("kdc.example.com");
    gssapiProperties.setRealm("EXAMPLE.COM");

    GSSAPIBindRequest bindRequest =
         new GSSAPIBindRequest(gssapiProperties);
    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // If we get here, then the bind was successful.
    }
    catch (LDAPException le)
    {
      // The bind failed for some reason.
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.AUTH_METHOD_NOT_SUPPORTED,
         ResultCode.LOCAL_ERROR);
  }



  /**
   * Tests the example in the {@code LDAPEntrySource} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPEntrySourceExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1");
    connection.add(
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2");


    /* ----- BEGIN EXAMPLE CODE ----- */
    SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, Filter.createEqualityFilter("objectClass", "person"));
    LDAPEntrySource entrySource = new LDAPEntrySource(connection,
         searchRequest, false);

    int entriesRead = 0;
    int referencesRead = 0;
    int exceptionsCaught = 0;
    try
    {
      while (true)
      {
        try
        {
          Entry entry = entrySource.nextEntry();
          if (entry == null)
          {
            // There are no more entries to be read.
            break;
          }
          else
          {
            // Do something with the entry here.
            entriesRead++;
          }
        }
        catch (SearchResultReferenceEntrySourceException e)
        {
          // The directory server returned a search result reference.
          SearchResultReference searchReference = e.getSearchReference();
          referencesRead++;
        }
        catch (EntrySourceException e)
        {
          // Some kind of problem was encountered (e.g., the connection is no
          // longer valid).  See if we can continue reading entries.
          exceptionsCaught++;
          if (! e.mayContinueReading())
          {
            break;
          }
        }
      }
    }
    finally
    {
      entrySource.close();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertEquals(entriesRead, 2);
    assertEquals(referencesRead, 0);
    assertEquals(exceptionsCaught, 0);
  }



  /**
   * Tests the example in the {@code ModifyDNRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    assertEntryExists(connection, "ou=People,dc=example,dc=com");
    assertEntryMissing(connection, "ou=Users,dc=example,dc=com");


    /* ----- BEGIN EXAMPLE CODE ----- */
    ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
    LDAPResult modifyDNResult;

    try
    {
      modifyDNResult = connection.modifyDN(modifyDNRequest);
      // If we get here, the delete was successful.
    }
    catch (LDAPException le)
    {
      // The modify DN operation failed.
      modifyDNResult = le.toLDAPResult();
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertResultCodeEquals(modifyDNResult, ResultCode.SUCCESS);
    assertEntryMissing(connection, "ou=People,dc=example,dc=com");
    assertEntryExists(connection, "ou=Users,dc=example,dc=com");
    connection.close();
  }



  /**
   * Tests the example in the {@code PLAINBindRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPLAINBindRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    PLAINBindRequest bindRequest =
         new PLAINBindRequest("u:test.user", "password");
    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      // If we get here, then the bind was successful.
    }
    catch (LDAPException le)
    {
      // The bind failed for some reason.
      bindResult = new BindResult(le);
      ResultCode resultCode = le.getResultCode();
      String errorMessageFromServer = le.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(bindResult, ResultCode.SUCCESS);
  }



  /**
   * Tests the example in the {@code RootDSE} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRootDSEExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection connection = ds.getConnection();


    /* ----- BEGIN EXAMPLE CODE ----- */
    RootDSE rootDSE = connection.getRootDSE();
    if (rootDSE.supportsControl(
         ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID))
    {
      // The directory server does support the server-side sort control.
    }
    else
    {
      // The directory server does not support the server-side sort control.
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertTrue(rootDSE.supportsControl(
         ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID));
  }



  /**
   * Tests the example in the {@code RoundRobinServerSet} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoundRobinServerSetExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig ds1Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds1Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(ds1Config);
    ds1.startListening();

    final InMemoryDirectoryServerConfig ds2Config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    ds2Config.addAdditionalBindCredentials("uid=pool.user,dc=example,dc=com",
         "password");
    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(ds2Config);
    ds2.startListening();

    final String server1Address = "localhost";
    final String server2Address = "localhost";
    final int server1Port = ds1.getListenPort();
    final int server2Port = ds2.getListenPort();


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create arrays with the addresses and ports of the directory server
    // instances.
    String[] addresses =
    {
      server1Address,
      server2Address
    };
    int[] ports =
    {
      server1Port,
      server2Port
    };

    // Create the server set using the address and port arrays.
    RoundRobinServerSet roundRobinSet =
         new RoundRobinServerSet(addresses, ports);

    // Verify that we can establish a single connection using the server set.
    LDAPConnection connection = roundRobinSet.getConnection();
    RootDSE rootDSEFromConnection = connection.getRootDSE();
    connection.close();

    // Verify that we can establish a connection pool using the server set.
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
    LDAPConnectionPool pool =
         new LDAPConnectionPool(roundRobinSet, bindRequest, 10);
    RootDSE rootDSEFromPool = pool.getRootDSE();
    pool.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    ds1.shutDown(true);
    ds2.shutDown(true);

    assertNotNull(rootDSEFromConnection);
    assertNotNull(rootDSEFromPool);
  }



  /**
   * Tests the example in the {@code RoundRobinDNSServerSet} class.  Note that
   * because this test case requires a special external setup, it will not
   * actually be invoked.  However, this test case at least ensures that the
   * example compiles.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled=false)
  public void testRoundRobinDNSServerSetExample()
         throws Exception
  {
    /* ----- BEGIN EXAMPLE CODE ----- */
    // Define a number of variables that will be used by the server set.
    String                hostname           = "directory.example.com";
    int                   port               = 389;
    AddressSelectionMode  selectionMode      =
         AddressSelectionMode.ROUND_ROBIN;
    long                  cacheTimeoutMillis = 3600000L; // 1 hour
    String                providerURL        = "dns:"; // Default DNS config.
    SocketFactory         socketFactory      = null; // Default socket factory.
    LDAPConnectionOptions connectionOptions  = null; // Default options.

    // Create the server set using the settings defined above.
    RoundRobinDNSServerSet serverSet = new RoundRobinDNSServerSet(hostname,
         port, selectionMode, cacheTimeoutMillis, providerURL, socketFactory,
         connectionOptions);

    // Verify that we can establish a single connection using the server set.
    LDAPConnection connection = serverSet.getConnection();
    RootDSE rootDSEFromConnection = connection.getRootDSE();
    connection.close();

    // Verify that we can establish a connection pool using the server set.
    SimpleBindRequest bindRequest =
         new SimpleBindRequest("uid=pool.user,dc=example,dc=com", "password");
    LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 10);
    RootDSE rootDSEFromPool = pool.getRootDSE();
    pool.close();
    /* ----- END EXAMPLE CODE ----- */
  }



  /**
   * Tests the example in the {@code SearchRequest} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection connection = ds.getConnection();
    connection.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    connection.add(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password",
         "ou: Sales");
    connection.add(
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "ou: Engineering");
    connection.add(
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "ou: Marketing");
    connection.add(
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "ou: Sales");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Construct a filter that can be used to find everyone in the Sales
    // department, and then create a search request to find all such users
    // in the directory.
    Filter filter = Filter.createEqualityFilter("ou", "Sales");
    SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB, filter,
              "cn", "mail");
    SearchResult searchResult;

    try
    {
      searchResult = connection.search(searchRequest);

      for (SearchResultEntry entry : searchResult.getSearchEntries())
      {
        String name = entry.getAttributeValue("cn");
        String mail = entry.getAttributeValue("mail");
      }
    }
    catch (LDAPSearchException lse)
    {
      // The search failed for some reason.
      searchResult = lse.getSearchResult();
      ResultCode resultCode = lse.getResultCode();
      String errorMessageFromServer = lse.getDiagnosticMessage();
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    connection.close();
    assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2);
  }



  /**
   * Tests the example in the {@code StartTLSPostConnectProcessor} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLSPostConnectProcessorExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setSchema(Schema.getDefaultStandardSchema());

    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    assertTrue(serverKeyStore.exists());

    // The server key store will also be used as the client trust store.
    final String trustStorePath = serverKeyStore.getAbsolutePath();

    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustAllTrustManager());

    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP with StartTLS", null, 0,
              serverSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    final String serverAddress = "localhost";
    final int nonSSLPort = ds.getListenPort();

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    ds.add(
         "dn: uid=john.doe,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: john.doe",
         "givenName: John",
         "sn: Doe",
         "cn: John Doe",
         "userPassword: password");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Configure an SSLUtil instance and use it to obtain an SSLContext.
    SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
    SSLContext sslContext = sslUtil.createSSLContext();

    // Establish an insecure connection to the directory server.
    LDAPConnection connection = new LDAPConnection(serverAddress, nonSSLPort);

    // Use the StartTLS extended operation to secure the connection.
    ExtendedResult startTLSResult = connection.processExtendedOperation(
         new StartTLSExtendedRequest(sslContext));

    // Create a connection pool that will secure its connections with StartTLS.
    BindResult bindResult = connection.bind(
         "uid=john.doe,ou=People,dc=example,dc=com", "password");
    StartTLSPostConnectProcessor startTLSProcessor =
         new StartTLSPostConnectProcessor(sslContext);
    LDAPConnectionPool pool =
         new LDAPConnectionPool(connection, 1, 10, startTLSProcessor);

    // Verify that we can use the pool to communicate with the directory server.
    RootDSE rootDSE = pool.getRootDSE();

    // Close the connection pool.
    pool.close();
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertNotNull(rootDSE);
  }
}
