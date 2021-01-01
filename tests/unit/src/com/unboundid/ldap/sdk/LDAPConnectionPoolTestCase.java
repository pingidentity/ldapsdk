/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.SSLUtil;



/**
 * This class provides a set of test cases for the LDAPConnectionPool class.
 */
public class LDAPConnectionPoolTestCase
       extends LDAPSDKTestCase
{
  // The connection pool to use for these test cases.
  private LDAPConnectionPool pool;



  /**
   * Creates the connection pool for use by these test cases and adds the base
   * entry to the pool.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createConnectionPool()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnection conn = new LDAPConnection(options, getTestHost(),
         getTestPort(), getTestBindDN(), getTestBindPassword());
    assertTrue(conn.synchronousMode());
    pool = new LDAPConnectionPool(conn, 2, 5);
    assertFalse(pool.isClosed());


    // Configure the pool so that it will not create new connections, and that
    // it will not block if no connections are available.
    pool.setCreateIfNecessary(false);
    assertFalse(pool.getCreateIfNecessary());

    pool.setMaxWaitTimeMillis(10L);
    assertEquals(pool.getMaxWaitTimeMillis(), 10L);

    pool.add(getTestBaseDN(), getBaseEntryAttributes());

    assertTrue(pool.trySynchronousReadDuringHealthCheck());
    pool.setTrySynchronousReadDuringHealthCheck(false);
    assertFalse(pool.trySynchronousReadDuringHealthCheck());
    pool.setTrySynchronousReadDuringHealthCheck(true);
    assertTrue(pool.trySynchronousReadDuringHealthCheck());
  }



  /**
   * Make sure that the connection pool is properly closed and that the base
   * entry is properly removed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void closeConnectionPool()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    pool.delete(getTestBaseDN());

    assertFalse(pool.isClosed());
    LDAPConnection conn1 = pool.getConnection();
    LDAPConnection conn2 = pool.getConnection();
    pool.close();
    assertTrue(pool.isClosed());
    pool.releaseConnection(conn1);
    pool.releaseDefunctConnection(conn2);

    try
    {
      pool.getConnection();
      fail("Expected an exception when checking out from a closed pool");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONNECT_ERROR);
    }

    assertTrue(pool.isClosed());
  }



  /**
   * Tests the behavior when trying to create a connection pool with a
   * connection that is not established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testCreateWithConnectionNotConnected()
         throws Exception
  {
    LDAPConnection conn = new LDAPConnection();
    new LDAPConnectionPool(conn, 1, 10, null);
  }



  /**
   * Tests the connection pool methods used to get and release connections.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndReleaseConnections()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    // Make sure that we can get all of the connections in the pool, and that
    // they can all be properly released back under various circumstances.
    ArrayList<LDAPConnection> connList = new ArrayList<LDAPConnection>(6);
    for (int i=0; i < 5; i++)
    {
      connList.add(pool.getConnection());
    }

    try
    {
      pool.getConnection();
      fail("Expected an exception when trying to get a connection from the " +
           "pool when none were available.");
    } catch (LDAPException le) {}

    pool.setMaxWaitTimeMillis(-1L);
    assertEquals(pool.getMaxWaitTimeMillis(), 0L);

    pool.setCreateIfNecessary(true);
    assertTrue(pool.getCreateIfNecessary());

    connList.add(pool.getConnection());

    for (LDAPConnection c : connList)
    {
      pool.releaseConnection(c);
    }

    pool.setCreateIfNecessary(false);
    assertFalse(pool.getCreateIfNecessary());

    connList.clear();
    for (int i=0; i < 5; i++)
    {
      connList.add(pool.getConnection());
    }

    for (LDAPConnection c : connList)
    {
      pool.releaseDefunctConnection(c);
    }

    connList.clear();
    for (int i=0; i < 5; i++)
    {
      connList.add(pool.getConnection());
    }

    for (LDAPConnection c : connList)
    {
      pool.releaseConnection(c);
    }

    pool.releaseConnection(null);
    pool.releaseDefunctConnection(null);
  }



  /**
   * Provides test coverage for the methods making it possible to get and set
   * the connection pool name.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetConnectionPoolName()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());

    c.setConnectionName("test connection name");

    assertNotNull(c.getConnectionName());
    assertEquals(c.getConnectionName(), "test connection name");

    LDAPConnectionPool p = new LDAPConnectionPool(c, 1, 10);

    assertNull(p.getConnectionPoolName());

    assertNotNull(p.toString());

    c = p.getConnection();

    assertNull(c.getConnectionName());
    c.setConnectionName("test connection name again");
    assertNull(c.getConnectionName());

    assertNull(c.getConnectionPoolName());
    assertNotNull(c.toString());

    p.releaseConnection(c);

    p.setConnectionPoolName("test connection pool");

    assertNotNull(p.getConnectionPoolName());
    assertEquals(p.getConnectionPoolName(), "test connection pool");

    assertNotNull(p.toString());

    c = p.getConnection();
    assertNotNull(c.getConnectionPoolName());
    assertEquals(c.getConnectionPoolName(), "test connection pool");
    assertNotNull(c.toString());

    LDAPConnectionInternals internals = c.getConnectionInternals(true);
    assertNotNull(internals);

    LDAPConnectionReader reader = internals.getConnectionReader();
    assertNotNull(reader);

    Thread t = reader.getReaderThread();
    assertNotNull(t);
    assertTrue(t.getName().contains("test connection pool"));

    LDAPConnection c2 = p.getConnection();
    assertNotNull(c2.getConnectionPoolName());
    assertEquals(c2.getConnectionPoolName(), "test connection pool");
    assertNotNull(c2.toString());

    p.releaseConnection(c);
    p.releaseConnection(c2);

    p.setConnectionPoolName(null);

    assertNull(p.getConnectionPoolName());

    c = p.getConnection();
    assertNull(c.getConnectionPoolName());
    p.releaseConnection(c);

    p.close();
  }



  /**
   * Tests the methods that may be used to get generic and parsed entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryMethods()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    // Provide coverage for the various operation methods.
    assertNotNull(pool.getRootDSE());
    assertNotNull(pool.getSchema());
    assertNotNull(pool.getSchema(""));
    assertNull(pool.getSchema("cn=missing"));
    assertNotNull(pool.getEntry(""));
    assertNotNull(pool.getEntry("", new String[] { "1.1" }));

    try
    {
      pool.getSchema("invaliddn");
      fail ("Expected an exception when calling pool.getSchema with an " +
            "invalid DN");
    } catch (LDAPException le) {}

    try
    {
      pool.getEntry("invaliddn");
      fail ("Expected an exception when calling pool.getEntry with an " +
            "invalid DN");
    } catch (LDAPException le) {}

    try
    {
      pool.getEntry("invaliddn", new String[] { "1.1" });
      fail ("Expected an exception when calling pool.getEntry with an " +
            "invalid DN");
    } catch (LDAPException le) {}
  }



  /**
   * Tests the methods used to add and delete entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAndDelete()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String testEntryDN = "ou=test," + getTestBaseDN();

    Attribute[] goodAttrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "test")
    };

    Attribute[] badAttrs =
    {
      new Attribute("objectClass", "top", "organizationalUnit"),
      new Attribute("ou", "test"),
      new Attribute("invalid", "invalid")
    };

    ArrayList<Attribute> goodAttrList = new ArrayList<Attribute>();
    for (Attribute a : goodAttrs)
    {
      goodAttrList.add(a);
    }

    ArrayList<Attribute> badAttrList = new ArrayList<Attribute>();
    for (Attribute a : badAttrs)
    {
      badAttrList.add(a);
    }


    // Create a delete request that we will use to clean up between successful
    // adds.
    DeleteRequest deleteRequest = new DeleteRequest(testEntryDN);


    // Test the first add method with valid data.
    pool.add(testEntryDN, goodAttrs);
    pool.delete(deleteRequest);


    // Test the first add method with bad data.
    try
    {
      pool.add(testEntryDN, badAttrs);
      fail("Expected a failure when calling pool.add with bad data");
    } catch (LDAPException le) {}


    // Test the second add method with valid data.
    pool.add(testEntryDN, goodAttrList);
    pool.delete(deleteRequest);


    // Test the second add method with bad data.
    try
    {
      pool.add(testEntryDN, badAttrList);
      fail("Expected a failure when calling pool.add with bad data");
    } catch (LDAPException le) {}


    // Test the third add method with valid data.
    pool.add(new Entry(testEntryDN, goodAttrs));
    pool.delete(deleteRequest);


    // Test the third add method with bad data.
    try
    {
      pool.add(new Entry(testEntryDN, badAttrs));
      fail("Expected a failure when calling pool.add with bad data");
    } catch (LDAPException le) {}


    // Test the fourth add method with valid data.
    pool.add(new Entry(testEntryDN, goodAttrs).toLDIF());
    pool.delete(deleteRequest);


    // Test the fourth add method with bad data.
    try
    {
      pool.add(new Entry(testEntryDN, badAttrs).toLDIF());
      fail("Expected a failure when calling pool.add with bad data");
    } catch (LDAPException le) {}


    // Test the fifth add method with valid data.
    pool.add(new AddRequest(testEntryDN, goodAttrs));
    pool.delete(deleteRequest);


    // Test the methods that take read-only requests with valid data.
    ReadOnlyAddRequest roar = new AddRequest(testEntryDN, goodAttrs);
    ReadOnlyDeleteRequest rodr = new DeleteRequest(testEntryDN);
    pool.add(roar);
    pool.delete(rodr);


    // Test the fifth add method with bad data.
    try
    {
      pool.add(new AddRequest(testEntryDN, badAttrs));
      fail("Expected a failure when calling pool.add with bad data");
    } catch (LDAPException le) {}


    // Test the first delete method with the DN of an entry that doesn't exist.
    try
    {
      pool.delete("cn=nonexistent," + getTestBaseDN());
      fail("Expected a failure when calling pool.delete on an invalid entry");
    } catch (LDAPException le) {}


    // Test the second delete method with the DN of an entry that doesn't exist.
    try
    {
      pool.delete(new DeleteRequest("cn=nonexistent," + getTestBaseDN()));
      fail("Expected a failure when calling pool.delete on an invalid entry");
    } catch (LDAPException le) {}
  }



  /**
   * Tests the methods used to perform bind operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    pool.bind(getTestBindDN(), getTestBindPassword());

    pool.bind(new SimpleBindRequest(getTestBindDN(),
                                    getTestBindPassword()));
  }



  /**
   * Tests the methods used to perform compare operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompare()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    assertTrue(pool.compare(getTestBaseDN(), "objectClass",
         "top").compareMatched());

    try
    {
      pool.compare("cn=nonexistent," + getTestBaseDN(), "foo", "bar");
      fail("Expected a failure when calling pool.compare on an invalid entry");
    } catch (LDAPException le) {}


    assertTrue(pool.compare(
         new CompareRequest(getTestBaseDN(), "objectClass",
                            "top")).compareMatched());

    try
    {
      pool.compare(new CompareRequest("cn=nonexistent," + getTestBaseDN(),
                                      "foo", "bar"));
      fail("Expected a failure when calling pool.compare on an invalid entry");
    } catch (LDAPException le) {}


    ReadOnlyCompareRequest r =
         new CompareRequest(getTestBaseDN(), "objectClass", "top");
    assertTrue(pool.compare(r).compareMatched());
  }



  /**
   * Tests the methods used to process extended operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessExtendedOperation()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    pool.processExtendedOperation(WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID);

    pool.processExtendedOperation(WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
                                  null);

    pool.processExtendedOperation(new WhoAmIExtendedRequest());
  }



  /**
   * Tests to ensure that attempts to use a pooled connection to process a
   * StartTLS extended operation will result in an exception.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProcessStartTLSExtendedOperation()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    try
    {
      pool.processExtendedOperation(
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID);
      fail("Expected an exception when attempting to process a " +
           "StartTLS operation on a pooled connection.");
    } catch (LDAPException le) {}

    try
    {
      pool.processExtendedOperation(
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID, null);
      fail("Expected an exception when attempting to process a " +
           "StartTLS operation on a pooled connection.");
    } catch (LDAPException le) {}

    try
    {
      pool.processExtendedOperation(new StartTLSExtendedRequest());
      fail("Expected an exception when attempting to process a " +
           "StartTLS operation on a pooled connection.");
    } catch (LDAPException le) {}
  }



  /**
   * Tests the methods used to perform modify operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    pool.modify(getTestBaseDN(),
         new Modification(ModificationType.REPLACE, "description", "desc1"));

    try
    {
      pool.modify(getTestBaseDN(),
           new Modification(ModificationType.REPLACE, "invalid", "invalid"));
      fail("Expected a failure when calling pool.modify with invalid data");
    } catch (LDAPException le) {}

    pool.modify(getTestBaseDN(),
         new Modification(ModificationType.ADD, "description", "desc2"),
         new Modification(ModificationType.DELETE, "description", "desc1"));

    try
    {
      pool.modify(getTestBaseDN(),
           new Modification(ModificationType.REPLACE, "invalid1", "invalid1"),
           new Modification(ModificationType.REPLACE, "invalid2", "invalid2"));
      fail("Expected a failure when calling pool.modify with invalid data");
    } catch (LDAPException le) {}

    ArrayList<Modification> goodModList = new ArrayList<Modification>();
    goodModList.add(new Modification(ModificationType.REPLACE, "description",
                                     "desc3"));
    pool.modify(getTestBaseDN(), goodModList);

    ArrayList<Modification> badModList = new ArrayList<Modification>();
    badModList.add(new Modification(ModificationType.REPLACE, "invalid",
         "invalid"));
    try
    {
      pool.modify(getTestBaseDN(), badModList);
      fail("Expected a failure when calling pool.modify with invalid data");
    } catch (LDAPException le) {}

    pool.modify("dn: " + getTestBaseDN(),
                "changetype: modify",
                "replace: description",
                "description: desc4");

    try
    {
      pool.modify("dn: " + getTestBaseDN(),
                  "changetype: modify",
                  "replace: invalid",
                  "invalid: invalid");
      fail("Expected a failure when calling pool.modify with invalid data");
    } catch (LDAPException le) {}

    try
    {
      pool.modify("dn: " + getTestBaseDN(),
                  "changetype: modify",
                  "invalid");
      fail("Expected a failure when calling pool.modify with invalid LDIF");
    } catch (LDIFException le) {}

    pool.modify(new ModifyRequest(getTestBaseDN(),
         new Modification(ModificationType.REPLACE, "description", "desc1")));

    try
    {
      pool.modify(new ModifyRequest(getTestBaseDN(),
           new Modification(ModificationType.REPLACE, "invalid", "invalid")));
      fail("Expected a failure when calling pool.modify with invalid data");
    } catch (LDAPException le) {}

    ReadOnlyModifyRequest r = new ModifyRequest(getTestBaseDN(),
         new Modification(ModificationType.REPLACE, "description", "desc2"));
    pool.modify(r);
  }



  /**
   * Tests the methods used to perform modify DN operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    pool.add("dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");

    pool.modifyDN("ou=test," + getTestBaseDN(), "ou=test2", true);

    pool.modifyDN("ou=test2," + getTestBaseDN(), "ou=test3", true, null);

    pool.modifyDN(new ModifyDNRequest("ou=test3," + getTestBaseDN(),
                                      "ou=test4", true));

    ReadOnlyModifyDNRequest r =
         new ModifyDNRequest("ou=test4," + getTestBaseDN(), "ou=test5", true);
    pool.modifyDN(r);

    pool.delete("ou=test5," + getTestBaseDN());

    try
    {
      pool.modifyDN("ou=test," + getTestBaseDN(), "ou=test2", true);
      fail("Expected a failure when calling pool.modifyDN on a nonexistent " +
           "entry");
    } catch (Exception e) {}

    try
    {
      pool.modifyDN("ou=test," + getTestBaseDN(), "ou=test2", true, null);
      fail("Expected a failure when calling pool.modifyDN on a nonexistent " +
           "entry");
    } catch (Exception e) {}

    try
    {
      pool.modifyDN(new ModifyDNRequest("ou=test," + getTestBaseDN(),
           "ou=test2", true));
      fail("Expected a failure when calling pool.modifyDN on a nonexistent " +
           "entry");
    } catch (Exception e) {}
  }



  /**
   * Tests the methods used to perform search operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearch()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }


    pool.search(getTestBaseDN(), SearchScope.BASE, "(objectClass=*)");

    try
    {
      pool.search("cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
                  "(objectClass=*)");
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(getTestBaseDN(), SearchScope.BASE,
         Filter.create("(objectClass=*)"));

    try
    {
      pool.search("cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
                  Filter.create("(objectClass=*)"));
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(null, getTestBaseDN(), SearchScope.BASE, "(objectClass=*)");

    try
    {
      pool.search(null, "cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
                  "(objectClass=*)");
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(null, getTestBaseDN(), SearchScope.BASE,
         Filter.create("(objectClass=*)"));

    try
    {
      pool.search(null, "cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
           Filter.create("(objectClass=*)"));
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(getTestBaseDN(), SearchScope.BASE, DereferencePolicy.NEVER, 0,
                0, false, "(objectClass=*)", new String[0]);
    try
    {
      pool.search("cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
           DereferencePolicy.NEVER, 0, 0, false, "(objectClass=*)",
           new String[0]);
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(getTestBaseDN(), SearchScope.BASE, DereferencePolicy.NEVER, 0,
                0, false, Filter.create("(objectClass=*)"), new String[0]);
    try
    {
      pool.search("cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
                  DereferencePolicy.NEVER, 0, 0, false,
                  Filter.create("(objectClass=*)"), new String[0]);
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(null, getTestBaseDN(), SearchScope.BASE,
                DereferencePolicy.NEVER, 0, 0, false, "(objectClass=*)");

    try
    {
      pool.search(null, "cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
                  DereferencePolicy.NEVER, 0, 0, false, "(objectClass=*)");
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(null, getTestBaseDN(), SearchScope.BASE,
                DereferencePolicy.NEVER, 0, 0, false,
                Filter.create("(objectClass=*)"));

    try
    {
      pool.search(null, "cn=nonexistent," + getTestBaseDN(), SearchScope.BASE,
                  DereferencePolicy.NEVER, 0, 0, false,
                  Filter.create("(objectClass=*)"));
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    pool.search(new SearchRequest(getTestBaseDN(), SearchScope.BASE,
                                  "(objectClass=*)"));

    try
    {
      pool.search(new SearchRequest("cn=nonexistent," + getTestBaseDN(),
                                    SearchScope.BASE,
                                    "(objectClass=*)"));
      fail("Expected a failure when calling pool.search with an invalid base");
    } catch (LDAPException le) {}

    ReadOnlySearchRequest r = new SearchRequest(getTestBaseDN(),
         SearchScope.BASE, "(objectClass=*)");
    pool.search(r);
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods with a valid,
   * matching search.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryValidMatching()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnectionPool p = new LDAPConnectionPool(
         new LDAPConnection(options, getTestHost(), getTestPort(),
              getTestBindDN(), getTestBindPassword()),
         1);

    p.add(
         "dn: uid=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    SearchResultEntry e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         "(uid=test)");
    assertNotNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         Filter.create("(uid=test)"));
    assertNotNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=test)");
    assertNotNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, Filter.create("(uid=test)"));
    assertNotNull(e);

    final SearchRequest req = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(uid=test)");
    req.setTimeLimitSeconds(1000);
    req.addControl(new ManageDsaITRequestControl());
    e = p.searchForEntry(req);
    assertNotNull(e);

    e = p.searchForEntry((ReadOnlySearchRequest) req);
    assertNotNull(e);


    p.delete("uid=test," + getTestBaseDN());

    p.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods with a valid,
   * non-matching search.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryValidNonMatching()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnectionPool p = new LDAPConnectionPool(
         new LDAPConnection(options, getTestHost(), getTestPort(),
              getTestBindDN(), getTestBindPassword()),
         1);

    SearchResultEntry e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         "(uid=test)");
    assertNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         Filter.create("(uid=test)"));
    assertNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=test)");
    assertNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, Filter.create("(uid=test)"));
    assertNull(e);

    final SearchRequest req = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(uid=test)");
    req.setTimeLimitSeconds(1000);
    req.addControl(new ManageDsaITRequestControl());
    e = p.searchForEntry(req);
    assertNull(e);

    e = p.searchForEntry((ReadOnlySearchRequest) req);
    assertNull(e);


    p.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods with a valid,
   * non-matching search.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryValidMissingBase()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnectionPool p = new LDAPConnectionPool(
         new LDAPConnection(options, getTestHost(), getTestPort(),
              getTestBindDN(), getTestBindPassword()),
         1);

    SearchResultEntry e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         "(uid=test)");
    assertNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         Filter.create("(uid=test)"));
    assertNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, "(uid=test)");
    assertNull(e);

    e = p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
         DereferencePolicy.NEVER, 0, false, Filter.create("(uid=test)"));
    assertNull(e);

    final SearchRequest req = new SearchRequest(getTestBaseDN(),
         SearchScope.SUB, "(uid=test)");
    req.setTimeLimitSeconds(1000);
    req.addControl(new ManageDsaITRequestControl());
    e = p.searchForEntry(req);
    assertNull(e);

    e = p.searchForEntry((ReadOnlySearchRequest) req);
    assertNull(e);


    p.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} methods which take
   * search filter strings using invalid filters.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryInvalidFilterString()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnectionPool p = new LDAPConnectionPool(
         new LDAPConnection(options, getTestHost(), getTestPort(),
              getTestBindDN(), getTestBindPassword()),
         1);

    try
    {
      p.searchForEntry(getTestBaseDN(), SearchScope.SUB, "invalidFilter");
      fail("Expected an exception with an invalid filter");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.FILTER_ERROR);
    }


    try
    {
      p.searchForEntry(getTestBaseDN(), SearchScope.SUB,
           DereferencePolicy.NEVER, 0, false, "invalidFilter");
      fail("Expected an exception with an invalid filter");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.FILTER_ERROR);
    }


    p.close();
  }



  /**
   * Provides test coverage for the {@code searchForEntry} method for a search
   * that matches multiple entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchForEntryMultipleMatches()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnectionPool p = new LDAPConnectionPool(
         new LDAPConnection(options, getTestHost(), getTestPort(),
              getTestBindDN(), getTestBindPassword()),
         1);

    p.add(
         "dn: uid=test.1," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: 1",
         "cn: Test 1");
    p.add(
         "dn: uid=test.2," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: 2",
         "cn: Test 2");

    try
    {
      p.searchForEntry(getTestBaseDN(), SearchScope.SUB, "(givenName=Test)");
      fail("Expected an exception when searching with multiple matches");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
    }

    p.delete("uid=test.1," + getTestBaseDN());
    p.delete("uid=test.2," + getTestBaseDN());

    p.close();
  }



  /**
   * Tests the {@code processRequests} method with a set of requests that should
   * all succeed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test
  public void testProcessRequests()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>();

    requests.add(new AddRequest(
         "dn: ou=testProcessRequests," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: testProcessRequests"));

    requests.add(new ModifyRequest(
         "dn: ou=testProcessRequests," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo"));

    requests.add(new CompareRequest("ou=testProcessRequests," + getTestBaseDN(),
                                    "description", "foo"));

    requests.add(new SearchRequest(getTestBaseDN(), SearchScope.SUB,
                                   "(objectClass=*)"));

    requests.add(new DeleteRequest("ou=testProcessRequests," +
                                   getTestBaseDN()));

    List<LDAPResult> results = pool.processRequests(requests, false);

    assertNotNull(results);
    assertEquals(results.size(), 5);

    assertEquals(results.get(0).getResultCode(), ResultCode.SUCCESS);

    assertEquals(results.get(1).getResultCode(), ResultCode.SUCCESS);

    assertTrue(results.get(2) instanceof CompareResult);
    assertEquals(results.get(2).getResultCode(), ResultCode.COMPARE_TRUE);

    assertTrue(results.get(3) instanceof SearchResult);
    assertEquals(results.get(3).getResultCode(), ResultCode.SUCCESS);
    assertEquals(((SearchResult) results.get(3)).getEntryCount(), 2);

    assertEquals(results.get(4).getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Tests the {@code processRequests} method with a set of requests in which
   * the first should fail and continueOnError is false.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test
  public void testProcessRequestsFailFirstNoContinue()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>();

    requests.add(new ModifyRequest(
         "dn: ou=testProcessRequests," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo"));

    requests.add(new CompareRequest("ou=testProcessRequests," + getTestBaseDN(),
                                    "description", "foo"));

    requests.add(new SearchRequest(getTestBaseDN(), SearchScope.SUB,
                                   "(objectClass=*)"));

    List<LDAPResult> results = pool.processRequests(requests, false);

    assertNotNull(results);
    assertEquals(results.size(), 1);

    assertEquals(results.get(0).getResultCode(), ResultCode.NO_SUCH_OBJECT);
  }



  /**
   * Tests the {@code processRequests} method with a set of requests in which
   * the first should fail and continueOnError is true.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test
  public void testProcessRequestsFailFirstWithContinue()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>();

    requests.add(new ModifyRequest(
         "dn: ou=testProcessRequests," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo"));

    requests.add(new AddRequest(
         "dn: ou=testProcessRequests," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: testProcessRequests"));

    requests.add(new ModifyRequest(
         "dn: ou=testProcessRequests," + getTestBaseDN(),
         "changetype: modify",
         "replace: description",
         "description: foo"));

    requests.add(new CompareRequest("ou=testProcessRequests," + getTestBaseDN(),
                                    "description", "foo"));

    requests.add(new SearchRequest(getTestBaseDN(), SearchScope.SUB,
                                   "(objectClass=*)"));

    requests.add(new DeleteRequest("ou=testProcessRequests," +
                                   getTestBaseDN()));

    List<LDAPResult> results = pool.processRequests(requests, true);

    assertNotNull(results);
    assertEquals(results.size(), 6);

    assertEquals(results.get(0).getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertEquals(results.get(1).getResultCode(), ResultCode.SUCCESS);

    assertEquals(results.get(2).getResultCode(), ResultCode.SUCCESS);

    assertTrue(results.get(3) instanceof CompareResult);
    assertEquals(results.get(3).getResultCode(), ResultCode.COMPARE_TRUE);

    assertTrue(results.get(4) instanceof SearchResult);
    assertEquals(results.get(4).getResultCode(), ResultCode.SUCCESS);
    assertEquals(((SearchResult) results.get(4)).getEntryCount(), 2);

    assertEquals(results.get(5).getResultCode(), ResultCode.SUCCESS);
  }



  /**
   * Tests the creation and use of a connection pool with SSL-based connections.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLPool()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory());

    conn.connect(getTestHost(), getTestSSLPort());
    conn.bind(getTestBindDN(), getTestBindPassword());

    LDAPConnectionPool p = new LDAPConnectionPool(conn, 1);

    try
    {
      p.getRootDSE();
    }
    finally
    {
      p.close();
    }
  }



  /**
   * Tests the creation and use of a connection pool with connections that use
   * StartTLS via a post-connect processor.
   * <BR><BR>
   * Access to an StartTLS-enabled Directory Server instance is required for
   * complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testStartTLSPool()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    StartTLSPostConnectProcessor startTLSProcessor =
         new StartTLSPostConnectProcessor(sslUtil.createSSLContext());

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setAutoReconnect(true);

    SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort(), options);
    SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());

    LDAPConnectionPool p = new LDAPConnectionPool(serverSet, bindRequest, 1, 2,
                                                  startTLSProcessor);

    try
    {
      p.getRootDSE();
    }
    finally
    {
      p.close();
    }
  }



  /**
   * Provides test coverage for the {@code throwLDAPException} method with an
   * {@code LDAPException} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowLDAPExceptionWithLDAPException()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.OTHER);
    }

    LDAPConnection conn = pool.getConnection();

    pool.throwLDAPException(new LDAPException(ResultCode.OTHER), conn);
  }



  /**
   * Provides test coverage for the {@code throwLDAPException} method with a
   * generic {@code Exception} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowLDAPExceptionWithGenericException()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.OTHER);
    }

    LDAPConnection conn = pool.getConnection();

    pool.throwLDAPException(new Exception(), conn);
  }



  /**
   * Provides test coverage for the {@code throwLDAPSearchException} method with
   * an {@code LDAPSearchException} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowLDAPSearchExceptionWithLDAPSearchException()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.OTHER);
    }

    LDAPConnection conn = pool.getConnection();

    pool.throwLDAPSearchException(
         new LDAPSearchException(ResultCode.OTHER, "foo"), conn);
  }



  /**
   * Provides test coverage for the {@code throwLDAPSearchException} method with
   * an {@code LDAPException} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowLDAPSearchExceptionWithLDAPException()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.OTHER);
    }

    LDAPConnection conn = pool.getConnection();

    pool.throwLDAPSearchException(new LDAPException(ResultCode.OTHER), conn);
  }



  /**
   * Provides test coverage for the {@code throwLDAPSearchException} method with
   * a generic {@code Exception} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testThrowLDAPSearchExceptionWithGenericException()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.OTHER);
    }

    LDAPConnection conn = pool.getConnection();

    pool.throwLDAPSearchException(new Exception(), conn);
  }



  /**
   * Provides test coverage for the case in which a connection is closed when
   * that connection is part of a connection pool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClosePooledConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = pool.getConnection();
    conn.close();
  }



  /**
   * Provides test coverage for the case in which a connection is closed when
   * that connection is part of a connection pool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClosePooledConnectionWithControls()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = pool.getConnection();
    conn.close(new Control[] { new Control("1.2.3.4", false) });
  }



  /**
   * Provides test coverage for the methods used for getting and setting the
   * maximum connection age.
   */
  @Test()
  public void testMaxConnectionAge()
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);

    assertEquals(pool.getMinDisconnectIntervalMillis(), 0L);

    assertFalse(pool.checkConnectionAgeOnRelease());

    pool.setMaxConnectionAgeMillis(1234L);
    assertEquals(pool.getMaxConnectionAgeMillis(), 1234L);

    pool.setMinDisconnectIntervalMillis(10L);
    assertEquals(pool.getMinDisconnectIntervalMillis(), 10L);

    pool.setCheckConnectionAgeOnRelease(true);
    assertTrue(pool.checkConnectionAgeOnRelease());

    pool.setMaxConnectionAgeMillis(-1L);
    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);

    pool.setMinDisconnectIntervalMillis(-1L);
    assertEquals(pool.getMinDisconnectIntervalMillis(), 0L);

    pool.setCheckConnectionAgeOnRelease(false);
    assertFalse(pool.checkConnectionAgeOnRelease());

    pool.setMaxConnectionAgeMillis(4321L);
    assertEquals(pool.getMaxConnectionAgeMillis(), 4321L);

    pool.setMinDisconnectIntervalMillis(1000L);
    assertEquals(pool.getMinDisconnectIntervalMillis(), 1000L);

    pool.setMaxConnectionAgeMillis(0L);
    assertEquals(pool.getMaxConnectionAgeMillis(), 0L);

    pool.setMinDisconnectIntervalMillis(0L);
    assertEquals(pool.getMinDisconnectIntervalMillis(), 0L);
  }



  /**
   * Tests the behavior with per-connection schema caching enabled.  It should
   * ensure that each connection has a reference to the same schema object
   * rather than different copies of equivalent objects.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPerConnectionSchema()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSchema(true);

    final LDAPConnection conn = new LDAPConnection(options, getTestHost(),
         getTestPort(), getTestBindDN(), getTestBindPassword());
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    assertNotNull(conn.getCachedSchema());

    final LDAPConnectionPool pool = new LDAPConnectionPool(conn, 5, 5);

    final LDAPConnection c1 = pool.getConnection();
    final LDAPConnection c2 = pool.getConnection();
    final LDAPConnection c3 = pool.getConnection();
    final LDAPConnection c4 = pool.getConnection();
    final LDAPConnection c5 = pool.getConnection();

    assertNotNull(c1);
    assertNotNull(c2);
    assertNotNull(c3);
    assertNotNull(c4);
    assertNotNull(c5);

    assertSame(c1.getCachedSchema(), c2.getCachedSchema());
    assertSame(c1.getCachedSchema(), c3.getCachedSchema());
    assertSame(c1.getCachedSchema(), c4.getCachedSchema());
    assertSame(c1.getCachedSchema(), c5.getCachedSchema());

    pool.releaseConnection(c1);
    pool.releaseConnection(c2);
    pool.releaseConnection(c3);
    pool.releaseConnection(c4);
    pool.releaseConnection(c5);

    pool.close();
  }



  /**
   * Tests the behavior with pool-wide schema caching enabled.  It should ensure
   * that each connection has a reference to the same schema object rather than
   * different copies of equivalent objects.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPooledSchema()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUsePooledSchema(true);

    final LDAPConnection conn = new LDAPConnection(options, getTestHost(),
         getTestPort(), getTestBindDN(), getTestBindPassword());
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    assertNull(conn.getCachedSchema());

    final LDAPConnectionPool pool = new LDAPConnectionPool(conn, 5, 5);
    assertNotNull(conn.getCachedSchema());

    final LDAPConnection c1 = pool.getConnection();
    final LDAPConnection c2 = pool.getConnection();
    final LDAPConnection c3 = pool.getConnection();
    final LDAPConnection c4 = pool.getConnection();
    final LDAPConnection c5 = pool.getConnection();

    assertNotNull(c1);
    assertNotNull(c2);
    assertNotNull(c3);
    assertNotNull(c4);
    assertNotNull(c5);

    assertSame(c1.getCachedSchema(), c2.getCachedSchema());
    assertSame(c1.getCachedSchema(), c3.getCachedSchema());
    assertSame(c1.getCachedSchema(), c4.getCachedSchema());
    assertSame(c1.getCachedSchema(), c5.getCachedSchema());

    pool.releaseConnection(c1);
    pool.releaseConnection(c2);
    pool.releaseConnection(c3);
    pool.releaseConnection(c4);
    pool.releaseConnection(c5);

    pool.close();
  }



  /**
   * Tests the ability to successfully create a pool of connections to a server
   * that is down, and have the pool work properly when the server comes up.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreatePoolToDownServer()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    assertTrue(ds.getListenPort() > 0L);
    assertTrue(ds.getListenPort() <= 65535L);

    final ServerSet serverSet =
         new SingleServerSet("localhost", ds.getListenPort());

    ds.shutDown(true);

    try
    {
      new LDAPConnectionPool(serverSet, null, 1, 10, null, true);
      fail("Expected an exception when trying to create a connection to a " +
           "down server");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    final LDAPConnectionPool p = new LDAPConnectionPool(serverSet, null, 1, 10,
         null, false);

    try
    {
      p.getRootDSE();
      fail("Expected an exception when trying to communicate with a down " +
           "server");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    ds.startListening();
    assertNotNull(p.getRootDSE());

    p.close(false, 1);
    ds.shutDown(true);
  }



  /**
   * Tests the ability to establish connections in parallel when provided with
   * an initial connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParallelConnectWithInitialConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    final LDAPConnection conn = new LDAPConnection(options, getTestHost(),
         getTestPort(), getTestBindDN(), getTestBindPassword());
    assertTrue(conn.synchronousMode());

    final LDAPConnectionPool p =
         new LDAPConnectionPool(conn, 10, 10, 2, null, true,
              new LDAPConnectionPoolHealthCheck());
    assertFalse(p.isClosed());

    assertEquals(p.getConnectionPoolStatistics().getNumAvailableConnections(),
         10);

    assertNotNull(p.getRootDSE());

    p.close(true, 2);
  }



  /**
   * Tests the ability to establish connections in parallel when provided with
   * a server set and bind request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParallelConnectWithServerSet()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final ServerSet serverSet = new SingleServerSet(
         getTestHost(), getTestPort());

    final BindRequest bindRequest = new SimpleBindRequest(getTestBindDN(),
         getTestBindPassword());

    final LDAPConnectionPool p =
         new LDAPConnectionPool(serverSet, bindRequest, 10, 10, 2, null, true,
              new LDAPConnectionPoolHealthCheck());
    assertFalse(p.isClosed());

    assertEquals(p.getConnectionPoolStatistics().getNumAvailableConnections(),
         10);

    assertNotNull(p.getRootDSE());

    p.close(false, 2);
  }



  /**
   * Tests the ability to establish connections in parallel when provided with
   * a server set and bind request.  The bind request will include the wrong
   * password, and the pool will be configured to throw an exception when a
   * connect failure is encountered.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParallelConnectWithServerSetWrongPasswordThrowOnFailure()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final ServerSet serverSet = new SingleServerSet(
         getTestHost(), getTestPort());

    final BindRequest bindRequest = new SimpleBindRequest(getTestBindDN(),
         "wrong-" + getTestBindPassword());

    try
    {
      final LDAPConnectionPool p =
           new LDAPConnectionPool(serverSet, bindRequest, 10, 10, 2, null,
                true);
      p.close(false, 2);
      fail("Expected an exception when trying to create a pool with the " +
           "wrong bind password.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the ability to establish connections in parallel when provided with
   * a server set and bind request.  The bind request will include the wrong
   * password, and the pool will be configured to not throw an exception when
   * a connect failure is encountered.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParallelConnectWithServerSetWrongPasswordAllowFailure()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final ServerSet serverSet = new SingleServerSet(
         getTestHost(), getTestPort());

    final BindRequest bindRequest = new SimpleBindRequest(getTestBindDN(),
         "wrong-" + getTestBindPassword());

    final LDAPConnectionPool p =
         new LDAPConnectionPool(serverSet, bindRequest, 10, 10, 2, null, false);
    assertFalse(p.isClosed());

    assertEquals(p.getConnectionPoolStatistics().getNumAvailableConnections(),
         0);

    p.close(false, 1);
  }



  /**
   * Tests teh ability to close connections in parallel when the connection pool
   * is empty.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParallelCloseOfEmptyPool()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    final LDAPConnectionPool p = new LDAPConnectionPool(c, 1);

    assertEquals(p.getMaximumAvailableConnections(), 1);
    assertEquals(p.getCurrentAvailableConnections(), 1);
    assertFalse(p.isClosed());

    c = p.getConnection();
    assertNotNull(c);

    assertEquals(p.getMaximumAvailableConnections(), 1);
    assertEquals(p.getCurrentAvailableConnections(), 0);
    assertFalse(p.isClosed());

    p.discardConnection(c);

    assertEquals(p.getMaximumAvailableConnections(), 1);
    assertEquals(p.getCurrentAvailableConnections(), 0);
    assertFalse(p.isClosed());

    p.close(true, 2);
    assertTrue(p.isClosed());
  }



  /**
   * Provides test coverage for the {@code releaseAndReAuthenticateConnection}
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReleaseAndReAuthenticateConnection()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=user1", "password1");
    cfg.addAdditionalBindCredentials("cn=user2", "password2");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Test a pool that uses unauthenticated connections.
    LDAPConnectionPool pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()), null, 1, 1);
    pool.releaseAndReAuthenticateConnection(null);

    LDAPConnection conn = pool.getConnection();
    assertBoundAs(conn, "");

    conn.bind("cn=user2", "password2");
    assertBoundAs(conn, "cn=user2");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    conn.bind("", "");
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    try
    {
      conn.bind("cn=missing", "invalid");
    } catch (final Exception e) {}
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with simple binds.
    pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new SimpleBindRequest("cn=user1", "password1"), 1, 1);

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("cn=user2", "password2");
    assertBoundAs(conn, "cn=user2");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("", "");
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    try
    {
      conn.bind("cn=missing", "invalid");
    } catch (final Exception e) {}
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with SASL PLAIN binds.
    pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new PLAINBindRequest("dn:cn=user1", "password1"), 1, 1);

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("cn=user2", "password2");
    assertBoundAs(conn, "cn=user2");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    conn.bind("", "");
    assertBoundAs(conn, "");

    pool.releaseConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    try
    {
      conn.bind("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    assertBoundAs(conn, "");

    pool.releaseAndReAuthenticateConnection(conn);
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    ds.shutDown(true);
    pool.releaseAndReAuthenticateConnection(conn);
    pool.close();
  }



  /**
   * Provides test coverage for the {@code bindAndRevertAuthentication} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindAndRevertAuthentication()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=user1", "password1");
    cfg.addAdditionalBindCredentials("cn=user2", "password2");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    // Test a pool that uses unauthenticated connections.
    LDAPConnectionPool pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()), null, 1, 1);
    pool.releaseAndReAuthenticateConnection(null);

    LDAPConnection conn = pool.getConnection();
    assertBoundAs(conn, "");
    pool.releaseConnection(conn);

    pool.bind("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "");
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    conn = pool.getConnection();
    assertBoundAs(conn, "");
    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with simple binds.
    pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new SimpleBindRequest("cn=user1", "password1"), 1, 1);

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bind("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("", "");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);
    pool.close();


    // Test a pool that uses connections authenticated with SASL PLAIN binds.
    pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new PLAINBindRequest("dn:cn=user1", "password1"), 1, 1);
    pool.setRetryFailedOperationsDueToInvalidConnections(true);

    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bind("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user2");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    pool.bindAndRevertAuthentication("", "");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=missing", "invalid");
      fail("Expected an exception with invalid credentials");
    } catch (final Exception e) {}
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    ds.shutDown(true);
    pool.releaseConnection(conn);

    try
    {
      pool.bindAndRevertAuthentication("cn=user2", "password2");
      fail("Expected an exception with the server shut down");
    } catch (final Exception e) {}

    ds.startListening();
    pool.bindAndRevertAuthentication("cn=user2", "password2");
    conn = pool.getConnection();
    assertBoundAs(conn, "cn=user1");

    ds.shutDown(true);
    pool.releaseConnection(conn);
    pool.close();
  }



  /**
   * Ensures that the provided connection is bound as the user with the
   * specified DN.
   *
   * @param  conn  The connection to examine.
   * @param  dn    The expected DN of the authenticated user.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void assertBoundAs(final LDAPConnection conn, final String dn)
          throws Exception
  {
    final WhoAmIExtendedResult whoAmIResult =
         (WhoAmIExtendedResult)
         conn.processExtendedOperation(new WhoAmIExtendedRequest());
    assertResultCodeEquals(whoAmIResult, ResultCode.SUCCESS);

    final String authzID = whoAmIResult.getAuthorizationID();
    assertNotNull(authzID);
    assertTrue(authzID.startsWith("dn:"));
    assertDNsEqual(authzID.substring(3), dn);
  }



  /**
   * Tests the behavior of the {@code connect} method that takes an address and
   * port of the server to which the desired connection should be established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionToServer()
         throws Exception
  {
    final InMemoryDirectoryServer ds1 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds1.startListening();
    final int port1 = ds1.getListenPort();
    assertTrue((port1 >= 1) && (port1 <= 65535));

    final InMemoryDirectoryServer ds2 =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds2.startListening();
    final int port2 = ds2.getListenPort();
    assertTrue((port2 >= 1) && (port2 <= 65535));
    assertFalse(port1 == port2);

    final String[] addresses =
    {
      "localhost",
      "localhost"
    };

    final int[] ports =
    {
      port1,
      port2
    };

    final RoundRobinServerSet roundRobinSet =
         new RoundRobinServerSet(addresses, ports);
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(roundRobinSet, null, 10, 10);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    int count1 = 0;
    int count2 = 0;
    final ArrayList<LDAPConnection> connList =
         new ArrayList<LDAPConnection>(10);
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      connList.add(conn);
      assertEquals(conn.getConnectedAddress(), "localhost");
      if (conn.getConnectedPort() == port1)
      {
        count1++;
      }
      else if (conn.getConnectedPort() == port2)
      {
        count2++;
      }
      else
      {
        fail("Unexpected connection port " + conn.getConnectedPort() +
             " doesn't match port1 " + port1 + " or port2 " + port2);
      }
      assertEquals(pool.getCurrentAvailableConnections(),
           (10 - i - 1));
    }
    assertEquals(count1, 5);
    assertEquals(count2, 5);
    assertEquals(pool.getCurrentAvailableConnections(), 0);

    for (int i=0; i < 10 ; i++)
    {
      pool.releaseConnection(connList.get(i));
      assertEquals(pool.getCurrentAvailableConnections(), (i+1));
    }
    connList.clear();
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    LDAPConnection conn = pool.getConnection("localhost", port1);
    assertNotNull(conn);
    assertEquals(conn.getConnectedAddress(), "localhost");
    assertEquals(conn.getConnectedPort(), port1);
    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    conn = pool.getConnection("localhost", port1);
    assertNotNull(conn);
    assertEquals(conn.getConnectedAddress(), "localhost");
    assertEquals(conn.getConnectedPort(), port1);
    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    conn = pool.getConnection("localhost", port2);
    assertNotNull(conn);
    assertEquals(conn.getConnectedAddress(), "localhost");
    assertEquals(conn.getConnectedPort(), port2);
    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    conn = pool.getConnection("localhost", port2);
    assertNotNull(conn);
    assertEquals(conn.getConnectedAddress(), "localhost");
    assertEquals(conn.getConnectedPort(), port2);
    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    assertNull(pool.getConnection("unknown.example.com", port1));
    assertNull(pool.getConnection("127.0.0.1", port1));
    assertNull(pool.getConnection("localhost", 123456));
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    for (int i=0; i < 5; i++)
    {
      conn = pool.getConnection("localhost", port1);
      assertNotNull(conn);
      connList.add(conn);
      assertEquals(pool.getCurrentAvailableConnections(), (10-i-1));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 5);
    assertNull(pool.getConnection("localhost", port1));

    for (int i=0; i < 5; i++)
    {
      conn = pool.getConnection("localhost", port2);
      assertNotNull(conn);
      connList.add(conn);
      assertEquals(pool.getCurrentAvailableConnections(), (5-i-1));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 0);
    assertNull(pool.getConnection("localhost", port1));
    assertNull(pool.getConnection("localhost", port2));

    for (int i=0; i < 10; i++)
    {
      pool.releaseConnection(connList.get(i));
      assertEquals(pool.getCurrentAvailableConnections(), (i+1));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    conn = pool.getConnection("localhost", port1);
    assertNotNull(conn);
    assertEquals(conn.getConnectedAddress(), "localhost");
    assertEquals(conn.getConnectedPort(), port1);
    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    conn = pool.getConnection("localhost", port2);
    assertNotNull(conn);
    assertEquals(conn.getConnectedAddress(), "localhost");
    assertEquals(conn.getConnectedPort(), port2);
    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    pool.close();
    assertEquals(pool.getCurrentAvailableConnections(), 0);

    assertNull(pool.getConnection("localhost", port1));
    assertNull(pool.getConnection("localhost", port2));
  }



  /**
   * Tests the behavior of the {@code discardConnection} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDiscardConnection()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("localhost", ds.getListenPort());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 10, 10);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    pool.setCreateIfNecessary(false);

    final ArrayList<LDAPConnection> connList =
         new ArrayList<LDAPConnection>(10);
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      assertEquals(pool.getCurrentAvailableConnections(), (10-i-1));
      connList.add(conn);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 0);

    try
    {
      pool.getConnection();
      fail("Expected an exception when trying to check out a connection when " +
           "the maximum number of connections were already checked out.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.CONNECT_ERROR);
    }

    for (int i=0; i < 10; i++)
    {
      pool.releaseConnection(connList.get(i));
      assertEquals(pool.getCurrentAvailableConnections(), (i+1));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 10);
    connList.clear();

    pool.discardConnection(null);
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      assertEquals(pool.getCurrentAvailableConnections(), (10 - i - 1));
      assertTrue(conn.isConnected());
      pool.discardConnection(conn);
      assertEquals(pool.getCurrentAvailableConnections(), (10 - i - 1));
      assertFalse(conn.isConnected());
    }
    assertEquals(pool.getCurrentAvailableConnections(), 0);

    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      assertEquals(pool.getCurrentAvailableConnections(), 0);
      connList.add(conn);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 0);

    try
    {
      pool.getConnection();
      fail("Expected an exception when trying to check out a connection when " +
           "the maximum number of connections were already checked out.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.CONNECT_ERROR);
    }

    for (int i=0; i < 10; i++)
    {
      pool.releaseConnection(connList.get(i));
      assertEquals(pool.getCurrentAvailableConnections(), (i+1));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 10);
    connList.clear();

    pool.close();
  }



  /**
   * Provides test coverage for the {@code processRequestsAsync} method.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create the connection pool.
    final SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 10, 10);


    // Add an initial set of data to the server.
    pool.add(
         "dn: ou=test 1," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 1");
    pool.add(
         "dn: ou=test 2," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 2");
    pool.add(
         "dn: ou=test 3," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 3");
    pool.add(
         "dn: ou=test 4," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 4");


    // Create a set of requests that will be processed asynchronously.
    final ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>(6);
    requests.add(new AddRequest(
         "dn: ou=test 5," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 5"));
    requests.add(new CompareRequest("ou=test 1," + getTestBaseDN(),
         "ou", "test 1"));
    requests.add(new DeleteRequest("ou=test 2," + getTestBaseDN()));
    requests.add(new ModifyRequest(
         "dn: ou=test 3," + getTestBaseDN(),
         "changetype: modify",
         "add: description",
         "description: foo"));
    requests.add(new ModifyDNRequest("ou=test 4," + getTestBaseDN(),
         "ou=test four", true));
    requests.add(new SearchRequest(
         new TestAsyncListener(), getTestBaseDN(), SearchScope.SUB,
         Filter.createPresenceFilter("objectClass")));


    // Process the given requests asynchronously.  Make sure that when the
    // method returns, all of the requests have completed and have a result.
    final List<AsyncRequestID> requestIDs =
         pool.processRequestsAsync(requests, 0L);
    assertNotNull(requestIDs);
    assertEquals(requestIDs.size(), requests.size());

    for (final AsyncRequestID requestID : requestIDs)
    {
      assertTrue(requestID.isDone());
      assertNotNull(requestID.get(1L, TimeUnit.MILLISECONDS));
      assertResultCodeEquals(requestID.get(1L, TimeUnit.MILLISECONDS),
           ResultCode.SUCCESS, ResultCode.COMPARE_TRUE);
    }


    // Remove the test entries from the server.
    pool.delete("ou=test 1," + getTestBaseDN());
    pool.delete("ou=test 3," + getTestBaseDN());
    pool.delete("ou=test four," + getTestBaseDN());
    pool.delete("ou=test 5," + getTestBaseDN());


    pool.close();
  }



  /**
   * Provides test coverage for the {@code processRequestsAsync} method using a
   * tiny timeout that may cause requests to be canceled.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncOperationsWithTinyTimeout()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create the connection pool.
    final SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort());
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 10, 10);


    // Add an initial set of data to the server.
    pool.add(
         "dn: ou=test 1," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 1");
    pool.add(
         "dn: ou=test 2," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 2");
    pool.add(
         "dn: ou=test 3," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 3");


    // Create a set of requests that will be processed asynchronously.  Just
    // use modify operations so we don't have to worry about which entries will
    // exist at the end of the testing.
    final ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>(3);
    requests.add(new ModifyRequest(
         "dn: ou=test 1," + getTestBaseDN(),
         "changetype: modify",
         "add: description",
         "description: foo"));
    requests.add(new ModifyRequest(
         "dn: ou=test 2," + getTestBaseDN(),
         "changetype: modify",
         "add: description",
         "description: bar"));
    requests.add(new ModifyRequest(
         "dn: ou=test 3," + getTestBaseDN(),
         "changetype: modify",
         "add: description",
         "description: baz"));


    // Process the given requests asynchronously.  Make sure that when the
    // method returns, all of the requests have completed and have a result.
    final List<AsyncRequestID> requestIDs =
         pool.processRequestsAsync(requests, 1L);
    assertNotNull(requestIDs);
    assertEquals(requestIDs.size(), requests.size());

    for (final AsyncRequestID requestID : requestIDs)
    {
      assertTrue(requestID.isDone());
      assertNotNull(requestID.get(1L, TimeUnit.MILLISECONDS));
    }


    // Remove the test entries from the server.
    pool.delete("ou=test 1," + getTestBaseDN());
    pool.delete("ou=test 2," + getTestBaseDN());
    pool.delete("ou=test 3," + getTestBaseDN());


    pool.close();
  }



  /**
   * Tests the behavior of the {@code processRequestsAsync} method for a
   * pool with connections operating in synchronous mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAsyncOperationsOnSynchronousConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create the connection pool.
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    final SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort(), options);
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 10, 10);


    // Create a set of requests that will be processed asynchronously.  This
    // list will have only a single request, and it won't be processed anyway.
    final ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>(1);
    requests.add(new AddRequest(
         "dn: ou=test 1," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 1"));

    try
    {
      pool.processRequestsAsync(requests, 0L);
      fail("Expected an exception for attempting asynchronous requests in " +
           "synchronous mode");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }
    finally
    {
      pool.close();
    }
  }



  /**
   * Tests the behavior of the {@code processRequestsAsync} method when
   * requesting operations that cannot be processed asynchronously.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisallowedAsyncOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // Create the connection pool.
    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);
    final SingleServerSet serverSet =
         new SingleServerSet(getTestHost(), getTestPort(), options);
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(getTestBindDN(), getTestBindPassword());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, bindRequest, 10, 10);


    // Ensure a bind request is rejected.
    final ArrayList<LDAPRequest> requests = new ArrayList<LDAPRequest>(1);
    requests.add(new SimpleBindRequest("", ""));
    try
    {
      pool.processRequestsAsync(requests, 0L);
      fail("Expected an exception when attempting an async bind request.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }


    // Ensure an extended request is rejected.
    requests.clear();
    requests.add(new WhoAmIExtendedRequest());
    try
    {
      pool.processRequestsAsync(requests, 0L);
      fail("Expected an exception when attempting an async extended request.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }


    // Ensure a search request is rejected if it doesn't include a search result
    // listener.
    requests.clear();
    requests.add(new SearchRequest("", SearchScope.BASE, "(objectClass=*)"));
    try
    {
      pool.processRequestsAsync(requests, 0L);
      fail("Expected an exception when attempting a non-async search request.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
      assertResultCodeEquals(le, ResultCode.PARAM_ERROR);
    }


    pool.close();
  }



  /**
   * Tests the behavior of the {@code shrinkPool} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShrinkPool()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("localhost", ds.getListenPort());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 10, 10);
    assertEquals(pool.getCurrentAvailableConnections(), 10);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.shrinkPool(5);
    assertEquals(pool.getCurrentAvailableConnections(), 5);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    final ArrayList<LDAPConnection> connList =
         new ArrayList<LDAPConnection>(10);
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      connList.add(conn);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 0);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    for (final LDAPConnection conn : connList)
    {
      pool.releaseConnection(conn);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 10);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.setCreateIfNecessary(false);

    connList.clear();
    for (int i=0; i < 10; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      connList.add(conn);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 0);

    for (int i=0; i < 7; i++)
    {
      pool.releaseConnection(connList.remove(0));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 7);

    pool.shrinkPool(3);
    assertEquals(pool.getCurrentAvailableConnections(), 3);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.shrinkPool(10);
    assertEquals(pool.getCurrentAvailableConnections(), 3);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    for (int i=0; i < 3; i++)
    {
      pool.releaseConnection(connList.remove(0));
    }
    assertEquals(pool.getCurrentAvailableConnections(), 6);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.close();
  }



  /**
   * Tests the behavior of the methods used to set a goal for the minimum number
   * of available connections.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimumAvailableConnectionGoal()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("localhost", ds.getListenPort());
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 5, 10);
    assertEquals(pool.getCurrentAvailableConnections(), 5);
    assertEquals(pool.getMaximumAvailableConnections(), 10);

    pool.setHealthCheckIntervalMillis(10L);
    assertEquals(pool.getMinimumAvailableConnectionGoal(), 0);

    pool.setMinimumAvailableConnectionGoal(5);
    assertEquals(pool.getMinimumAvailableConnectionGoal(), 5);

    final LDAPConnection conn = pool.getConnection();
    long stopWaitingTime = System.currentTimeMillis() + 5000L;
    while ((pool.getCurrentAvailableConnections() < 5) &&
           (System.currentTimeMillis() < stopWaitingTime))
    {
      Thread.sleep(10L);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 5);

    pool.releaseConnection(conn);
    assertEquals(pool.getCurrentAvailableConnections(), 6);

    pool.setMinimumAvailableConnectionGoal(50);
    assertEquals(pool.getMinimumAvailableConnectionGoal(), 10);

    stopWaitingTime = System.currentTimeMillis() + 5000L;
    while ((pool.getCurrentAvailableConnections() < 10) &&
           (System.currentTimeMillis() < stopWaitingTime))
    {
      Thread.sleep(10L);
    }
    assertEquals(pool.getCurrentAvailableConnections(), 10);

    pool.setMinimumAvailableConnectionGoal(-1);
    assertEquals(pool.getMinimumAvailableConnectionGoal(), 0);

    pool.close();
  }



  /**
   * Tests the behavior of the connection pool when using a health check that
   * may throw an exception in the
   * {@code ensureConnectionValidAfterAuthentication}  method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPostBindHealthCheckFailure()
         throws Exception
  {
    // Create health checks that will fail and pass, respectively.
    final TestLDAPConnectionPoolHealthCheck failureHealthCheck =
         new TestLDAPConnectionPoolHealthCheck(null,
              new LDAPBindException(new BindResult(1,
                   ResultCode.INVALID_CREDENTIALS, "Health check failure", null,
                   null, null)),
              null, null, null, null);

    final TestLDAPConnectionPoolHealthCheck successHealthCheck =
         new TestLDAPConnectionPoolHealthCheck();


    // Create a new in-memory directory server instance and use it to get a
    // connection pool to that instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnectionPool pool = new LDAPConnectionPool(
         new SingleServerSet("127.0.0.1", ds.getListenPort()),
         new SimpleBindRequest("cn=Directory Manager", "password"), 0, 1, 0,
         null, false, failureHealthCheck);


    // Ensure that an attempt to use the connection pool to get the server root
    // DSE fails because of the health check.
    try
    {
      pool.getRootDSE();
      fail("Expected an exception when trying to get the root DSE for a " +
           "newly-created connection");
    }
    catch (final LDAPBindException lbe)
    {
      assertEquals(lbe.getResultCode(), ResultCode.INVALID_CREDENTIALS);
      assertEquals(lbe.getDiagnosticMessage(), "Health check failure");
    }


    // Replace the health check and verify that the attempt to get the root DSE
    // will now succeed.
    pool.setHealthCheck(successHealthCheck);
    assertNotNull(pool.getRootDSE());
    assertEquals(pool.getCurrentAvailableConnections(), 1);


    // Ensure that the bindAndRevertAuthentication method succeeds with the
    // success health check in place.
    pool.bindAndRevertAuthentication("", "");
    assertEquals(pool.getCurrentAvailableConnections(), 1);


    // Replace the health check with a failure health check and verify that
    // the bindAndRevertAuthentication method still succeeds but now ends up
    // without any available connections.
    pool.setHealthCheck(failureHealthCheck);
    pool.bindAndRevertAuthentication("", "");
    assertEquals(pool.getCurrentAvailableConnections(), 0);


    // Clean up after testing has completed.
    pool.setHealthCheck(successHealthCheck);
    pool.close();
    ds.shutDown(true);
  }



  /**
   * Tests the behavior when trying to replace a defunct connection in a
   * connection pool when it's not possible to immediately replace the
   * connection and {@code createIfNecessary} is false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReplaceDefunctConnectionWithCreateIfNecessaryFalse()
         throws Exception
  {
    // Create an in-memory directory server to use for testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    // Create a connection pool to use for testing.  Make sure to set
    // createIfNecessary to false.
    final LDAPConnectionPool pool = new LDAPConnectionPool(
         new SingleServerSet("localhost", ds.getListenPort()),
         new SimpleBindRequest("cn=Directory Manager", "password"), 5, 5);
    pool.setCreateIfNecessary(false);
    pool.setMaxWaitTimeMillis(0L);

    // Check out all five connections from the pool.
    final ArrayList<LDAPConnection> checkedOutConnections =
         new ArrayList<LDAPConnection>(5);
    for (int i=0; i < 5; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      assertNotNull(conn.getRootDSE());
      checkedOutConnections.add(conn);
    }

    // Verify that it's not possible to check out any more connections.
    try
    {
      pool.getConnection();
      fail("Expected an exception when trying to check out another " +
           "connection when all connections are currently checked out");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    // Shut down the in-memory directory server so that it's not possible to
    // replace defunct connections.
    ds.shutDown(true);

    // Replace all the defunct connections.  This should fail because the server
    // is down.
    for (final LDAPConnection conn : checkedOutConnections)
    {
      try
      {
        pool.replaceDefunctConnection(conn);
        fail("Expected an exception when trying to replace a defunct " +
             "connection with the server offline");
      }
      catch (final LDAPException le)
      {
        // This was expected.
      }
    }

    // Start the server again.
    ds.startListening();

    // Verify that it is once again possible to retrieve and use connections
    // from the pool.
    checkedOutConnections.clear();
    for (int i=0; i < 5; i++)
    {
      final LDAPConnection conn = pool.getConnection();
      assertNotNull(conn);
      assertNotNull(conn.getRootDSE());
      checkedOutConnections.add(conn);
    }

    // Verify that we still can't check out a connection when all available
    // connections are taken.
    try
    {
      pool.getConnection();
      fail("Expected an exception when trying to check out another " +
           "connection when all connections are currently checked out");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    // Release all of the connections, close the pool, and shut down the server.
    for (final LDAPConnection conn : checkedOutConnections)
    {
      pool.releaseConnection(conn);
    }

    pool.close();
    ds.shutDown(true);
  }
}
