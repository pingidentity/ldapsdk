/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases which may be used to test the
 * behavior of LDAP connections operating in synchronous mode.
 */
public class SynchronousModeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the LDAP SDK when attempting to process a number of
   * operations in synchronous mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection conn = new LDAPConnection(options);
    assertEquals(conn.getActiveOperationCount(), -1);

    conn.connect(getTestHost(), getTestPort());
    assertEquals(conn.getActiveOperationCount(), -1);

    try
    {
      assertTrue(conn.synchronousMode());


      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


      LDAPResult result = conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      String peopleDN = "ou=People," + getTestBaseDN();
      result = conn.add(
           "dn: " + peopleDN,
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      assertTrue(conn.compare(peopleDN, "ou", "people").compareMatched());


      result = conn.modify(
           "dn: " + peopleDN,
           "changetype: modify",
           "replace: description",
           "description: Test description");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      Entry e = conn.getEntry(peopleDN);
      assertNotNull(e);
      assertTrue(e.hasAttributeValue("description", "Test description"));


      result = conn.modifyDN(peopleDN, "ou=Users", true);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
           "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getSearchEntries().size(), 2);


      result = conn.delete("ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      result = conn.delete(getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the behavior of the LDAP SDK when attempting to process a number of
   * operations in synchronous mode over an SSL-based connection.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperationsOverSSL()
       throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection conn =
         new LDAPConnection(sslUtil.createSSLSocketFactory(), options);

    conn.connect(getTestHost(), getTestSSLPort());

    try
    {
      assertTrue(conn.synchronousMode());


      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


      LDAPResult result = conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      String peopleDN = "ou=People," + getTestBaseDN();
      result = conn.add(
           "dn: " + peopleDN,
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      assertTrue(conn.compare(peopleDN, "ou", "people").compareMatched());


      result = conn.modify(
           "dn: " + peopleDN,
           "changetype: modify",
           "replace: description",
           "description: Test description");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      Entry e = conn.getEntry(peopleDN);
      assertNotNull(e);
      assertTrue(e.hasAttributeValue("description", "Test description"));


      result = conn.modifyDN(peopleDN, "ou=Users", true);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
                                              "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getSearchEntries().size(), 2);


      result = conn.delete("ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      result = conn.delete(getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the behavior of the LDAP SDK when attempting to process a number of
   * operations in synchronous mode over a StartTLS-based connection.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperationsOverStartTLS()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection conn = new LDAPConnection(options);

    conn.connect(getTestHost(), getTestPort());

    try
    {
      assertTrue(conn.synchronousMode());


      ExtendedResult extendedResult = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);


      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


      LDAPResult result = conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      String peopleDN = "ou=People," + getTestBaseDN();
      result = conn.add(
           "dn: " + peopleDN,
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      assertTrue(conn.compare(peopleDN, "ou", "people").compareMatched());


      result = conn.modify(
           "dn: " + peopleDN,
           "changetype: modify",
           "replace: description",
           "description: Test description");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      Entry e = conn.getEntry(peopleDN);
      assertNotNull(e);
      assertTrue(e.hasAttributeValue("description", "Test description"));


      result = conn.modifyDN(peopleDN, "ou=Users", true);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
           "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getSearchEntries().size(), 2);


      result = conn.delete("ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      result = conn.delete(getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the behavior of the LDAP SDK when attempting to process a number of
   * operations in synchronous mode when using a connection pool.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperationsWithConnectionPool()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection c = new LDAPConnection(options);

    c.connect(getTestHost(), getTestPort());
    assertTrue(c.synchronousMode());
    c.bind(getTestBindDN(), getTestBindPassword());

    LDAPConnectionPool pool = new LDAPConnectionPool(c, 5,  5);

    try
    {
      LinkedList<LDAPConnection> connList = new LinkedList<LDAPConnection>();
      for (int i=0; i < 5; i++)
      {
        c = pool.getConnection();
        assertTrue(c.synchronousMode());
        connList.add(c);
      }

      for (LDAPConnection conn : connList)
      {
        pool.releaseConnection(conn);
      }


      LDAPResult result = pool.add(getTestBaseDN(), getBaseEntryAttributes());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      String peopleDN = "ou=People," + getTestBaseDN();
      result = pool.add(
           "dn: " + peopleDN,
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      assertTrue(pool.compare(peopleDN, "ou", "people").compareMatched());


      result = pool.modify(
           "dn: " + peopleDN,
           "changetype: modify",
           "replace: description",
           "description: Test description");
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      Entry e = pool.getEntry(peopleDN);
      assertNotNull(e);
      assertTrue(e.hasAttributeValue("description", "Test description"));


      result = pool.modifyDN(peopleDN, "ou=Users", true);
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      SearchResult searchResult = pool.search(getTestBaseDN(), SearchScope.SUB,
           "(objectClass=*)");
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 2);
      assertEquals(searchResult.getSearchEntries().size(), 2);


      result = pool.delete("ou=Users," + getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);


      result = pool.delete(getTestBaseDN());
      assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      pool.close();
    }
  }



  /**
   * Tests the behavior of the LDAP SDK when attempting to perform a SASL bind
   * using a connection in synchronous mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLBind()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection conn = new LDAPConnection(options);

    conn.connect(getTestHost(), getTestPort());

    try
    {
      assertTrue(conn.synchronousMode());


      BindResult bindResult = conn.bind(new PLAINBindRequest(
           "dn:" + getTestBindDN(), getTestBindPassword()));
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the behavior of the LDAP SDK when attempting to perform operations
   * that are not allowed in synchronous mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProhibitedSynchronousOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setUseSynchronousMode(true);

    LDAPConnection conn = new LDAPConnection(options);

    conn.connect(getTestHost(), getTestPort());

    try
    {
      assertTrue(conn.synchronousMode());


      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


      try
      {
        conn.abandon(new AsyncRequestID(1, conn));
        fail("Expected an exception when attempting an abandon on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.processExtendedOperation(new CancelExtendedRequest(1));
        fail("Expected an exception when attempting a cancel on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.asyncAdd(new AddRequest(getTestBaseDN(), getBaseEntryAttributes()),
                      new TestAsyncListener());
        fail("Expected an exception when attempting an async add on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.asyncCompare(new CompareRequest("", "objectClass", "top"),
                          new TestAsyncListener());
        fail("Expected an exception when attempting an async compare on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.asyncDelete(new DeleteRequest(getTestBaseDN()),
                         new TestAsyncListener());
        fail("Expected an exception when attempting an async delete on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.asyncModify(new ModifyRequest(getTestBaseDN(),
             new Modification(ModificationType.REPLACE, "description", "foo")),
             new TestAsyncListener());
        fail("Expected an exception when attempting an async modify on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.asyncModifyDN(new ModifyDNRequest("ou=People," + getTestBaseDN(),
             "ou=Users", true), new TestAsyncListener());
        fail("Expected an exception when attempting an async modify DN on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }


      try
      {
        conn.asyncSearch(new SearchRequest(new TestAsyncListener(), "",
             SearchScope.BASE, "(objectClass=*)"));
        fail("Expected an exception when attempting an async search on a " +
             "synchronous connection");
      }
      catch (LDAPException le)
      {
        // This was expected.
        assertEquals(le.getResultCode(), ResultCode.NOT_SUPPORTED);
      }
    }
    finally
    {
      conn.close();
    }
  }
}
