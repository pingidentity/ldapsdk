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



import java.util.ArrayList;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the LDAPReadWriteConnectionPool
 * class.
 */
public class LDAPReadWriteConnectionPoolTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests using the provided connection pool.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @param  pool  The pool to use for the tests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testPools")
  public void testPool(LDAPReadWriteConnectionPool pool)
         throws Exception
  {
    String base = getTestBaseDN();


    // Test the ability to get and release connections from the pool.
    LDAPConnection conn1 = pool.getReadConnection();
    assertNotNull(conn1);

    LDAPConnection conn2 = pool.getReadConnection();
    assertNotNull(conn2);

    pool.releaseReadConnection(conn2);
    pool.releaseDefunctReadConnection(conn2);

    conn1 = pool.getWriteConnection();
    assertNotNull(conn1);

    conn2 = pool.getWriteConnection();
    assertNotNull(conn2);

    pool.releaseWriteConnection(conn1);
    pool.releaseDefunctWriteConnection(conn2);


    // Test methods for getting special types of entries.
    assertNotNull(pool.getRootDSE());

    assertNotNull(pool.getSchema());
    assertNotNull(pool.getSchema(""));

    assertNotNull(pool.getEntry(""));

    assertNotNull(pool.getEntry("", "objectClass"));


    // Test add operations.
    LDAPResult ldapResult = pool.add(base, getBaseEntryAttributes());
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ArrayList<Attribute> attrList = new ArrayList<Attribute>();
    attrList.add(new Attribute("objectClass", "top", "organizationalUnit"));
    attrList.add(new Attribute("ou", "test1"));
    ldapResult = pool.add("ou=test1," + base, attrList);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    Entry e = new Entry(
         "dn: ou=test2," + base,
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test2");
    ldapResult = pool.add(e);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.add(
         "dn: ou=test3," + base,
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test3");
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    AddRequest addRequest = new AddRequest(
         "dn: ou=test4," + base,
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test4");
    ldapResult = pool.add(addRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ReadOnlyAddRequest readOnlyAddRequest = new AddRequest(
         "dn: ou=test5," + base,
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test4");
    ldapResult = pool.add(readOnlyAddRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);


    // Test bind operations.
    BindResult bindResult = pool.bind(getTestBindDN(), getTestBindPassword());
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    bindResult = pool.bind(new SimpleBindRequest(getTestBindDN(),
                                                 getTestBindPassword()));
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


    // Test compare operations.
    CompareResult compareResult =
         pool.compare("ou=test1," + base, "ou", "test1");
    assertTrue(compareResult.compareMatched());

    CompareRequest compareRequest =
         new CompareRequest("ou=test2," + base, "ou", "test2");
    compareResult = pool.compare(compareRequest);
    assertTrue(compareResult.compareMatched());

    ReadOnlyCompareRequest readOnlyCompareRequest =
         new CompareRequest("ou=test3," + base, "ou", "test3");
    compareResult = pool.compare(readOnlyCompareRequest);
    assertTrue(compareResult.compareMatched());


    // Test modify operations.
    ldapResult = pool.modify("ou=test1," + base,
         new Modification(ModificationType.REPLACE, "description", "foo"));
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.modify("ou=test2," + base,
         new Modification(ModificationType.REPLACE, "l", "Austin"),
         new Modification(ModificationType.REPLACE, "st", "Texas"),
         new Modification(ModificationType.REPLACE, "description", "foo"));
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ArrayList<Modification> mods = new ArrayList<Modification>();
    mods.add(new Modification(ModificationType.REPLACE, "l", "Austin"));
    mods.add(new Modification(ModificationType.REPLACE, "st", "Texas"));
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));
    ldapResult = pool.modify("ou=test3," + base, mods);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.modify(
         "dn: ou=test4," + base,
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ModifyRequest modifyRequest = new ModifyRequest(
         "ou=test5," + base,
         new Modification(ModificationType.REPLACE, "description", "foo"));
    ldapResult = pool.modify(modifyRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ReadOnlyModifyRequest readOnlyModifyRequest = new ModifyRequest(
         "ou=test5," + base,
         new Modification(ModificationType.REPLACE, "description", "bar"));
    ldapResult = pool.modify(readOnlyModifyRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);


    // Test modify DN operations.
    ldapResult = pool.modifyDN("ou=test1," + base, "ou=test1-new", true);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.modifyDN("ou=test1-new," + base, "ou=test1", true, null);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=test1," + base, "ou=test1-new", true);
    ldapResult = pool.modifyDN(modifyDNRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ReadOnlyModifyDNRequest readOnlyModifyDNRequest = new ModifyDNRequest(
         "ou=test1-new," + base, "ou=test1", true);
    ldapResult = pool.modifyDN(readOnlyModifyDNRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);


    // Test search operations.
    SearchResult searchResult =
         pool.search(base, SearchScope.BASE, "(objectClass=*)", "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    Filter filter = Filter.createPresenceFilter("objectClass");
    searchResult = pool.search(base, SearchScope.BASE, filter, "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    searchResult = pool.search(null, base, SearchScope.BASE, "(objectClass=*)",
                               "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    searchResult = pool.search(null, base, SearchScope.BASE, filter,
                               "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    searchResult = pool.search(base, SearchScope.BASE, DereferencePolicy.NEVER,
                               0, 0, false, "(objectClass=*)", "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    searchResult = pool.search(base, SearchScope.BASE, DereferencePolicy.NEVER,
                               0, 0, false, filter, "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    searchResult = pool.search(null, base, SearchScope.BASE,
                               DereferencePolicy.NEVER, 0, 0, false,
                               "(objectClass=*)", "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    searchResult = pool.search(null, base, SearchScope.BASE,
                               DereferencePolicy.NEVER, 0, 0, false, filter,
                               "objectClass");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    SearchRequest searchRequest =
         new SearchRequest(base, SearchScope.BASE, "(objectClass=*)");
    searchResult = pool.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    ReadOnlySearchRequest readOnlySearchRequest =
         new SearchRequest(base, SearchScope.BASE, "(objectClass=*)");
    searchResult = pool.search(readOnlySearchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);

    assertNotNull(pool.searchForEntry(base, SearchScope.BASE,
         "(objectClass=*)"));

    assertNotNull(pool.searchForEntry(base, SearchScope.BASE,
         Filter.create("(objectClass=*)")));

    assertNotNull(pool.searchForEntry(base, SearchScope.BASE,
         DereferencePolicy.NEVER, 0, false, "(objectClass=*)"));

    assertNotNull(pool.searchForEntry(base, SearchScope.BASE,
         DereferencePolicy.NEVER, 0, false, Filter.create("(objectClass=*)")));

    assertNotNull(pool.searchForEntry(new SearchRequest(base, SearchScope.BASE,
         "(objectClass=*)")));

    assertNotNull(pool.searchForEntry(
         (ReadOnlySearchRequest)
         new SearchRequest(base, SearchScope.BASE, "(objectClass=*)")));


    // Test delete operations.
    ldapResult = pool.delete("ou=test5," + base);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.delete("ou=test4," + base);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.delete(new DeleteRequest("ou=test3," + base));
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ReadOnlyDeleteRequest deleteRequest =
         new DeleteRequest("ou=test2," + base);
    ldapResult = pool.delete(deleteRequest);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.delete("ou=test1," + base);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);

    ldapResult = pool.delete(base);
    assertEquals(ldapResult.getResultCode(), ResultCode.SUCCESS);


    assertNotNull(pool.getReadPool());
    assertNotNull(pool.getWritePool());

    assertNotNull(pool.getReadPoolStatistics());
    assertNotNull(pool.getWritePoolStatistics());

    assertFalse(pool.isClosed());
    pool.close();
    assertTrue(pool.isClosed());
  }



  /**
   * Retrieves a set of connection pools that may be used for testing.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @return  A set of connection pools that may be used for testing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testPools")
  public Object[][] getTestPools()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return new Object[0][];
    }

    LDAPConnection readConn1 = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnection readConn2 = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnection writeConn1 = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());
    LDAPConnection writeConn2 = new LDAPConnection(getTestHost(), getTestPort(),
         getTestBindDN(), getTestBindPassword());

    return new Object[][]
    {
      new Object[]
      {
        new LDAPReadWriteConnectionPool(readConn1, 1, 10, writeConn1, 1, 10)
      },

      new Object[]
      {
        new LDAPReadWriteConnectionPool(
             new LDAPConnectionPool(readConn2, 1, 10),
             new LDAPConnectionPool(writeConn2, 1, 10))
      }
    };
  }
}
