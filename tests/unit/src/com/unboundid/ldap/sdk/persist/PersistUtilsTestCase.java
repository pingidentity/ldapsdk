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
package com.unboundid.ldap.sdk.persist;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;



/**
 * This class provides test coverage for the {@code PersistUtils} class.
 */
public class PersistUtilsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code isValidLDAPName} method.
   *
   * @param  s   The string to test.
   * @param  vo  Indicates whether the provided string is a valid LDAP name if
   *             options are allowed.
   * @param  vn  Indicates whether the provided string is a valid LDAP name if
   *             options are not allowed.
   */
  @Test(dataProvider="testLDAPNames")
  public void testIsValidLDAPName(final String s, final boolean vo,
                                  final boolean vn)
  {
    StringBuilder b = new StringBuilder();

    if (vo)
    {

      assertTrue(PersistUtils.isValidLDAPName(s, true, b));
      assertEquals(b.length(), 0);
    }
    else
    {
      assertFalse(PersistUtils.isValidLDAPName(s, true, b));
      assertTrue(b.length() > 0);
    }

    if (vn)
    {

      assertTrue(PersistUtils.isValidLDAPName(s, false, b));
      assertEquals(b.length(), 0);
    }
    else
    {
      assertFalse(PersistUtils.isValidLDAPName(s, false, b));
      assertTrue(b.length() > 0);
    }
  }



  /**
   * Provides a set of data for testing the {@code isValidLDAPName} method.
   *
   * @return  A set of data for testing the {@code isValidLDAPName} method.
   */
  @DataProvider(name="testLDAPNames")
  public Object[][] getTestLDAPNames()
  {
    return new Object[][]
    {
      new Object[] { null, false, false },
      new Object[] { "", false, false },
      new Object[] { "a", true, true },
      new Object[] { "A", true, true },
      new Object[] { "ab", true, true },
      new Object[] { "aB", true, true },
      new Object[] { "a1", true, true },
      new Object[] { "a-", true, true },
      new Object[] { "a-1", true, true },
      new Object[] { "1", false, false },
      new Object[] { "1a", false, false },
      new Object[] { "-1", false, false },
      new Object[] { "_", false, false },
      new Object[] { "a_1", false, false },
      new Object[] { "1.2", true, true },
      new Object[] { "1.2.", false, false },
      new Object[] { "1.", false, false },
      new Object[] { "11", false, false },
      new Object[] { "a;b", true, false },
      new Object[] { "aa;bb", true, false },
      new Object[] { "a;b;c", true, false },
      new Object[] { "a;", false, false },
      new Object[] { "a;b;", false, false },
      new Object[] { "a;b;;c", false, false },
      new Object[] { "a;b c", false, false },
      new Object[] { "a;b_c", false, false },
    };
  }



  /**
   * Tests the {@code toJavaIdentifier} method.
   *
   * @param  i  The string to use as input.
   * @param  o  The expected output.
   */
  @Test(dataProvider="testIdentifiers")
  public void testToJavaIdentifier(final String i, final String o)
  {
    String s = PersistUtils.toJavaIdentifier(i);
    assertNotNull(s);
    assertTrue(s.length() > 0);

    if (o != null)
    {
      assertEquals(s, o);
    }
  }



  /**
   * Provides a set of data for testing the {@code toJavaIdentifier} method.
   *
   * @return  A set of data for testing the {@code toJavaIdentifier} method.
   */
  @DataProvider(name="testIdentifiers")
  public Object[][] getTestIdentifiers()
  {
    return new Object[][]
    {
      new Object[] { null, null },
      new Object[] { "", null },
      new Object[] { "_", null },
      new Object[] { "a", "a" },
      new Object[] { "A", "A" },
      new Object[] { "a1", "a1" },
      new Object[] { "a-1", "a1" },
      new Object[] { "ab", "ab" },
      new Object[] { "aB", "aB" },
      new Object[] { "a-b", "aB" },
      new Object[] { "1", "_1" }
    };
  }



  /**
   * Provides test coverage for the {@code getEntryAsObject} method.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryAsObject()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit ou = new TestOrganizationalUnit();
      ou.setName("test");
      ou.setDescription("testLDAPOperations");

      LDAPResult addResult = persister.add(ou, conn, getTestBaseDN());
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(ou.getLDAPEntry(), new ReadOnlyEntry(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: organizationalUnit",
           "ou: test",
           "description: testLDAPOperations"));

      ou = PersistUtils.getEntryAsObject(new DN("ou=test," + getTestBaseDN()),
           TestOrganizationalUnit.class, conn);
      assertNotNull(ou);

      ou = PersistUtils.getEntryAsObject(
           new DN("ou=nonexistent," + getTestBaseDN()),
           TestOrganizationalUnit.class, conn);
      assertNull(ou);
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN(),
           new Control[] { new SubtreeDeleteRequestControl() });
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Provides test coverage for the {@code getEntriesAsObjects} method.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntriesAsObjects()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit ou = new TestOrganizationalUnit();
      ou.setName("test1");
      ou.setDescription("testLDAPOperations");

      LDAPResult addResult = persister.add(ou, conn, getTestBaseDN());
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(ou.getLDAPEntry(), new ReadOnlyEntry(
           "dn: ou=test1," + getTestBaseDN(),
           "objectClass: organizationalUnit",
           "ou: test1",
           "description: testLDAPOperations"));


      ou = new TestOrganizationalUnit();
      ou.setName("test2");
      ou.setDescription("testLDAPOperations");

      addResult = persister.add(ou, conn, getTestBaseDN());
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(ou.getLDAPEntry(), new ReadOnlyEntry(
           "dn: ou=test2," + getTestBaseDN(),
           "objectClass: organizationalUnit",
           "ou: test2",
           "description: testLDAPOperations"));


      DN[] dns =
      {
        new DN("ou=test1," + getTestBaseDN()),
        new DN("ou=test2," + getTestBaseDN()),
      };
      PersistedObjects<TestOrganizationalUnit> results =
           PersistUtils.getEntriesAsObjects(dns, TestOrganizationalUnit.class,
                conn);

      assertNotNull(results);

      ou = results.next();
      assertNotNull(ou);
      assertNotNull(ou.getLDAPEntry());
      assertEquals(ou.getLDAPEntry().getParsedDN(),
           new DN("ou=test1," + getTestBaseDN()));

      ou = results.next();
      assertNotNull(ou);
      assertNotNull(ou.getLDAPEntry());
      assertEquals(ou.getLDAPEntry().getParsedDN(),
           new DN("ou=test2," + getTestBaseDN()));


      ou= results.next();
      assertNull(ou);
    }
    finally
    {
      DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN(),
           new Control[] { new SubtreeDeleteRequestControl() });
      conn.delete(deleteRequest);

      conn.close();
    }
  }
}
