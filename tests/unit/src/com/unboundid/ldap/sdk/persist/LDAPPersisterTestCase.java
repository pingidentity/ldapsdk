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



import java.util.LinkedList;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides test coverage for the {@code LDAPPersister} class.
 */
public class LDAPPersisterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provide test coverage for the {@code getLDAPObjectAnnotation} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLDAPObjectAnnotation()
         throws Exception
  {
    final LDAPPersister<TestOrganizationalUnit> persister =
         LDAPPersister.getInstance(TestOrganizationalUnit.class);

    assertNotNull(persister.getLDAPObjectAnnotation());
  }



  /**
   * Provides test coverage for the methods used to encode an object to an LDAP
   * entry, and decode the entry back to an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncode()
         throws Exception
  {
    final LDAPPersister<TestOrganizationalUnit> persister =
         LDAPPersister.getInstance(TestOrganizationalUnit.class);

    TestOrganizationalUnit ou = new TestOrganizationalUnit();
    ou.setName("test");
    ou.setDescription("testEncode");

    assertNull(ou.getLDAPEntry());

    Entry ouEntry = persister.encode(ou, null);
    assertNotNull(ouEntry);

    assertEquals(ouEntry, new Entry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: testEncode"));

    assertNotNull(ou.getLDAPEntry());
    assertEquals(ou.getLDAPEntry(), new ReadOnlyEntry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: testEncode"));

    TestOrganizationalUnit decodedOU = persister.decode(ouEntry);
    assertNotNull(decodedOU);

    assertEquals(decodedOU.getName(), "test");

    assertEquals(decodedOU.getDescription(), "testEncode");

    assertNotNull(decodedOU.getLDAPEntry());
    assertEquals(decodedOU.getLDAPEntry(), new ReadOnlyEntry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: testEncode"));

    decodedOU = new TestOrganizationalUnit();
    persister.decode(decodedOU, ouEntry);
    assertNotNull(decodedOU);

    assertEquals(decodedOU.getName(), "test");

    assertEquals(decodedOU.getDescription(), "testEncode");

    assertNotNull(decodedOU.getLDAPEntry());
    assertEquals(decodedOU.getLDAPEntry(), new ReadOnlyEntry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: testEncode"));
  }



  /**
   * Provides test coverage for the methods used to interact with a directory
   * server.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPOperations()
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

      List<Modification> mods = persister.getModifications(ou, true);
      assertNotNull(mods);
      assertTrue(mods.isEmpty());

      LDAPResult modifyResult =
           persister.modify(ou, conn, "ou=test," + getTestBaseDN(), true);
      assertNull(modifyResult);

      ou.setDescription("testldapoperations");
      modifyResult =
           persister.modify(ou, conn, "ou=test," + getTestBaseDN(), true);
      assertNull(modifyResult);

      ou.setDescription("testldapoperations");
      modifyResult =
           persister.modify(ou, conn, "ou=test," + getTestBaseDN(), true,
                false, null);
      assertNull(modifyResult);

      modifyResult =
           persister.modify(ou, conn, "ou=test," + getTestBaseDN(), true,
                true, null);
      assertNotNull(modifyResult);
      assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

      ou.setDescription("new description");
      mods = persister.getModifications(ou, true);
      assertNotNull(mods);
      assertFalse(mods.isEmpty());
      assertEquals(mods.size(), 1);
      assertEquals(mods.get(0),
           new Modification(ModificationType.REPLACE, "description",
                "new description"));

      modifyResult = persister.modify(ou, conn, null, true);
      assertNotNull(modifyResult);
      assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

      ou = persister.get(ou, conn, "ou=test," + getTestBaseDN());

      ou.setDescription("New Description");
      mods = persister.getModifications(ou, true);
      assertNotNull(mods);
      assertTrue(mods.isEmpty());

      mods = persister.getModifications(ou, true, false);
      assertNotNull(mods);
      assertTrue(mods.isEmpty());

      mods = persister.getModifications(ou, true, true);
      assertNotNull(mods);
      assertFalse(mods.isEmpty());

      modifyResult = persister.modify(ou, conn, null, true, true, null);
      assertNotNull(modifyResult);
      assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

      ou.setDescription("another new description");
      modifyResult =
           persister.modify(ou, conn, "ou=test," + getTestBaseDN(), true);
      assertNotNull(modifyResult);
      assertEquals(modifyResult.getResultCode(), ResultCode.SUCCESS);

      TestOrganizationalUnit getOU = persister.get(
           "ou=test," + getTestBaseDN(), conn);
      assertNotNull(getOU);
      assertEquals(getOU.getName(), "test");
      assertEquals(getOU.getDescription(), "another new description");
      assertNotNull(getOU.getEntryUUID());
      assertNotNull(getOU.getLDAPEntry());


      TestOrganizationalUnit filterOU = new TestOrganizationalUnit();
      filterOU.setName("test");

      if (DN.equals(getTestBaseDN(), "dc=example,dc=com"))
      {
        PersistedObjects<TestOrganizationalUnit> results =
             persister.search(filterOU, conn);
        assertNotNull(results);

        TestOrganizationalUnit resultOU = results.next();
        assertNotNull(resultOU);
        assertEquals(resultOU.getName(), "test");
        assertEquals(resultOU.getDescription(), "another new description");
        assertNotNull(resultOU.getLDAPEntry());

        assertNull(results.next());
        assertNull(results.next());
        results.close();
        assertNotNull(results.getSearchResult());
        assertNull(results.next());
        assertNull(results.next());
        results.close();
        assertNotNull(results.getSearchResult());
        assertNull(results.next());
        assertNull(results.next());
        assertNotNull(results.getSearchResult());


        Control[] controls =
        {
          new ManageDsaITRequestControl()
        };
        results = persister.search(filterOU, conn, "dc=example,dc=com",
             SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
             Filter.createPresenceFilter("objectClass"), controls);
        assertNotNull(results);

        resultOU = results.next();
        assertNotNull(resultOU);
        assertEquals(resultOU.getName(), "test");
        assertEquals(resultOU.getDescription(), "another new description");
        assertNotNull(resultOU.getLDAPEntry());

        assertNull(results.next());
        assertNull(results.next());
        results.close();
        assertNotNull(results.getSearchResult());
        assertNull(results.next());
        assertNull(results.next());
        results.close();
        assertNotNull(results.getSearchResult());
        assertNull(results.next());
        assertNull(results.next());
        assertNotNull(results.getSearchResult());


        results = persister.search(conn, "dc=example,dc=com",
             SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
             Filter.createEqualityFilter("ou", "test"), controls);
        assertNotNull(results);

        resultOU = results.next();
        assertNotNull(resultOU);
        assertEquals(resultOU.getName(), "test");
        assertEquals(resultOU.getDescription(), "another new description");
        assertNotNull(resultOU.getLDAPEntry());

        assertNull(results.next());
        assertNull(results.next());
        results.close();
        assertNotNull(results.getSearchResult());
        assertNull(results.next());
        assertNull(results.next());
        results.close();
        assertNotNull(results.getSearchResult());
        assertNull(results.next());
        assertNull(results.next());
        assertNotNull(results.getSearchResult());


        TestObjectSearchListener listener = new TestObjectSearchListener();
        assertEquals(listener.getValidCount(), 0);
        assertEquals(listener.getInvalidCount(), 0);
        assertEquals(listener.getReferenceCount(), 0);

        SearchResult result = persister.search(filterOU, conn, listener);
        assertNotNull(result);

        assertEquals(listener.getValidCount(), 1);
        assertEquals(listener.getInvalidCount(), 0);
        assertEquals(listener.getReferenceCount(), 0);


        listener = new TestObjectSearchListener();
        result = persister.search(filterOU, conn, "dc=example,dc=com",
             SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
             Filter.createPresenceFilter("objectClass"), listener, controls);
        assertNotNull(result);

        assertEquals(listener.getValidCount(), 1);
        assertEquals(listener.getInvalidCount(), 0);
        assertEquals(listener.getReferenceCount(), 0);


        listener = new TestObjectSearchListener();
        result = persister.search(conn, "dc=example,dc=com",
             SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
             Filter.createEqualityFilter("ou", "test"), listener, controls);
        assertNotNull(result);

        assertEquals(listener.getValidCount(), 1);
        assertEquals(listener.getInvalidCount(), 0);
        assertEquals(listener.getReferenceCount(), 0);


        listener = new TestObjectSearchListener();
        result = persister.getAll(conn, "dc=example,dc=com", listener,
             controls);
        assertNotNull(result);

        assertEquals(listener.getValidCount(), 1);
        assertEquals(listener.getInvalidCount(), 0);
        assertEquals(listener.getReferenceCount(), 0);


        listener = new TestObjectSearchListener();
        result = persister.getAll(conn, null, listener,
             controls);
        assertNotNull(result);

        assertEquals(listener.getValidCount(), 1);
        assertEquals(listener.getInvalidCount(), 0);
        assertEquals(listener.getReferenceCount(), 0);


        resultOU = persister.searchForObject(filterOU, conn);
        assertNotNull(resultOU);
        assertEquals(resultOU.getName(), "test");
        assertEquals(resultOU.getDescription(), "another new description");
        assertNotNull(resultOU.getLDAPEntry());

        resultOU = persister.searchForObject(filterOU, conn,
             "dc=example,dc=com", SearchScope.SUB);
        assertNotNull(resultOU);
        assertEquals(resultOU.getName(), "test");
        assertEquals(resultOU.getDescription(), "another new description");
        assertNotNull(resultOU.getLDAPEntry());


        TestOrganizationalUnit nonMatchingOU = new TestOrganizationalUnit();
        nonMatchingOU.setName("non-matching");
        assertNull(persister.searchForObject(nonMatchingOU, conn,
             "dc=example,dc=com", SearchScope.SUB, DereferencePolicy.NEVER,
             0, 0, Filter.createPresenceFilter("objectClass")));
      }


      PersistedObjects<TestOrganizationalUnit> results =
           persister.search(filterOU, conn, getTestBaseDN(), SearchScope.SUB);
      assertNotNull(results);

      TestOrganizationalUnit resultOU = results.next();
      assertNotNull(resultOU);
      assertEquals(resultOU.getName(), "test");
      assertEquals(resultOU.getDescription(), "another new description");
      assertNotNull(resultOU.getLDAPEntry());

      assertNull(results.next());
      assertNull(results.next());
      results.close();
      assertNotNull(results.getSearchResult());
      assertNull(results.next());
      assertNull(results.next());
      results.close();
      assertNotNull(results.getSearchResult());
      assertNull(results.next());
      assertNull(results.next());
      assertNotNull(results.getSearchResult());


      TestObjectSearchListener listener = new TestObjectSearchListener();
      assertEquals(listener.getValidCount(), 0);
      assertEquals(listener.getInvalidCount(), 0);
      assertEquals(listener.getReferenceCount(), 0);

      SearchResult result = persister.search(filterOU, conn, getTestBaseDN(),
           SearchScope.SUB, listener);
      assertNotNull(result);

      assertEquals(listener.getValidCount(), 1);
      assertEquals(listener.getInvalidCount(), 0);
      assertEquals(listener.getReferenceCount(), 0);


      persister.delete(ou, conn);
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
   * Provides test coverage for a case in which an add attempt fails because the
   * parent doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedAdd()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit ou = new TestOrganizationalUnit();
      ou.setName("test");
      ou.setDescription("testLDAPOperations");

      persister.add(ou, conn, getTestBaseDN());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a delete attempt fails because
   * the object doesn't include a DN value.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedDeleteCannotDetermineDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit ou = new TestOrganizationalUnit();

      persister.delete(ou, conn);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a delete attempt fails because
   * the target entry doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedDeleteNonexistent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      Entry ouEntry = new Entry(
           "dn: ou=test,dc=example,dc=com",
           "objectClass: organizationalUnit",
           "ou: test",
           "description: testEncode");
      TestOrganizationalUnit ou = persister.decode(ouEntry);

      persister.delete(ou, conn);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a modify attempt fails because
   * the object doesn't include a DN value.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedModifyCannotDetermineDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit ou = new TestOrganizationalUnit();
      ou.setDescription("foo");

      persister.modify(ou, conn, null, true);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a modify attempt fails because
   * the target entry doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedModifyNonexistent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      Entry ouEntry = new Entry(
           "dn: ou=test,dc=example,dc=com",
           "objectClass: organizationalUnit",
           "ou: test",
           "description: testEncode");
      TestOrganizationalUnit ou = persister.decode(ouEntry);

      ou.setDescription("foo");

      persister.modify(ou, conn, null, true);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get succeeds with a
   * constructed DN with an explicitly-provided parent.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSuccessfulConstructedDNExplicitParent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    try
    {
      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test",
           "description: foo");

      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      final TestOrganizationalUnit template = new TestOrganizationalUnit();
      template.setName("test");
      assertEquals(template.getName(), "test");
      assertNull(template.getDescription());

      final TestOrganizationalUnit retrieved =
           persister.get(template, conn, getTestBaseDN());
      assertNotNull(retrieved);
      assertNotSame(retrieved, template);
      assertEquals(retrieved.getName(), "test");
      assertEquals(retrieved.getDescription(), "foo");
    }
    finally
    {
      final DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN(),
           new Control[] { new SubtreeDeleteRequestControl() });
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get succeeds with a
   * constructed DN using the default parent.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSuccessfulConstructedDNDefaultParent()
         throws Exception
  {
    if (! (isDirectoryInstanceAvailable() &&
           DN.equals(getTestBaseDN(), "dc=example,dc=com")))
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    try
    {
      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test",
           "description: foo");

      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      final TestOrganizationalUnit template = new TestOrganizationalUnit();
      template.setName("test");
      assertEquals(template.getName(), "test");
      assertNull(template.getDescription());

      final TestOrganizationalUnit retrieved =
           persister.get(template, conn, null);
      assertNotNull(retrieved);
      assertNotSame(retrieved, template);
      assertEquals(retrieved.getName(), "test");
      assertEquals(retrieved.getDescription(), "foo");
    }
    finally
    {
      final DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN(),
           new Control[] { new SubtreeDeleteRequestControl() });
      conn.delete(deleteRequest);

      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get fails because the DN could
   * not be constructed.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetSuccessfulConstructedDNMissingRDNField()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    final LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      final TestOrganizationalUnit template = new TestOrganizationalUnit();
      assertNull(template.getName());
      assertNull(template.getDescription());

      persister.get(template, conn, getTestBaseDN());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get fails because the DN could
   * not be constructed.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSuccessfulConstructedDNNonexistent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      final TestOrganizationalUnit template = new TestOrganizationalUnit();
      template.setName("test");
      assertEquals(template.getName(), "test");
      assertNull(template.getDescription());

      assertNull(persister.get(template, conn,
           "ou=nonexistent," + getTestBaseDN()));
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get fails because the DN could
   * not be constructed.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testGetSuccessfulConstructedDNMalformedParent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    final LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      final TestOrganizationalUnit template = new TestOrganizationalUnit();
      template.setName("test");
      assertEquals(template.getName(), "test");
      assertNull(template.getDescription());

      template.setLDAPEntry(new ReadOnlyEntry("malformed,dc=example,dc=com",
           new Attribute("objectClass", "top", "organizationalUnit"),
           new Attribute("ou", "malformed"),
           new Attribute("description", "foo")));

      persister.get(template, conn, null);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get attempt fails because
   * the target entry doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedGetNonexistent()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      assertNull(persister.get("ou=nonexistent," + getTestBaseDN(), conn));
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a get attempt fails because
   * the target entry doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedGetCannotDecode()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    try
    {
      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test"); // Missing "description" attribute required for decode.

      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      persister.get("ou=test," + getTestBaseDN(), conn);
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
   * Provides test coverage for a case in which a get attempt fails because
   * the target DN is malformed.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedGetMalformedDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      persister.get("malformed", conn);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a search attempt fails because
   * target base DN doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedSearchObjectsNonexistentBase()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit filterOU = new TestOrganizationalUnit();
      filterOU.setName("test");

      PersistedObjects<TestOrganizationalUnit> results = persister.search(
           filterOU, conn, "ou=nonexistent," + getTestBaseDN(),
           SearchScope.SUB);
      assertNotNull(results);

      try
      {
        results.next();
        fail("Expected an exception from the search");
      }
      catch (LDAPPersistException lpe)
      {
        // This was expected.
      }

      assertNull(results.next());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a search attempt fails because
   * target base DN doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testFailedSearchListenerNonexistentBase()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No directory instance available.");
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit filterOU = new TestOrganizationalUnit();
      filterOU.setName("test");

      TestObjectSearchListener listener = new TestObjectSearchListener();
      persister.search(filterOU, conn, "ou=nonexistent," + getTestBaseDN(),
           SearchScope.SUB, listener);
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Provides test coverage for a case in which a search attempt fails because
   * the target entry doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchObjectsCannotDecode()
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
      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test"); // Missing "description" attribute required for decode.

      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit filterOU = new TestOrganizationalUnit();
      filterOU.setName("test");

      PersistedObjects<TestOrganizationalUnit> results = persister.search(
           filterOU, conn, getTestBaseDN(), SearchScope.SUB);
      assertNotNull(results);

      try
      {
        results.next();
        fail("Expected an exception from the search");
      }
      catch (LDAPPersistException lpe)
      {
        // This was expected.
      }

      assertNull(results.next());
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
   * Provides test coverage for a case in which a search attempt fails because
   * the target entry doesn't exist.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchListenerCannotDecode()
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
      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test"); // Missing "description" attribute required for decode.

      final LDAPPersister<TestOrganizationalUnit> persister =
           LDAPPersister.getInstance(TestOrganizationalUnit.class);

      TestOrganizationalUnit filterOU = new TestOrganizationalUnit();
      filterOU.setName("test");

      TestObjectSearchListener listener = new TestObjectSearchListener();

      SearchResult results = persister.search(filterOU, conn, getTestBaseDN(),
           SearchScope.SUB, listener);
      assertNotNull(results);

      assertEquals(listener.getValidCount(), 0);
      assertEquals(listener.getInvalidCount(), 1);
      assertEquals(listener.getReferenceCount(), 0);
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
   * Tests the behavior of the {@code updateSchema} method.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUpdateSchema()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPPersister<TestBasicObject> p =
         LDAPPersister.getInstance(TestBasicObject.class);
    final List<ObjectClassDefinition> ocDefs = p.constructObjectClasses();
    final List<AttributeTypeDefinition> attrDefs = p.constructAttributeTypes();

    LDAPConnection conn = getAdminConnection();

    Schema s = conn.getSchema();


    LDAPObjectHandler<TestBasicObject> objectHandler = p.getObjectHandler();

    LinkedList<String> missingOCs   = new LinkedList<String>();
    LinkedList<String> missingAttrs = new LinkedList<String>();

    for (final ObjectClassDefinition d : ocDefs)
    {
      if (s.getObjectClass(d.getNameOrOID()) == null)
      {
        missingOCs.add(d.toString());
      }
    }

    for (final AttributeTypeDefinition d : attrDefs)
    {
      if (s.getAttributeType(d.getNameOrOID()) == null)
      {
        missingAttrs.add(d.toString());
      }
    }

    assertTrue(p.updateSchema(conn));
    assertFalse(p.updateSchema(conn));

    s = conn.getSchema();
    assertNotNull(s.getObjectClass(objectHandler.getStructuralClass()));
    for (final String auxClass : objectHandler.getAuxiliaryClasses())
    {
      assertNotNull(s.getObjectClass(auxClass));
    }
    for (final String supClass : objectHandler.getSuperiorClasses())
    {
      assertNotNull(s.getObjectClass(supClass));
    }

    for (final FieldInfo f : objectHandler.getFields().values())
    {
      assertNotNull(s.getAttributeType(f.getAttributeName()));
    }

    for (final GetterInfo f : objectHandler.getGetters().values())
    {
      assertNotNull(s.getAttributeType(f.getAttributeName()));
    }


    final LinkedList<Modification> mods = new LinkedList<Modification>();
    mods.add(new Modification(ModificationType.DELETE, Schema.ATTR_OBJECT_CLASS,
         missingOCs.toArray(new String[0])));
    mods.add(new Modification(ModificationType.DELETE,
         Schema.ATTR_ATTRIBUTE_TYPE, missingAttrs.toArray(new String[0])));
    conn.modify(s.getSchemaEntry().getDN(), mods);

    conn.close();
  }



  /**
   * Tests the behavior of the {@code bind} method under a number of conditions.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
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


    // Add the top entries to the directory.
    final LDAPConnection adminConn = getAdminConnection();
    adminConn.add(getTestBaseDN(), getBaseEntryAttributes());
    adminConn.add(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    // Add a user that we will use to perform the bind.
    LDAPPersister<TestInetOrgPerson> p =
         LDAPPersister.getInstance(TestInetOrgPerson.class);
    assertNotNull(p);

    TestInetOrgPerson u = new TestInetOrgPerson();
    u.setUid("test.user");
    u.setGivenName("Test");
    u.setSn("User");
    u.setCn("Test User");
    u.setUserPassword("password");

    assertNull(u.getLDAPEntryDN());

    final LDAPResult addResult =
         p.add(u, adminConn, "ou=People," + getTestBaseDN());
    assertNotNull(addResult);
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(u.getLDAPEntryDN());


    // Create a new connection and perform a successful bind on it as the target
    // user.  Since the user object already has a DN associated with it, then no
    // search should be required.
    final LDAPConnection bindConn = getUnauthenticatedConnection();
    BindResult bindResult = p.bind(u, getTestBaseDN(), "password", bindConn);
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


    // Now try an unsuccessful bind as the user.
    try
    {
      bindResult = p.bind(u, getTestBaseDN(), "wrongpassword", bindConn);
      fail("Expected an exception when trying to bind with the wrong " +
           "password.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Create a new object that will require a search and try to bind with it.
    // We'll explicitly provide the base DN to use for the search.  Since we
    // have to perform a search, go ahead and authenticate with admin
    // credentials first so we know that we won't have any access control
    // problems.
    bindResult = bindConn.bind(getTestBindDN(), getTestBindPassword());
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    u = new TestInetOrgPerson();
    u.setUid("test.user");
    bindResult = p.bind(u, getTestBaseDN(), "password", bindConn);
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);


    // If the test base DN is "dc=example,dc=com", then perform the same search
    // with a null base DN so that we'll use the default parent DN from the
    // object.
    if (DN.equals(getTestBaseDN(), "dc=example,dc=com"))
    {
      bindResult = bindConn.bind(getTestBindDN(), getTestBindPassword());
      assertNotNull(bindResult);
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

      u = new TestInetOrgPerson();
      u.setUid("test.user");
      bindResult = p.bind(u, null, "password", bindConn);
      assertNotNull(bindResult);
      assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);
    }


    // Test the behavior when trying to bind as a user that doesn't exist.
    bindResult = bindConn.bind(getTestBindDN(), getTestBindPassword());
    assertNotNull(bindResult);
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    u = new TestInetOrgPerson();
    u.setUid("no.such.user");
    try
    {
      bindResult = p.bind(u, getTestBaseDN(), "password", bindConn);
      fail("Expected an exception when trying to bind with a missing user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_RESULTS_RETURNED);
    }

    bindConn.close();


    // Remove the entries from the directory.
    final DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
    deleteRequest.addControl(new SubtreeDeleteRequestControl(true));
    adminConn.delete(deleteRequest);
    adminConn.close();
  }
}
