/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases that cover lazily-loaded attributes.
 */
public final class LazyLoadingTestCase
       extends LDAPSDKTestCase
{
  // The connection to the directory server.
  private LDAPConnection conn;

  // The LDAPPersister instance to use for testing.
  private LDAPPersister<TestGroupOfNames> p;



  /**
   * Adds test entries to the directory.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    p = LDAPPersister.getInstance(TestGroupOfNames.class);

    conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    final TestGroupOfNames g = new TestGroupOfNames();
    g.setCn("Test Group");
    g.setMember(
         new DN("uid=user.1,ou=People," + getTestBaseDN()),
         new DN("uid=user.2,ou=People," + getTestBaseDN()),
         new DN("uid=user.3,ou=People," + getTestBaseDN()),
         new DN("uid=user.4,ou=People," + getTestBaseDN()),
         new DN("uid=user.5,ou=People," + getTestBaseDN()));
    g.setDescription("test");
    p.add(g, conn, getTestBaseDN());
  }



  /**
   * Removes test entries from the directory.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    try
    {
      conn.delete("cn=Test Group," + getTestBaseDN());
    } catch (final Exception e) {}

    try
    {
      conn.delete(getTestBaseDN());
    } catch (final Exception e) {}

    conn.close();
  }



  /**
   * Verifies that lazy loading works properly when no specific fields are
   * requested.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLazyLoadingNoFieldsRequested()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final TestGroupOfNames g =
         p.get("cn=Test Group," + getTestBaseDN(), conn);
    assertNotNull(g);

    assertNotNull(g.getCn());
    assertEquals(g.getCn().length, 1);
    assertEquals(g.getFirstCn(), "Test Group");

    assertNotNull(g.getDescription());
    assertEquals(g.getDescription().length, 1);
    assertEquals(g.getFirstDescription(), "test");

    assertNull(g.getMemberDNs());

    assertNotNull(g.getCreatorsNameDN());

    assertNull(g.getCreateTimestamp());

    p.lazilyLoad(g, conn);

    assertNotNull(g.getCn());
    assertEquals(g.getCn().length, 1);
    assertEquals(g.getFirstCn(), "Test Group");

    assertNotNull(g.getDescription());
    assertEquals(g.getDescription().length, 1);
    assertEquals(g.getFirstDescription(), "test");

    assertNotNull(g.getMemberDNs());
    assertEquals(g.getMemberDNs().length, 5);
    assertEquals(g.getFirstMemberDN(),
         new DN("uid=user.1,ou=People," + getTestBaseDN()));

    assertNotNull(g.getCreatorsNameDN());

    assertNotNull(g.getCreateTimestamp());
  }



  /**
   * Verifies that lazy loading works properly when fields are requested.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLazyLoadingWithFieldsRequested()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final FieldInfo memberField =
         p.getObjectHandler().getFields().get("member");
    assertNotNull(memberField);

    final FieldInfo descriptionField =
         p.getObjectHandler().getFields().get("description");
    assertNotNull(descriptionField);

    final TestGroupOfNames g =
         p.get("cn=Test Group," + getTestBaseDN(), conn);
    assertNotNull(g);

    assertNotNull(g.getCn());
    assertEquals(g.getCn().length, 1);
    assertEquals(g.getFirstCn(), "Test Group");

    assertNotNull(g.getDescription());
    assertEquals(g.getDescription().length, 1);
    assertEquals(g.getFirstDescription(), "test");

    assertNull(g.getMemberDNs());

    assertNotNull(g.getCreatorsNameDN());

    assertNull(g.getCreateTimestamp());

    p.lazilyLoad(g, conn, memberField, descriptionField);

    assertNotNull(g.getCn());
    assertEquals(g.getCn().length, 1);
    assertEquals(g.getFirstCn(), "Test Group");

    assertNotNull(g.getDescription());
    assertEquals(g.getDescription().length, 1);
    assertEquals(g.getFirstDescription(), "test");

    assertNotNull(g.getMemberDNs());
    assertEquals(g.getMemberDNs().length, 5);
    assertEquals(g.getFirstMemberDN(),
         new DN("uid=user.1,ou=People," + getTestBaseDN()));

    assertNotNull(g.getCreatorsNameDN());

    assertNull(g.getCreateTimestamp());
  }



  /**
   * Verifies that lazy loading works properly when fields are requested but
   * none of those fields should be lazily loaded.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLazyLoadingWithOnlyNonLazyFieldsRequested()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final FieldInfo descriptionField =
         p.getObjectHandler().getFields().get("description");
    assertNotNull(descriptionField);

    final TestGroupOfNames g =
         p.get("cn=Test Group," + getTestBaseDN(), conn);
    assertNotNull(g);

    assertNotNull(g.getCn());
    assertEquals(g.getCn().length, 1);
    assertEquals(g.getFirstCn(), "Test Group");

    assertNotNull(g.getDescription());
    assertEquals(g.getDescription().length, 1);
    assertEquals(g.getFirstDescription(), "test");

    assertNull(g.getMemberDNs());

    assertNotNull(g.getCreatorsNameDN());

    assertNull(g.getCreateTimestamp());

    p.lazilyLoad(g, conn, descriptionField);

    assertNotNull(g.getCn());
    assertEquals(g.getCn().length, 1);
    assertEquals(g.getFirstCn(), "Test Group");

    assertNotNull(g.getDescription());
    assertEquals(g.getDescription().length, 1);
    assertEquals(g.getFirstDescription(), "test");

    assertNull(g.getMemberDNs());

    assertNotNull(g.getCreatorsNameDN());

    assertNull(g.getCreateTimestamp());
  }



  /**
   * Verifies that lazy loading works properly when the DN of the target entry
   * cannot be determined.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPPersistException.class })
  public void testLazyLoadingCannotDetermineDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No server available for this test");
    }

    p.lazilyLoad(new TestGroupOfNames(), conn);
  }



  /**
   * Verifies that lazy loading works properly when the target entry cannot be
   * retrieved.
   * <BR><BR>
   * Access to a directory server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPPersistException.class })
  public void testLazyLoadingCannotGetEntry()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPPersistException("No server available for this test");
    }

    final TestGroupOfNames g = new TestGroupOfNames();
    g.setCn("Test 2");
    g.setMember(
         new DN("uid=user.1,ou=People," + getTestBaseDN()),
         new DN("uid=user.2,ou=People," + getTestBaseDN()),
         new DN("uid=user.3,ou=People," + getTestBaseDN()),
         new DN("uid=user.4,ou=People," + getTestBaseDN()),
         new DN("uid=user.5,ou=People," + getTestBaseDN()));
    g.setDescription("test 2");

    p.add(g, conn, getTestBaseDN());
    assertNotNull(g.getLDAPEntryDN());
    p.delete(g, conn);

    p.lazilyLoad(g, conn);
  }
}
