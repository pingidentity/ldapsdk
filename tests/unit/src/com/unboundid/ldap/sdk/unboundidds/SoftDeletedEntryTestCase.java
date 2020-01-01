/*
 * Copyright 2012-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2012-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code SoftDeletedEntry}
 * class.
 */
public final class SoftDeletedEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a soft-deleted entry that has all supported
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullEntry()
         throws Exception
  {
    final SoftDeletedEntry e = new SoftDeletedEntry(new Entry(
         "dn: entryUUID=12345+dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: ds-soft-delete-entry",
         "dc: example",
         "entryUUID: 12345",
         "ds-soft-delete-from-dn: dc=example,dc=com",
         "ds-soft-delete-timestamp: 20120101123456.789Z",
         "ds-soft-delete-requester-dn: cn=Directory Manager",
         "ds-soft-delete-requester-ip-address: 127.0.0.1"));

    assertNotNull(e);

    assertNotNull(e.getSoftDeleteFromDN());
    assertEquals(new DN(e.getSoftDeleteFromDN()),
         new DN("dc=example,dc=com"));

    assertNotNull(e.getSoftDeleteTimestamp());
    assertEquals(e.getSoftDeleteTimestamp(),
         StaticUtils.decodeGeneralizedTime("20120101123456.789Z"));

    assertNotNull(e.getSoftDeleteRequesterDN());
    assertEquals(new DN(e.getSoftDeleteRequesterDN()),
         new DN("cn=Directory Manager"));

    assertNotNull(e.getSoftDeleteRequesterIPAddress());
    assertEquals(e.getSoftDeleteRequesterIPAddress(),
         "127.0.0.1");

    assertNotNull(e.getUndeletedEntry());
    assertEquals(e.getUndeletedEntry(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "entryUUID: 12345"));

    assertTrue(SoftDeletedEntry.isSoftDeletedEntry(e));
  }



  /**
   * Provides test coverage for a soft-deleted entry that has the minimum set of
   * supported attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalEntry()
         throws Exception
  {
    final SoftDeletedEntry e = new SoftDeletedEntry(new Entry(
         "dn: entryUUID=12345+dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: ds-soft-delete-entry",
         "dc: example",
         "entryUUID: 12345",
         "ds-soft-delete-from-dn: dc=example,dc=com"));

    assertNotNull(e);

    assertNotNull(e.getSoftDeleteFromDN());
    assertEquals(new DN(e.getSoftDeleteFromDN()),
         new DN("dc=example,dc=com"));

    assertNull(e.getSoftDeleteTimestamp());

    assertNull(e.getSoftDeleteRequesterDN());

    assertNull(e.getSoftDeleteRequesterIPAddress());

    assertNotNull(e.getUndeletedEntry());
    assertEquals(e.getUndeletedEntry(), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "entryUUID: 12345"));

    assertTrue(SoftDeletedEntry.isSoftDeletedEntry(e));
  }



  /**
   * Provides test coverage for an entry that is missing the
   * ds-soft-delete-entry object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryMissingOC()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: entryUUID=12345+dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "entryUUID: 12345",
         "ds-soft-delete-from-dn: dc=example,dc=com");

    assertFalse(SoftDeletedEntry.isSoftDeletedEntry(e));

    try
    {
      new SoftDeletedEntry(e);
      fail("Expected an exception when trying to create a soft-deleted entry " +
           "without the ds-soft-delete-entry object class");
    }
    catch (final Exception ex)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for an entry that is missing the required
   * ds-soft-delete-from-dn attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryMissingFromDN()
         throws Exception
  {
    final Entry e = new Entry(
         "dn: entryUUID=12345+dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: ds-soft-delete-entry",
         "dc: example",
         "entryUUID: 12345");

    assertFalse(SoftDeletedEntry.isSoftDeletedEntry(e));

    try
    {
      new SoftDeletedEntry(e);
      fail("Expected an exception when trying to create a soft-deleted entry " +
           "without the ds-soft-delete-from-dn attribute");
    }
    catch (final Exception ex)
    {
      // This was expected.
    }
  }
}
