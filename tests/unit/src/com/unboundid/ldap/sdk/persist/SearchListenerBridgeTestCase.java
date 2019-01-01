/*
 * Copyright 2009-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2019 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;



/**
 * This class provides test coverage for the {@code SearchListenerBridge}
 * class.
 */
public class SearchListenerBridgeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the methods of this class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerBridge()
         throws Exception
  {
    final LDAPPersister<TestOrganizationalUnit> persister =
         LDAPPersister.getInstance(TestOrganizationalUnit.class);

    TestObjectSearchListener listener = new TestObjectSearchListener();
    assertEquals(listener.getValidCount(), 0);
    assertEquals(listener.getInvalidCount(), 0);
    assertEquals(listener.getReferenceCount(), 0);

    SearchListenerBridge<TestOrganizationalUnit> bridge =
         new SearchListenerBridge<TestOrganizationalUnit>(persister, listener);


    // A valid result that can be decoded.
    bridge.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "description: valid")));
    assertEquals(listener.getValidCount(), 1);
    assertEquals(listener.getInvalidCount(), 0);
    assertEquals(listener.getReferenceCount(), 0);


    // An invalid result that cannot be decoded because it's missing
    // description.
    bridge.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));
    assertEquals(listener.getValidCount(), 1);
    assertEquals(listener.getInvalidCount(), 1);
    assertEquals(listener.getReferenceCount(), 0);


    // A reference.
    bridge.searchReferenceReturned(new SearchResultReference(
         new String[] { "ldap://server.example.com/dc=example,dc=com" },
         new Control[0]));
    assertEquals(listener.getValidCount(), 1);
    assertEquals(listener.getInvalidCount(), 1);
    assertEquals(listener.getReferenceCount(), 1);
  }
}
