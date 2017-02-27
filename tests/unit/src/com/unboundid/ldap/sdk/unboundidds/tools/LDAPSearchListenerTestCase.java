/*
 * Copyright 2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;



/**
 * This class provides a set of test cases for the {@code LDAPSearchListener}
 * class.
 */
public final class LDAPSearchListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the {@code searchEntryReturned} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchEntryReturned()
         throws Exception
  {
    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final LDAPSearchListener listener =
         new LDAPSearchListener(new LDIFLDAPSearchOutputHandler(ldapSearch,
              Integer.MAX_VALUE), null);

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));
  }



  /**
   * Tests the behavior of the {@code searchReferenceReturned} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchReferenceReturned()
         throws Exception
  {
    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final LDAPSearchListener listener =
         new LDAPSearchListener(new LDIFLDAPSearchOutputHandler(ldapSearch,
              Integer.MAX_VALUE), null);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    listener.searchReferenceReturned(
         new SearchResultReference(referralURLs, null));

    listener.searchReferenceReturned(
         new SearchResultReference(referralURLs, null));
  }
}
