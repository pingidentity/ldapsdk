/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.HashSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the LDAPModify search listener
 * class.
 */
public final class LDAPModifySearchListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code searchEntryReceived} method for an
   * entry that has already been processed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchEntryReceivedAlreadyProcessed()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnectionPool pool = ds.getConnectionPool(1);
    final LDIFModifyChangeRecord changeRecord = new LDIFModifyChangeRecord(
         "dn: dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"));

    final LDAPModify ldapModify = new LDAPModify(null, null, null);
    ldapModify.runTool("--help");

    final HashSet<DN> processedDNs = new HashSet<DN>(1);
    processedDNs.add(new DN("dc=example,dc=com"));

    final LDAPModifySearchListener listener = new LDAPModifySearchListener(
         ldapModify, changeRecord, Filter.createPresenceFilter("objectClass"),
         Collections.<Control>emptyList(), pool, null, null, processedDNs);

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    pool.close();
  }



  /**
   * Provides test coverage for the {@code searchEntryReceived} method for an
   * entry with a malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchEntryMalformedDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnectionPool pool = ds.getConnectionPool(1);
    final LDIFModifyChangeRecord changeRecord = new LDIFModifyChangeRecord(
         "dn: dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"));

    final LDAPModify ldapModify = new LDAPModify(null, null, null);
    ldapModify.runTool("--help");

    final HashSet<DN> processedDNs = new HashSet<DN>(1);
    processedDNs.add(new DN("dc=example,dc=com"));

    final LDAPModifySearchListener listener = new LDAPModifySearchListener(
         ldapModify, changeRecord, Filter.createPresenceFilter("objectClass"),
         Collections.<Control>emptyList(), pool, null, null, processedDNs);

    listener.searchEntryReturned(new SearchResultEntry(new Entry(
         "dn: malformed",
         "objectClass: top",
         "objectClass: domain",
         "dc: example")));

    pool.close();
  }



  /**
   * Provides test coverage for the {@code searchReferenceReceived} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchReferenceReceived()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnectionPool pool = ds.getConnectionPool(1);
    final LDIFModifyChangeRecord changeRecord = new LDIFModifyChangeRecord(
         "dn: dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"));

    final LDAPModify ldapModify = new LDAPModify(null, null, null);
    ldapModify.runTool("--help");

    final LDAPModifySearchListener listener = new LDAPModifySearchListener(
         ldapModify, changeRecord, Filter.createPresenceFilter("objectClass"),
         Collections.<Control>emptyList(), pool, null, null,
         new HashSet<DN>(0));

    listener.searchReferenceReturned(new SearchResultReference(
         new String[]
         {
           "ldap://ds1.example.com:389/dc=example,dc=com",
           "ldap://ds2.example.com:389/dc=example,dc=com"
         },
         StaticUtils.NO_CONTROLS));

    pool.close();
  }
}
