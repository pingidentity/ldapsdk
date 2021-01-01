/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the LDAP delete search listener.
 */
public final class LDAPDeleteSearchListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the {@code searchEntryReturned} method when provided
   * with an entry that has a valid DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEntryReturned()
         throws Exception
  {
    final LDAPDelete ldapDelete = new LDAPDelete(null, null);
    final TreeSet<DN> dnSet = new TreeSet<>();
    final AtomicReference<ResultCode> returnCode = new AtomicReference<>();

    final LDAPDeleteSearchListener listener = new LDAPDeleteSearchListener(
         ldapDelete, dnSet, "dc=example,dc=com", "(dc=example)",
         returnCode);

    listener.searchEntryReturned(
         new SearchResultEntry(new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));

    assertFalse(dnSet.isEmpty());
    assertEquals(dnSet.size(), 1);
    assertTrue(dnSet.contains(new DN("dc=example,dc=com")));

    assertNull(returnCode.get());
  }



  /**
   * Tests the behavior of the {@code searchEntryReturned} method when provided
   * with an entry that has a malformed DN and the return code is unset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidEntryReturnedUnSetReturnCode()
         throws Exception
  {
    final LDAPDelete ldapDelete = new LDAPDelete(null, null);
    final TreeSet<DN> dnSet = new TreeSet<>();
    final AtomicReference<ResultCode> returnCode = new AtomicReference<>();

    final LDAPDeleteSearchListener listener = new LDAPDeleteSearchListener(
         ldapDelete, dnSet, "dc=example,dc=com", "(dc=example)",
         returnCode);

    listener.searchEntryReturned(
         new SearchResultEntry(new Entry(
              "dn: malformed",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));

    assertTrue(dnSet.isEmpty());

    assertNotNull(returnCode.get());
    assertEquals(returnCode.get(), ResultCode.INVALID_DN_SYNTAX);
  }



  /**
   * Tests the behavior of the {@code searchEntryReturned} method when provided
   * with an entry that has a malformed DN and the return code is already set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidEntryReturnedSetReturnCode()
         throws Exception
  {
    final LDAPDelete ldapDelete = new LDAPDelete(null, null);
    final TreeSet<DN> dnSet = new TreeSet<>();
    final AtomicReference<ResultCode> returnCode =
         new AtomicReference<>(ResultCode.OTHER);

    final LDAPDeleteSearchListener listener = new LDAPDeleteSearchListener(
         ldapDelete, dnSet, "dc=example,dc=com", "(dc=example)",
         returnCode);

    listener.searchEntryReturned(
         new SearchResultEntry(new Entry(
              "dn: malformed",
              "objectClass: top",
              "objectClass: domain",
              "dc: example")));

    assertTrue(dnSet.isEmpty());

    assertNotNull(returnCode.get());
    assertEquals(returnCode.get(), ResultCode.OTHER);
  }



  /**
   * Tests the behavior of the {@code searchReferenceReturned} method when
   * provided with an entry that has a malformed DN and the return code is
   * not yet set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferenceReturnedUnSetReturnCode()
         throws Exception
  {
    final LDAPDelete ldapDelete = new LDAPDelete(null, null);
    final TreeSet<DN> dnSet = new TreeSet<>();
    final AtomicReference<ResultCode> returnCode = new AtomicReference<>();

    final LDAPDeleteSearchListener listener = new LDAPDeleteSearchListener(
         ldapDelete, dnSet, "dc=example,dc=com", "(dc=example)",
         returnCode);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/"
    };

    listener.searchReferenceReturned(new SearchResultReference(referralURLs,
         StaticUtils.NO_CONTROLS));

    assertTrue(dnSet.isEmpty());

    assertNotNull(returnCode.get());
    assertEquals(returnCode.get(), ResultCode.REFERRAL);
  }



  /**
   * Tests the behavior of the {@code searchReferenceReturned} method when
   * provided with an entry that has a malformed DN and the return code is
   * already set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferenceReturnedSetReturnCode()
         throws Exception
  {
    final LDAPDelete ldapDelete = new LDAPDelete(null, null);
    final TreeSet<DN> dnSet = new TreeSet<>();
    final AtomicReference<ResultCode> returnCode =
         new AtomicReference<>(ResultCode.OTHER);

    final LDAPDeleteSearchListener listener = new LDAPDeleteSearchListener(
         ldapDelete, dnSet, "dc=example,dc=com", "(dc=example)",
         returnCode);

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/",
      "ldap://ds2.example.com:389/"
    };

    listener.searchReferenceReturned(new SearchResultReference(referralURLs,
         StaticUtils.NO_CONTROLS));

    assertTrue(dnSet.isEmpty());

    assertNotNull(returnCode.get());
    assertEquals(returnCode.get(), ResultCode.OTHER);
  }
}
