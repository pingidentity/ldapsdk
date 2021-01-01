/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the
 * IgnoreNoUserModificationRequestControl class.
 */
public class IgnoreNoUserModificationRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the no-argument constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoArgumentConstructor()
         throws Exception
  {
    IgnoreNoUserModificationRequestControl c =
         new IgnoreNoUserModificationRequestControl();
    c = new IgnoreNoUserModificationRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the constructor that takes a criticality argument with a criticality
   * of {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCriticalityTrueConstructor()
         throws Exception
  {
    IgnoreNoUserModificationRequestControl c =
         new IgnoreNoUserModificationRequestControl(true);
    c = new IgnoreNoUserModificationRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the constructor that takes a criticality argument with a criticality
   * of {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCriticalityFalseConstructor()
         throws Exception
  {
    IgnoreNoUserModificationRequestControl c =
         new IgnoreNoUserModificationRequestControl(false);
    c = new IgnoreNoUserModificationRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the constructor that takes a control with a valid generic control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlConstructorValid()
         throws Exception
  {
    Control genericControl = new Control(
         IgnoreNoUserModificationRequestControl.
              IGNORE_NO_USER_MODIFICATION_REQUEST_OID, true, null);
    IgnoreNoUserModificationRequestControl c =
         new IgnoreNoUserModificationRequestControl(genericControl);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the constructor that takes a control with an invalid generic control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testControlConstructorInvalid()
         throws Exception
  {
    Control genericControl = new Control(
         IgnoreNoUserModificationRequestControl.
              IGNORE_NO_USER_MODIFICATION_REQUEST_OID, true,
              new ASN1OctetString("foo"));
    new IgnoreNoUserModificationRequestControl(genericControl);
  }



  /**
   * Sends a request to the server containing the ignore NO-USER-MODIFICATION
   * request control.  This will first add a base entry to the server, then
   * retrieve the entire entry (user and operational attributes, but including
   * the real-attributes-only control to ensure that we don't get any virtual
   * attributes), and try to add it back using the ignore NO-USER-MODIFICATION
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendBaseEntryWithIgnoreNoUserModificationRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      LDAPResult addResult =
           conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

      SearchRequest searchRequest = new SearchRequest(getTestBaseDN(),
           SearchScope.BASE, "(objectClass=*)", "*", "+");
      searchRequest.addControl(new RealAttributesOnlyRequestControl());
      SearchResult searchResult = conn.search(searchRequest);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      SearchResultEntry entry = searchResult.getSearchEntries().get(0);
      assertNotNull(entry);

      conn.delete(getTestBaseDN());

      AddRequest addRequest = new AddRequest(entry);
      addRequest.addControl(new IgnoreNoUserModificationRequestControl());
      addResult = conn.add(addRequest);
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

      SearchResult searchResult2 = conn.search(searchRequest);
      assertEquals(searchResult2.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult2.getEntryCount(), 1);

      SearchResultEntry entry2 = searchResult.getSearchEntries().get(0);
      assertNotNull(entry2);

      assertTrue(entry.equals(entry2));
    }
    finally
    {
      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }



  /**
   * Sends a request to the server containing the ignore NO-USER-MODIFICATION
   * request control.  This will first add a user entry to the server, then
   * retrieve the entire entry (user and operational attributes, but including
   * the real-attributes-only control to ensure that we don't get any virtual
   * attributes), and try to add it back using the ignore NO-USER-MODIFICATION
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendUserEntryWithIgnoreNoUserModificationRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();

    try
    {
      LDAPResult addResult =
           conn.add(getTestBaseDN(), getBaseEntryAttributes());
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

      addResult = conn.add(
           "dn: uid=test.user," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password");
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

      SearchRequest searchRequest = new SearchRequest(
           "uid=test.user," + getTestBaseDN(),
           SearchScope.BASE, "(objectClass=*)", "*", "+");
      searchRequest.addControl(new RealAttributesOnlyRequestControl());
      SearchResult searchResult = conn.search(searchRequest);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      SearchResultEntry entry = searchResult.getSearchEntries().get(0);
      assertNotNull(entry);

      conn.delete("uid=test.user," + getTestBaseDN());

      AddRequest addRequest = new AddRequest(entry);
      addRequest.addControl(new IgnoreNoUserModificationRequestControl());
      addResult = conn.add(addRequest);
      assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);

      SearchResult searchResult2 = conn.search(searchRequest);
      assertEquals(searchResult2.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult2.getEntryCount(), 1);

      SearchResultEntry entry2 = searchResult.getSearchEntries().get(0);
      assertNotNull(entry2);

      assertTrue(entry.equals(entry2));
    }
    finally
    {
      try
      {
        conn.delete("uid=test.user," + getTestBaseDN());
      } catch (Exception e) {}

      try
      {
        conn.delete(getTestBaseDN());
      } catch (Exception e) {}

      conn.close();
    }
  }
}
