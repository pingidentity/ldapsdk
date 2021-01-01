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
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the
 * {@code AccountUsableRequestControl} class.
 */
public class AccountUsableRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    AccountUsableRequestControl c = new AccountUsableRequestControl();
    c = new AccountUsableRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a criticality of {@code true}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2True()
         throws Exception
  {
    AccountUsableRequestControl c = new AccountUsableRequestControl(true);
    c = new AccountUsableRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a criticality of {@code false}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2False()
         throws Exception
  {
    AccountUsableRequestControl c = new AccountUsableRequestControl(false);
    c = new AccountUsableRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a generic control that can be properly
   * decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3Generic()
         throws Exception

  {
    Control genericControl =
         new Control(AccountUsableRequestControl.ACCOUNT_USABLE_REQUEST_OID,
                     false, null);
    AccountUsableRequestControl c =
         new AccountUsableRequestControl(genericControl);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a generic control that contains a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3WithValue()
         throws Exception
  {
    Control genericControl =
         new Control(AccountUsableRequestControl.ACCOUNT_USABLE_REQUEST_OID,
                     false, new ASN1OctetString("foo"));
    new AccountUsableRequestControl(genericControl);
  }



  /**
   * Sends a search request to the server with an account usable request
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithAccountUsableRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    conn.add("dn: uid=test.user," + getTestBaseDN(),
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectclass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

    SearchRequest searchRequest =
         new SearchRequest(getTestBaseDN(), SearchScope.SUB,
                           "(uid=test.user)");
    searchRequest.addControl(new AccountUsableRequestControl());

    try
    {
      SearchResult result = conn.search(searchRequest);

      assertEquals(result.getResultCode(), ResultCode.SUCCESS);

      assertEquals(result.getEntryCount(), 1);

      SearchResultEntry entry = result.getSearchEntries().get(0);
      assertNotNull(entry);

      Control[] responseControls = entry.getControls();
      assertNotNull(responseControls);
      assertEquals(responseControls.length, 1);

      assertTrue(responseControls[0] instanceof AccountUsableResponseControl);

      AccountUsableResponseControl c = AccountUsableResponseControl.get(entry);

      assertTrue(c.isUsable());
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
    }

    conn.close();
  }
}
