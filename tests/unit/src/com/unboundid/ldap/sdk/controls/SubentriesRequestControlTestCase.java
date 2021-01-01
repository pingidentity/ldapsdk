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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the SubentriesRequestControl
 * class.
 */
@SuppressWarnings("deprecation")
public class SubentriesRequestControlTestCase
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
    SubentriesRequestControl c = new SubentriesRequestControl();
    c = new SubentriesRequestControl(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a criticality of TRUE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2True()
         throws Exception
  {
    SubentriesRequestControl c = new SubentriesRequestControl(true);
    c = new SubentriesRequestControl(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a criticality of FALSE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2False()
         throws Exception
  {
    SubentriesRequestControl c = new SubentriesRequestControl(false);
    c = new SubentriesRequestControl(c);

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
    Control c = new Control(SubentriesRequestControl.SUBENTRIES_REQUEST_OID,
                            true, new ASN1OctetString("foo"));
    new SubentriesRequestControl(c);
  }



  /**
   * Sends a request to the server containing the LDAP subentries request
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithSubentriesRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();


    // Normally the schema subentry is not returned for a non-base level search.
    // Verify that.
    String schemaDN = conn.getRootDSE().getSubschemaSubentryDN();
    assertNotNull(schemaDN);

    SearchRequest searchRequest =
         new SearchRequest(schemaDN, SearchScope.SUB, "(objectClass=*)");

    SearchResult result = conn.search(searchRequest);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertEquals(result.getEntryCount(), 0);


    // Verify that the schema subentry is returned when we issue the same
    // search with the subentries control.
    searchRequest.addControl(new SubentriesRequestControl(true));
    result = conn.search(searchRequest);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertEquals(result.getEntryCount(), 1);

    conn.close();
  }
}
