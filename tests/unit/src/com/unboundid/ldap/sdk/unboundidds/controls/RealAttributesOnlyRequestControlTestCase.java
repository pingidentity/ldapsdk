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
import com.unboundid.ldap.sdk.DereferencePolicy;
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
 * RealAttributesOnlyRequestControl class.
 */
public class RealAttributesOnlyRequestControlTestCase
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
    RealAttributesOnlyRequestControl c = new RealAttributesOnlyRequestControl();
    c = new RealAttributesOnlyRequestControl(c);

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
    RealAttributesOnlyRequestControl c =
         new RealAttributesOnlyRequestControl(true);
    c = new RealAttributesOnlyRequestControl(c);

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
    RealAttributesOnlyRequestControl c =
         new RealAttributesOnlyRequestControl(false);
    c = new RealAttributesOnlyRequestControl(c);

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
    Control c = new Control(
         RealAttributesOnlyRequestControl.REAL_ATTRIBUTES_ONLY_REQUEST_OID,
         true, new ASN1OctetString("foo"));
    new RealAttributesOnlyRequestControl(c);
  }



  /**
   * Sends a request to the server containing the real attributes only request
   * control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithRealAttributesOnlyRequestControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());


    // Perform a search to read the base entry without any controls.  Request
    // both the "objectClass" attribute (which should be real) and the
    // "ds-entry-checksum" attribute (which should be virtual), and verify that
    // both are returned when no controls are included.
    String[] attrs = { "objectClass", "ds-entry-checksum" };
    SearchRequest searchRequest =
         new SearchRequest(getTestBaseDN(), SearchScope.BASE,
                           DereferencePolicy.NEVER, 0, 0, false,
                           "(objectClass=*)", attrs);

    SearchResult result = conn.search(searchRequest);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertEquals(result.getEntryCount(), 1);

    SearchResultEntry searchEntry = result.getSearchEntries().get(0);
    assertTrue(searchEntry.hasAttribute("objectClass"));
    assertTrue(searchEntry.hasAttribute("ds-entry-checksum"));


    // Add the real attributes only control to the request and verify that
    // the ds-entry-checksum attribute is no longer returned but the objectClass
    // attribute still is.
    searchRequest.addControl(new RealAttributesOnlyRequestControl(true));
    result = conn.search(searchRequest);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);
    assertEquals(result.getEntryCount(), 1);

    searchEntry = result.getSearchEntries().get(0);
    assertTrue(searchEntry.hasAttribute("objectClass"));
    assertFalse(searchEntry.hasAttribute("ds-entry-checksum"));

    conn.delete(getTestBaseDN());
    conn.close();
  }
}
