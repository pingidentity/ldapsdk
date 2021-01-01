/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the PreReadRequestControl class.
 */
public class PreReadRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null}, non-empty set of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PreReadRequestControl c =
         new PreReadRequestControl("cn", "sn");
    c = new PreReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 2);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a {@code null} set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Null()
         throws Exception
  {
    PreReadRequestControl c = new PreReadRequestControl((String[]) null);
    c = new PreReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with an empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Empty()
         throws Exception
  {
    PreReadRequestControl c = new PreReadRequestControl(new String[0]);
    c = new PreReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a non-{@code null}, non-empty set of
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    PreReadRequestControl c =
         new PreReadRequestControl(false, "cn", "sn");
    c = new PreReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 2);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a {@code null} set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Null()
         throws Exception
  {
    PreReadRequestControl c = new PreReadRequestControl(false, (String[]) null);
    c = new PreReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with an empty set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Empty()
         throws Exception
  {
    PreReadRequestControl c = new PreReadRequestControl(false, new String[0]);
    c = new PreReadRequestControl(c);

    assertNotNull(c.getAttributes());
    assertEquals(c.getAttributes().length, 0);

    assertFalse(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a generic control that does not contain a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    Control c = new Control(PreReadRequestControl.PRE_READ_REQUEST_OID,
                            true, null);
    new PreReadRequestControl(c);
  }



  /**
   * Tests the third constructor with a generic control with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3InvalidValue()
         throws Exception
  {
    Control c = new Control(PreReadRequestControl.PRE_READ_REQUEST_OID,
                            true, new ASN1OctetString("foo"));
    new PreReadRequestControl(c);
  }



  /**
   * Adds an entry with the pre-read request control and ensures that the
   * corresponding response control is included in the response.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSendRequestWithPreReadControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    Control[] controls =
    {
      new PreReadRequestControl((String[]) null)
    };

    LDAPResult deleteResult =
         conn.delete(new DeleteRequest(getTestBaseDN(), controls));

    boolean hasControl = false;
    for (Control c : deleteResult.getResponseControls())
    {
      if (c instanceof PreReadResponseControl)
      {
        hasControl = true;
        PreReadResponseControl prrc = (PreReadResponseControl) c;
        assertNotNull(prrc.getEntry());
        assertEquals(prrc.getEntry().getDN(), getTestBaseDN());
      }
      else if (c.getOID().equals(PreReadResponseControl.
                                      PRE_READ_RESPONSE_OID))
      {
        fail("Failed to decode a response control with the appropriate " +
             "OID as a pre-read response.");
      }
    }

    conn.close();
    assertTrue(hasControl);
  }
}
