/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code GetServerIDRequestControl} class.
 */
public class GetServerIDRequestControlTestCase
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
    GetServerIDRequestControl c = new GetServerIDRequestControl();
    c = new GetServerIDRequestControl(c);

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
    GetServerIDRequestControl c = new GetServerIDRequestControl(true);
    c = new GetServerIDRequestControl(c);

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
    GetServerIDRequestControl c = new GetServerIDRequestControl(false);
    c = new GetServerIDRequestControl(c);

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
    final Control genericControl =
         new Control(GetServerIDRequestControl.GET_SERVER_ID_REQUEST_OID,
                     false, null);
    final GetServerIDRequestControl c =
         new GetServerIDRequestControl(genericControl);

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
    final Control genericControl =
         new Control(GetServerIDRequestControl.GET_SERVER_ID_REQUEST_OID,
                     false, new ASN1OctetString("foo"));
    new GetServerIDRequestControl(genericControl);
  }
}
