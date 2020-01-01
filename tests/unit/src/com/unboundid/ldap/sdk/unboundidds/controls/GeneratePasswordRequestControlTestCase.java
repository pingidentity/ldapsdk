/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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
 * This class provides a set of test cases for the generate password request
 * control.
 */
public final class GeneratePasswordRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    GeneratePasswordRequestControl c = new GeneratePasswordRequestControl();

    c = new GeneratePasswordRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.58");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for a control with an explicit criticality of true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitlyCriticalControl()
         throws Exception
  {
    GeneratePasswordRequestControl c = new GeneratePasswordRequestControl(true);

    c = new GeneratePasswordRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.58");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for a control with an explicit criticality of false.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitlyNonCriticalControl()
         throws Exception
  {
    GeneratePasswordRequestControl c =
         new GeneratePasswordRequestControl(false);

    c = new GeneratePasswordRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.58");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that has a value.
   *
   * @throws  Exception  If an unexpected problem occurs
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithValue()
         throws Exception
  {
    new GeneratePasswordRequestControl(new Control("1.3.6.1.4.1.30221.2.5.58",
         true, new ASN1OctetString("foo")));
  }
}
