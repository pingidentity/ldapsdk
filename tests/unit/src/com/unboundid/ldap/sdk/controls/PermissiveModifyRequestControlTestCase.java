/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the permissive modify request
 * control.
 */
public class PermissiveModifyRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the first constructor, which does not require
   * any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PermissiveModifyRequestControl c = new PermissiveModifyRequestControl();
    c = new PermissiveModifyRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.2.840.113556.1.4.1413");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the second constructor, which takes a boolean
   * criticality with a value of "true".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Critical()
         throws Exception
  {
    PermissiveModifyRequestControl c = new PermissiveModifyRequestControl(true);
    c = new PermissiveModifyRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.2.840.113556.1.4.1413");

    assertTrue(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the second constructor, which takes a boolean
   * criticality with a value of "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NotCritical()
         throws Exception
  {
    PermissiveModifyRequestControl c =
         new PermissiveModifyRequestControl(false);
    c = new PermissiveModifyRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.2.840.113556.1.4.1413");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the third constructor, which takes a generic
   * control, using a control that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3WithoutValue()
         throws Exception
  {
    Control ctl = new Control("1.2.840.113556.1.4.1413", false);
    PermissiveModifyRequestControl c = new PermissiveModifyRequestControl(ctl);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.2.840.113556.1.4.1413");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the third constructor, which takes a generic
   * control, using a control that has a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3WithValue()
         throws Exception
  {
    Control ctl =
         new Control("1.2.840.113556.1.4.1413", false, new ASN1OctetString());
    new PermissiveModifyRequestControl(ctl);
  }
}
