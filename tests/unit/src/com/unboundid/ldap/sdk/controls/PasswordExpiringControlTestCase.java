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
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the PasswordExpiringControl
 * class.
 */
public class PasswordExpiringControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    new PasswordExpiringControl();
  }



  /**
   * Tests the second constructor.
   */
  @Test()
  public void testConstructor2()
  {
    PasswordExpiringControl c = new PasswordExpiringControl(1234);

    assertEquals(c.getSecondsUntilExpiration(), 1234);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a valid set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlValid()
         throws Exception
  {
    PasswordExpiringControl c =
         new PasswordExpiringControl().decodeControl("2.16.840.1.113730.3.4.5",
                  false, new ASN1OctetString("12345"));

    assertEquals(c.getSecondsUntilExpiration(), 12345);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlNull()
         throws Exception
  {
    new PasswordExpiringControl().decodeControl("2.16.840.1.113730.3.4.5",
                                                false, null);
  }



  /**
   * Tests the {@code decodeControl} method with a non-numeric value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlNonNumeric()
         throws Exception
  {
    new PasswordExpiringControl().decodeControl("2.16.840.1.113730.3.4.5",
             false, new ASN1OctetString("nonnumeric"));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a password
   * expiring control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null, null,
         controls);

    final PasswordExpiringControl c = PasswordExpiringControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new PasswordExpiringControl(1234)
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PasswordExpiringControl c = PasswordExpiringControl.get(r);
    assertNotNull(c);

    assertEquals(c.getSecondsUntilExpiration(), 1234);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a password expiring
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new PasswordExpiringControl(1234);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PasswordExpiringControl c = PasswordExpiringControl.get(r);
    assertNotNull(c);

    assertEquals(c.getSecondsUntilExpiration(), 1234);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an password expiring
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(PasswordExpiringControl.PASSWORD_EXPIRING_OID, false, null)
    };

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    PasswordExpiringControl.get(r);
  }
}
