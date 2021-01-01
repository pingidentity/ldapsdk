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
 * This class provides a set of test cases for the PasswordExpiredControl
 * class.
 */
public class PasswordExpiredControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    PasswordExpiredControl c = new PasswordExpiredControl();

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
    PasswordExpiredControl c =
         new PasswordExpiredControl().decodeControl("2.16.840.1.113730.3.4.4",
                  false, new ASN1OctetString("0"));

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
    new PasswordExpiredControl().decodeControl("2.16.840.1.113730.3.4.4",
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
    new PasswordExpiredControl().decodeControl("2.16.840.1.113730.3.4.4",
             false, new ASN1OctetString("nonnumeric"));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a password
   * expired control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final BindResult r = new BindResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PasswordExpiredControl c = PasswordExpiredControl.get(r);
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
      new PasswordExpiredControl()
    };

    final BindResult r = new BindResult(1, ResultCode.INVALID_CREDENTIALS, null,
         null, null, controls);

    final PasswordExpiredControl c = PasswordExpiredControl.get(r);
    assertNotNull(c);
  }



  /**
   * Tests the {@code get} method using an LDAPException.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetFromException()
         throws Exception
  {
    final Control[] controls =
    {
      new PasswordExpiredControl()
    };

    final LDAPException le = new LDAPException(ResultCode.INVALID_CREDENTIALS,
         null, null, null, controls);

    final PasswordExpiredControl c = PasswordExpiredControl.get(le);
    assertNotNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a password expired control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new PasswordExpiredControl();

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final BindResult r = new BindResult(1, ResultCode.INVALID_CREDENTIALS, null,
         null, null, controls);

    final PasswordExpiredControl c = PasswordExpiredControl.get(r);
    assertNotNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an password expired
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
      new Control(PasswordExpiredControl.PASSWORD_EXPIRED_OID, false,
           new ASN1OctetString("foo"))
    };

    final BindResult r = new BindResult(1, ResultCode.INVALID_CREDENTIALS, null,
         null, null, controls);

    PasswordExpiredControl.get(r);
  }
}
