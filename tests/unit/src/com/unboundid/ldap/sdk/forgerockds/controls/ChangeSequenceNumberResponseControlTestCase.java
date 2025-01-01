/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.forgerockds.controls;



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * ChangeSequenceNumberResponseControl class.
 */
public class ChangeSequenceNumberResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor that may be used to create a new instance of the
   * response control with a given CSN value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeConstructor()
         throws Exception
  {
    final String testCSN = UUID.randomUUID().toString();

    ChangeSequenceNumberResponseControl c =
         new ChangeSequenceNumberResponseControl(testCSN);
    c = new ChangeSequenceNumberResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.42.2.27.9.5.9");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getCSN());
    assertEquals(c.getCSN(), testCSN);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the ability to decode a control that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new ChangeSequenceNumberResponseControl(
         "1.3.6.1.4.1.42.2.27.9.5.9", false, null);
  }



  /**
   * Tests the {@code get} method for a result that does not have any response
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutAnyControls()
         throws Exception
  {
    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS);

    assertNull(ChangeSequenceNumberResponseControl.get(result));
  }



  /**
   * Tests the {@code get} method for a result that includes controls but does
   * not have a CSN response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutCSNResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNull(ChangeSequenceNumberResponseControl.get(result));
  }



  /**
   * Tests the {@code get} method for a result that includes a CSN response
   * control that is already an appropriate instance of that control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithCorrectInstanceType()
         throws Exception
  {
    final String testCSN = UUID.randomUUID().toString();

    final Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo")),
      new ChangeSequenceNumberResponseControl(testCSN)
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    final ChangeSequenceNumberResponseControl c =
         ChangeSequenceNumberResponseControl.get(result);
    assertNotNull(c);

    assertEquals(c.getCSN(), testCSN);
  }



  /**
   * Tests the {@code get} method for a result that includes a CSN response
   * control that has not yet been decoded but is a generic control instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithGenericControl()
         throws Exception
  {
    final String testCSN = UUID.randomUUID().toString();

    final Control[] responseControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo")),
      new Control("1.3.6.1.4.1.42.2.27.9.5.9", false,
           new ASN1OctetString(testCSN))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    final ChangeSequenceNumberResponseControl c =
         ChangeSequenceNumberResponseControl.get(result);
    assertNotNull(c);

    assertEquals(c.getCSN(), testCSN);
  }
}
