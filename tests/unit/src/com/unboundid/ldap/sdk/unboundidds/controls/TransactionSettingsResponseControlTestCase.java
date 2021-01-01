/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the transaction settings response
 * control.
 */
public final class TransactionSettingsResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of a response control without any conflicts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutConflicts()
         throws Exception
  {
    TransactionSettingsResponseControl c =
         new TransactionSettingsResponseControl(0, false);

    c = new TransactionSettingsResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.39");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertEquals(c.getNumLockConflicts(), 0);

    assertFalse(c.backendLockAcquired());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of a response control with conflicts.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWitConflicts()
         throws Exception
  {
    TransactionSettingsResponseControl c =
         new TransactionSettingsResponseControl(1234, true);

    c = new TransactionSettingsResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.39");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertEquals(c.getNumLockConflicts(), 1234);

    assertTrue(c.backendLockAcquired());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new TransactionSettingsResponseControl("1.3.6.1.4.1.30221.2.5.39", false,
         null);
  }



  /**
   * Tests the behavior when trying to decode a control that has a malformed
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new TransactionSettingsResponseControl("1.3.6.1.4.1.30221.2.5.39", false,
         new ASN1OctetString("malformed"));
  }



  /**
   * Tests the get method for a result without any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutControls()
         throws Exception
  {
    final Control[] controls =
    {
    };

    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, controls);
    assertNull(TransactionSettingsResponseControl.get(r));
  }



  /**
   * Tests the get method for a result without any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutTxnSettingsResponseControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString("foo"))
    };

    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, controls);
    assertNull(TransactionSettingsResponseControl.get(r));
  }



  /**
   * Tests the get method for a result with a valid, pre-decoded transaction
   * settings response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithDecodedTxnSettingsResponseControl()
         throws Exception
  {
    final Control[] controls =
    {
      new TransactionSettingsResponseControl(0, false)
    };

    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, controls);

    final TransactionSettingsResponseControl c =
         TransactionSettingsResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getNumLockConflicts(), 0);

    assertFalse(c.backendLockAcquired());
  }



  /**
   * Tests the get method for a result with a valid but undecoded transaction
   * settings response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithUndecodedTxnSettingsResponseControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.39", false,
           new TransactionSettingsResponseControl(5, true).getValue())
    };

    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, controls);

    final TransactionSettingsResponseControl c =
         TransactionSettingsResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getNumLockConflicts(), 5);

    assertTrue(c.backendLockAcquired());
  }



  /**
   * Tests the get method for a result with a malformed transaction settings
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithMalformedTxnSettingsResponseControl()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.39", false,
           new ASN1OctetString("malformed"))
    };

    final ExtendedResult r = new ExtendedResult(1, ResultCode.SUCCESS, null,
         null, null, null, null, controls);

    TransactionSettingsResponseControl.get(r);
  }
}
