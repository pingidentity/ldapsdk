/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * TransactionIDRequestControl class.
 */
public class TransactionIDRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which allows specifying the transaction ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    final String testTxnID = UUID.randomUUID().toString();

    TransactionIDRequestControl c = new TransactionIDRequestControl(testTxnID);
    c = new TransactionIDRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.1");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getTransactionID());
    assertEquals(c.getTransactionID(), testTxnID);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor, which allows specifying the criticality and
   * transaction ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    final String testTxnID = UUID.randomUUID().toString();

    TransactionIDRequestControl c =
         new TransactionIDRequestControl(true, testTxnID);
    c = new TransactionIDRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.1");

    assertTrue(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getTransactionID());
    assertEquals(c.getTransactionID(), testTxnID);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor, which can be used to decode a generic control
   * as a transaction ID request control, with a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPException.class)
  public void testConstructor3MissingValue()
         throws Exception
  {
    final Control genericControl = new Control("1.3.6.1.4.1.36733.2.1.5.1");
    new TransactionIDRequestControl(genericControl);
  }
}
