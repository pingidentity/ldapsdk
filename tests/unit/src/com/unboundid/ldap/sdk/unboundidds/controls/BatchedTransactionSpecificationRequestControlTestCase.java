/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2018 Ping Identity Corporation
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
 * BatchedTransactionSpecificationRequestControl class.
 */
public class BatchedTransactionSpecificationRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a non-{@code null} transaction ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    BatchedTransactionSpecificationRequestControl c =
         new BatchedTransactionSpecificationRequestControl(
                  new ASN1OctetString("123"));
    c = new BatchedTransactionSpecificationRequestControl(c);

    assertNotNull(c.getTransactionID());
    assertEquals(c.getTransactionID().stringValue(), "123");

    assertTrue(c.isCritical());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a {@code null} transaction ID.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testConstructor1Null()
  {
    new BatchedTransactionSpecificationRequestControl((ASN1OctetString) null);
  }



  /**
   * Tests the second constructor with a generic control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2NoValue()
         throws Exception
  {
    Control c = new Control(BatchedTransactionSpecificationRequestControl.
                                 BATCHED_TRANSACTION_SPECIFICATION_REQUEST_OID,
                            true, null);
    new BatchedTransactionSpecificationRequestControl(c);
  }
}
