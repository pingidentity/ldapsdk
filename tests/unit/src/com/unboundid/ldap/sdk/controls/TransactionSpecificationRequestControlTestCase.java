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
package com.unboundid.ldap.sdk.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * {@code TransactionSpecificationRequestControl} class.
 */
public final class TransactionSpecificationRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor that takes a transaction ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor()
         throws Exception
  {
    TransactionSpecificationRequestControl c =
         new TransactionSpecificationRequestControl(
              new ASN1OctetString("txnid"));
    c = new TransactionSpecificationRequestControl(c);

    assertNotNull(c);

    assertEquals(c.getTransactionID(), new ASN1OctetString("txnid"));

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.1.21.2");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor that takes a control using a
   * control without any value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructorWithControlMissingValue()
         throws Exception
  {
    new TransactionSpecificationRequestControl(new Control("1.3.6.1.1.21.2",
         true));
  }
}
