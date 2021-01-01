/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the interactive transaction
 * specification request control.
 */
@SuppressWarnings("deprecation")
public class InteractiveTransactionSpecificationRequestControlTestCase
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
    InteractiveTransactionSpecificationRequestControl c =
         new InteractiveTransactionSpecificationRequestControl(
                  new ASN1OctetString("txnid"));
    c = new InteractiveTransactionSpecificationRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getTransactionID());
    assertEquals(c.getTransactionID().stringValue(), "txnid");

    assertFalse(c.abortOnFailure());

    assertTrue(c.writeLock());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with default values for the abortOnFailure and
   * writeLock elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Defaults()
         throws Exception
  {
    InteractiveTransactionSpecificationRequestControl c =
         new InteractiveTransactionSpecificationRequestControl(
                  new ASN1OctetString("txnid"), false, true);
    c = new InteractiveTransactionSpecificationRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getTransactionID());
    assertEquals(c.getTransactionID().stringValue(), "txnid");

    assertFalse(c.abortOnFailure());

    assertTrue(c.writeLock());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with non-default values for the abortOnFailure
   * and writeLock elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NonDefaults()
         throws Exception
  {
    InteractiveTransactionSpecificationRequestControl c =
         new InteractiveTransactionSpecificationRequestControl(
                  new ASN1OctetString("txnid"), true, false);
    c = new InteractiveTransactionSpecificationRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getTransactionID());
    assertEquals(c.getTransactionID().stringValue(), "txnid");

    assertTrue(c.abortOnFailure());

    assertFalse(c.writeLock());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a control that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3NoValue()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.4");
    new InteractiveTransactionSpecificationRequestControl(c);
  }



  /**
   * Tests the third constructor with a control whose value is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueNotSequence()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", true,
                            new ASN1OctetString("x"));
    new InteractiveTransactionSpecificationRequestControl(c);
  }



  /**
   * Tests the third constructor with a control whose value is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueEmptySequence()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", true,
                            new ASN1OctetString(new ASN1Sequence().encode()));
    new InteractiveTransactionSpecificationRequestControl(c);
  }



  /**
   * Tests the third constructor with a control whose value sequence contains an
   * element with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3ValueSequenceInvalidElementType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x01, "Invalid BER type")
    };

    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", true,
         new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new InteractiveTransactionSpecificationRequestControl(c);
  }



  /**
   * Tests the third constructor with a control in which the abortOnFailure
   * element cannot be decoded as a Boolean.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3AbortOnFailureNotBoolean()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x80, "txnid"),
      new ASN1OctetString((byte) 0x81, "not boolean")
    };

    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", true,
         new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new InteractiveTransactionSpecificationRequestControl(c);
  }



  /**
   * Tests the third constructor with a control in which the writeLock element
   * cannot be decoded as a Boolean.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor3WriteLockNotBoolean()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString((byte) 0x80, "txnid"),
      new ASN1OctetString((byte) 0x82, "not boolean")
    };

    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", true,
         new ASN1OctetString(new ASN1Sequence(elements).encode()));
    new InteractiveTransactionSpecificationRequestControl(c);
  }
}
