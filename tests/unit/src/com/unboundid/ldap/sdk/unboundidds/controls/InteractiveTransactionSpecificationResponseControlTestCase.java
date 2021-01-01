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



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the interactive transaction
 * specification response control.
 */
@SuppressWarnings("deprecation")
public class InteractiveTransactionSpecificationResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a {@code null} set of base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NoBaseDNs()
         throws Exception
  {
    InteractiveTransactionSpecificationResponseControl c =
         new InteractiveTransactionSpecificationResponseControl(true, null);
    c = c.decodeControl(c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.4");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertTrue(c.transactionValid());

    assertNull(c.getBaseDNs());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with a {@code null} set of base DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithBaseDNs()
         throws Exception
  {
    ArrayList<String> baseDNs = new ArrayList<String>(2);
    baseDNs.add("dc=example,dc=com");
    baseDNs.add("o=example.com");

    InteractiveTransactionSpecificationResponseControl c =
         new InteractiveTransactionSpecificationResponseControl(true, baseDNs);
    c = c.decodeControl(c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.4");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertTrue(c.transactionValid());

    assertNotNull(c.getBaseDNs());
    assertEquals(c.getBaseDNs().size(), 2);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlNoValue()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.4");

    new InteractiveTransactionSpecificationResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code decodeControl} method with a control whose value is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", false,
                            new ASN1OctetString("x"));

    new InteractiveTransactionSpecificationResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code decodeControl} method with a control whose value is an
   * empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueEmptySequence()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", false,
         new ASN1OctetString(new ASN1Sequence().encode()));

    new InteractiveTransactionSpecificationResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code decodeControl} method with a control in which the
   * transactionValid element is not a Boolean.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlTxnValidNotBoolean()
         throws Exception
  {
    ASN1Element[] element =
    {
      new ASN1OctetString((byte) 0x80, "Not Boolean")
    };

    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", false,
         new ASN1OctetString(new ASN1Sequence(element).encode()));

    new InteractiveTransactionSpecificationResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code decodeControl} method with a control in which the
   * base DN sequence cannot be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlBaseDNSequenceInvalid()
         throws Exception
  {
    ASN1Element[] element =
    {
      new ASN1OctetString((byte) 0xA1, "x")
    };

    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", false,
         new ASN1OctetString(new ASN1Sequence(element).encode()));

    new InteractiveTransactionSpecificationResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code decodeControl} method with a control in which the
   * value sequence has an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlInvalidElementType()
         throws Exception
  {
    ASN1Element[] element =
    {
      new ASN1OctetString((byte) 0x01, "Invalid BER type")
    };

    Control c = new Control("1.3.6.1.4.1.30221.2.5.4", false,
         new ASN1OctetString(new ASN1Sequence(element).encode()));

    new InteractiveTransactionSpecificationResponseControl().decodeControl(
         c.getOID(), c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code get} method with a result that does not contain an
   * interactive transaction specification response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);

    final InteractiveTransactionSpecificationResponseControl c =
         InteractiveTransactionSpecificationResponseControl.get(r);
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
      new InteractiveTransactionSpecificationResponseControl(true,
           Arrays.asList("dc=example,dc=com"))
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final InteractiveTransactionSpecificationResponseControl c =
         InteractiveTransactionSpecificationResponseControl.get(r);
    assertNotNull(c);

    assertTrue(c.transactionValid());

    assertNotNull(c.getBaseDNs());
    assertFalse(c.getBaseDNs().isEmpty());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as an interactive transaction
   * specification response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new InteractiveTransactionSpecificationResponseControl(
         true, Arrays.asList("dc=example,dc=com"));

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final InteractiveTransactionSpecificationResponseControl c =
         InteractiveTransactionSpecificationResponseControl.get(r);
    assertNotNull(c);

    assertTrue(c.transactionValid());

    assertNotNull(c.getBaseDNs());
    assertFalse(c.getBaseDNs().isEmpty());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an interactive
   * transaction specification response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(InteractiveTransactionSpecificationResponseControl.
           INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID, false, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    InteractiveTransactionSpecificationResponseControl.get(r);
  }
}
