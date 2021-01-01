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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the PasswordPolicyResponseControl
 * class.
 */
public class PasswordPolicyResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    new PasswordPolicyResponseControl();
  }



  /**
   * Tests the second constructor with all element types.
   */
  @Test()
  public void testConstructor2AllTypes()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(
                  PasswordPolicyWarningType.GRACE_LOGINS_REMAINING, 2,
                  PasswordPolicyErrorType.PASSWORD_EXPIRED);

    assertNotNull(c.getWarningType());
    assertEquals(c.getWarningType(),
                 PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);
    assertEquals(c.getWarningValue(), 2);

    assertNotNull(c.getErrorType());
    assertEquals(c.getErrorType(),
                 PasswordPolicyErrorType.PASSWORD_EXPIRED);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with only a warning element.
   */
  @Test()
  public void testConstructor2OnlyWarning()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(
                  PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION, 12345,
                  null);

    assertNotNull(c.getWarningType());
    assertEquals(c.getWarningType(),
                 PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
    assertEquals(c.getWarningValue(), 12345);

    assertNull(c.getErrorType());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with only an error element.
   */
  @Test()
  public void testConstructor2OnlyError()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(null, -1,
                  PasswordPolicyErrorType.ACCOUNT_LOCKED);

    assertNull(c.getWarningType());
    assertEquals(c.getWarningValue(), -1);

    assertNotNull(c.getErrorType());
    assertEquals(c.getErrorType(), PasswordPolicyErrorType.ACCOUNT_LOCKED);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with all no types.
   */
  @Test()
  public void testConstructor2NoTypes()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(null, -1, null);

    assertNull(c.getWarningType());
    assertEquals(c.getWarningValue(), -1);

    assertNull(c.getErrorType());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with all element types.
   */
  @Test()
  public void testConstructor3AllTypes()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(
                  PasswordPolicyWarningType.GRACE_LOGINS_REMAINING, 2,
                  PasswordPolicyErrorType.PASSWORD_EXPIRED, false);

    assertNotNull(c.getWarningType());
    assertEquals(c.getWarningType(),
                 PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);
    assertEquals(c.getWarningValue(), 2);

    assertNotNull(c.getErrorType());
    assertEquals(c.getErrorType(),
                 PasswordPolicyErrorType.PASSWORD_EXPIRED);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with only a warning element.
   */
  @Test()
  public void testConstructor3OnlyWarning()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(
                  PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION, 12345, null,
                  false);

    assertNotNull(c.getWarningType());
    assertEquals(c.getWarningType(),
                 PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
    assertEquals(c.getWarningValue(), 12345);

    assertNull(c.getErrorType());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with only an error element.
   */
  @Test()
  public void testConstructor3OnlyError()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(null, -1,
                  PasswordPolicyErrorType.ACCOUNT_LOCKED, false);

    assertNull(c.getWarningType());
    assertEquals(c.getWarningValue(), -1);

    assertNotNull(c.getErrorType());
    assertEquals(c.getErrorType(), PasswordPolicyErrorType.ACCOUNT_LOCKED);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with all no types.
   */
  @Test()
  public void testConstructor3NoTypes()
  {
    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl(null, -1, null, true);

    assertNull(c.getWarningType());
    assertEquals(c.getWarningValue(), -1);

    assertNull(c.getErrorType());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a valid set of information
   * with all element types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlAllTypes()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0xA0,
                      new ASN1Integer((byte) 0x80, 12345).encode()),
      new ASN1Enumerated((byte) 0x81, 0)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl().decodeControl(
                  "1.3.6.1.4.1.42.2.27.8.5.1", false, value);

    assertNotNull(c.getWarningType());
    assertEquals(c.getWarningType(),
                 PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);
    assertEquals(c.getWarningValue(), 12345);

    assertNotNull(c.getErrorType());
    assertEquals(c.getErrorType(),
                 PasswordPolicyErrorType.PASSWORD_EXPIRED);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a valid set of information
   * with only a warning element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlOnlyWarning()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0xA0,
                      new ASN1Integer((byte) 0x81, 2).encode())
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl().decodeControl(
                  "1.3.6.1.4.1.42.2.27.8.5.1", false, value);

    assertNotNull(c.getWarningType());
    assertEquals(c.getWarningType(),
                 PasswordPolicyWarningType.GRACE_LOGINS_REMAINING);
    assertEquals(c.getWarningValue(), 2);

    assertNull(c.getErrorType());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a valid set of information
   * with only an error element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlOnlyError()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Enumerated((byte) 0x81, 1)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl().decodeControl(
                  "1.3.6.1.4.1.42.2.27.8.5.1", false, value);

    assertNull(c.getWarningType());
    assertEquals(c.getWarningValue(), -1);

    assertNotNull(c.getErrorType());
    assertEquals(c.getErrorType(),
                 PasswordPolicyErrorType.ACCOUNT_LOCKED);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a valid set of information
   * with no element types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeControlNoTypes()
         throws Exception
  {
    ASN1Element[] valueElements = new ASN1Element[0];

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    PasswordPolicyResponseControl c =
         new PasswordPolicyResponseControl().decodeControl(
                  "1.3.6.1.4.1.42.2.27.8.5.1", false, value);

    assertNull(c.getWarningType());
    assertEquals(c.getWarningValue(), -1);

    assertNull(c.getErrorType());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlNullValue()
         throws Exception
  {
    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, null);
  }



  /**
   * Tests the {@code decodeControl} method with a value that can't be decoded
   * as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false,
             new ASN1OctetString(new ASN1Integer(0).encode()));
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with too many
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceTooManyElements()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0xA0,
                      new ASN1Integer((byte) 0x80, 12345).encode()),
      new ASN1Enumerated((byte) 0x81, 0),
      new ASN1Integer(0)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidElementType()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Integer(5)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with multiple
   * warning elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMultipleWarningElements()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0xA0,
                      new ASN1Integer((byte) 0x80, 12345).encode()),
      new ASN1Element((byte) 0xA0,
                      new ASN1Integer((byte) 0x81, 2).encode()),
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence multiple value
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMultipleValueElements()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Enumerated((byte) 0x81, 0),
      new ASN1Enumerated((byte) 0x81, 1),
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with an
   * invalid warning type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidWarningType()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0xA0,
                      new ASN1Integer((byte) 0x82, 12345).encode())
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with a
   * warning element that can't be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceCannotDecodeWarningType()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0xA0, new ASN1OctetString().encode())
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with an
   * invalid error type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidErrorType()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Enumerated((byte) 0x81, 999)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code decodeControl} method with a value sequence with an error
   * element that can't be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceCannotDecodeErrorType()
         throws Exception
  {
    ASN1Element[] valueElements =
    {
      new ASN1Element((byte) 0x81)
    };

    ASN1OctetString value =
         new ASN1OctetString(new ASN1Sequence(valueElements).encode());

    new PasswordPolicyResponseControl().decodeControl(
             "1.3.6.1.4.1.42.2.27.8.5.1", false, value);
  }



  /**
   * Tests the {@code get} method with a result that does not contain a password
   * policy response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);

    final PasswordPolicyResponseControl c =
         PasswordPolicyResponseControl.get(r);
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
      new PasswordPolicyResponseControl(
           PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION, 1234, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PasswordPolicyResponseControl c =
         PasswordPolicyResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getWarningType(),
         PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);

    assertEquals(c.getWarningValue(), 1234);

    assertNull(c.getErrorType());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a password policy response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new PasswordPolicyResponseControl(
         PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION, 1234, null);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final PasswordPolicyResponseControl c =
         PasswordPolicyResponseControl.get(r);
    assertNotNull(c);

    assertEquals(c.getWarningType(),
         PasswordPolicyWarningType.TIME_BEFORE_EXPIRATION);

    assertEquals(c.getWarningValue(), 1234);

    assertNull(c.getErrorType());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a password policy
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(PasswordPolicyResponseControl.PASSWORD_POLICY_RESPONSE_OID,
           false, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    PasswordPolicyResponseControl.get(r);
  }
}
