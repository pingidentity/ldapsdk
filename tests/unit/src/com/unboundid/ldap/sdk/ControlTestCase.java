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
package com.unboundid.ldap.sdk;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the Control class.
 */
public class ControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes only an OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5");

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertFalse(c.isCritical());
    assertNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor by providing a null OID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullOID()
  {
    new Control((String) null);
  }



  /**
   * Tests the second constructor with a control that is critical.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Critical()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5", true);

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertTrue(c.isCritical());
    assertNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a control that is not critical.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NonCritical()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5", false);

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertFalse(c.isCritical());
    assertNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a control that is critical and has a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2CriticalValue()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5", true,
                            new ASN1OctetString(new byte[1]));

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertTrue(c.isCritical());
    assertNotNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a control that is critical and does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2CriticalNoValue()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5", true, null);

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertTrue(c.isCritical());
    assertNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a control that is not critical and has a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NotCriticalValue()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5", false,
                            new ASN1OctetString(new byte[1]));

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertFalse(c.isCritical());
    assertNotNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a control that is not critical and has no
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NotCriticalNoValue()
         throws Exception
  {
    Control c = new Control("1.2.3.4.5", false, null);

    assertEquals(c.getOID(), "1.2.3.4.5");
    assertFalse(c.isCritical());
    assertNull(c.getValue());

    ASN1Sequence controlSequence = c.encode();
    assertNotNull(controlSequence);

    Control decodedControl = Control.decode(controlSequence);
    assertEquals(decodedControl.hashCode(), c.hashCode());
    assertEquals(decodedControl, c);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor by providing a null OID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullOID()
  {
    new Control(null, false, null);
  }



  /**
   * Tests the {@code encodeControls} and {@code decodeControls} methods with an
   * empty array.
   *
   * @throws  LDAPException  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeControlsEmpty()
         throws LDAPException
  {
    ASN1Sequence controlsSequence = Control.encodeControls(new Control[0]);
    Control[] decodedControls = Control.decodeControls(controlsSequence);
    assertNotNull(decodedControls);
    assertEquals(decodedControls.length, 0);
  }



  /**
   * Tests the {@code encodeControls} and {@code decodeControls} methods with an
   * array containing a single element.
   *
   * @throws  LDAPException  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeControlsSingle()
         throws LDAPException
  {
    Control c1 = new Control("1.2.3.4");
    Control[] controls =
    {
      c1
    };

    ASN1Sequence controlsSequence = Control.encodeControls(controls);
    Control[] decodedControls = Control.decodeControls(controlsSequence);
    assertNotNull(decodedControls);
    assertEquals(decodedControls.length, 1);
    assertEquals(decodedControls[0], c1);
  }



  /**
   * Tests the {@code encodeControls} and {@code decodeControls} methods with an
   * array containing multiple elements.
   *
   * @throws  LDAPException  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeControlsMultiple()
         throws LDAPException
  {
    Control c1 = new Control("1.2.3.4");
    Control c2 = new Control("1.2.3.5", true, new ASN1OctetString());
    Control c3 = new Control("1.2.3.6", false, new ASN1OctetString("foo"));
    Control[] controls =
    {
      c1,
      c2,
      c3
    };

    ASN1Sequence controlsSequence = Control.encodeControls(controls);
    Control[] decodedControls = Control.decodeControls(controlsSequence);
    assertNotNull(decodedControls);
    assertEquals(decodedControls.length, 3);
    assertEquals(decodedControls[0], c1);
    assertEquals(decodedControls[1], c2);
    assertEquals(decodedControls[2], c3);
  }



  /**
   * Tests the {@code equals} method with a {@code null} object.
   */
  @Test()
  public void testEqualsNull()
  {
    Control c =
         new Control("1.2.3.4.5", true, new ASN1OctetString(new byte[1]));
    assertFalse(c.equals(null));
  }



  /**
   * Tests the {@code equals} method with an identity comparison.
   */
  @Test()
  public void testEqualsIdentity()
  {
    Control c =
         new Control("1.2.3.4.5", true, new ASN1OctetString(new byte[1]));
    assertTrue(c.equals(c));
  }



  /**
   * Tests the {@code equals} method with an object that is not a control.
   */
  @Test()
  public void testEqualsNotControl()
  {
    Control c =
         new Control("1.2.3.4.5", true, new ASN1OctetString(new byte[1]));
    assertFalse(c.equals("not a control"));
  }



  /**
   * Tests the {@code equals} method with an equivalent control.
   */
  @Test()
  public void testEqualsEquivalentControl()
  {
    Control c =
         new Control("1.2.3.4.5", true, new ASN1OctetString(new byte[1]));
    assertTrue(c.equals(new Control("1.2.3.4.5", true,
                                    new ASN1OctetString(new byte[1]))));
  }



  /**
   * Tests the {@code equals} method with a control that has a different OID.
   */
  @Test()
  public void testEqualsControlDifferentOID()
  {
    Control c =
         new Control("1.2.3.4.5", true, new ASN1OctetString(new byte[1]));
    assertFalse(c.equals(new Control("1.2.3.4.6", true,
                                     new ASN1OctetString(new byte[1]))));
  }



  /**
   * Tests the {@code equals} method with a control that has a different
   * criticality.
   */
  @Test()
  public void testEqualsControlDifferentCriticality()
  {
    Control c =
         new Control("1.2.3.4.5", true, new ASN1OctetString(new byte[1]));
    assertFalse(c.equals(new Control("1.2.3.4.5", false,
                                     new ASN1OctetString(new byte[1]))));
  }



  /**
   * Tests the {@code equals} method with a control that has a value but this
   * control does not (or vice-versa).
   */
  @Test()
  public void testEqualsControlMissingValue()
  {
    Control c1 = new Control("1.2.3.4.5", true,
                             new ASN1OctetString(new byte[1]));
    Control c2 = new Control("1.2.3.4.5", true, null);

    assertFalse(c1.equals(c2));
    assertFalse(c2.equals(c1));
  }



  /**
   * Tests the {@code equals} method with a control with a different value from
   * this control.
   */
  @Test()
  public void testEqualsControlDifferentValue()
  {
    Control c1 = new Control("1.2.3.4.5", true,
                             new ASN1OctetString(new byte[1]));
    Control c2 = new Control("1.2.3.4.5", true,
                             new ASN1OctetString(new byte[2]));

    assertFalse(c1.equals(c2));
    assertFalse(c2.equals(c1));
  }



  /**
   * Tests the {@code decode} method with a sequence containing an invalid
   * number of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidElementCount()
         throws Exception
  {
    Control.decode(new ASN1Sequence());
  }



  /**
   * Tests the {@code decode} method with an invalid criticality when there are
   * only two elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidCriticalityTwoElements()
         throws Exception
  {
    Control.decode(new ASN1Sequence(
         new ASN1OctetString("1.2.3.4"),
         new ASN1OctetString((byte) 0x01, "foo")));
  }



  /**
   * Tests the {@code decode} method with an invalid criticality when there are
   * three elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidCriticalityThreeElements()
         throws Exception
  {
    Control.decode(new ASN1Sequence(
         new ASN1OctetString("1.2.3.4"),
         new ASN1OctetString((byte) 0x01, "foo"),
         new ASN1OctetString()));
  }



  /**
   * Tests the {@code decode} method with an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidElementType()
         throws Exception
  {
    Control.decode(new ASN1Sequence(
         new ASN1OctetString("1.2.3.4"),
         new ASN1OctetString((byte) 0x00)));
  }



  /**
   * Tests the {@code decode} method for a malformed decodeable control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMalformedDecodeableControl()
         throws Exception
  {
    Control c = Control.decode(AuthorizationIdentityResponseControl.
                                    AUTHORIZATION_IDENTITY_RESPONSE_OID,
                               false, null);
    assertFalse(c instanceof AuthorizationIdentityResponseControl);
  }



  /**
   * Tests the {@code decodeControls} method in which the control sequence
   * contains an element that is not a valid control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlsMalformedElement()
         throws Exception
  {
    Control.decodeControls(new ASN1Sequence(new ASN1Integer(1)));
  }



  /**
   * Provides test coverage for the methods that may be used to register and
   * deregister decodeable controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRegisterDecodeableControl()
         throws Exception
  {
    Control.registerDecodeableControl(TestDecodeableControl.OID,
                                      new TestDecodeableControl());
    Control.registerDecodeableControl(TestDecodeableControl.OID,
                                      new TestDecodeableControl());

    Control.deregisterDecodeableControl(TestDecodeableControl.OID);
    Control.deregisterDecodeableControl(TestDecodeableControl.OID);
  }
}
