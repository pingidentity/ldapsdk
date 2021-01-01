/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.util.EnumSet;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the suppress operational
 * attribute update request control.
 */
public final class SuppressOperationalAttributeUpdateRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the control created with the constructor that uses
   * only a varargs set of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsWithoutCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(
              SuppressType.LAST_ACCESS_TIME);

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(),
         EnumSet.of(SuppressType.LAST_ACCESS_TIME));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control created with the constructor that uses a
   * criticality and a varargs set of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVarargsWithCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              SuppressType.LAST_ACCESS_TIME, SuppressType.LAST_LOGIN_TIME,
              SuppressType.LAST_LOGIN_IP, SuppressType.LASTMOD);

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(), EnumSet.allOf(SuppressType.class));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control created with the constructor that uses
   * only a collection of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionWithoutCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(
              EnumSet.of(SuppressType.LASTMOD));

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(),
         EnumSet.of(SuppressType.LASTMOD));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control created with the constructor that uses a
   * criticality and a collection of suppress types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionWithCriticality()
         throws Exception
  {
    SuppressOperationalAttributeUpdateRequestControl c =
         new SuppressOperationalAttributeUpdateRequestControl(true,
              EnumSet.of(SuppressType.LAST_LOGIN_TIME,
                   SuppressType.LAST_LOGIN_IP));

    c = new SuppressOperationalAttributeUpdateRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.27");

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getSuppressTypes());
    assertEquals(c.getSuppressTypes(),
         EnumSet.of(SuppressType.LAST_LOGIN_TIME,
              SuppressType.LAST_LOGIN_IP));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a generic control that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeWithoutValue()
         throws Exception
  {
    new SuppressOperationalAttributeUpdateRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.27"));
  }



  /**
   * Tests the behavior when trying to decode a generic control that cannot be
   * decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new SuppressOperationalAttributeUpdateRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.27", false,
              new ASN1OctetString("this is a malformed value")));
  }



  /**
   * Tests the behavior when trying to decode a generic control that cannot be
   * decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueUnrecognizedSuppressType()
         throws Exception
  {
    new SuppressOperationalAttributeUpdateRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.27", false,
              new ASN1OctetString(
                   new ASN1Sequence(
                        new ASN1Sequence((byte) 0x80,
                             new ASN1Enumerated(1234))).encode())));
  }
}
