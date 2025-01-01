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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * AffinityRequestControl class.
 */
public class AffinityRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which will always use a randomly generated
   * affinity value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    AffinityRequestControl c = new AffinityRequestControl(true);
    c = new AffinityRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.2");

    assertTrue(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getAffinityValue());
    assertTrue(c.getAffinityValue().getValueLength() > 0);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor, which allows you to specify the affinity
   * value as a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    AffinityRequestControl c =
         new AffinityRequestControl(false, "test-affinity-value");
    c = new AffinityRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.2");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getAffinityValue());
    assertEquals(c.getAffinityValue().stringValue(), "test-affinity-value");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor, which allows you to specify the affinity
   * value as a byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    final byte[] affinityValueBytes = StaticUtils.byteArray(1, 2, 3, 4, 5);

    AffinityRequestControl c =
         new AffinityRequestControl(false, affinityValueBytes);
    c = new AffinityRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.2");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getAffinityValue());
    assertEquals(c.getAffinityValue().getValue(), affinityValueBytes);

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the fourth constructor, which allows you to specify the affinity
   * value as an ASN.1 octet string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    AffinityRequestControl c =
         new AffinityRequestControl(true, new
              ASN1OctetString("value-octet-string"));
    c = new AffinityRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.36733.2.1.5.2");

    assertTrue(c.isCritical());

    assertTrue(c.hasValue());

    assertNotNull(c.getAffinityValue());
    assertEquals(c.getAffinityValue().stringValue(), "value-octet-string");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when attempting to decode a generic control as an
   * affinity request control when the generic control does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new AffinityRequestControl(new Control("1.3.6.1.4.1.36733.2.1.5.2"));
  }
}
