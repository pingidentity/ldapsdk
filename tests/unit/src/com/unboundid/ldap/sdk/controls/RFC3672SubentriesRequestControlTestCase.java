/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
 * This class provides a set of test cases for the
 * RFC3672SubentriesRequestControl class.
 */
public class RFC3672SubentriesRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating an instance of the control without a
   * criticality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutCriticality()
         throws Exception
  {
    RFC3672SubentriesRequestControl c =
         new RFC3672SubentriesRequestControl(true);
    c = new RFC3672SubentriesRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.10.1");

    assertFalse(c.isCritical());

    assertTrue(c.returnOnlySubEntries());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when creating an instance of the control with a
   * criticality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithCriticality()
         throws Exception
  {
    RFC3672SubentriesRequestControl c =
         new RFC3672SubentriesRequestControl(false, true);
    c = new RFC3672SubentriesRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.10.1");

    assertTrue(c.isCritical());

    assertFalse(c.returnOnlySubEntries());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode an instance of the control without
   * a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new RFC3672SubentriesRequestControl(
         new Control("1.3.6.1.4.1.4203.1.10.1", false, null));
  }



  /**
   * Tests the behavior when trying to decode an instance of the control with a
   * malformed value that cannot be parsed as a BER-encoded boolean.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithMalformedValue()
         throws Exception
  {
    new RFC3672SubentriesRequestControl(
         new Control("1.3.6.1.4.1.4203.1.10.1", false,
              new ASN1OctetString("malformed")));
  }
}
