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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.RootDSE;



/**
 * This class provides a set of test cases for the get user resource limits
 * request control.
 */
public final class GetUserResourceLimitsRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasic()
         throws Exception
  {
    GetUserResourceLimitsRequestControl c =
         new GetUserResourceLimitsRequestControl();

    c = new GetUserResourceLimitsRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.25");

    assertFalse(c.isCritical());

    assertNull(c.getValue());

    assertFalse(c.excludeGroups());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the case in which group information should be
   * excluded from the response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeGroups()
         throws Exception
  {
    GetUserResourceLimitsRequestControl c =
         new GetUserResourceLimitsRequestControl(false, true);

    c = new GetUserResourceLimitsRequestControl(c);
    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.25");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertTrue(c.excludeGroups());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that has a malformed
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithMalformedValue()
         throws Exception
  {
    new GetUserResourceLimitsRequestControl(
         new Control("1.2.3.4", false, new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior of the {@code serverAdvertisesExcludeGroupsFeature}
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdvertisesExcludeGroupsFeature()
         throws Exception
  {
    final RootDSE defaultRootDSE = getTestDS().getRootDSE();
    assertNotNull(defaultRootDSE);
    assertFalse(GetUserResourceLimitsRequestControl.
         serverAdvertisesExcludeGroupsFeature(defaultRootDSE));

    final Entry updatedRootDSEEntry = defaultRootDSE.duplicate();
    updatedRootDSEEntry.addAttribute(RootDSE.ATTR_SUPPORTED_FEATURE,
         "1.3.6.1.4.1.30221.2.12.6");
    final RootDSE updatedRootDSE = new RootDSE(updatedRootDSEEntry);
    assertTrue(GetUserResourceLimitsRequestControl.
         serverAdvertisesExcludeGroupsFeature(updatedRootDSE));
  }
}
