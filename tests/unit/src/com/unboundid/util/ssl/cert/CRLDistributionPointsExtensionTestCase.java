/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the
 * CRLDistributionPointsExtension class.
 */
public final class CRLDistributionPointsExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with a valid extension that has a single distribution point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleDistributionPoint()
         throws Exception
  {
    CRLDistributionPointsExtension e = new CRLDistributionPointsExtension(false,
         Collections.singletonList(new CRLDistributionPoint(
              new GeneralNamesBuilder().addDNSName("dp1.example.com").build(),
              null, null)));

    e = new CRLDistributionPointsExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.31");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertNotNull(e.getCRLDistributionPoints());
    assertFalse(e.getCRLDistributionPoints().isEmpty());
    assertEquals(e.getCRLDistributionPoints().size(), 1);

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.31"));

    assertNotNull(e.toString());
  }



  /**
   * Tests with a valid extension that has multiple distribution points.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleDistributionPoints()
         throws Exception
  {
    CRLDistributionPointsExtension e = new CRLDistributionPointsExtension(true,
         Arrays.asList(
              new CRLDistributionPoint(
                   new GeneralNamesBuilder().addDNSName("dp1").build(),
                   null, null),
              new CRLDistributionPoint(
                   new GeneralNamesBuilder().addDNSName("dp2").build(),
                   null, null)));

    e = new CRLDistributionPointsExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.31");

    assertTrue(e.isCritical());

    assertNotNull(e.getValue());

    assertNotNull(e.getCRLDistributionPoints());
    assertFalse(e.getCRLDistributionPoints().isEmpty());
    assertEquals(e.getCRLDistributionPoints().size(), 2);

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.31"));

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when trying to create an extension with a full name
   * value that has a malformed OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeMalformedFullName()
         throws Exception
  {
    new CRLDistributionPointsExtension(false,
         Collections.singletonList(new CRLDistributionPoint(
              new GeneralNamesBuilder().addRegisteredID(new OID("1234.5678")).
                        build(),
              null, null)));
  }



  /**
   * Tests the behavior when trying to decode a generic extension that is not
   * a valid CRL distribution points extension.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedExtension()
         throws Exception
  {
    final X509CertificateExtension genericExtension =
         new X509CertificateExtension(new OID("2.5.29.31"), false,
         "not a valid CRL distribution points value".getBytes("UTF-8"));
    new CRLDistributionPointsExtension(genericExtension);
  }
}
