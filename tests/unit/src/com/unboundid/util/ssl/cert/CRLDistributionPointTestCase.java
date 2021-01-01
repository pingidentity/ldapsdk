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



import java.util.EnumSet;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the CRLDistributionPoint class.
 */
public final class CRLDistributionPointTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a CRL distribution point with no elements created using the
   * constructor that takes a full name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoElementsWithNullFullName()
         throws Exception
  {
    CRLDistributionPoint dp = new CRLDistributionPoint((GeneralNames) null,
         null, null);

    dp = new CRLDistributionPoint(dp.encode());

    assertNull(dp.getFullName());

    assertNull(dp.getNameRelativeToCRLIssuer());

    assertNotNull(dp.getPotentialRevocationReasons());
    assertFalse(dp.getPotentialRevocationReasons().isEmpty());
    assertEquals(dp.getPotentialRevocationReasons(),
         EnumSet.allOf(CRLDistributionPointRevocationReason.class));

    assertNull(dp.getCRLIssuer());

    assertNotNull(dp.toString());
  }



  /**
   * Tests a CRL distribution point with no elements created using the
   * constructor that takes an RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoElementsWithNullRDN()
         throws Exception
  {
    CRLDistributionPoint dp = new CRLDistributionPoint((RDN) null,
         null, null);

    dp = new CRLDistributionPoint(dp.encode());

    assertNull(dp.getFullName());

    assertNull(dp.getNameRelativeToCRLIssuer());

    assertNotNull(dp.getPotentialRevocationReasons());
    assertFalse(dp.getPotentialRevocationReasons().isEmpty());
    assertEquals(dp.getPotentialRevocationReasons(),
         EnumSet.allOf(CRLDistributionPointRevocationReason.class));

    assertNull(dp.getCRLIssuer());

    assertNotNull(dp.toString());
  }



  /**
   * Tests a CRL distribution point with all elements, using the full name
   * variant of the constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsWithFullName()
         throws Exception
  {
    final GeneralNames fullName = new GeneralNamesBuilder().addDNSName(
         "full.name.example.com").build();
    final GeneralNames crlIssuer = new GeneralNamesBuilder().addDNSName(
         "crl.issuer.example.com").build();

    CRLDistributionPoint dp = new CRLDistributionPoint(fullName,
         EnumSet.of(CRLDistributionPointRevocationReason.KEY_COMPROMISE),
         crlIssuer);

    dp = new CRLDistributionPoint(dp.encode());

    assertNotNull(dp.getFullName());
    assertEquals(dp.getFullName().getDNSNames().get(0),
         "full.name.example.com");

    assertNull(dp.getNameRelativeToCRLIssuer());

    assertNotNull(dp.getPotentialRevocationReasons());
    assertFalse(dp.getPotentialRevocationReasons().isEmpty());
    assertEquals(dp.getPotentialRevocationReasons(),
         EnumSet.of(CRLDistributionPointRevocationReason.KEY_COMPROMISE));

    assertNotNull(dp.getCRLIssuer());
    assertEquals(dp.getCRLIssuer().getDNSNames().get(0),
         "crl.issuer.example.com");

    assertNotNull(dp.toString());
  }



  /**
   * Tests a CRL distribution point with no elements created using the
   * constructor that takes an RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsWithNullRDN()
         throws Exception
  {
    final RDN nameRelativeToIssuer = new RDN("CN=ldap.example.com");
    final GeneralNames crlIssuer = new GeneralNamesBuilder().addDirectoryName(
         new DN("ou=Issuer,o=Example Corp,C=US")).build();

    CRLDistributionPoint dp = new CRLDistributionPoint(nameRelativeToIssuer,
         EnumSet.of(
              CRLDistributionPointRevocationReason.KEY_COMPROMISE,
              CRLDistributionPointRevocationReason.CA_COMPROMISE,
              CRLDistributionPointRevocationReason.AA_COMPROMISE),
         crlIssuer);

    dp = new CRLDistributionPoint(dp.encode());

    assertNull(dp.getFullName());

    assertNotNull(dp.getNameRelativeToCRLIssuer());
    assertEquals(dp.getNameRelativeToCRLIssuer(), nameRelativeToIssuer);

    assertNotNull(dp.getPotentialRevocationReasons());
    assertFalse(dp.getPotentialRevocationReasons().isEmpty());
    assertEquals(dp.getPotentialRevocationReasons(),
         EnumSet.of(
              CRLDistributionPointRevocationReason.KEY_COMPROMISE,
              CRLDistributionPointRevocationReason.CA_COMPROMISE,
              CRLDistributionPointRevocationReason.AA_COMPROMISE));

    assertNotNull(dp.getCRLIssuer());
    assertEquals(dp.getCRLIssuer().getDirectoryNames().get(0),
         new DN("OU=Issuer,O=Example Corp,C=US"));

    assertNotNull(dp.toString());
  }



  /**
   * Tests the behavior when trying to encode a distribution point with a
   * malformed general names object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeGeneralNamesNotValid()
         throws Exception
  {
    new CRLDistributionPoint(
         new GeneralNamesBuilder().addRegisteredID(new OID("1234.567")).build(),
         null, null).encode();
  }



  /**
   * Tests the behavior when trying to encode a distribution point with a
   * malformed general names object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeRDNWithUndefinedAttributeType()
         throws Exception
  {
    new CRLDistributionPoint(
         new RDN("undefinedAttributeType", "value"),
         null, null).encode();
  }



  /**
   * Tests the behavior when trying to decode a malformed element as a CRL
   * distribution point.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeElementNotSequence()
         throws Exception
  {
    new CRLDistributionPoint(new ASN1OctetString("not a valid sequence"));
  }



  /**
   * Tests the behavior when trying to decode a an element with an unrecognized
   * distribution point element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeUnrecognizedDistributionPointElementType()
         throws Exception
  {
    final ASN1Sequence dpSequence = new ASN1Sequence(
         new ASN1Element((byte) 0xA0,
             new ASN1OctetString((byte) 0xAF, "foo").encode()));
    new CRLDistributionPoint(dpSequence);
  }
}
