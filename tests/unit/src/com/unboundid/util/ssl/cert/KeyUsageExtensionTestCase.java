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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the KeyUsageExtension class.
 */
public final class KeyUsageExtensionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a key usage extension without any of the bits set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoBitsSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(true, false, false, false,
         false, false, false, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertTrue(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with all of the bits set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllBitsSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, true, true, true, true,
         true, true, true, true, true);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertTrue(e.isDigitalSignatureBitSet());

    assertTrue(e.isNonRepudiationBitSet());

    assertTrue(e.isKeyEnciphermentBitSet());

    assertTrue(e.isDataEnciphermentBitSet());

    assertTrue(e.isKeyAgreementBitSet());

    assertTrue(e.isKeyCertSignBitSet());

    assertTrue(e.isCRLSignBitSet());

    assertTrue(e.isEncipherOnlyBitSet());

    assertTrue(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the digital signature bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyDigitalSignatureBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, true, false, false,
         false, false, false, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertTrue(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the non-repudiation bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyNonRepudiationBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, true, false,
         false, false, false, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertTrue(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the key encipherment bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyKeyEnciphermentBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, true,
         false, false, false, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertTrue(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the data encipherment bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyDataEnciphermentBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, false,
         true, false, false, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertTrue(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the key agreement bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyKeyAgreementBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, false,
         false, true, false, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertTrue(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the key cert sign bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyKeyCertSignBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, false,
         false, false, true, false, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertTrue(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the CRL sign bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyCRLSignBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, false,
         false, false, false, true, false, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertTrue(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the encipher only bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyEncipherOnlyBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, false,
         false, false, false, false, true, false);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertTrue(e.isEncipherOnlyBitSet());

    assertFalse(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests a key usage extension with only the decipher only bit set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyDecipherOnlyBitSet()
         throws Exception
  {
    KeyUsageExtension e = new KeyUsageExtension(false, false, false, false,
         false, false, false, false, false, true);

    e = new KeyUsageExtension(e);

    assertNotNull(e.getOID());
    assertEquals(e.getOID().toString(), "2.5.29.15");

    assertFalse(e.isCritical());

    assertNotNull(e.getValue());

    assertFalse(e.isDigitalSignatureBitSet());

    assertFalse(e.isNonRepudiationBitSet());

    assertFalse(e.isKeyEnciphermentBitSet());

    assertFalse(e.isDataEnciphermentBitSet());

    assertFalse(e.isKeyAgreementBitSet());

    assertFalse(e.isKeyCertSignBitSet());

    assertFalse(e.isCRLSignBitSet());

    assertFalse(e.isEncipherOnlyBitSet());

    assertTrue(e.isDecipherOnlyBitSet());

    assertNotNull(e.getExtensionName());
    assertFalse(e.getExtensionName().equals("2.5.29.15"));

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when trying to decode an extension whose value is not
   * a valid bit string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeValueNotBitString()
         throws Exception
  {
    new KeyUsageExtension(new X509CertificateExtension(new OID("2.5.29.15"),
         false, StaticUtils.NO_BYTES));
  }
}
