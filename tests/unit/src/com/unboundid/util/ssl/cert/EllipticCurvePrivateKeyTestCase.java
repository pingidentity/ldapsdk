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

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.OID;



/**
 * This class provides a set of test cases for the EllipticCurvePrivateKey
 * class.
 */
public final class EllipticCurvePrivateKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a private key with the minimum set of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalElements()
         throws Exception
  {
    EllipticCurvePrivateKey privateKey = new EllipticCurvePrivateKey(1,
         new byte[32], null, null);

    privateKey = new EllipticCurvePrivateKey(privateKey.encode());

    assertEquals(privateKey.getVersion(), 1);

    assertNotNull(privateKey.getPrivateKeyBytes());
    assertEquals(privateKey.getPrivateKeyBytes(), new byte[32]);

    assertNull(privateKey.getNamedCurveOID());

    assertNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());
  }



  /**
   * Tests a private key with all elements and a public key size that is a
   * multiple of eight bits.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsWithPublicKeyMultipleOfEightBits()
         throws Exception
  {
    EllipticCurvePrivateKey privateKey = new EllipticCurvePrivateKey(1,
         new byte[32], NamedCurve.SECP256R1.getOID(),
         new ASN1BitString(new boolean[256]));

    privateKey = new EllipticCurvePrivateKey(privateKey.encode());

    assertEquals(privateKey.getVersion(), 1);

    assertNotNull(privateKey.getPrivateKeyBytes());
    assertEquals(privateKey.getPrivateKeyBytes(), new byte[32]);

    assertNotNull(privateKey.getNamedCurveOID());
    assertEquals(privateKey.getNamedCurveOID(), NamedCurve.SECP256R1.getOID());

    assertNotNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());
  }



  /**
   * Tests a private key with all elements and a public key size that is not a
   * multiple of eight bits.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElementsWithPublicKeyNotMultipleOfEightBits()
         throws Exception
  {
    EllipticCurvePrivateKey privateKey = new EllipticCurvePrivateKey(1,
         new byte[32], NamedCurve.SECP256R1.getOID(),
         new ASN1BitString(new boolean[25]));

    privateKey = new EllipticCurvePrivateKey(privateKey.encode());

    assertEquals(privateKey.getVersion(), 1);

    assertNotNull(privateKey.getPrivateKeyBytes());
    assertEquals(privateKey.getPrivateKeyBytes(), new byte[32]);

    assertNotNull(privateKey.getNamedCurveOID());
    assertEquals(privateKey.getNamedCurveOID(), NamedCurve.SECP256R1.getOID());

    assertNotNull(privateKey.getPublicKey());

    assertNotNull(privateKey.toString());
  }



  /**
   * Tests the behavior when trying to encode a private key with an invalid
   * named curve OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class  })
  public void testEncodeInvalidNamedCurveOID()
         throws Exception
  {
    new EllipticCurvePrivateKey(1, new byte[32], new OID("1234.5678"),
         null).encode();
  }



  /**
   * Tests the behavior when trying to decode a private key from an octet string
   * whose value is not a valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class  })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new EllipticCurvePrivateKey(new ASN1OctetString("not a valid sequence"));
  }



  /**
   * Tests the behavior when trying to decode a private key with an invalid
   * version number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class  })
  public void testDecodeUnsupportedVersion()
         throws Exception
  {
    final EllipticCurvePrivateKey key = new EllipticCurvePrivateKey(999,
        new byte[32], null, null);
    new EllipticCurvePrivateKey(key.encode());
  }
}
