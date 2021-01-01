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



import java.math.BigInteger;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the RSAPublicKey class.
 */
public final class RSAPublicKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid RSA public key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidPublicKey()
         throws Exception
  {
    final byte[] modulusBytes = new byte[256];
    modulusBytes[0] = 0x40;
    modulusBytes[255] = 0x01;
    final BigInteger modulus = new BigInteger(modulusBytes);

    final BigInteger exponent = BigInteger.valueOf(65537L);

    RSAPublicKey publicKey = new RSAPublicKey(modulus, exponent);

    publicKey = new RSAPublicKey(publicKey.encode());

    assertNotNull(publicKey.getModulus());
    assertEquals(publicKey.getModulus(), modulus);

    assertNotNull(publicKey.getPublicExponent());
    assertEquals(publicKey.getPublicExponent(), exponent);

    assertNotNull(publicKey.toString());
  }



  /**
   * Tests the behavior when trying to decode a malformed bit string as an RSA
   * public key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeMalformedBitString()
         throws Exception
  {
    new RSAPublicKey(new ASN1BitString(false));
  }
}
