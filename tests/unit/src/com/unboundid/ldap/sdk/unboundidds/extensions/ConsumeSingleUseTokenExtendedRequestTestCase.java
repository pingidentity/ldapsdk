/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ConsumeSingleUseTokenExtendedRequest} class.
 */
public final class ConsumeSingleUseTokenExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the request without controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutControls()
         throws Exception
  {
    ConsumeSingleUseTokenExtendedRequest r =
         new ConsumeSingleUseTokenExtendedRequest(
              "uid=test.user,dc=example,dc=com", "tokenID", "tokenValue");

    r = new ConsumeSingleUseTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.51");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=test.user,dc=example,dc=com");

    assertNotNull(r.getTokenID());
    assertEquals(r.getTokenID(), "tokenID");

    assertNotNull(r.getTokenValue());
    assertEquals(r.getTokenValue(), "tokenValue");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the request with controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithControls()
         throws Exception
  {
    ConsumeSingleUseTokenExtendedRequest r =
         new ConsumeSingleUseTokenExtendedRequest(
              "uid=different.user,dc=example,dc=com", "differentTokenID",
              "differentTokenValue", new Control("1.2.3.4"),
              new Control("5.6.7.8"));

    r = new ConsumeSingleUseTokenExtendedRequest(r.duplicate());

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.51");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getUserDN());
    assertDNsEqual(r.getUserDN(), "uid=different.user,dc=example,dc=com");

    assertNotNull(r.getTokenID());
    assertEquals(r.getTokenID(), "differentTokenID");

    assertNotNull(r.getTokenValue());
    assertEquals(r.getTokenValue(), "differentTokenValue");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode an extended request that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new ConsumeSingleUseTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.51", (ASN1OctetString) null));
  }



  /**
   * Tests the behavior when trying to decode an extended request with a
   * value that cannot be decoded as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new ConsumeSingleUseTokenExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.51", new ASN1OctetString("not a sequence")));
  }
}
