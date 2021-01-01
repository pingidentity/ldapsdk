/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the deregister YubiKey OTP device
 * extended request.
 */
public final class DeregisterYubiKeyOTPDeviceExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the extended request when none of the optional
   * arguments are given.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyRequest()
         throws Exception
  {
    DeregisterYubiKeyOTPDeviceExtendedRequest r =
         new DeregisterYubiKeyOTPDeviceExtendedRequest(null, null);

    r = r.duplicate();
    assertNotNull(r);

    r = new DeregisterYubiKeyOTPDeviceExtendedRequest(r);
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.55");

    assertNull(r.getAuthenticationID());

    assertNull(r.getStaticPasswordString());

    assertNull(r.getStaticPasswordBytes());

    assertNull(r.getYubiKeyOTP());

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request when all of the optional
   * arguments are given and the static password is given as a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullRequestStringPassword()
         throws Exception
  {
    DeregisterYubiKeyOTPDeviceExtendedRequest r =
         new DeregisterYubiKeyOTPDeviceExtendedRequest("u:authid",
              "passwordString", "YubiKeyOTP",
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = r.duplicate();
    assertNotNull(r);

    r = new DeregisterYubiKeyOTPDeviceExtendedRequest(r);
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.55");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:authid");

    assertNotNull(r.getStaticPasswordString());
    assertEquals(r.getStaticPasswordString(), "passwordString");

    assertNotNull(r.getStaticPasswordBytes());
    assertEquals(r.getStaticPasswordBytes(),
         "passwordString".getBytes("UTF-8"));

    assertNotNull(r.getYubiKeyOTP());
    assertEquals(r.getYubiKeyOTP(), "YubiKeyOTP");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the extended request when all of the optional
   * arguments are given and the static password is given as a byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullRequestByteArrayPassword()
         throws Exception
  {
    DeregisterYubiKeyOTPDeviceExtendedRequest r =
         new DeregisterYubiKeyOTPDeviceExtendedRequest("u:authid",
              "passwordBytes".getBytes("UTF-8"), "YubiKeyOTP",
              new Control("1.2.3.4"), new Control("1.2.3.5"));

    r = r.duplicate();
    assertNotNull(r);

    r = new DeregisterYubiKeyOTPDeviceExtendedRequest(r);
    assertNotNull(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.55");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "u:authid");

    assertNotNull(r.getStaticPasswordString());
    assertEquals(r.getStaticPasswordString(), "passwordBytes");

    assertNotNull(r.getStaticPasswordBytes());
    assertEquals(r.getStaticPasswordBytes(),
         "passwordBytes".getBytes("UTF-8"));

    assertNotNull(r.getYubiKeyOTP());
    assertEquals(r.getYubiKeyOTP(), "YubiKeyOTP");

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a request that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new DeregisterYubiKeyOTPDeviceExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.55"));
  }



  /**
   * Tests the behavior when trying to decode a request that has a malformed
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedValue()
         throws Exception
  {
    new DeregisterYubiKeyOTPDeviceExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.55", new ASN1OctetString("malformed")));
  }



  /**
   * Tests the behavior when trying to decode a request that has a value with
   * an unrecognized element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUnrecognizedValueElementType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x00, "Unrecognized Type"));
    new DeregisterYubiKeyOTPDeviceExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.55",
         new ASN1OctetString(valueSequence.encode())));
  }
}
