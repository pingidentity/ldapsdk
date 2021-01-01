/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.jndi;



import java.util.Arrays;
import javax.naming.NamingException;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code JNDIExtendedRequest} class.
 */
public class JNDIExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a JNDI extended request created from an SDK
   * extended request with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromSDKRequestWithOIDWithoutValue()
         throws Exception
  {
    ExtendedRequest sdkRequest = new ExtendedRequest("1.2.3.4", null, null);
    JNDIExtendedRequest r = new JNDIExtendedRequest(sdkRequest);

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNull(r.getEncodedValue());

    JNDIExtendedResponse resp = r.createExtendedResponse("1.2.3.5", null, 0, 0);
    assertNotNull(resp);
    assertNotNull(resp.getID());
    assertEquals(resp.getID(), "1.2.3.5");
    assertNull(resp.getEncodedValue());

    assertNotNull(r.toSDKExtendedRequest());

    assertNotNull(JNDIExtendedRequest.toSDKExtendedRequest(r));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended request created from an SDK
   * extended request with an OID and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromSDKRequestWithOIDAndValue()
         throws Exception
  {
    ExtendedRequest sdkRequest = new ExtendedRequest("1.2.3.4",
         new ASN1OctetString("foo"));
    JNDIExtendedRequest r = new JNDIExtendedRequest(sdkRequest);

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNotNull(r.getEncodedValue());
    assertTrue(Arrays.equals(r.getEncodedValue(),
         new ASN1OctetString("foo").encode()));

    byte[] valueBytes = new ASN1OctetString("bar").encode();
    JNDIExtendedResponse resp = r.createExtendedResponse("1.2.3.5", valueBytes,
         0, valueBytes.length);
    assertNotNull(resp);
    assertNotNull(resp.getID());
    assertEquals(resp.getID(), "1.2.3.5");
    assertNotNull(resp.getEncodedValue());
    assertTrue(Arrays.equals(resp.getEncodedValue(), valueBytes));

    assertNotNull(r.toSDKExtendedRequest());

    assertNotNull(JNDIExtendedRequest.toSDKExtendedRequest(r));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended request created from a JNDI
   * extended request with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromJNDIRequestWithOIDWithoutValue()
         throws Exception
  {
    JNDIExtendedRequest r =
         new JNDIExtendedRequest(new TestExtendedRequest("1.2.3.4", null));

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNull(r.getEncodedValue());

    byte[] valueBytes = new ASN1OctetString("bar").encode();
    byte[] biggerValueBytes = new byte[valueBytes.length + 5];
    System.arraycopy(valueBytes, 0, biggerValueBytes, 0, valueBytes.length);
    JNDIExtendedResponse resp = r.createExtendedResponse(null, biggerValueBytes,
         0, valueBytes.length);
    assertNotNull(resp);
    assertNull(resp.getID());
    assertNotNull(resp.getEncodedValue());
    assertTrue(Arrays.equals(resp.getEncodedValue(), valueBytes));

    assertNotNull(r.toSDKExtendedRequest());

    assertNotNull(JNDIExtendedRequest.toSDKExtendedRequest(r));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended request created from an SDK
   * extended request with an OID and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromJNDIRequestWithOIDAndValue()
         throws Exception
  {
    JNDIExtendedRequest r = new JNDIExtendedRequest(
         new TestExtendedRequest("1.2.3.4",
              new ASN1OctetString("foo").encode()));

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNotNull(r.getEncodedValue());
    assertTrue(Arrays.equals(r.getEncodedValue(),
         new ASN1OctetString("foo").encode()));

    byte[] valueBytes = new ASN1OctetString("bar").encode();
    byte[] biggerValueBytes = new byte[valueBytes.length + 5];
    System.arraycopy(valueBytes, 0, biggerValueBytes, 5, valueBytes.length);
    JNDIExtendedResponse resp = r.createExtendedResponse("1.2.3.5",
         biggerValueBytes, 5, valueBytes.length);
    assertNotNull(resp);
    assertNotNull(resp.getID());
    assertEquals(resp.getID(), "1.2.3.5");
    assertNotNull(resp.getEncodedValue());
    assertTrue(Arrays.equals(resp.getEncodedValue(), valueBytes));

    assertNotNull(r.toSDKExtendedRequest());

    assertNotNull(JNDIExtendedRequest.toSDKExtendedRequest(r));

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to convert a request with a malformed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NamingException.class })
  public void testConvertWithMalformedValue()
         throws Exception
  {
    byte[] malformedValue = new byte[] { (byte) 0x01 };
    JNDIExtendedRequest.toSDKExtendedRequest(
         new TestExtendedRequest("1.2.3.4", malformedValue));
  }



  /**
   * Tests the behavior when trying to convert a {@code null} request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConvertNullRequest()
         throws Exception
  {
    assertNull(JNDIExtendedRequest.toSDKExtendedRequest(null));
  }
}
