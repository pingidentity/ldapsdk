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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the {@code JNDIExtendedResponse} class.
 */
public class JNDIExtendedResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a JNDI extended response created from an SDK
   * extended result with neither an OID nor value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromSDKResultWithooutOIDWithoutValue()
         throws Exception
  {
    ExtendedResult result = new ExtendedResult(-1, ResultCode.SUCCESS, null,
         null, null, null, null, null);
    JNDIExtendedResponse r = new JNDIExtendedResponse(result);

    assertNotNull(r);

    assertNull(r.getID());

    assertNull(r.getEncodedValue());

    assertNotNull(r.toSDKExtendedResult());

    assertNotNull(JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse(null, null, 0, 0)));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended response created from an SDK
   * extended result with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromSDKResultWithOIDWithoutValue()
         throws Exception
  {
    ExtendedResult result = new ExtendedResult(-1, ResultCode.SUCCESS, null,
         null, null, "1.2.3.4", null, null);
    JNDIExtendedResponse r = new JNDIExtendedResponse(result);

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNull(r.getEncodedValue());

    assertNotNull(r.toSDKExtendedResult());

    assertNotNull(JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse(null, null, 0, 0)));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended response created from an SDK
   * extended result with an OID and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromSDKResultWithOIDWithValue()
         throws Exception
  {
    ExtendedResult result = new ExtendedResult(-1, ResultCode.SUCCESS, null,
         null, null, "1.2.3.4", new ASN1OctetString("foo"), null);
    JNDIExtendedResponse r = new JNDIExtendedResponse(result);

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNotNull(r.getEncodedValue());
    assertTrue(Arrays.equals(r.getEncodedValue(),
         new ASN1OctetString("foo").encode()));

    assertNotNull(r.toSDKExtendedResult());

    assertNotNull(JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse(null, null, 0, 0)));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended response created from a JNDI
   * extended response with neither an OID nor value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromJNDIResponseWithooutOIDWithoutValue()
         throws Exception
  {
    JNDIExtendedResponse r = new JNDIExtendedResponse(new TestExtendedResponse(
         null, null, 0, 0));

    assertNotNull(r);

    assertNull(r.getID());

    assertNull(r.getEncodedValue());

    assertNotNull(r.toSDKExtendedResult());

    assertNotNull(JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse(null, null, 0, 0)));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended response created from an SDK
   * extended result with an OID but no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromJNDIResponseWithOIDWithoutValue()
         throws Exception
  {
    JNDIExtendedResponse r = new JNDIExtendedResponse(new TestExtendedResponse(
         "1.2.3.4", null, 0, 0));

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNull(r.getEncodedValue());

    assertNotNull(r.toSDKExtendedResult());

    assertNotNull(JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse(null, null, 0, 0)));

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a JNDI extended response created from an SDK
   * extended result with an OID and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromJNDIResponseWithOIDWithValue()
         throws Exception
  {
    byte[] valueBytes = new ASN1OctetString("foo").encode();
    JNDIExtendedResponse r = new JNDIExtendedResponse(new TestExtendedResponse(
         "1.2.3.4", valueBytes, 0, valueBytes.length));

    assertNotNull(r);

    assertNotNull(r.getID());
    assertEquals(r.getID(), "1.2.3.4");

    assertNotNull(r.getEncodedValue());
    assertTrue(Arrays.equals(r.getEncodedValue(),
         new ASN1OctetString("foo").encode()));

    assertNotNull(r.toSDKExtendedResult());

    assertNotNull(JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse(null, null, 0, 0)));

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to convert a response with a malformed
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NamingException.class })
  public void testConvertWithMalformedValue()
         throws Exception
  {
    byte[] malformedValue = new byte[] { (byte) 0x01 };
    JNDIExtendedResponse.toSDKExtendedResult(
         new TestExtendedResponse("1.2.3.4", malformedValue, 0, 1));
  }



  /**
   * Tests the behavior when trying to convert a {@code null} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConvertNullResult()
         throws Exception
  {
    assertNull(JNDIExtendedResponse.toSDKExtendedResult(null));
  }
}
