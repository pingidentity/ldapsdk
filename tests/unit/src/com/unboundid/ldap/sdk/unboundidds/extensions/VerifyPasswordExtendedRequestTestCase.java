/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of unit tests for the verify password extended
 * request.
 */
public final class VerifyPasswordExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a valid instance of the request without any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRequestWithoutControls()
         throws Exception
  {
    final String uid = UUID.randomUUID().toString();
    final String dn = "uid=" + uid + ",ou=People,dc=example,dc=com";

    final String password = UUID.randomUUID().toString();

    VerifyPasswordExtendedRequest r =
         new VerifyPasswordExtendedRequest(dn, password);
    r = new VerifyPasswordExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.72");

    assertNotNull(r.getValue());

    final JSONObject valueObject = new JSONObject(r.getValue().stringValue());
    assertNotNull(valueObject);
    assertEquals(valueObject,
         new JSONObject(
              new JSONField("dn", dn),
              new JSONField("password", password)));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), dn);

    assertNotNull(r.getPassword());
    assertEquals(r.getPassword(), password);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests a valid instance of the request that includes controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRequestWithControls()
         throws Exception
  {
    final String uid = UUID.randomUUID().toString();
    final String dn = "uid=" + uid + ",ou=People,dc=example,dc=com";

    final String password = UUID.randomUUID().toString();

    VerifyPasswordExtendedRequest r =
         new VerifyPasswordExtendedRequest(dn, password,
              new Control("1.2.3.4"),
              new Control("1.2.3.5", true, new ASN1OctetString("foo")));
    r = new VerifyPasswordExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.30221.2.6.72");

    assertNotNull(r.getValue());

    final JSONObject valueObject = new JSONObject(r.getValue().stringValue());
    assertNotNull(valueObject);
    assertEquals(valueObject,
         new JSONObject(
              new JSONField("dn", dn),
              new JSONField("password", password)));

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);
    assertNotNull(r.getControl("1.2.3.4"));
    assertNotNull(r.getControl("1.2.3.5"));

    assertNotNull(r.getDN());
    assertEquals(r.getDN(), dn);

    assertNotNull(r.getPassword());
    assertEquals(r.getPassword(), password);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when attempting to decode a generic extended request
   * that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestWithoutValue()
         throws Exception
  {
    try
    {
      new VerifyPasswordExtendedRequest(
           new ExtendedRequest("1.3.6.1.4.1.30221.2.6.72"));
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when attempting to decode a generic extended request
   * that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestValueNotJSON()
         throws Exception
  {
    try
    {
      new VerifyPasswordExtendedRequest(
           new ExtendedRequest("1.3.6.1.4.1.30221.2.6.72",
                new ASN1OctetString("this-is-not-a-json-object")));
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when attempting to decode a generic extended request
   * whose value is a JSON object that is missing the required "dn" field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestValueMissingDN()
         throws Exception
  {
    try
    {
      new VerifyPasswordExtendedRequest(
           new ExtendedRequest("1.3.6.1.4.1.30221.2.6.72",
                new ASN1OctetString(
                     new JSONObject(
                          new JSONField("password",
                               "the-password")).toSingleLineString())));
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when attempting to decode a generic extended request
   * whose value is a JSON object that is has an empty "dn" field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestValueEmptyDN()
         throws Exception
  {
    try
    {
      new VerifyPasswordExtendedRequest(
           new ExtendedRequest("1.3.6.1.4.1.30221.2.6.72",
                new ASN1OctetString(
                     new JSONObject(
                          new JSONField("dn", ""),
                          new JSONField("password",
                               "the-password")).toSingleLineString())));
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when attempting to decode a generic extended request
   * whose value is a JSON object that is missing the required "password" field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestValueMissingPassword()
         throws Exception
  {
    try
    {
      new VerifyPasswordExtendedRequest(
           new ExtendedRequest("1.3.6.1.4.1.30221.2.6.72",
                new ASN1OctetString(
                     new JSONObject(
                          new JSONField("dn",
                               "uid=x")).toSingleLineString())));
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when attempting to decode a generic extended request
   * whose value is a JSON object that has an empty "password" field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeRequestValueEmptyPassword()
         throws Exception
  {
    try
    {
      new VerifyPasswordExtendedRequest(
           new ExtendedRequest("1.3.6.1.4.1.30221.2.6.72",
                new ASN1OctetString(
                     new JSONObject(
                          new JSONField("dn", "uid=x"),
                          new JSONField("password",
                               "")).toSingleLineString())));
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }
}
