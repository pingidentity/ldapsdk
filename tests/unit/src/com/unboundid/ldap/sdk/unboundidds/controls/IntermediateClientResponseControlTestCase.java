/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of unit tests for the
 * IntermediateClientResponseControl class.
 */
public class IntermediateClientResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with all non-{@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1NonNull()
         throws Exception
  {
    IntermediateClientResponseValue upstreamResponse =
         new IntermediateClientResponseValue(null, null, null,
                  "directory server", "conn=123", "op=456");

    IntermediateClientResponseControl c =
         new IntermediateClientResponseControl(upstreamResponse, "1.2.3.4",
                  true, "directory proxy server", "conn=789", "op=987");

    c = new IntermediateClientResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getResponseValue());

    assertNotNull(c.getUpstreamResponse());
    assertEquals(c.getUpstreamResponse(), upstreamResponse);

    assertNotNull(c.getUpstreamServerAddress());
    assertEquals(c.getUpstreamServerAddress(), "1.2.3.4");

    assertNotNull(c.upstreamServerSecure());
    assertEquals(c.upstreamServerSecure(), Boolean.TRUE);

    assertNotNull(c.getServerName());
    assertEquals(c.getServerName(), "directory proxy server");

    assertNotNull(c.getServerSessionID());
    assertEquals(c.getServerSessionID(), "conn=789");

    assertNotNull(c.getServerResponseID());
    assertEquals(c.getServerResponseID(), "op=987");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the first constructor with all {@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Null()
         throws Exception
  {
    IntermediateClientResponseControl c =
         new IntermediateClientResponseControl(null, null, null, null, null,
                                               null);

    c = new IntermediateClientResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getResponseValue());

    assertNull(c.getUpstreamResponse());

    assertNull(c.getUpstreamServerAddress());

    assertNull(c.upstreamServerSecure());

    assertNull(c.getServerName());

    assertNull(c.getServerSessionID());

    assertNull(c.getServerResponseID());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a response value containing all
   * non-{@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NonNullElements()
         throws Exception
  {
    IntermediateClientResponseValue upstreamResponse =
         new IntermediateClientResponseValue(null, null, null,
                  "directory server", "conn=123", "op=456");

    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(upstreamResponse, "1.2.3.4",
                  true, "directory proxy server", "conn=789", "op=987");

    IntermediateClientResponseControl c =
         new IntermediateClientResponseControl(v);

    c = new IntermediateClientResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getResponseValue());
    assertEquals(c.getResponseValue(), v);

    assertNotNull(c.getUpstreamResponse());
    assertEquals(c.getUpstreamResponse(), upstreamResponse);

    assertNotNull(c.getUpstreamServerAddress());
    assertEquals(c.getUpstreamServerAddress(), "1.2.3.4");

    assertNotNull(c.upstreamServerSecure());
    assertEquals(c.upstreamServerSecure(), Boolean.TRUE);

    assertNotNull(c.getServerName());
    assertEquals(c.getServerName(), "directory proxy server");

    assertNotNull(c.getServerSessionID());
    assertEquals(c.getServerSessionID(), "conn=789");

    assertNotNull(c.getServerResponseID());
    assertEquals(c.getServerResponseID(), "op=987");

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the second constructor with a response value containing all
   * {@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullElements()
         throws Exception
  {
    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(null, null, null, null, null,
                                             null);

    IntermediateClientResponseControl c =
         new IntermediateClientResponseControl(v);

    c = new IntermediateClientResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertFalse(c.isCritical());

    assertNotNull(c.getResponseValue());
    assertEquals(c.getResponseValue(), v);

    assertNull(c.getUpstreamResponse());

    assertNull(c.getUpstreamServerAddress());

    assertNull(c.upstreamServerSecure());

    assertNull(c.getServerName());

    assertNull(c.getServerSessionID());

    assertNull(c.getServerResponseID());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the third constructor with a response value containing all
   * {@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullElements()
         throws Exception
  {
    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(null, null, null, null, null,
                                             null);

    IntermediateClientResponseControl c =
         new IntermediateClientResponseControl(true, v);

    c = new IntermediateClientResponseControl().decodeControl(
                 c.getOID(), c.isCritical(), c.getValue());

    assertNotNull(c);

    assertTrue(c.isCritical());

    assertNotNull(c.getResponseValue());
    assertEquals(c.getResponseValue(), v);

    assertNull(c.getUpstreamResponse());

    assertNull(c.getUpstreamServerAddress());

    assertNull(c.upstreamServerSecure());

    assertNull(c.getServerName());

    assertNull(c.getServerSessionID());

    assertNull(c.getServerResponseID());

    assertNotNull(c.getControlName());
    assertNotNull(c.toString());
  }



  /**
   * Tests the {@code decodeControl} method with a control that doesn't have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlNoValue()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.2");

    new IntermediateClientResponseControl().decodeControl(c.getOID(),
             c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code decodeControl} method with a control that has an invalid
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlInvalidValue()
         throws Exception
  {
    Control c = new Control("1.3.6.1.4.1.30221.2.5.2", false,
                            new ASN1OctetString(new byte[1]));

    new IntermediateClientResponseControl().decodeControl(c.getOID(),
             c.isCritical(), c.getValue());
  }



  /**
   * Tests the {@code get} method with a result that does not contain an
   * intermediate client response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);

    final IntermediateClientResponseControl c =
         IntermediateClientResponseControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new IntermediateClientResponseControl(null, null, null, "test", "conn=1",
           "op=2")
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final IntermediateClientResponseControl c =
         IntermediateClientResponseControl.get(r);
    assertNotNull(c);

    assertNull(c.getUpstreamResponse());

    assertEquals(c.getServerName(), "test");

    assertEquals(c.getServerSessionID(), "conn=1");

    assertEquals(c.getServerResponseID(), "op=2");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as an intermediate client
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp = new IntermediateClientResponseControl(null, null, null,
         "test", "conn=1", "op=2");

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final IntermediateClientResponseControl c =
         IntermediateClientResponseControl.get(r);
    assertNotNull(c);

    assertNull(c.getUpstreamResponse());

    assertEquals(c.getServerName(), "test");

    assertEquals(c.getServerSessionID(), "conn=1");

    assertEquals(c.getServerResponseID(), "op=2");
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as an intermediate client
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(
           IntermediateClientResponseControl.INTERMEDIATE_CLIENT_RESPONSE_OID,
           false, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    IntermediateClientResponseControl.get(r);
  }
}
