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

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of unit tests for the
 * IntermediateClientResponseValue class.
 */
public class IntermediateClientResponseValueTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor with all elements set to non-{@code null} values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllNotNull()
         throws Exception
  {
    IntermediateClientResponseValue upstreamResponse =
         new IntermediateClientResponseValue(null, null, null,
                  "directory server", "conn=123", "op=456");

    upstreamResponse =
         IntermediateClientResponseValue.decode(upstreamResponse.encode());

    assertNotNull(upstreamResponse);

    assertNull(upstreamResponse.getUpstreamResponse());

    assertNull(upstreamResponse.getUpstreamServerAddress());

    assertNull(upstreamResponse.upstreamServerSecure());

    assertNotNull(upstreamResponse.getServerName());
    assertEquals(upstreamResponse.getServerName(), "directory server");

    assertNotNull(upstreamResponse.getServerSessionID());
    assertEquals(upstreamResponse.getServerSessionID(), "conn=123");

    assertNotNull(upstreamResponse.getServerResponseID());
    assertEquals(upstreamResponse.getServerResponseID(), "op=456");

    assertNotNull(upstreamResponse.toString());


    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(upstreamResponse, "1.2.3.4", true,
                                             "directory proxy server",
                                             "conn=789", "op=987");

    v = IntermediateClientResponseValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getUpstreamResponse());
    assertEquals(v.getUpstreamResponse(), upstreamResponse);
    assertEquals(v.getUpstreamResponse().hashCode(),
                 upstreamResponse.hashCode());

    assertNotNull(v.getUpstreamServerAddress());
    assertEquals(v.getUpstreamServerAddress(), "1.2.3.4");

    assertNotNull(v.upstreamServerSecure());
    assertEquals(v.upstreamServerSecure(), Boolean.TRUE);

    assertNotNull(v.getServerName());
    assertEquals(v.getServerName(), "directory proxy server");

    assertNotNull(v.getServerSessionID());
    assertEquals(v.getServerSessionID(), "conn=789");

    assertNotNull(v.getServerResponseID());
    assertEquals(v.getServerResponseID(), "op=987");

    assertNotNull(v.toString());
  }



  /**
   * Tests the constructor with multiple levels of wrapping.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorMultipleWraps()
         throws Exception
  {
    IntermediateClientResponseValue ultimateResponse =
         new IntermediateClientResponseValue(null, null, null,
                  "directory server", "conn=123", "op=456");

    ultimateResponse =
         IntermediateClientResponseValue.decode(ultimateResponse.encode());

    assertNotNull(ultimateResponse);

    assertNull(ultimateResponse.getUpstreamResponse());

    assertNull(ultimateResponse.getUpstreamServerAddress());

    assertNull(ultimateResponse.upstreamServerSecure());

    assertNotNull(ultimateResponse.getServerName());
    assertEquals(ultimateResponse.getServerName(), "directory server");

    assertNotNull(ultimateResponse.getServerSessionID());
    assertEquals(ultimateResponse.getServerSessionID(), "conn=123");

    assertNotNull(ultimateResponse.getServerResponseID());
    assertEquals(ultimateResponse.getServerResponseID(), "op=456");

    assertNotNull(ultimateResponse.toString());


    IntermediateClientResponseValue upstreamResponse =
         new IntermediateClientResponseValue(ultimateResponse, "1.2.3.4", true,
                                             "directory proxy server",
                                             "conn=789", "op=987");

    upstreamResponse =
         IntermediateClientResponseValue.decode(upstreamResponse.encode());

    assertNotNull(upstreamResponse);

    assertNotNull(upstreamResponse.getUpstreamResponse());
    assertEquals(upstreamResponse.getUpstreamResponse(), ultimateResponse);
    assertEquals(upstreamResponse.getUpstreamResponse().hashCode(),
                 ultimateResponse.hashCode());

    assertNotNull(upstreamResponse.getUpstreamServerAddress());
    assertEquals(upstreamResponse.getUpstreamServerAddress(), "1.2.3.4");

    assertNotNull(upstreamResponse.upstreamServerSecure());
    assertEquals(upstreamResponse.upstreamServerSecure(), Boolean.TRUE);

    assertNotNull(upstreamResponse.getServerName());
    assertEquals(upstreamResponse.getServerName(), "directory proxy server");

    assertNotNull(upstreamResponse.getServerSessionID());
    assertEquals(upstreamResponse.getServerSessionID(), "conn=789");

    assertNotNull(upstreamResponse.getServerResponseID());
    assertEquals(upstreamResponse.getServerResponseID(), "op=987");

    assertNotNull(upstreamResponse.toString());


    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(upstreamResponse, "1.2.3.3", true,
                                             "directory-enabled app",
                                             "session-id", "response-id");

    v = IntermediateClientResponseValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getUpstreamResponse());
    assertEquals(v.getUpstreamResponse(), upstreamResponse);
    assertEquals(v.getUpstreamResponse().hashCode(),
                 upstreamResponse.hashCode());

    assertNotNull(v.getUpstreamServerAddress());
    assertEquals(v.getUpstreamServerAddress(), "1.2.3.3");

    assertNotNull(v.upstreamServerSecure());
    assertEquals(v.upstreamServerSecure(), Boolean.TRUE);

    assertNotNull(v.getServerName());
    assertEquals(v.getServerName(), "directory-enabled app");

    assertNotNull(v.getServerSessionID());
    assertEquals(v.getServerSessionID(), "session-id");

    assertNotNull(v.getServerResponseID());
    assertEquals(v.getServerResponseID(), "response-id");

    assertNotNull(v.toString());
  }



  /**
   * Tests the constructor with all elements set to {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllNull()
         throws Exception
  {
    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(null, null, null, null, null,
                                             null);

    v = IntermediateClientResponseValue.decode(v.encode());

    assertNotNull(v);

    assertNull(v.getUpstreamResponse());

    assertNull(v.getUpstreamServerAddress());

    assertNull(v.upstreamServerSecure());

    assertNull(v.getServerName());

    assertNull(v.getServerSessionID());

    assertNull(v.getServerResponseID());

    assertNotNull(v.toString());
  }



  /**
   * Tests the {@code decode} method with an element containing an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidType()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Element((byte) 0x00, new byte[0])
    };

    IntermediateClientResponseValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method with an element containing an invalid
   * upstream response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidUpstreamResponse()
         throws Exception
  {
    ASN1Element[] downstreamElements =
    {
      new ASN1Element((byte) 0x00, new byte[0])
    };

    ASN1Element[] elements =
    {
      new ASN1Sequence((byte) 0xA0, downstreamElements)
    };

    IntermediateClientResponseValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method with an element containing an upstream
   * response that is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeUpstreamResponseNotSequence()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Element((byte) 0xA0, new byte[1])
    };

    IntermediateClientResponseValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method with an element containing an invalid
   * upstream server secure value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidUpstreamServerSecure()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Element((byte) 0x82, new byte[0])
    };

    IntermediateClientResponseValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code equals} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    IntermediateClientResponseValue v = new IntermediateClientResponseValue(
         null, null, null, null, null, null);

    assertFalse(v.equals(null));
  }



  /**
   * Tests the {@code equals} method with the same object instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSameInstance()
         throws Exception
  {
    IntermediateClientResponseValue v = new IntermediateClientResponseValue(
         null, null, null, null, null, null);

    assertTrue(v.equals(v));
  }



  /**
   * Tests the {@code equals} method with an object that is not an intermediate
   * client response value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotRightType()
         throws Exception
  {
    IntermediateClientResponseValue v = new IntermediateClientResponseValue(
         null, null, null, null, null, null);

    assertFalse(v.equals("foo"));
  }



  /**
   * Tests the {@code equals} method with various types of intermediate client
   * response values that don't match where most of the elements are
   * {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonMatchingMostNull()
         throws Exception
  {
    IntermediateClientResponseValue v = new IntermediateClientResponseValue(
         null, null, null, null, null, null);

    assertFalse(v.equals(new IntermediateClientResponseValue(v, null, null,
         null, null, null)));

    assertFalse(v.equals(new IntermediateClientResponseValue(null, "1.2.3.4",
         null, null, null, null)));

    assertFalse(v.equals(new IntermediateClientResponseValue(null, null, true,
         null, null, null)));

    assertFalse(v.equals(new IntermediateClientResponseValue(null, null, null,
         "server name", null, null)));

    assertFalse(v.equals(new IntermediateClientResponseValue(null, null, null,
         null, "session-id", null)));

    assertFalse(v.equals(new IntermediateClientResponseValue(null, null, null,
         null, null, "response-id")));
  }



  /**
   * Tests the {@code equals} method with various types of intermediate client
   * response values that don't match where the elements are not {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonMatchingNotNull()
         throws Exception
  {
    IntermediateClientResponseValue wrapped =
         new IntermediateClientResponseValue(null, null, null, null, null,
                                             null);
    IntermediateClientResponseValue v =
         new IntermediateClientResponseValue(wrapped, "1.2.3.4", true,
                  "server-name", "session-id", "response-id");

    assertFalse(v.equals(new IntermediateClientResponseValue(v, "1.2.3.4",
         true, "server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(null, "1.2.3.4",
         true, "server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.5",
         true, "server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, null,
         true, "server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         false, "server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         null, "server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         true, "different-server-name", "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         true, null, "session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         true, "server-name", "different-session-id", "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         true, "server-name", null, "response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         true, "server-name", "session-id", "different-response-id")));

    assertFalse(v.equals(new IntermediateClientResponseValue(wrapped, "1.2.3.4",
         true, "server-name", "session-id", null)));
  }
}
