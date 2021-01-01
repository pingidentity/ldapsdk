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
 * IntermediateClientRequestValue class.
 */
public class IntermediateClientRequestValueTestCase
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
    IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(null, "1.2.3.4", true, "u:end-user",
                                            "directory-enabled app",
                                            "webapp-session-id",
                                            "webapp-request-id");

    downstreamRequest =
         IntermediateClientRequestValue.decode(downstreamRequest.encode());

    assertNotNull(downstreamRequest);

    assertNull(downstreamRequest.getDownstreamRequest());

    assertNotNull(downstreamRequest.getDownstreamClientAddress());
    assertEquals(downstreamRequest.getDownstreamClientAddress(), "1.2.3.4");

    assertNotNull(downstreamRequest.downstreamClientSecure());
    assertEquals(downstreamRequest.downstreamClientSecure(), Boolean.TRUE);

    assertNotNull(downstreamRequest.getClientIdentity());
    assertEquals(downstreamRequest.getClientIdentity(), "u:end-user");

    assertNotNull(downstreamRequest.getClientName());
    assertEquals(downstreamRequest.getClientName(),
                 "directory-enabled app");

    assertNotNull(downstreamRequest.getClientSessionID());
    assertEquals(downstreamRequest.getClientSessionID(), "webapp-session-id");

    assertNotNull(downstreamRequest.getClientRequestID());
    assertEquals(downstreamRequest.getClientRequestID(), "webapp-request-id");

    assertNotNull(downstreamRequest.toString());



    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(downstreamRequest, "1.2.3.5", true,
                                            "u:webapp", "directory proxy",
                                            "conn=123", "op=456");

    v = IntermediateClientRequestValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getDownstreamRequest());
    assertEquals(v.getDownstreamRequest(), downstreamRequest);
    assertEquals(v.getDownstreamRequest().hashCode(),
                 downstreamRequest.hashCode());

    assertNotNull(v.getDownstreamClientAddress());
    assertEquals(v.getDownstreamClientAddress(), "1.2.3.5");

    assertNotNull(v.downstreamClientSecure());
    assertEquals(v.downstreamClientSecure(), Boolean.TRUE);

    assertNotNull(v.getClientIdentity());
    assertEquals(v.getClientIdentity(), "u:webapp");

    assertNotNull(v.getClientName());
    assertEquals(v.getClientName(), "directory proxy");

    assertNotNull(v.getClientSessionID());
    assertEquals(v.getClientSessionID(), "conn=123");

    assertNotNull(v.getClientRequestID());
    assertEquals(v.getClientRequestID(), "op=456");

    assertNotNull(v.toString());
  }



  /**
   * Tests the constructor with all elements set to non-{@code null} values and
   * multiple levels of wrapping.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllNotNullMultipleWraps()
         throws Exception
  {
    IntermediateClientRequestValue innerDownstreamRequest =
         new IntermediateClientRequestValue(null, null, false, null, "browser",
                                            null, null);

    innerDownstreamRequest =
         IntermediateClientRequestValue.decode(innerDownstreamRequest.encode());

    assertNotNull(innerDownstreamRequest);

    assertNull(innerDownstreamRequest.getDownstreamRequest());

    assertNull(innerDownstreamRequest.getDownstreamClientAddress());

    assertNotNull(innerDownstreamRequest.downstreamClientSecure());
    assertEquals(innerDownstreamRequest.downstreamClientSecure(),
                 Boolean.FALSE);

    assertNull(innerDownstreamRequest.getClientIdentity());

    assertNotNull(innerDownstreamRequest.getClientName());
    assertEquals(innerDownstreamRequest.getClientName(), "browser");

    assertNull(innerDownstreamRequest.getClientSessionID());

    assertNull(innerDownstreamRequest.getClientRequestID());



    IntermediateClientRequestValue downstreamRequest =
         new IntermediateClientRequestValue(innerDownstreamRequest, "1.2.3.4",
                                            true, "u:end-user",
                                            "directory-enabled app",
                                            "webapp-session-id",
                                            "webapp-request-id");

    downstreamRequest =
         IntermediateClientRequestValue.decode(downstreamRequest.encode());

    assertNotNull(downstreamRequest);

    assertNotNull(downstreamRequest.getDownstreamRequest());
    assertEquals(downstreamRequest.getDownstreamRequest(),
                 innerDownstreamRequest);
    assertEquals(downstreamRequest.getDownstreamRequest().hashCode(),
                 innerDownstreamRequest.hashCode());

    assertNotNull(downstreamRequest.getDownstreamClientAddress());
    assertEquals(downstreamRequest.getDownstreamClientAddress(), "1.2.3.4");

    assertNotNull(downstreamRequest.downstreamClientSecure());
    assertEquals(downstreamRequest.downstreamClientSecure(), Boolean.TRUE);

    assertNotNull(downstreamRequest.getClientIdentity());
    assertEquals(downstreamRequest.getClientIdentity(), "u:end-user");

    assertNotNull(downstreamRequest.getClientName());
    assertEquals(downstreamRequest.getClientName(),
                 "directory-enabled app");

    assertNotNull(downstreamRequest.getClientSessionID());
    assertEquals(downstreamRequest.getClientSessionID(), "webapp-session-id");

    assertNotNull(downstreamRequest.getClientRequestID());
    assertEquals(downstreamRequest.getClientRequestID(), "webapp-request-id");

    assertNotNull(downstreamRequest.toString());



    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(downstreamRequest, "1.2.3.5", true,
                                            "u:webapp", "directory proxy",
                                            "conn=123", "op=456");

    v = IntermediateClientRequestValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getDownstreamRequest());
    assertEquals(v.getDownstreamRequest(), downstreamRequest);
    assertEquals(v.getDownstreamRequest().hashCode(),
                 downstreamRequest.hashCode());

    assertNotNull(v.getDownstreamClientAddress());
    assertEquals(v.getDownstreamClientAddress(), "1.2.3.5");

    assertNotNull(v.downstreamClientSecure());
    assertEquals(v.downstreamClientSecure(), Boolean.TRUE);

    assertNotNull(v.getClientIdentity());
    assertEquals(v.getClientIdentity(), "u:webapp");

    assertNotNull(v.getClientName());
    assertEquals(v.getClientName(), "directory proxy");

    assertNotNull(v.getClientSessionID());
    assertEquals(v.getClientSessionID(), "conn=123");

    assertNotNull(v.getClientRequestID());
    assertEquals(v.getClientRequestID(), "op=456");

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
    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(null, null, null, null, null,
                                            null, null);
    v = IntermediateClientRequestValue.decode(v.encode());

    assertNull(v.getDownstreamRequest());

    assertNull(v.getDownstreamClientAddress());

    assertNull(v.downstreamClientSecure());

    assertNull(v.getClientIdentity());

    assertNull(v.getClientName());

    assertNull(v.getClientSessionID());

    assertNull(v.getClientRequestID());

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

    IntermediateClientRequestValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method with an element containing an invalid
   * downstream request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidDownstreamRequest()
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

    IntermediateClientRequestValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method with an element containing a downstream
   * request that is not an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeDownstreamRequestNotSequence()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Element((byte) 0xA0, new byte[1])
    };

    IntermediateClientRequestValue.decode(new ASN1Sequence(elements));
  }



  /**
   * Tests the {@code decode} method with an element containing an invalid
   * downstream client secure value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidDownstreamClientSecure()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1Element((byte) 0x82, new byte[0])
    };

    IntermediateClientRequestValue.decode(new ASN1Sequence(elements));
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
    IntermediateClientRequestValue v = new IntermediateClientRequestValue(null,
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
    IntermediateClientRequestValue v = new IntermediateClientRequestValue(null,
         null, null, null, null, null, null);

    assertTrue(v.equals(v));
  }



  /**
   * Tests the {@code equals} method with an object that is not an intermediate
   * client request value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotRightType()
         throws Exception
  {
    IntermediateClientRequestValue v = new IntermediateClientRequestValue(null,
         null, null, null, null, null, null);

    assertFalse(v.equals("foo"));
  }



  /**
   * Tests the {@code equals} method with various types of intermediate client
   * request values that don't match where most of the elements are
   * {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonMatchingMostNull()
         throws Exception
  {
    IntermediateClientRequestValue v = new IntermediateClientRequestValue(null,
         null, null, null, null, null, null);

    assertFalse(v.equals(new IntermediateClientRequestValue(v, null, null, null,
         null, null, null)));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, "1.2.3.4",
         null, null, null, null, null)));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, null, true,
         null, null, null, null)));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, null, null,
         "u:authzid", null, null, null)));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, null, null,
         null, "client-name", null, null)));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, null, null,
         null, null, "session-id", null)));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, null, null,
         null, null, null, "request-id")));
  }



  /**
   * Tests the {@code equals} method with various types of intermediate client
   * request values that don't match where the elements are not {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonMatchingNotNull()
         throws Exception
  {
    IntermediateClientRequestValue wrapped =
         new IntermediateClientRequestValue(null, null, null, null, null, null,
                                            null);
    IntermediateClientRequestValue v =
         new IntermediateClientRequestValue(wrapped, "1.2.3.4", true,
                  "u:authzid", "client-name", "session-id", "request-id");

    assertFalse(v.equals(new IntermediateClientRequestValue(v, "1.2.3.4",
         true, "u:authzid", "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(null, "1.2.3.4",
         true, "u:authzid", "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.5",
         true, "u:authzid", "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, null, true,
         "u:authzid", "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         false, "u:authzid", "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         null, "u:authzid", "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:different-authzid", "client-name", "session-id",
         "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, null, "client-name", "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:authzid", "different-client-name", "session-id",
         "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:authzid", null, "session-id", "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:authzid", "client-name", "different-session-id",
         "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:authzid", "client-name", null, "request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:authzid", "client-name", "session-id",
         "different-request-id")));

    assertFalse(v.equals(new IntermediateClientRequestValue(wrapped, "1.2.3.4",
         true, "u:authzid", "client-name", "session-id", null)));
  }
}
