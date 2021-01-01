/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the ExtendedRequest class.
 */
public class ExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ExtendedRequest extendedRequest = new ExtendedRequest("4.3.2.1");
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "4.3.2.1");

    assertNull(extendedRequest.getValue());

    assertFalse(extendedRequest.hasControl());
    assertFalse(extendedRequest.hasControl("1.2.3.4"));
    assertNull(extendedRequest.getControl("1.2.3.4"));
    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    extendedRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    extendedRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(extendedRequest);

    assertEquals(extendedRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(extendedRequest.getExtendedRequestName());

    extendedRequest.getLastMessageID();

    assertNull(extendedRequest.getIntermediateResponseListener());
    extendedRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(extendedRequest.getIntermediateResponseListener());
    extendedRequest.setIntermediateResponseListener(null);
    assertNull(extendedRequest.getIntermediateResponseListener());
  }



  /**
   * Tests the first constructor with a {@code null} OID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullOID()
  {
    new ExtendedRequest((String) null);
  }



  /**
   * Tests the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedRequest extendedRequest = new ExtendedRequest("4.3.2.1", controls);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "4.3.2.1");

    assertNull(extendedRequest.getValue());

    assertTrue(extendedRequest.hasControl());
    assertTrue(extendedRequest.hasControl("1.2.3.4"));
    assertNotNull(extendedRequest.getControl("1.2.3.4"));
    assertFalse(extendedRequest.hasControl("1.2.3.6"));
    assertNull(extendedRequest.getControl("1.2.3.6"));
    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    extendedRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    extendedRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(extendedRequest);

    assertEquals(extendedRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(extendedRequest.getExtendedRequestName());

    extendedRequest.getLastMessageID();
  }



  /**
   * Tests the second constructor with a {@code null} OID.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullOIDAndControls()
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    new ExtendedRequest((String) null, controls);
  }



  /**
   * Tests the third constructor with a non-{@code null} OID and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    ExtendedRequest extendedRequest =
         new ExtendedRequest("4.3.2.1", new ASN1OctetString());
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "4.3.2.1");

    assertNotNull(extendedRequest.getValue());

    assertFalse(extendedRequest.hasControl());
    assertFalse(extendedRequest.hasControl("1.2.3.4"));
    assertNull(extendedRequest.getControl("1.2.3.4"));
    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    extendedRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    extendedRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(extendedRequest);

    assertEquals(extendedRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(extendedRequest.getExtendedRequestName());

    extendedRequest.getLastMessageID();
  }



  /**
   * Tests the third constructor with a non-{@code null} OID and a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NullValue()
         throws Exception
  {
    ExtendedRequest extendedRequest =
         new ExtendedRequest("4.3.2.1", (ASN1OctetString) null);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "4.3.2.1");

    assertNull(extendedRequest.getValue());

    assertFalse(extendedRequest.hasControl());
    assertFalse(extendedRequest.hasControl("1.2.3.4"));
    assertNull(extendedRequest.getControl("1.2.3.4"));
    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 0);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    extendedRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    extendedRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(extendedRequest);

    assertEquals(extendedRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(extendedRequest.getExtendedRequestName());

    extendedRequest.getLastMessageID();
  }



  /**
   * Tests the third constructor with a {@code null} OID and value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullOIDAndValue()
  {
    new ExtendedRequest((String) null, (ASN1OctetString) null);
  }



  /**
   * Tests the fourth constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedRequest extendedRequest =
         new ExtendedRequest("4.3.2.1", new ASN1OctetString(), controls);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "4.3.2.1");

    assertNotNull(extendedRequest.getValue());

    assertTrue(extendedRequest.hasControl());
    assertTrue(extendedRequest.hasControl("1.2.3.4"));
    assertNotNull(extendedRequest.getControl("1.2.3.4"));
    assertFalse(extendedRequest.hasControl("1.2.3.6"));
    assertNull(extendedRequest.getControl("1.2.3.6"));
    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    extendedRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    extendedRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(extendedRequest);

    assertEquals(extendedRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(extendedRequest.getExtendedRequestName());

    extendedRequest.getLastMessageID();
  }



  /**
   * Tests the third constructor with a non-{@code null} OID and a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullValue()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    ExtendedRequest extendedRequest =
         new ExtendedRequest("4.3.2.1", (ASN1OctetString) null, controls);
    extendedRequest = extendedRequest.duplicate();

    assertNotNull(extendedRequest.getOID());
    assertEquals(extendedRequest.getOID(), "4.3.2.1");

    assertNull(extendedRequest.getValue());

    assertTrue(extendedRequest.hasControl());
    assertTrue(extendedRequest.hasControl("1.2.3.4"));
    assertNotNull(extendedRequest.getControl("1.2.3.4"));
    assertFalse(extendedRequest.hasControl("1.2.3.6"));
    assertNull(extendedRequest.getControl("1.2.3.6"));
    assertNotNull(extendedRequest.getControls());
    assertEquals(extendedRequest.getControls().length, 2);

    assertNotNull(extendedRequest.getExtendedRequestName());
    assertNotNull(extendedRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    extendedRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    extendedRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    testEncoding(extendedRequest);

    assertEquals(extendedRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(extendedRequest.getExtendedRequestName());

    extendedRequest.getLastMessageID();
  }



  /**
   * Tests the third constructor with a {@code null} OID and value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NullOIDAndValue()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, null)
    };

    new ExtendedRequest((String) null, (ASN1OctetString) null, controls);
  }



  /**
   * Tests to ensure that the encoding for the provided extended request is
   * identical when using the stream-based and non-stream-based ASN.1 encoding
   * mechanisms.
   *
   * @param  extendedRequest  The extended request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final ExtendedRequest extendedRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = extendedRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    extendedRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
