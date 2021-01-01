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
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the DeleteRequest class.
 */
public class DeleteRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor, which takes a DN string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    DeleteRequest deleteRequest = new DeleteRequest("dc=example,dc=com");
    deleteRequest = deleteRequest.duplicate();

    assertNotNull(deleteRequest.getDN());
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertFalse(deleteRequest.hasControl());
    assertFalse(deleteRequest.hasControl("1.2.3.4"));
    assertNull(deleteRequest.getControl("1.2.3.4"));
    assertNotNull(deleteRequest.getControls());
    assertEquals(deleteRequest.getControls().length, 0);

    assertNotNull(deleteRequest.toLDIFChangeRecord());

    assertNotNull(deleteRequest.toLDIF());
    assertTrue(deleteRequest.toLDIF().length > 0);

    assertNotNull(deleteRequest.toLDIFString());

    assertNotNull(deleteRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    deleteRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    deleteRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(deleteRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    testEncoding(deleteRequest);

    assertNull(deleteRequest.getIntermediateResponseListener());
    deleteRequest.setIntermediateResponseListener(
         new TestIntermediateResponseListener());
    assertNotNull(deleteRequest.getIntermediateResponseListener());
    deleteRequest.setIntermediateResponseListener(null);
    assertNull(deleteRequest.getIntermediateResponseListener());
  }



  /**
   * Tests the first constructor, which takes a DN string, with a {@code null}
   * value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullDN()
  {
    new DeleteRequest((String) null);
  }



  /**
   * Tests the second constructor, which takes a DN string and set of controls.
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

    DeleteRequest deleteRequest =
         new DeleteRequest("dc=example,dc=com", controls);
    deleteRequest.setFollowReferrals(true);
    deleteRequest = deleteRequest.duplicate();

    assertNotNull(deleteRequest.getDN());
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertTrue(deleteRequest.hasControl());
    assertTrue(deleteRequest.hasControl("1.2.3.4"));
    assertNotNull(deleteRequest.getControl("1.2.3.4"));
    assertFalse(deleteRequest.hasControl("1.2.3.6"));
    assertNull(deleteRequest.getControl("1.2.3.6"));
    assertNotNull(deleteRequest.getControls());
    assertEquals(deleteRequest.getControls().length, 2);

    assertNotNull(deleteRequest.toLDIFChangeRecord());

    assertNotNull(deleteRequest.toLDIF());
    assertTrue(deleteRequest.toLDIF().length > 0);

    assertNotNull(deleteRequest.toLDIFString());

    assertNotNull(deleteRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    deleteRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    deleteRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(deleteRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    testEncoding(deleteRequest);
  }



  /**
   * Tests the second constructor, which takes a DN string and set of controls,
   * with a {@code null} set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NullControls()
         throws Exception
  {
    DeleteRequest deleteRequest =
         new DeleteRequest("dc=example,dc=com", null);
    deleteRequest.setFollowReferrals(false);
    deleteRequest = deleteRequest.duplicate();

    assertNotNull(deleteRequest.getDN());
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertFalse(deleteRequest.hasControl());
    assertFalse(deleteRequest.hasControl("1.2.3.4"));
    assertNull(deleteRequest.getControl("1.2.3.4"));
    assertNotNull(deleteRequest.getControls());
    assertEquals(deleteRequest.getControls().length, 0);

    assertNotNull(deleteRequest.toLDIFChangeRecord());

    assertNotNull(deleteRequest.toLDIF());
    assertTrue(deleteRequest.toLDIF().length > 0);

    assertNotNull(deleteRequest.toLDIFString());

    assertNotNull(deleteRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    deleteRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    deleteRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(deleteRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    testEncoding(deleteRequest);
  }



  /**
   * Tests the third constructor, which takes a DN object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    DeleteRequest deleteRequest =
         new DeleteRequest(new DN("dc=example,dc=com"));
    deleteRequest = deleteRequest.duplicate();

    assertNotNull(deleteRequest.getDN());
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertFalse(deleteRequest.hasControl());
    assertFalse(deleteRequest.hasControl("1.2.3.4"));
    assertNull(deleteRequest.getControl("1.2.3.4"));
    assertNotNull(deleteRequest.getControls());
    assertEquals(deleteRequest.getControls().length, 0);

    assertNotNull(deleteRequest.toLDIFChangeRecord());

    assertNotNull(deleteRequest.toLDIF());
    assertTrue(deleteRequest.toLDIF().length > 0);

    assertNotNull(deleteRequest.toLDIFString());

    assertNotNull(deleteRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    deleteRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    deleteRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(deleteRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    testEncoding(deleteRequest);
  }



  /**
   * Tests the third constructor, which takes a DN object, with a {@code null}
   * value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullDN()
  {
    new DeleteRequest((DN) null);
  }



  /**
   * Tests the fourth constructor, which takes a DN string and set of controls.
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

    DeleteRequest deleteRequest =
         new DeleteRequest(new DN("dc=example,dc=com"), controls);
    deleteRequest = deleteRequest.duplicate();

    assertNotNull(deleteRequest.getDN());
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertTrue(deleteRequest.hasControl());
    assertTrue(deleteRequest.hasControl("1.2.3.4"));
    assertNotNull(deleteRequest.getControl("1.2.3.4"));
    assertFalse(deleteRequest.hasControl("1.2.3.6"));
    assertNull(deleteRequest.getControl("1.2.3.6"));
    assertNotNull(deleteRequest.getControls());
    assertEquals(deleteRequest.getControls().length, 2);

    assertNotNull(deleteRequest.toLDIFChangeRecord());

    assertNotNull(deleteRequest.toLDIF());
    assertTrue(deleteRequest.toLDIF().length > 0);

    assertNotNull(deleteRequest.toLDIFString());

    assertNotNull(deleteRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    deleteRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    deleteRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(deleteRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    testEncoding(deleteRequest);
  }



  /**
   * Tests the fourth constructor, which takes a DN object and set of controls,
   * with a {@code null} set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullControls()
         throws Exception
  {
    DeleteRequest deleteRequest =
         new DeleteRequest(new DN("dc=example,dc=com"), null);
    deleteRequest = deleteRequest.duplicate();

    assertNotNull(deleteRequest.getDN());
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    assertFalse(deleteRequest.hasControl());
    assertFalse(deleteRequest.hasControl("1.2.3.4"));
    assertNull(deleteRequest.getControl("1.2.3.4"));
    assertNotNull(deleteRequest.getControls());
    assertEquals(deleteRequest.getControls().length, 0);

    assertNotNull(deleteRequest.toLDIFChangeRecord());

    assertNotNull(deleteRequest.toLDIF());
    assertTrue(deleteRequest.toLDIF().length > 0);

    assertNotNull(deleteRequest.toLDIFString());

    assertNotNull(deleteRequest.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    deleteRequest.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    deleteRequest.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());

    assertEquals(deleteRequest.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    testEncoding(deleteRequest);
  }



  /**
   * Tests the {@code getDN} and {@code setDN} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetDN()
         throws Exception
  {
    DeleteRequest deleteRequest = new DeleteRequest("dc=example,dc=com");
    assertEquals(deleteRequest.getDN(), "dc=example,dc=com");

    deleteRequest.setDN("ou=People,dc=example,dc=com");
    assertEquals(deleteRequest.getDN(), "ou=People,dc=example,dc=com");

    deleteRequest.setDN(new DN("ou=Groups,dc=example,dc=com"));
    assertEquals(deleteRequest.getDN(), "ou=Groups,dc=example,dc=com");

    testEncoding(deleteRequest);
  }



  /**
   * Tests to ensure that the encoding for the provided delete request is
   * identical when using the stream-based and non-stream-based ASN.1 encoding
   * mechanisms.
   *
   * @param  deleteRequest  The delete request to be tested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void testEncoding(final DeleteRequest deleteRequest)
          throws Exception
  {
    ASN1Element protocolOpElement = deleteRequest.encodeProtocolOp();

    ASN1Buffer b = new ASN1Buffer();
    deleteRequest.writeTo(b);

    assertTrue(Arrays.equals(b.toByteArray(), protocolOpElement.encode()));
  }
}
