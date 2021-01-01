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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the
 * {@code StreamProxyValuesExtendedRequest} class.
 */
public class StreamProxyValuesExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the case in which only information about entry
   * DNs should be returned.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyEntryDNs()
         throws Exception
  {
    LinkedList<StreamProxyValuesBackendSet> backendSets =
         new LinkedList<StreamProxyValuesBackendSet>();
    backendSets.add(new StreamProxyValuesBackendSet(new ASN1OctetString("a"),
         new String[] { "ds1a.example.com", "ds2a.example.com" },
         new int[] { 389, 389 }));
    backendSets.add(new StreamProxyValuesBackendSet(new ASN1OctetString("b"),
         new String[] { "ds1b.example.com", "ds2b.example.com" },
         new int[] { 389, 389 }));

    StreamProxyValuesExtendedRequest r = new StreamProxyValuesExtendedRequest(
         "dc=example,dc=com", SearchScope.SUB, true, null, 1000, backendSets);
    r = new StreamProxyValuesExtendedRequest(new ExtendedRequest(
         r.getOID(), r.getValue()));
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(r.getDNScope());
    assertEquals(r.getDNScope(), SearchScope.SUB);

    assertTrue(r.returnRelativeDNs());

    assertNotNull(r.getAttributes());
    assertTrue(r.getAttributes().isEmpty());

    assertEquals(r.getValuesPerResponse(), 1000);

    assertNotNull(r.getBackendSets());
    assertFalse(r.getBackendSets().isEmpty());
    assertEquals(r.getBackendSets().size(), 2);
    assertEquals(r.getBackendSets().get(0).getBackendSetID().stringValue(),
                 "a");
    assertEquals(r.getBackendSets().get(1).getBackendSetID().stringValue(),
                 "b");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the case in which only information about a
   * specified set of attribute values should be returned.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyAttributeValues()
         throws Exception
  {
    LinkedList<String> attrNames = new LinkedList<String>();
    attrNames.add("cn");
    attrNames.add("uid");

    LinkedList<StreamProxyValuesBackendSet> backendSets =
         new LinkedList<StreamProxyValuesBackendSet>();
    backendSets.add(new StreamProxyValuesBackendSet(new ASN1OctetString("1"),
         new String[] { "ds1.example.com" }, new int[] { 1389 }));

    StreamProxyValuesExtendedRequest r = new StreamProxyValuesExtendedRequest(
         "dc=example,dc=com", null, true, attrNames, -1, backendSets,
         new Control("1.2.3.4"));
    r = new StreamProxyValuesExtendedRequest(new ExtendedRequest(
         r.getOID(), r.getValue(), r.getControls()));
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNull(r.getDNScope());

    assertNotNull(r.getAttributes());
    assertFalse(r.getAttributes().isEmpty());
    assertEquals(r.getAttributes().size(), 2);
    assertEquals(r.getAttributes().get(0), "cn");
    assertEquals(r.getAttributes().get(1), "uid");

    assertEquals(r.getValuesPerResponse(), 0);

    assertNotNull(r.getBackendSets());
    assertFalse(r.getBackendSets().isEmpty());
    assertEquals(r.getBackendSets().size(), 1);
    assertEquals(r.getBackendSets().get(0).getBackendSetID().stringValue(),
                 "1");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 1);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the case in which information about both entry
   * DNs and attribute values should be returned.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryDNsAndAttributeValues()
         throws Exception
  {
    LinkedList<String> attrNames = new LinkedList<String>();
    attrNames.add("uid");

    LinkedList<StreamProxyValuesBackendSet> backendSets =
         new LinkedList<StreamProxyValuesBackendSet>();
    backendSets.add(new StreamProxyValuesBackendSet(new ASN1OctetString("1"),
         new String[] { "ds1.example.com" }, new int[] { 1389 }));
    backendSets.add(new StreamProxyValuesBackendSet(new ASN1OctetString("2"),
         new String[] { "ds2.example.com" }, new int[] { 2389 }));

    StreamProxyValuesExtendedRequest r = new StreamProxyValuesExtendedRequest(
         "dc=example,dc=com", SearchScope.SUB, false, attrNames, -1,
         backendSets, new Control("1.2.3.4"), new Control("1.2.3.5"));
    r = new StreamProxyValuesExtendedRequest(new ExtendedRequest(
         r.getOID(), r.getValue(), r.getControls()));
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(r.getDNScope());
    assertEquals(r.getDNScope(), SearchScope.SUB);

    assertFalse(r.returnRelativeDNs());

    assertNotNull(r.getAttributes());
    assertFalse(r.getAttributes().isEmpty());
    assertEquals(r.getAttributes().size(), 1);
    assertEquals(r.getAttributes().get(0), "uid");

    assertEquals(r.getValuesPerResponse(), 0);

    assertNotNull(r.getBackendSets());
    assertFalse(r.getBackendSets().isEmpty());
    assertEquals(r.getBackendSets().size(), 2);
    assertEquals(r.getBackendSets().get(0).getBackendSetID().stringValue(),
                 "1");
    assertEquals(r.getBackendSets().get(1).getBackendSetID().stringValue(),
                 "2");

    assertNotNull(r.getControls());
    assertEquals(r.getControls().length, 2);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior when trying to decode a request with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new StreamProxyValuesExtendedRequest(new ExtendedRequest(
         "1.3.6.1.4.1.30221.2.6.8", (ASN1OctetString) null));
  }



  /**
   * Tests the behavior when trying to decode a request with no base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoBaseDN()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "ds.example.com" },
         new int[] { 389 });

    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence((byte) 0xA4, s.encode()));
    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.8", value);
    new StreamProxyValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior when trying to decode a request with an invalid scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidScope()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "ds.example.com" },
         new int[] { 389 });

    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
         new ASN1Sequence((byte) 0xA1,
                          new ASN1Enumerated((byte) 0x80, 1234)),
         new ASN1Sequence((byte) 0xA4, s.encode()));
    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.8", value);
    new StreamProxyValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior when trying to decode a request with a malformed scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedScope()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "ds.example.com" },
         new int[] { 389 });

    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
         new ASN1Sequence((byte) 0xA1,
                          new ASN1OctetString((byte) 0x80)),
         new ASN1Sequence((byte) 0xA4, s.encode()));
    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.8", value);
    new StreamProxyValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior when trying to decode a request with a malformed
   * includeDNs element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedIncludeDNs()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "ds.example.com" },
         new int[] { 389 });

    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
         new ASN1Sequence((byte) 0xA1,
                          new ASN1OctetString((byte) 0x83)),
         new ASN1Sequence((byte) 0xA4, s.encode()));
    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.8", value);
    new StreamProxyValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior when trying to decode a request with a malformed
   * attributes element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedAttributes()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "ds.example.com" },
         new int[] { 389 });

    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
         new ASN1OctetString((byte) 0xA2, "foo"),
         new ASN1Sequence((byte) 0xA4, s.encode()));
    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.8", value);
    new StreamProxyValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior when trying to decode a request with an invalid value
   * sequence element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidValueSequenceElement()
         throws Exception
  {
    StreamProxyValuesBackendSet s = new StreamProxyValuesBackendSet(
         new ASN1OctetString("foo"), new String[] { "ds.example.com" },
         new int[] { 389 });

    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
         new ASN1Sequence((byte) 0xA1,
                          new ASN1Enumerated((byte) 0x80, 2)),
         new ASN1Integer((byte) 0x83, -1),
         new ASN1Sequence((byte) 0xA4, s.encode()),
         new ASN1OctetString((byte) 0x8F));
    ASN1OctetString value = new ASN1OctetString(valueSequence.encode());

    ExtendedRequest r = new ExtendedRequest("1.3.6.1.4.1.30221.2.6.8", value);
    new StreamProxyValuesExtendedRequest(r);
  }
}
