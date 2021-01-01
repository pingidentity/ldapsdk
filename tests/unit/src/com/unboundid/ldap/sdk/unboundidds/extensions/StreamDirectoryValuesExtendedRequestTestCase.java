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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
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
 * This class provides a set of test cases for the stream directory values
 * extended request.
 */
public class StreamDirectoryValuesExtendedRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a request that should only return full
   * DNs and no controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1FullDNsOnlyNoControls()
         throws Exception
  {
    StreamDirectoryValuesExtendedRequest r =
         new StreamDirectoryValuesExtendedRequest("dc=example,dc=com",
                  SearchScope.SUB, false, null, -1);
    r = new StreamDirectoryValuesExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getDNScope());
    assertEquals(r.getDNScope(), SearchScope.SUB);

    assertFalse(r.returnRelativeDNs());

    assertNotNull(r.getAttributes());
    assertTrue(r.getAttributes().isEmpty());

    assertEquals(r.getValuesPerResponse(), 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a request that should only return values
   * for the "cn" attribute and a single control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorSingleAttrSingleControl()
         throws Exception
  {
    StreamDirectoryValuesExtendedRequest r =
         new StreamDirectoryValuesExtendedRequest("dc=example,dc=com", null,
                  true, Arrays.asList("cn"), 1024,
         new Control("1.2.3.4"));
    r = new StreamDirectoryValuesExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()), new DN("dc=example,dc=com"));

    assertNull(r.getDNScope());

    assertTrue(r.returnRelativeDNs());

    assertNotNull(r.getAttributes());
    assertFalse(r.getAttributes().isEmpty());
    assertEquals(r.getAttributes().size(), 1);
    assertEquals(r.getAttributes().iterator().next(), "cn");

    assertEquals(r.getValuesPerResponse(), 1024);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a request that should return relative DNs,
   * as well as the givenName, sn, and cn attributes.  It will have multiple
   * controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorRelativeDNsMultipleAttrsMultipleControls()
         throws Exception
  {
    StreamDirectoryValuesExtendedRequest r =
         new StreamDirectoryValuesExtendedRequest("dc=example,dc=com",
                  SearchScope.SUB, true, Arrays.asList("givenName", "sn", "cn"),
                  0, new Control("1.2.3.4"), new Control("1.2.3.5"));
    r = new StreamDirectoryValuesExtendedRequest(r);
    r = r.duplicate();

    assertNotNull(r.getBaseDN());
    assertEquals(new DN(r.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(r.getDNScope());
    assertEquals(r.getDNScope(), SearchScope.SUB);

    assertTrue(r.returnRelativeDNs());

    assertNotNull(r.getAttributes());
    assertFalse(r.getAttributes().isEmpty());
    assertEquals(r.getAttributes().size(), 3);

    assertEquals(r.getValuesPerResponse(), 0);

    assertNotNull(r.getExtendedRequestName());

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior of the second constructor with a request that does not
   * have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2NoValue()
         throws Exception
  {
    ExtendedRequest r = new ExtendedRequest(
         StreamDirectoryValuesExtendedRequest.
              STREAM_DIRECTORY_VALUES_REQUEST_OID);
    new StreamDirectoryValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior of the second constructor with a request whose value is
   * not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2ValueNotSequence()
         throws Exception
  {
    ExtendedRequest r = new ExtendedRequest(
         StreamDirectoryValuesExtendedRequest.
              STREAM_DIRECTORY_VALUES_REQUEST_OID,
         new ASN1OctetString("foo"));
    new StreamDirectoryValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior of the second constructor with a request that does not
   * have a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2NoBaseDN()
         throws Exception
  {
    ASN1Element[] idElements =
    {
      new ASN1Enumerated((byte) 0x80, 0x02),
      new ASN1Boolean((byte) 0x81, true)
    };

    ASN1Element[] svElements =
    {
      new ASN1Sequence((byte) 0xA1, idElements),
      new ASN1Integer((byte) 0x83, -1)
    };

    ExtendedRequest r = new ExtendedRequest(
         StreamDirectoryValuesExtendedRequest.
              STREAM_DIRECTORY_VALUES_REQUEST_OID,
         new ASN1OctetString(new ASN1Sequence(svElements).encode()));
    new StreamDirectoryValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior of the second constructor with a request that has an
   * invalid scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2InvalidScope()
         throws Exception
  {
    ASN1Element[] idElements =
    {
      new ASN1Enumerated((byte) 0x80, 0x05)
    };

    ASN1Element[] svElements =
    {
      new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
      new ASN1Sequence((byte) 0xA1, idElements),
    };

    ExtendedRequest r = new ExtendedRequest(
         StreamDirectoryValuesExtendedRequest.
              STREAM_DIRECTORY_VALUES_REQUEST_OID,
         new ASN1OctetString(new ASN1Sequence(svElements).encode()));
    new StreamDirectoryValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior of the second constructor with a request that has an
   * invalid element type in the includeDNs sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2InvalidIDElementType()
         throws Exception
  {
    ASN1Element[] idElements =
    {
      new ASN1Enumerated((byte) 0x80, 0x02),
      new ASN1OctetString((byte) 0x85, "foo")
    };

    ASN1Element[] svElements =
    {
      new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
      new ASN1Sequence((byte) 0xA1, idElements),
    };

    ExtendedRequest r = new ExtendedRequest(
         StreamDirectoryValuesExtendedRequest.
              STREAM_DIRECTORY_VALUES_REQUEST_OID,
         new ASN1OctetString(new ASN1Sequence(svElements).encode()));
    new StreamDirectoryValuesExtendedRequest(r);
  }



  /**
   * Tests the behavior of the second constructor with a request that has an
   * invalid element type in the value sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructor2InvalidValueSequenceElementType()
         throws Exception
  {
    ASN1Element[] idElements =
    {
      new ASN1Enumerated((byte) 0x80, 0x02)
    };

    ASN1Element[] svElements =
    {
      new ASN1OctetString((byte) 0x80, "dc=example,dc=com"),
      new ASN1Sequence((byte) 0xA1, idElements),
      new ASN1OctetString((byte) 0x85, "foo"),
    };

    ExtendedRequest r = new ExtendedRequest(
         StreamDirectoryValuesExtendedRequest.
              STREAM_DIRECTORY_VALUES_REQUEST_OID,
         new ASN1OctetString(new ASN1Sequence(svElements).encode()));
    new StreamDirectoryValuesExtendedRequest(r);
  }
}
