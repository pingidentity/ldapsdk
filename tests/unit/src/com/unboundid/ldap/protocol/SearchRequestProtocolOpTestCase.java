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
package com.unboundid.ldap.protocol;



import java.io.ByteArrayInputStream;
import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the
 * {@code SearchRequestProtocolOp} class.
 */
public class SearchRequestProtocolOpTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the search request protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestProtocolOp()
         throws Exception
  {
    LinkedList<String> attrs = new LinkedList<String>();
    attrs.add("*");
    attrs.add("+");

    SearchRequestProtocolOp op = new SearchRequestProtocolOp(
         "dc=example,dc=com", SearchScope.SUB, DereferencePolicy.NEVER, 1, 2,
         false, Filter.createEqualityFilter("uid", "test.user"), attrs);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new SearchRequestProtocolOp(reader);

    op = SearchRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new SearchRequestProtocolOp(op.toSearchRequest());

    assertEquals(new DN(op.getBaseDN()),
                 new DN("dc=example,dc=com"));

    assertEquals(op.getScope(), SearchScope.SUB);

    assertEquals(op.getDerefPolicy(), DereferencePolicy.NEVER);

    assertEquals(op.getSizeLimit(), 1);

    assertEquals(op.getTimeLimit(), 2);

    assertFalse(op.typesOnly());

    assertNotNull(op.getFilter());
    assertEquals(op.getFilter(), Filter.create("(uid=test.user)"));

    assertNotNull(op.getAttributes());
    assertEquals(op.getAttributes().size(), 2);

    assertEquals(op.getProtocolOpType(), (byte) 0x63);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the search request protocol op with a minimal
   * set of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestProtocolOpMinimal()
         throws Exception
  {
    SearchRequestProtocolOp op = new SearchRequestProtocolOp(null,
         SearchScope.SUB, DereferencePolicy.NEVER, -1, -2,
         true, Filter.createEqualityFilter("uid", "test.user"), null);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new SearchRequestProtocolOp(reader);

    op = SearchRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new SearchRequestProtocolOp(op.toSearchRequest());

    assertEquals(new DN(op.getBaseDN()), DN.NULL_DN);

    assertEquals(op.getScope(), SearchScope.SUB);

    assertEquals(op.getDerefPolicy(), DereferencePolicy.NEVER);

    assertEquals(op.getSizeLimit(), 0);

    assertEquals(op.getTimeLimit(), 0);

    assertTrue(op.typesOnly());

    assertNotNull(op.getFilter());
    assertEquals(op.getFilter(), Filter.create("(uid=test.user)"));

    assertNotNull(op.getAttributes());
    assertEquals(op.getAttributes().size(), 0);

    assertEquals(op.getProtocolOpType(), (byte) 0x63);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when trying to read a malformed search request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadMalformedRequest()
         throws Exception
  {
    byte[] requestBytes = { (byte) 0x63, 0x00 };
    ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new SearchRequestProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to decode a malformed search request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRequest()
         throws Exception
  {
    SearchRequestProtocolOp.decodeProtocolOp(
         new ASN1Element(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST));
  }



  /**
   * Tests the behavior when trying to decode a search request with a malformed
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedFilter()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence((byte) 0x63);
    b.addOctetString("dc=example,dc=com");
    b.addEnumerated(2);
    b.addEnumerated(0);
    b.addInteger(0);
    b.addInteger(0);
    b.addBoolean(false);
    b.addOctetString((byte) 0x00);
    b.beginSequence().end();
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new SearchRequestProtocolOp(reader);
  }
}
