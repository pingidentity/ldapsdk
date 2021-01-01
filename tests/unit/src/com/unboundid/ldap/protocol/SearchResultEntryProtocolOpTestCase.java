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
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code SearchResultEntryProtocolOp} class.
 */
public class SearchResultEntryProtocolOpTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the search result entry protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultEntryProtocolOp()
         throws Exception
  {
    List<Attribute> attrs = new LinkedList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    SearchResultEntryProtocolOp op =
         new SearchResultEntryProtocolOp("dc=example,dc=com", attrs);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new SearchResultEntryProtocolOp(reader);

    op = SearchResultEntryProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new SearchResultEntryProtocolOp(op.toSearchResultEntry());

    assertEquals(new DN(op.getDN()),
                 new DN("dc=example,dc=com"));

    attrs = op.getAttributes();
    assertEquals(attrs.size(), 2);

    assertEquals(op.getProtocolOpType(), (byte) 0x64);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when trying to decode a malformed search result entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRequest()
         throws Exception
  {
    byte[] requestBytes = { (byte) 0x64, 0x00 };
    ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new SearchResultEntryProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to read a malformed search result entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadMalformedRequest()
         throws Exception
  {
    SearchResultEntryProtocolOp.decodeProtocolOp(
         new ASN1Element(LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY));
  }



  /**
   * Tests the behavior when trying to decode a search result entry with a
   * malformed attribute list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestMalformedAttr()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence opSequence = b.beginSequence((byte) 0x64);
    b.addOctetString("dc=example,dc=com");
    ASN1BufferSequence attrsSequence = b.beginSequence();
    b.addOctetString();
    attrsSequence.end();
    opSequence.end();

    byte[] requestBytes = b.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new SearchResultEntryProtocolOp(reader);
  }
}
