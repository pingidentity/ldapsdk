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
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;



/**
 * This class provides a set of test cases for the
 * {@code ModifyRequestProtocolOp} class.
 */
public class ModifyRequestProtocolOpTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the modify request protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyRequestProtocolOp()
         throws Exception
  {
    LinkedList<Modification> mods = new LinkedList<Modification>();
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));
    mods.add(new Modification(ModificationType.REPLACE, "o", "example.com"));

    ModifyRequestProtocolOp op = new ModifyRequestProtocolOp(
         "dc=example,dc=com", mods);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new ModifyRequestProtocolOp(reader);

    op = ModifyRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new ModifyRequestProtocolOp(op.toModifyRequest());

    assertEquals(new DN(op.getDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(op.getModifications());
    assertEquals(op.getModifications().size(), 2);

    assertEquals(op.getProtocolOpType(), (byte) 0x66);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when trying to read a malformed modify request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadMalformedRequest()
         throws Exception
  {
    byte[] requestBytes = { (byte) 0x66, 0x00 };
    ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new ModifyRequestProtocolOp(reader);
  }



  /**
   * Tests the behavior when trying to decode a malformed modify request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRequest()
         throws Exception
  {
    ModifyRequestProtocolOp.decodeProtocolOp(
         new ASN1Element(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST));
  }



  /**
   * Tests the behavior when trying to decode a modify request with a malformed
   * modification list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeRequestMalformedAttr()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence opSequence = b.beginSequence((byte) 0x66);
    b.addOctetString("dc=example,dc=com");
    ASN1BufferSequence attrsSequence = b.beginSequence();
    b.addOctetString();
    attrsSequence.end();
    opSequence.end();

    byte[] requestBytes = b.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new ModifyRequestProtocolOp(reader);
  }
}
