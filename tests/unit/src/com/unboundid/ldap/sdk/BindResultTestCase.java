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



import java.io.ByteArrayInputStream;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.protocol.LDAPMessage;



/**
 * This class provides a set of test cases for the BindResult class.
 */
public class BindResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    BindResult bindResult = new BindResult(1, ResultCode.INVALID_CREDENTIALS,
                                           "Your password was wrong",
                                           null, null, null);
    bindResult = new BindResult(bindResult);
    assertNull(bindResult.getServerSASLCredentials());
    assertEquals(bindResult.getMessageID(), 1);
  }



  /**
   * Tests the second constructor with a {@code null} server SASL credentials
   * element.
   */
  @Test()
  public void testConstructor2Null()
  {
    BindResult bindResult = new BindResult(1, ResultCode.INVALID_CREDENTIALS,
                                           "Your password was wrong",
                                           null, null, null, null);
    bindResult = new BindResult(bindResult);
    assertNull(bindResult.getServerSASLCredentials());
    assertEquals(bindResult.getMessageID(), 1);
  }



  /**
   * Tests the second constructor with a non-{@code null} server SASL
   * credentials element.
   */
  @Test()
  public void testConstructor2NotNull()
  {
    BindResult bindResult = new BindResult(1, ResultCode.INVALID_CREDENTIALS,
                                           "Your password was wrong",
                                           null, null, null,
                                           new ASN1OctetString());
    bindResult = new BindResult(bindResult);
    assertNotNull(bindResult.getServerSASLCredentials());
    assertEquals(bindResult.getMessageID(), 1);
  }



  /**
   * Tests the third constructor with a generic LDAP result.
   */
  @Test()
  public void testConstructor3()
  {
    BindResult bindResult = new BindResult(new LDAPResult(1,
         ResultCode.INVALID_CREDENTIALS, "Your password was wrong", null,
         (String[]) null, (Control[]) null));
    bindResult = new BindResult(bindResult);
    assertNull(bindResult.getServerSASLCredentials());
    assertEquals(bindResult.getMessageID(), 1);
  }



  /**
   * Tests the {@code readBindResultFrom} method with an element containing
   * a response sequence that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadBindResultFromTooShort()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE);
    b.addEnumerated(0);
    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the {@code readBindResultFrom} method with a sequence containing an
   * invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadBindResultFromInvalidElementType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);

    ASN1BufferSequence opSequence =
         b.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE);
    b.addEnumerated(0);
    b.addOctetString();
    b.addOctetString();
    b.addOctetString((byte) 0x00);
    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }
}
