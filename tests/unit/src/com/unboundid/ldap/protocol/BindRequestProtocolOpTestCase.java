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

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.GenericSASLBindRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ReadFromFilePasswordProvider;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the {@code BindRequestProtocolOp}
 * class.
 */
public class BindRequestProtocolOpTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor which takes a string DN and a
   * string password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpSimpleStringPassword()
         throws Exception
  {
    BindRequestProtocolOp op = new BindRequestProtocolOp(
         "uid=test.user,ou=People,dc=example,dc=com", "password");
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op = BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindRequestProtocolOp((SimpleBindRequest) op.toBindRequest());

    assertEquals(op.getVersion(), 3);

    assertEquals(new DN(op.getBindDN()),
                 new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SIMPLE);

    assertEquals(op.getSimplePassword().stringValue(),
                 "password");

    assertNull(op.getSASLMechanism());

    assertNull(op.getSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a string DN and a
   * binary password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpSimpleBinaryPassword()
         throws Exception
  {
    BindRequestProtocolOp op = new BindRequestProtocolOp(
         "uid=test.user,ou=People,dc=example,dc=com", "password".getBytes());
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op= BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindRequestProtocolOp((SimpleBindRequest) op.toBindRequest());

    assertEquals(op.getVersion(), 3);

    assertEquals(new DN(op.getBindDN()),
                 new DN("uid=test.user,ou=People,dc=example,dc=com"));

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SIMPLE);

    assertEquals(op.getSimplePassword().stringValue(),
                 "password");

    assertNull(op.getSASLMechanism());

    assertNull(op.getSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a string DN and a
   * string password with an anonymous bind.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpSimpleStringPasswordAnonymous()
         throws Exception
  {
    BindRequestProtocolOp op = new BindRequestProtocolOp(null, (String) null);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op = BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindRequestProtocolOp((SimpleBindRequest) op.toBindRequest());

    assertEquals(op.getVersion(), 3);

    assertEquals(new DN(op.getBindDN()), DN.NULL_DN);

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SIMPLE);

    assertEquals(op.getSimplePassword().stringValue(), "");

    assertNull(op.getSASLMechanism());

    assertNull(op.getSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a string DN and a
   * binary password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpSimpleBinaryPasswordAnonymous()
         throws Exception
  {
    BindRequestProtocolOp op = new BindRequestProtocolOp(null, (byte[]) null);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op = BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindRequestProtocolOp((SimpleBindRequest) op.toBindRequest());

    assertEquals(op.getVersion(), 3);

    assertEquals(new DN(op.getBindDN()), DN.NULL_DN);

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SIMPLE);

    assertEquals(op.getSimplePassword().stringValue(), "");

    assertNull(op.getSASLMechanism());

    assertNull(op.getSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a SASL mechanism
   * and credentials with no credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpSASLNoCredentials()
         throws Exception
  {
    BindRequestProtocolOp op =
         new BindRequestProtocolOp("", "EXTERNAL", null);
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op = BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    assertEquals(op.getVersion(), 3);

    assertNotNull(op.getBindDN());
    assertEquals(op.getBindDN(), "");

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SASL);

    assertNull(op.getSimplePassword());

    assertNotNull(op.getSASLMechanism());
    assertEquals(op.getSASLMechanism(), "EXTERNAL");

    assertNull(op.getSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a SASL mechanism
   * and credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpSASLWithCredentials()
         throws Exception
  {
    BindRequestProtocolOp op = new BindRequestProtocolOp(null, "PLAIN",
         new ASN1OctetString("\u0000u:test.user\u00000password"));
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op = BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    assertEquals(op.getVersion(), 3);

    assertNotNull(op.getBindDN());
    assertEquals(op.getBindDN(), "");

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SASL);

    assertNull(op.getSimplePassword());

    assertNotNull(op.getSASLMechanism());
    assertEquals(op.getSASLMechanism(), "PLAIN");

    assertNotNull(op.getSASLCredentials());

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when attempting to read a malformed bind request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadMalformedRequest()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence((byte) 0x60);
    b.addOctetString();
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new BindRequestProtocolOp(reader);
  }



  /**
   * Tests the behavior when attempting to decode a malformed bind request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRequest()
         throws Exception
  {
    BindRequestProtocolOp.decodeProtocolOp(
         new ASN1Element(LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST));
  }



  /**
   * Tests the behavior when attempting to read a bind request protocol op
   * with an invalid type of credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadInvalidCredType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence((byte) 0x60);
    b.addInteger(3);
    b.addOctetString();
    b.addOctetString((byte) 0x0F);
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    new BindRequestProtocolOp(reader);
  }



  /**
   * Tests the behavior when attempting to decode a bind request protocol op
   * with an invalid type of credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidCredType()
         throws Exception
  {
    final ASN1Sequence s = new ASN1Sequence(
         LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST,
         new ASN1Integer(3),
         new ASN1OctetString(),
         new ASN1Element((byte) 0x0F));

    BindRequestProtocolOp.decodeProtocolOp(s);
  }



  /**
   * Provides test coverage for the bind request protocol op when using a
   * generic SASL bind request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestProtocolOpGenericSASLMechanism()
         throws Exception
  {
    BindRequestProtocolOp op =
         new BindRequestProtocolOp("", "TEST",
              new ASN1OctetString(BindRequestProtocolOp.CRED_TYPE_SASL, "foo"));
    ASN1Buffer buffer = new ASN1Buffer();
    op.writeTo(buffer);

    byte[] opBytes = buffer.toByteArray();
    ByteArrayInputStream inputStream = new ByteArrayInputStream(opBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    op = new BindRequestProtocolOp(reader);

    op = BindRequestProtocolOp.decodeProtocolOp(op.encodeProtocolOp());

    op = new BindRequestProtocolOp((GenericSASLBindRequest) op.toBindRequest());

    assertEquals(op.getVersion(), 3);

    assertNotNull(op.getBindDN());
    assertEquals(op.getBindDN(), "");

    assertEquals(op.getCredentialsType(),
                 BindRequestProtocolOp.CRED_TYPE_SASL);

    assertNull(op.getSimplePassword());

    assertNotNull(op.getSASLMechanism());
    assertEquals(op.getSASLMechanism(), "TEST");

    assertNotNull(op.getSASLCredentials());
    assertEquals(op.getSASLCredentials().stringValue(), "foo");

    assertEquals(op.getProtocolOpType(), (byte) 0x60);

    assertNotNull(op.toString());
  }



  /**
   * Tests the behavior when trying to create a bind request protocol op from a
   * simple bind request that has a password provider rather than a static
   * password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateFromSimpleBindRequestWithPasswordProvider()
         throws Exception
  {
    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(createTempFile("password"));

    final SimpleBindRequest r = new SimpleBindRequest(
         "uid=test.user,ou=People,dc=example,dc=com", passwordProvider);

    new BindRequestProtocolOp(r);
  }
}
