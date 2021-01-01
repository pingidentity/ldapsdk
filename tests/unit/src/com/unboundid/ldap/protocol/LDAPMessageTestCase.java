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
import java.io.IOException;
import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.TestInputStream;



/**
 * This class provides a set of test cases for the {@code LDAPMessage} class.
 */
public class LDAPMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor which takes an array of controls with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorEmptyControlArray()
         throws Exception
  {
    LDAPMessage m = new LDAPMessage(1, new UnbindRequestProtocolOp());

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the constructor which takes an array of controls with a {@code null}
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNullControlArray()
         throws Exception
  {
    LDAPMessage m =
         new LDAPMessage(1, new UnbindRequestProtocolOp(), (Control[]) null);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the constructor which takes an array of controls with a non-empty
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNonEmptyControlArray()
         throws Exception
  {
    LDAPMessage m = new LDAPMessage(1, new UnbindRequestProtocolOp(),
         new Control("1.2.3.4"), new Control("1.2.3.5"));

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the constructor which takes a list of controls with an empty list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorEmptyControlList()
         throws Exception
  {
    LinkedList<Control> controlList = new LinkedList<Control>();

    LDAPMessage m =
         new LDAPMessage(1, new UnbindRequestProtocolOp(), controlList);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the constructor which takes a list of controls with a {@code null}
   * list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNullControlList()
         throws Exception
  {
    LinkedList<Control> controlList = null;

    LDAPMessage m =
         new LDAPMessage(1, new UnbindRequestProtocolOp(), controlList);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the constructor which takes a list of controls with a non-empty
   * list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNonEmptyControlList()
         throws Exception
  {
    LinkedList<Control> controlList = new LinkedList<Control>();
    controlList.add(new Control("1.2.3.4"));
    controlList.add(new Control("1.2.3.5"));

    LDAPMessage m =
         new LDAPMessage(1, new UnbindRequestProtocolOp(), controlList);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an abandon request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAbandonRequestMessage()
         throws Exception
  {
    AbandonRequestProtocolOp op = new AbandonRequestProtocolOp(1);

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof AbandonRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_ABANDON_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getAbandonRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an add request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddRequestMessage()
         throws Exception
  {
    LinkedList<Attribute> attrs = new LinkedList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    AddRequestProtocolOp op =
         new AddRequestProtocolOp("dc=example,dc=com", attrs);

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof AddRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getAddRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a bind request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindRequestMessage()
         throws Exception
  {
    BindRequestProtocolOp op = new BindRequestProtocolOp(
         "uid=test.user,ou=People,dc=example,dc=com", "password");

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof BindRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_BIND_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getBindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a compare request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareRequestMessage()
         throws Exception
  {
    CompareRequestProtocolOp op = new CompareRequestProtocolOp(
         "dc=example,dc=com", "dc", new ASN1OctetString("example"));

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof CompareRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getCompareRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a delete request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteRequestMessage()
         throws Exception
  {
    DeleteRequestProtocolOp op =
         new DeleteRequestProtocolOp("dc=example,dc=com");

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof DeleteRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getDeleteRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an extended
   * request protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedRequestMessage()
         throws Exception
  {
    ExtendedRequestProtocolOp op =
         new ExtendedRequestProtocolOp("1.2.3.4", null);

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof ExtendedRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getExtendedRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a modify request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyRequestMessage()
         throws Exception
  {
    LinkedList<Modification> mods = new LinkedList<Modification>();
    mods.add(new Modification(ModificationType.REPLACE, "description", "foo"));

    ModifyRequestProtocolOp op =
         new ModifyRequestProtocolOp("dc=example,dc=com", mods);

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof ModifyRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getModifyRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a modify DN
   * request protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNRequestMessage()
         throws Exception
  {
    ModifyDNRequestProtocolOp op = new ModifyDNRequestProtocolOp(
         "ou=People,dc=example,dc=com", "ou=Users", true, null);

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof ModifyDNRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getModifyDNRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a search request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchDNRequestMessage()
         throws Exception
  {
    SearchRequestProtocolOp op = new SearchRequestProtocolOp(
         "dc=example,dc=com", SearchScope.SUB, DereferencePolicy.NEVER, 0, 0,
         false, Filter.createEqualityFilter("uid", "test.user"), null);

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof SearchRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getSearchRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an unbind request
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnbindRequestMessage()
         throws Exception
  {
    UnbindRequestProtocolOp op = new UnbindRequestProtocolOp();

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof UnbindRequestProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_UNBIND_REQUEST);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getUnbindRequestProtocolOp());

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an add response
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    AddResponseProtocolOp op = new AddResponseProtocolOp(0, null, null, refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof AddResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getAddResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a bind response
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    BindResponseProtocolOp op =
         new BindResponseProtocolOp(0, null, null, refs, new ASN1OctetString());

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof BindResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_BIND_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getBindResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a compare response
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    CompareResponseProtocolOp op =
         new CompareResponseProtocolOp(0, null, null, refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof CompareResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_COMPARE_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getCompareResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a delete response
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    DeleteResponseProtocolOp op =
         new DeleteResponseProtocolOp(0, null, null, refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof DeleteResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getDeleteResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an extended
   * response protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    ExtendedResponseProtocolOp op =
         new ExtendedResponseProtocolOp(0, null, null, refs, "1.2.3.4",
                                        new ASN1OctetString());

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof ExtendedResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getExtendedResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a modify response
   * protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    ModifyResponseProtocolOp op =
         new ModifyResponseProtocolOp(0, null, null, refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof ModifyResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getModifyResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a modify DN
   * response protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNResponseMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    ModifyDNResponseProtocolOp op =
         new ModifyDNResponseProtocolOp(0, null, null, refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof ModifyDNResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getModifyDNResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a search result
   * done protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultDoneMessage()
         throws Exception
  {
    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    SearchResultDoneProtocolOp op =
         new SearchResultDoneProtocolOp(0, null, null, refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof SearchResultDoneProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_DONE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getSearchResultDoneProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a search result
   * entry protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultEntryMessage()
         throws Exception
  {
    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    LinkedList<Attribute> attrs = new LinkedList<Attribute>();
    attrs.add(new Attribute("objectClass", "top", "domain"));
    attrs.add(new Attribute("dc", "example"));

    SearchResultEntryProtocolOp op =
         new SearchResultEntryProtocolOp("dc=example,dc=com", attrs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof SearchResultEntryProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_ENTRY);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getSearchResultEntryProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with a search result
   * reference protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchResultReferenceMessage()
         throws Exception
  {
    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    LinkedList<String> refs = new LinkedList<String>();
    refs.add("ldap://server1.example.com:389/dc=example,dc=com");
    refs.add("ldap://server2.example.com:389/dc=example,dc=com");

    SearchResultReferenceProtocolOp op =
         new SearchResultReferenceProtocolOp(refs);

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof SearchResultReferenceProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_SEARCH_RESULT_REFERENCE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getSearchResultReferenceProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an intermediate
   * response protocol op.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseMessage()
         throws Exception
  {
    LinkedList<Control> controls = new LinkedList<Control>();
    controls.add(new Control("1.2.3.4"));
    controls.add(new Control("1.2.3.5", true, new ASN1OctetString()));

    IntermediateResponseProtocolOp op =
         new IntermediateResponseProtocolOp("1.2.3.4", new ASN1OctetString());

    LDAPMessage m = new LDAPMessage(1, op, controls);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof IntermediateResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE);

    assertNotNull(m.getControls());
    assertFalse(m.getControls().isEmpty());

    assertNotNull(m.getIntermediateResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the behavior of the {@code LDAPMessage} class with an intermediate
   * response protocol op without any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntermediateResponseMessageNoControls()
         throws Exception
  {
    IntermediateResponseProtocolOp op =
         new IntermediateResponseProtocolOp("1.2.3.4", new ASN1OctetString());

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);
    m = LDAPMessage.readFrom(reader, true);

    m = LDAPMessage.decode(m.encode());

    assertEquals(m.getMessageID(), 1);

    assertNotNull(m.getProtocolOp());
    assertTrue(m.getProtocolOp() instanceof IntermediateResponseProtocolOp);

    assertEquals(m.getProtocolOpType(),
                 LDAPMessage.PROTOCOL_OP_TYPE_INTERMEDIATE_RESPONSE);

    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    assertNotNull(m.getIntermediateResponseProtocolOp());

    inputStream = new ByteArrayInputStream(b.toByteArray());
    reader = new ASN1StreamReader(inputStream);
    LDAPResponse r = LDAPMessage.readLDAPResponseFrom(reader, true);

    assertNotNull(m.toString());
  }



  /**
   * Tests the {@code LDAPMessage.readFrom} method with an empty stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFromEmptyStream()
         throws Exception
  {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(LDAPMessage.readFrom(reader, true));
  }



  /**
   * Tests the {@code LDAPMessage.readFrom} method with invalid protocol op
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadFromInvalidProtocolOpType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence();
    b.addInteger(1);
    b.addOctetString();
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readFrom(reader, true);
  }



  /**
   * Tests the {@code LDAPMessage.readFrom} method with a {@code null} reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadFromNullReader()
         throws Exception
  {
    LDAPMessage.readFrom(null, true);
  }



  /**
   * Tests the {@code LDAPMessage.readFrom} method with an input stream that
   * throws an exception after the first byte has been read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadFromIOExceptionAfterFirst()
         throws Exception
  {
    ByteArrayInputStream baos = new ByteArrayInputStream(new byte[10]);
    TestInputStream is = new TestInputStream(baos, new IOException(), 1,
                                             false);

    LDAPMessage.readFrom(new ASN1StreamReader(is), false);
  }



  /**
   * Tests the {@code LDAPMessage.readLDAPResponseFrom} method with an empty
   * stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadLDAPResponseFromEmptyStream()
         throws Exception
  {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(LDAPMessage.readLDAPResponseFrom(reader, true));
  }



  /**
   * Tests the {@code LDAPMessage.readLDAPResponseFrom} method with invalid
   * protocol op type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadLDAPResponseFromInvalidProtocolOpType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence();
    b.addInteger(1);
    b.addOctetString();
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the {@code LDAPMessage.readLDAPResponseFrom} method with a protocol
   * op type that is not a response type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadLDAPResponseFromProtocolOpTypeNotResponse()
         throws Exception
  {
    UnbindRequestProtocolOp op = new UnbindRequestProtocolOp();

    LDAPMessage m = new LDAPMessage(1, op);

    ASN1Buffer b = new ASN1Buffer();
    m.writeTo(b);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the {@code LDAPMessage.readLDAPResponseFrom} method with a
   * {@code null} reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadLDAPResponseFromNullReader()
         throws Exception
  {
    LDAPMessage.readLDAPResponseFrom(null, true);
  }



  /**
   * Tests the behavior when trying to read an invalid result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadLDAPResponseFromInvalidResult()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);
    ASN1BufferSequence opSequence = b.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE);
    b.addOctetString();
    opSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the behavior when trying to read a result containing a malformed
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadLDAPResponseFromMalformedControl()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);
    ASN1BufferSequence opSequence = b.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE);
    b.addEnumerated(0);
    b.addOctetString();
    b.addOctetString();
    opSequence.end();
    ASN1BufferSequence controlsSequence = b.beginSequence();
    ASN1BufferSequence controlSequence = b.beginSequence();
    b.addOctetString("1.2.3.4");
    b.addOctetString((byte) 0x01);
    controlSequence.end();
    controlsSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the behavior when trying to read a result containing a control with
   * an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadLDAPResponseFromInvalidControlElementType()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence msgSequence = b.beginSequence();
    b.addInteger(1);
    ASN1BufferSequence opSequence = b.beginSequence(
         LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE);
    b.addEnumerated(0);
    b.addOctetString();
    b.addOctetString();
    opSequence.end();
    ASN1BufferSequence controlsSequence = b.beginSequence();
    ASN1BufferSequence controlSequence = b.beginSequence();
    b.addOctetString("1.2.3.4");
    b.addInteger(5);
    controlSequence.end();
    controlsSequence.end();
    msgSequence.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    LDAPMessage.readLDAPResponseFrom(reader, true);
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is not a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void tetDecodeNotSequence()
         throws Exception
  {
    LDAPMessage.decode(new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is a
   * sequence but with an invalid element count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void tetSequenceInvalidElementCount()
         throws Exception
  {
    LDAPMessage.decode(new ASN1Sequence());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that is a
   * sequence but with an invalid protocol op type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void tetSequenceInvalidProtocolOpType()
         throws Exception
  {
    LDAPMessage.decode(new ASN1Sequence(
         new ASN1Integer(1),
         new ASN1OctetString()));
  }
}
