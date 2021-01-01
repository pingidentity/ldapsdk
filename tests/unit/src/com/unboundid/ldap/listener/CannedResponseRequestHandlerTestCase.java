/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the
 * {@code CannedResponseRequestHandler} class.
 */
public final class CannedResponseRequestHandlerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the request handler with the default configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    final CannedResponseRequestHandler handler =
         new CannedResponseRequestHandler().newInstance(null);

    LDAPMessage m = handler.processAddRequest(1, new AddRequestProtocolOp(
         "dc=example,dc=com",
         Arrays.asList(new Attribute("objectClass", "top", "domain"),
              new Attribute("dc", "example"))),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 1);
    assertTrue(m.getProtocolOp() instanceof AddResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processBindRequest(2,
         new BindRequestProtocolOp("uid=admin,dc=example,dc=com", "password"),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 2);
    assertTrue(m.getProtocolOp() instanceof BindResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processCompareRequest(3, new CompareRequestProtocolOp(
         "dc=example,dc=com", "objectClass", new ASN1OctetString("top")),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 3);
    assertTrue(m.getProtocolOp() instanceof CompareResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processDeleteRequest(4,
         new DeleteRequestProtocolOp("dc=example,dc=com"),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 4);
    assertTrue(m.getProtocolOp() instanceof DeleteResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processExtendedRequest(5,
         new ExtendedRequestProtocolOp("1.2.3.4", null),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 5);
    assertTrue(m.getProtocolOp() instanceof ExtendedResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processModifyRequest(6, new ModifyRequestProtocolOp(
         "dc=example,dc=com", Arrays.asList(new Modification(
              ModificationType.REPLACE, "description", "foo"))),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 6);
    assertTrue(m.getProtocolOp() instanceof ModifyResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processModifyDNRequest(6, new ModifyDNRequestProtocolOp(
         "ou=People,dc=example,dc=com", "ou=Users", true, null),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 6);
    assertTrue(m.getProtocolOp() instanceof ModifyDNResponseProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());

    m = handler.processSearchRequest(7,
         new SearchRequestProtocolOp("dc=example,dc=com", SearchScope.SUB,
              DereferencePolicy.NEVER, 0, 0, false,
              Filter.createEqualityFilter("uid", "test"),
              Arrays.<String>asList()),
         Collections.<Control>emptyList());
    assertNotNull(m);
    assertEquals(m.getMessageID(), 7);
    assertTrue(m.getProtocolOp() instanceof SearchResultDoneProtocolOp);
    assertNotNull(m.getControls());
    assertTrue(m.getControls().isEmpty());
  }



  /**
   * Tests the behavior of the request handler when search result entries and
   * references should be returned.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithEntriesAndReferences()
         throws Exception
  {
    final List<Entry> entries = Arrays.asList(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    final String[] refArray =
    {
      "ldap://server.example.com/dc=example,dc=com"
    };
    final List<SearchResultReference> refs = Arrays.asList(
         new SearchResultReference(refArray, StaticUtils.NO_CONTROLS));

    final CannedResponseRequestHandler handler =
         new CannedResponseRequestHandler(ResultCode.SUCCESS, null, null, null,
              entries, refs);

    final LDAPListenerConfig config = new LDAPListenerConfig(0, handler);
    final LDAPListener listener = new LDAPListener(config);

    listener.startListening();
    final int listenPort = listener.getListenPort();
    final LDAPConnection conn = new LDAPConnection("127.0.0.1", listenPort);

    final SearchResult searchResult = conn.search("dc=example,dc=com",
         SearchScope.BASE, "(objectClass=*)");
    assertResultCodeEquals(searchResult, ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0), new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    assertEquals(searchResult.getReferenceCount(), 1);
    assertEquals(searchResult.getSearchReferences().get(0).getReferralURLs()[0],
         "ldap://server.example.com/dc=example,dc=com");

    conn.close();
    listener.shutDown(true);
  }
}
