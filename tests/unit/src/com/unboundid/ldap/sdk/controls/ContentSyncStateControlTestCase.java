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
package com.unboundid.ldap.sdk.controls;



import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;



/**
 * This class provides a set of test cases for the
 * {@code ContentSyncStateControl} class.
 */
public final class ContentSyncStateControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor which does not include a cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithoutCookie()
         throws Exception
  {
    final UUID uuid = UUID.randomUUID();

    ContentSyncStateControl c =
         new ContentSyncStateControl(ContentSyncState.PRESENT, uuid, null);
    c = new ContentSyncStateControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.9.1.2");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getState());
    assertEquals(c.getState(), ContentSyncState.PRESENT);

    assertNotNull(c.getEntryUUID());
    assertEquals(c.getEntryUUID(), uuid);

    assertNull(c.getCookie());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor which includes a cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithCookie()
         throws Exception
  {
    final UUID uuid = UUID.randomUUID();

    ContentSyncStateControl c = new ContentSyncStateControl(
         ContentSyncState.ADD, uuid, new ASN1OctetString("foo"));
    c = new ContentSyncStateControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.9.1.2");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getState());
    assertEquals(c.getState(), ContentSyncState.ADD);

    assertNotNull(c.getEntryUUID());
    assertEquals(c.getEntryUUID(), uuid);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie(), new ASN1OctetString("foo"));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlNoValue()
         throws Exception
  {
    new ContentSyncStateControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.2", false, null);
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control whose value is not a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new ContentSyncStateControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.2", false, new ASN1OctetString("foo"));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control whose value sequence contains an invalid state.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueInvalidState()
         throws Exception
  {
    new ContentSyncStateControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.2", false,
         new ASN1OctetString(new ASN1Sequence(new ASN1Enumerated(5),
              new ASN1OctetString(UUID.randomUUID().toString())).encode()));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control whose value sequence does not contain an entryUUID value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueMissingUUID()
         throws Exception
  {
    new ContentSyncStateControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.2", false,
         new ASN1OctetString(new ASN1Sequence(new ASN1Enumerated(5)).encode()));
  }



  /**
   * Tests the {@code get} method with an entry that does not contain a content
   * sync state control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final ContentSyncStateControl c = ContentSyncStateControl.get(e);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with an entry that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new ContentSyncStateControl(ContentSyncState.ADD,
           UUID.randomUUID(), new ASN1OctetString("foo"))
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final ContentSyncStateControl c = ContentSyncStateControl.get(e);
    assertNotNull(c);

    assertEquals(c.getState(), ContentSyncState.ADD);

    assertNotNull(c.getEntryUUID());

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with an entry that contains a response control
   * that is a generic control that can be parsed as a content sync state
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEntryValidGenericType()
         throws Exception
  {
    final Control tmp = new ContentSyncStateControl(ContentSyncState.ADD,
         UUID.randomUUID(), new ASN1OctetString("foo"));

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final ContentSyncStateControl c = ContentSyncStateControl.get(e);
    assertNotNull(c);

    assertEquals(c.getState(), ContentSyncState.ADD);

    assertNotNull(c.getEntryUUID());

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with an entry that contains a response control
   * that is a generic control that cannot be parsed as a content sync state
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetEntryInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(ContentSyncStateControl.SYNC_STATE_OID, false, null)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    ContentSyncStateControl.get(e);
  }



  /**
   * Tests the {@code get} method with a reference that does not contain a
   * content sync state control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReferenceMissing()
         throws Exception
  {
    final String[] refs = { "ldap://server.example.com/dc=example,dc=com" };

    final Control[] controls = new Control[0];

    final SearchResultReference r = new SearchResultReference(refs, controls);

    final ContentSyncStateControl c = ContentSyncStateControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a reference that contains a response
   * control that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReferenceValidCorrectType()
         throws Exception
  {
    final String[] refs = { "ldap://server.example.com/dc=example,dc=com" };

    final Control[] controls =
    {
      new ContentSyncStateControl(ContentSyncState.ADD,
           UUID.randomUUID(), new ASN1OctetString("foo"))
    };

    final SearchResultReference r = new SearchResultReference(refs, controls);

    final ContentSyncStateControl c = ContentSyncStateControl.get(r);
    assertNotNull(c);

    assertEquals(c.getState(), ContentSyncState.ADD);

    assertNotNull(c.getEntryUUID());

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a reference that contains a response
   * control that is a generic control that can be parsed as a content sync
   * state control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetReferenceValidGenericType()
         throws Exception
  {
    final String[] refs = { "ldap://server.example.com/dc=example,dc=com" };

    final Control tmp = new ContentSyncStateControl(ContentSyncState.ADD,
         UUID.randomUUID(), new ASN1OctetString("foo"));

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultReference r = new SearchResultReference(refs, controls);

    final ContentSyncStateControl c = ContentSyncStateControl.get(r);
    assertNotNull(c);

    assertEquals(c.getState(), ContentSyncState.ADD);

    assertNotNull(c.getEntryUUID());

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");
  }



  /**
   * Tests the {@code get} method with a reference that contains a response
   * control that is a generic control that cannot be parsed as content sync
   * state control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetReferenceInvalidGenericType()
         throws Exception
  {
    final String[] refs = { "ldap://server.example.com/dc=example,dc=com" };

    final Control[] controls =
    {
      new Control(ContentSyncStateControl.SYNC_STATE_OID, false, null)
    };

    final SearchResultReference r = new SearchResultReference(refs, controls);

    ContentSyncStateControl.get(r);
  }
}
