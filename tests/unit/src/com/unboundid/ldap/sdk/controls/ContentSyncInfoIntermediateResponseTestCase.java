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



import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ContentSyncInfoIntermediateResponse} class.
 */
public final class ContentSyncInfoIntermediateResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a response used to provide a new cookie.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNewCookieResponse()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse r =
         ContentSyncInfoIntermediateResponse.createNewCookieResponse(
              new ASN1OctetString("foo"));
    r = ContentSyncInfoIntermediateResponse.decode(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.4203.1.9.1.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getType());
    assertEquals(r.getType(), ContentSyncInfoType.NEW_COOKIE);

    assertNotNull(r.getCookie());
    assertEquals(r.getCookie(), new ASN1OctetString("foo"));

    assertFalse(r.refreshDone());

    assertNull(r.getEntryUUIDs());

    assertFalse(r.refreshDeletes());

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a response used to indicate that the refresh
   * delete phase is complete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRefreshDeleteResponse()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse r =
         ContentSyncInfoIntermediateResponse.createRefreshDeleteResponse(
              new ASN1OctetString("foo"), false);
    r = ContentSyncInfoIntermediateResponse.decode(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.4203.1.9.1.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getType());
    assertEquals(r.getType(), ContentSyncInfoType.REFRESH_DELETE);

    assertNotNull(r.getCookie());
    assertEquals(r.getCookie(), new ASN1OctetString("foo"));

    assertFalse(r.refreshDone());

    assertNull(r.getEntryUUIDs());

    assertFalse(r.refreshDeletes());

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a response used to indicate that the refresh
   * present phase is complete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRefreshPresentResponse()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse r =
         ContentSyncInfoIntermediateResponse.createRefreshPresentResponse(
              new ASN1OctetString("foo"), true);
    r = ContentSyncInfoIntermediateResponse.decode(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.4203.1.9.1.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getType());
    assertEquals(r.getType(), ContentSyncInfoType.REFRESH_PRESENT);

    assertNotNull(r.getCookie());
    assertEquals(r.getCookie(), new ASN1OctetString("foo"));

    assertTrue(r.refreshDone());

    assertNull(r.getEntryUUIDs());

    assertFalse(r.refreshDeletes());

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for a response used to indicate a set of entries
   * have been removed or remained unchanged.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSyncIDSetResponse()
         throws Exception
  {
    final List<UUID> uuidList =
         Arrays.asList(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());

    ContentSyncInfoIntermediateResponse r =
         ContentSyncInfoIntermediateResponse.createSyncIDSetResponse(
              new ASN1OctetString("foo"), uuidList, true);
    r = ContentSyncInfoIntermediateResponse.decode(r);

    assertNotNull(r.getOID());
    assertEquals(r.getOID(), "1.3.6.1.4.1.4203.1.9.1.4");

    assertNotNull(r.getValue());

    assertNotNull(r.getType());
    assertEquals(r.getType(), ContentSyncInfoType.SYNC_ID_SET);

    assertNotNull(r.getCookie());
    assertEquals(r.getCookie(), new ASN1OctetString("foo"));

    assertFalse(r.refreshDone());

    assertNotNull(r.getEntryUUIDs());
    assertEquals(r.getEntryUUIDs(), uuidList);

    assertTrue(r.refreshDeletes());

    assertNotNull(r.getIntermediateResponseName());

    assertNotNull(r.valueToString());

    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * response that does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4", null));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * response whose value cannot be parsed as an element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotElement()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4", new ASN1OctetString("foo")));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * response whose value element is not a recognized type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueElementUnrecognizedType()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4",  new ASN1OctetString(
              new ASN1OctetString((byte) 0x84, "foo").encode())));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * malformed REFRESH_DELETE response whose value sequence contains an
   * element with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRefreshDelete()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4",  new ASN1OctetString(
              new ASN1Sequence((byte) 0xA1, new ASN1OctetString("foo"),
                   new ASN1Integer(0)).encode())));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * malformed REFRESH_PRESENT response whose value sequence contains a
   * malformed element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedRefreshPresent()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4",  new ASN1OctetString(
              new ASN1Sequence((byte) 0xA1, new ASN1OctetString("foo"),
                   new ASN1OctetString((byte) 0x01, "bar")).encode())));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * malformed SYNC_ID_SET response whose value sequence contains an element
   * with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformedSyncIDSet()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4",  new ASN1OctetString(
              new ASN1Sequence((byte) 0xA3, new ASN1OctetString("foo"),
                   new ASN1Integer(0)).encode())));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * malformed SYNC_ID_SET response whose value sequence that does not contain
   * an entryUUID set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSyncIDSetNoUUIDs()
         throws Exception
  {
    ContentSyncInfoIntermediateResponse.decode(new IntermediateResponse(
         "1.3.6.1.4.1.4203.1.9.1.4",  new ASN1OctetString(
              new ASN1Sequence((byte) 0xA3,
                   new ASN1OctetString("foo")).encode())));
  }
}
