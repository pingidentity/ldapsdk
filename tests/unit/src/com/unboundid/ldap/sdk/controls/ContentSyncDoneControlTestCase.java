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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * {@code ContentSyncDoneControl} class.
 */
public final class ContentSyncDoneControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor which does not include either a
   * cookie or a refreshDeletes value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNoElements()
         throws Exception
  {
    ContentSyncDoneControl c = new ContentSyncDoneControl(null, false);
    c = new ContentSyncDoneControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.9.1.3");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNull(c.getCookie());

    assertFalse(c.refreshDeletes());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor which includes both a cookie and
   * a refreshDeletes value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllElements()
         throws Exception
  {
    ContentSyncDoneControl c =
         new ContentSyncDoneControl(new ASN1OctetString("foo"), true);
    c = new ContentSyncDoneControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.9.1.3");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie(), new ASN1OctetString("foo"));

    assertTrue(c.refreshDeletes());

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
    new ContentSyncDoneControl().decodeControl("1.3.6.1.4.1.4203.1.9.1.3",
         false, null);
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control that does has a value which cannot be parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new ContentSyncDoneControl().decodeControl("1.3.6.1.4.1.4203.1.9.1.3",
         false, new ASN1OctetString("foo"));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control that does has a value which is a sequence with an invalid element
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidElementType()
         throws Exception
  {
    new ContentSyncDoneControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.3", false,
         new ASN1OctetString(new ASN1Sequence(new ASN1Enumerated(1)).encode()));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control whose value sequence contains multiple cookies.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMultipleCookies()
         throws Exception
  {
    new ContentSyncDoneControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.3", false,
         new ASN1OctetString(new ASN1Sequence(new ASN1OctetString("foo"),
              new ASN1OctetString("bar")).encode()));
  }



  /**
   * Provides test coverage for the constructor which attempts to decode a
   * control whose value sequence contains multiple refreshDeletes values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMultipleRefreshDeletes()
         throws Exception
  {
    new ContentSyncDoneControl().decodeControl(
         "1.3.6.1.4.1.4203.1.9.1.3", false,
         new ASN1OctetString(new ASN1Sequence(new ASN1Boolean(true),
              new ASN1Boolean(false)).encode()));
  }



  /**
   * Tests the {@code get} method with a result that does not contain a content
   * sync done response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS);

    final ContentSyncDoneControl c = ContentSyncDoneControl.get(r);
    assertNull(c);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is already of the appropriate type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidCorrectType()
         throws Exception
  {
    final Control[] controls =
    {
      new ContentSyncDoneControl(new ASN1OctetString("foo"), true)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final ContentSyncDoneControl c = ContentSyncDoneControl.get(r);
    assertNotNull(c);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");

    assertTrue(c.refreshDeletes());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a content sync done
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final Control tmp =
         new ContentSyncDoneControl(new ASN1OctetString("foo"), true);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    final ContentSyncDoneControl c = ContentSyncDoneControl.get(r);
    assertNotNull(c);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");

    assertTrue(c.refreshDeletes());
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a content sync done
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(ContentSyncDoneControl.SYNC_DONE_OID, false, null)
    };

    final LDAPResult r = new LDAPResult(1, ResultCode.SUCCESS, null, null,
         null, controls);

    ContentSyncDoneControl.get(r);
  }
}
