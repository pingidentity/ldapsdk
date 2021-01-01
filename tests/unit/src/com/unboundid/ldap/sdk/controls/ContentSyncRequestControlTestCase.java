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
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the
 * {@code ContentSyncRequestControl} class.
 */
public final class ContentSyncRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor which takes only a mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithModeOnly()
         throws Exception
  {
    ContentSyncRequestControl c = new ContentSyncRequestControl(
         ContentSyncRequestMode.REFRESH_ONLY);
    c = new ContentSyncRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.9.1.1");

    assertTrue(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getMode());
    assertEquals(c.getMode(), ContentSyncRequestMode.REFRESH_ONLY);

    assertNull(c.getCookie());

    assertFalse(c.getReloadHint());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a mode, cookie,
   * and reload hint value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithModeAllElements()
         throws Exception
  {
    ContentSyncRequestControl c = new ContentSyncRequestControl(
         ContentSyncRequestMode.REFRESH_AND_PERSIST, new ASN1OctetString("foo"),
         true);
    c = new ContentSyncRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.4203.1.9.1.1");

    assertTrue(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getMode());
    assertEquals(c.getMode(), ContentSyncRequestMode.REFRESH_AND_PERSIST);

    assertNotNull(c.getCookie());
    assertEquals(c.getCookie().stringValue(), "foo");

    assertTrue(c.getReloadHint());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control which does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value cannot be
   * parsed as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is an empty
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueEmptySequence()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString(new ASN1Sequence().encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is a
   * sequence with an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceInvalidElementType()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString(new ASN1Sequence(new ASN1Integer(1)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value has an
   * invalid request mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueInvalidRequestMode()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Enumerated(0)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value has multiple
   * request modes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueMultipleRequestModes()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Enumerated(1), new ASN1Enumerated(3)).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value has multiple
   * cookies.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueMultipleCookies()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Enumerated(1), new ASN1OctetString("foo"),
              new ASN1OctetString("bar")).encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value has multiple
   * reload hint values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueReloadHints()
         throws Exception
  {
    new ContentSyncRequestControl(new Control("1.2.3.4", false,
         new ASN1OctetString(new ASN1Sequence(
              new ASN1Enumerated(1), new ASN1Boolean(true),
              new ASN1Boolean(false)).encode())));
  }
}
