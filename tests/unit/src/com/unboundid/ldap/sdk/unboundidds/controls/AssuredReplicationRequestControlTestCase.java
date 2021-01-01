/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the assured replication request
 * control.
 */
public final class AssuredReplicationRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a version of the assured replication request control with the minimal
   * set of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalElements()
         throws Exception
  {
    AssuredReplicationRequestControl c =
         new AssuredReplicationRequestControl(null, null, null);

    c = new AssuredReplicationRequestControl(c);
    assertNotNull(c);

    assertNull(c.getMinimumLocalLevel());

    assertNull(c.getMaximumLocalLevel());

    assertNull(c.getMinimumRemoteLevel());

    assertNull(c.getMaximumRemoteLevel());

    assertFalse(c.sendResponseImmediately());

    assertNull(c.getTimeoutMillis());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests a version of the assured replication request control with a basic set
   * of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicElements()
         throws Exception
  {
    AssuredReplicationRequestControl c = new AssuredReplicationRequestControl(
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
         1234L);

    c = new AssuredReplicationRequestControl(c);
    assertNotNull(c);

    assertEquals(c.getMinimumLocalLevel(),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);

    assertNull(c.getMaximumLocalLevel());

    assertEquals(c.getMinimumRemoteLevel(),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);

    assertNull(c.getMaximumRemoteLevel());

    assertFalse(c.sendResponseImmediately());

    assertEquals(c.getTimeoutMillis(), Long.valueOf(1234L));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests a version of the assured replication request control with a complete
   * set of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteElements()
         throws Exception
  {
    AssuredReplicationRequestControl c = new AssuredReplicationRequestControl(
         true, AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS,
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS,
         5678L, true);

    c = new AssuredReplicationRequestControl(c);
    assertNotNull(c);

    assertEquals(c.getMinimumLocalLevel(),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);

    assertEquals(c.getMaximumLocalLevel(),
         AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS);

    assertEquals(c.getMinimumRemoteLevel(),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);

    assertEquals(c.getMaximumRemoteLevel(),
         AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS);

    assertTrue(c.sendResponseImmediately());

    assertEquals(c.getTimeoutMillis(), Long.valueOf(5678L));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value cannot be
   * parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28", false,
              new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is a
   * sequence with an unrecognized element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceHasUnrecognizedElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString((byte) 0x8F, "foo"));

    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28", false,
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * has an invalid minimum local level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMalformedMinimumLocalLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x80, 1234));

    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28", false,
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * has an invalid maximum local level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMalformedMaximumLocalLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x81, 1234));

    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28", false,
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * has an invalid minimum remote level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMalformedMinimumRemoteLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x82, 1234));

    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28", false,
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * has an invalid maximum remote level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueSequenceMalformedMaximumRemoteLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x83, 1234));

    new AssuredReplicationRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.28", false,
              new ASN1OctetString(valueSequence.encode())));
  }
}
