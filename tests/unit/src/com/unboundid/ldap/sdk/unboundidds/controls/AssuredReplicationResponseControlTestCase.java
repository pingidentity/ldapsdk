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



import java.util.Arrays;

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
 * This class provides a set of test cases for the assured replication response
 * control class.
 */
public final class AssuredReplicationResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with a version of the control that has a minimal set of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalElements()
         throws Exception
  {
    AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, true,
              null, null, null);

    c = new AssuredReplicationResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNull(c.getLocalLevel());

    assertTrue(c.localAssuranceSatisfied());

    assertNull(c.getLocalAssuranceMessage());

    assertNull(c.getRemoteLevel());

    assertTrue(c.remoteAssuranceSatisfied());

    assertNull(c.getRemoteAssuranceMessage());

    assertNull(c.getCSN());

    assertNotNull(c.getServerResults());
    assertTrue(c.getServerResults().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior with a version of the control that contains all
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllElements()
         throws Exception
  {
    AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER,
              false, "Local assurance failed",
              AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION,
              false, "Remote assurance failed", "test-csn",
              Arrays.<AssuredReplicationServerResult>asList(
                   new AssuredReplicationServerResult(
                        AssuredReplicationServerResultCode.COMPLETE,
                        (short) 1234, null),
                   new AssuredReplicationServerResult(
                        AssuredReplicationServerResultCode.COMPLETE,
                        (short) 5678, null)));

    c = new AssuredReplicationResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertEquals(c.getLocalLevel(),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);

    assertFalse(c.localAssuranceSatisfied());

    assertEquals(c.getLocalAssuranceMessage(), "Local assurance failed");

    assertEquals(c.getRemoteLevel(),
         AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION);

    assertFalse(c.remoteAssuranceSatisfied());

    assertEquals(c.getRemoteAssuranceMessage(), "Remote assurance failed");

    assertEquals(c.getCSN(), "test-csn");

    assertNotNull(c.getServerResults());
    assertFalse(c.getServerResults().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMissingValue()
         throws Exception
  {
    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value cannot be
   * parsed as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an unexpected element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceUnexpectedElement()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Boolean((byte) 0x81, true),
         new ASN1Boolean((byte) 0x84, true),
         new ASN1OctetString((byte) 0x8F, "foo"));

    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a malformed local level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedLocalLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated((byte) 0x80, 1234),
         new ASN1Boolean((byte) 0x81, true),
         new ASN1Boolean((byte) 0x84, true));

    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a malformed remote level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedRemoteLevel()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Boolean((byte) 0x81, true),
         new ASN1Boolean((byte) 0x84, true),
         new ASN1Enumerated((byte) 0x83, 1234));

    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * does not include an element indicating whether the local assurance was
   * satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingLocalSatisfied()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Boolean((byte) 0x84, true));

    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * does not include an element indicating whether the remote assurance was
   * satisfied.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMissingRemoteSatisfied()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Boolean((byte) 0x81, true));

    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a malformed server results element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceMalformedServerResults()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence((byte) 0xA7,
              new ASN1OctetString("foo")));

    new AssuredReplicationResponseControl("1.3.6.1.4.1.30221.2.5.29", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior of the get method with no matches.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetNoMatches()
         throws Exception
  {
    final Control[] controls =
    {
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    assertNull(AssuredReplicationResponseControl.get(result));

    assertNotNull(AssuredReplicationResponseControl.getAll(result));
    assertTrue(AssuredReplicationResponseControl.getAll(result).isEmpty());
  }



  /**
   * Tests the behavior of the get method with a single match.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetOneMatchEncoded()
         throws Exception
  {
    final Control[] controls =
    {
      new AssuredReplicationResponseControl(
           AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true, null,
           AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION, true,
           null, "foo", null)
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    assertNotNull(AssuredReplicationResponseControl.get(result));
    assertEquals(AssuredReplicationResponseControl.get(result).getCSN(), "foo");

    assertNotNull(AssuredReplicationResponseControl.getAll(result));
    assertEquals(AssuredReplicationResponseControl.getAll(result).size(), 1);
  }



  /**
   * Tests the behavior of the get method with a single match.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetOneMatchGeneric()
         throws Exception
  {
    final Control[] controls =
    {
      new AssuredReplicationResponseControl(
           AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true, null,
           AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION, true,
           null, "foo", null)
    };

    controls[0] = new Control(controls[0].getOID(), controls[0].isCritical(),
         controls[0].getValue());

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    assertNotNull(AssuredReplicationResponseControl.get(result));
    assertEquals(AssuredReplicationResponseControl.get(result).getCSN(), "foo");

    assertNotNull(AssuredReplicationResponseControl.getAll(result));
    assertEquals(AssuredReplicationResponseControl.getAll(result).size(), 1);
  }



  /**
   * Tests the behavior of the get method with multiple matches.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMultipleMatchesEncoded()
         throws Exception
  {
    final Control[] controls =
    {
      new AssuredReplicationResponseControl(
           AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true, null,
           AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION, true,
           null, "foo", null),

      new AssuredReplicationResponseControl(
           AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true, null,
           AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS, true,
           null, "bar", null)
    };

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    assertNotNull(AssuredReplicationResponseControl.get(result));
    assertEquals(AssuredReplicationResponseControl.get(result).getCSN(), "foo");

    assertNotNull(AssuredReplicationResponseControl.getAll(result));
    assertEquals(AssuredReplicationResponseControl.getAll(result).size(), 2);

  }



  /**
   * Tests the behavior of the get method with multiple matches.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMultipleMatchesGeneric()
         throws Exception
  {
    final Control[] controls =
    {
      new AssuredReplicationResponseControl(
           AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true, null,
           AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION, true,
           null, "foo", null),

      new AssuredReplicationResponseControl(
           AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true, null,
           AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS, true,
           null, "bar", null)
    };

    controls[0] = new Control(controls[0].getOID(), controls[0].isCritical(),
         controls[0].getValue());
    controls[1] = new Control(controls[1].getOID(), controls[1].isCritical(),
         controls[1].getValue());

    final LDAPResult result = new LDAPResult(1, ResultCode.SUCCESS, null,
         null, null, controls);

    assertNotNull(AssuredReplicationResponseControl.get(result));
    assertEquals(AssuredReplicationResponseControl.get(result).getCSN(), "foo");

    assertNotNull(AssuredReplicationResponseControl.getAll(result));
    assertEquals(AssuredReplicationResponseControl.getAll(result).size(), 2);

  }
}
