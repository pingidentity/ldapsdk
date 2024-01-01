/*
 * Copyright 2013-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2024 Ping Identity Corporation
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
 * Copyright (C) 2013-2024 Ping Identity Corporation
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
import java.util.List;

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
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;



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



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when a minimum set of elements are included.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalControl()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);


    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 2);

    assertNull(valueObject.getFieldAsString("local-level"));

    assertEquals(valueObject.getFieldAsBoolean("local-assurance-satisfied"),
         Boolean.TRUE);

    assertNull(valueObject.getFieldAsString("local-assurance-message"));

    assertNull(valueObject.getFieldAsString("remote-level"));

    assertEquals(valueObject.getFieldAsBoolean("remote-assurance-satisfied"),
         Boolean.FALSE);

    assertNull(valueObject.getFieldAsString("remote-assurance-message"));

    assertNull(valueObject.getFieldAsString("csn"));

    assertNull(valueObject.getFieldAsArray("server-results"));


    AssuredReplicationResponseControl decodedControl =
         AssuredReplicationResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getLocalLevel());

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertNull(decodedControl.getLocalAssuranceMessage());

    assertNull(decodedControl.getRemoteLevel());

    assertFalse(decodedControl.remoteAssuranceSatisfied());

    assertNull(decodedControl.getRemoteAssuranceMessage());

    assertNull(decodedControl.getCSN());

    assertNotNull(decodedControl.getServerResults());
    assertTrue(decodedControl.getServerResults().isEmpty());


    decodedControl =
         (AssuredReplicationResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getLocalLevel());

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertNull(decodedControl.getLocalAssuranceMessage());

    assertNull(decodedControl.getRemoteLevel());

    assertFalse(decodedControl.remoteAssuranceSatisfied());

    assertNull(decodedControl.getRemoteAssuranceMessage());

    assertNull(decodedControl.getCSN());

    assertNotNull(decodedControl.getServerResults());
    assertTrue(decodedControl.getServerResults().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when a complete set of elements are included.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlCompleteControl()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(
              AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER, true,
              "Received by at least one server.",
              AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS,
              false, "Could not verify reception in all remote locations.",
              "this-is-a-csn",
              Arrays.asList(
                   new AssuredReplicationServerResult(
                        AssuredReplicationServerResultCode.COMPLETE, (short) 2,
                        null),
                   new AssuredReplicationServerResult(
                        AssuredReplicationServerResultCode.TIMEOUT, null,
                        (short) 3)));


    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.FALSE);

    assertFalse(controlObject.hasField("value-base64"));

    final JSONObject valueObject = controlObject.getFieldAsObject("value-json");
    assertNotNull(valueObject);
    assertEquals(valueObject.getFields().size(), 8);

    assertEquals(valueObject.getFieldAsString("local-level"),
         "received-any-server");

    assertEquals(valueObject.getFieldAsBoolean("local-assurance-satisfied"),
         Boolean.TRUE);

    assertEquals(valueObject.getFieldAsString("local-assurance-message"),
         "Received by at least one server.");

    assertEquals(valueObject.getFieldAsString("remote-level"),
         "received-all-remote-locations");

    assertEquals(valueObject.getFieldAsBoolean("remote-assurance-satisfied"),
         Boolean.FALSE);

    assertEquals(valueObject.getFieldAsString("remote-assurance-message"),
         "Could not verify reception in all remote locations.");

    assertEquals(valueObject.getFieldAsString("csn"), "this-is-a-csn");

    final List<JSONValue> serverResultValues =
         valueObject.getFieldAsArray("server-results");
    assertNotNull(serverResultValues);
    assertEquals(serverResultValues.size(), 2);

    final JSONObject resultObject1 = (JSONObject) serverResultValues.get(0);
    assertEquals(resultObject1.getFields().size(), 3);

    assertEquals(
         resultObject1.getFieldAsInteger("result-code-value").intValue(),
         AssuredReplicationServerResultCode.COMPLETE.intValue());

    assertEquals(resultObject1.getFieldAsString("result-code-name"),
         AssuredReplicationServerResultCode.COMPLETE.name());

    assertEquals(resultObject1.getFieldAsInteger("replication-server-id"),
         Integer.valueOf(2));

    assertNull(resultObject1.getFieldAsInteger("replica-id"));

    final JSONObject resultObject2 = (JSONObject) serverResultValues.get(1);
    assertEquals(resultObject2.getFields().size(), 3);

    assertEquals(
         resultObject2.getFieldAsInteger("result-code-value").intValue(),
         AssuredReplicationServerResultCode.TIMEOUT.intValue());

    assertEquals(resultObject2.getFieldAsString("result-code-name"),
         AssuredReplicationServerResultCode.TIMEOUT.name());

    assertNull(resultObject2.getFieldAsInteger("replication-server-id"));

    assertEquals(resultObject2.getFieldAsInteger("replica-id"),
         Integer.valueOf(3));


    AssuredReplicationResponseControl decodedControl =
         AssuredReplicationResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getLocalLevel(),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertEquals(decodedControl.getLocalAssuranceMessage(),
         "Received by at least one server.");

    assertEquals(decodedControl.getRemoteLevel(),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);

    assertFalse(decodedControl.remoteAssuranceSatisfied());

    assertEquals(decodedControl.getRemoteAssuranceMessage(),
         "Could not verify reception in all remote locations.");

    assertEquals(decodedControl.getCSN(), "this-is-a-csn");

    assertNotNull(decodedControl.getServerResults());
    assertEquals(decodedControl.getServerResults().size(), 2);

    AssuredReplicationServerResult result1 =
         decodedControl.getServerResults().get(0);

    assertEquals(result1.getResultCode(),
         AssuredReplicationServerResultCode.COMPLETE);

    assertEquals(result1.getReplicationServerID().intValue(), 2);

    assertNull(result1.getReplicaID());

    AssuredReplicationServerResult result2 =
         decodedControl.getServerResults().get(1);

    assertEquals(result2.getResultCode(),
         AssuredReplicationServerResultCode.TIMEOUT);

    assertNull(result2.getReplicationServerID());

    assertEquals(result2.getReplicaID().intValue(), 3);



    decodedControl =
         (AssuredReplicationResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertEquals(decodedControl.getLocalLevel(),
         AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER);

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertEquals(decodedControl.getLocalAssuranceMessage(),
         "Received by at least one server.");

    assertEquals(decodedControl.getRemoteLevel(),
         AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS);

    assertFalse(decodedControl.remoteAssuranceSatisfied());

    assertEquals(decodedControl.getRemoteAssuranceMessage(),
         "Could not verify reception in all remote locations.");

    assertEquals(decodedControl.getCSN(), "this-is-a-csn");

    assertNotNull(decodedControl.getServerResults());
    assertEquals(decodedControl.getServerResults().size(), 2);

    result1 = decodedControl.getServerResults().get(0);

    assertEquals(result1.getResultCode(),
         AssuredReplicationServerResultCode.COMPLETE);

    assertEquals(result1.getReplicationServerID().intValue(), 2);

    assertNull(result1.getReplicaID());

    result2 = decodedControl.getServerResults().get(1);

    assertEquals(result2.getResultCode(),
         AssuredReplicationServerResultCode.TIMEOUT);

    assertNull(result2.getReplicationServerID());

    assertEquals(result2.getReplicaID().intValue(), 3);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);


    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    AssuredReplicationResponseControl decodedControl =
         AssuredReplicationResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getLocalLevel());

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertNull(decodedControl.getLocalAssuranceMessage());

    assertNull(decodedControl.getRemoteLevel());

    assertFalse(decodedControl.remoteAssuranceSatisfied());

    assertNull(decodedControl.getRemoteAssuranceMessage());

    assertNull(decodedControl.getCSN());

    assertNotNull(decodedControl.getServerResults());
    assertTrue(decodedControl.getServerResults().isEmpty());


    decodedControl =
         (AssuredReplicationResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNull(decodedControl.getLocalLevel());

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertNull(decodedControl.getLocalAssuranceMessage());

    assertNull(decodedControl.getRemoteLevel());

    assertFalse(decodedControl.remoteAssuranceSatisfied());

    assertNull(decodedControl.getRemoteAssuranceMessage());

    assertNull(decodedControl.getCSN());

    assertNotNull(decodedControl.getServerResults());
    assertTrue(decodedControl.getServerResults().isEmpty());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object has an invalid local assurance level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlInvalidLocalAssuranceLevel()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "invalid"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object is missing the local-assurance-satisfied field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingLocalAssuranceSatisfied()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object has an invalid remote assurance level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlInvalidRemoteAssuranceLevel()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "invalid"),
              new JSONField("remote-assurance-satisfied", true))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object is missing the remote-assurance-satisfied field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingRemoteAssuranceSatisfied()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the server results array contains a value that is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlServerResultsValueNotObject()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("server-results", new JSONArray(
                   new JSONString("not-a-valid-server-results"))))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the server results array contains a value that is missing a result code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlServerResultsValueMissingResultCode()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("server-results", new JSONArray(
                   JSONObject.EMPTY_OBJECT)))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the server results array contains a value that has an invalid result code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlServerResultsValueInvalidResultCode()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("server-results", new JSONArray(
                   new JSONObject(
                        new JSONField("result-code-value", 999),
                        new JSONField("result-code-name", "invalid")))))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("unrecognized", "foo"))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("unrecognized", "foo"))));

    final AssuredReplicationResponseControl decodedControl =
         AssuredReplicationResponseControl.decodeJSONControl(controlObject,
              false);

    assertEquals(decodedControl.getLocalLevel(),
         AssuredReplicationLocalLevel.NONE);

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertNull(decodedControl.getLocalAssuranceMessage());

    assertEquals(decodedControl.getRemoteLevel(),
         AssuredReplicationRemoteLevel.NONE);

    assertTrue(decodedControl.remoteAssuranceSatisfied());

    assertNull(decodedControl.getRemoteAssuranceMessage());

    assertNull(decodedControl.getCSN());

    assertTrue(decodedControl.getServerResults().isEmpty());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * a server result object has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlServeResultUnrecognizedFieldStrict()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("server-results", new JSONArray(
                   new JSONObject(
                        new JSONField("result-code-value", 0),
                        new JSONField("result-code-name", "COMPLETE"),
                        new JSONField("unrecognized", "foo")))))));

    AssuredReplicationResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * a server result object has an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlServeResultUnrecognizedFieldNonStrict()
          throws Exception
  {
    final AssuredReplicationResponseControl c =
         new AssuredReplicationResponseControl(null, true, null, null, false,
              null, null, null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("local-level", "none"),
              new JSONField("local-assurance-satisfied", true),
              new JSONField("remote-level", "none"),
              new JSONField("remote-assurance-satisfied", true),
              new JSONField("server-results", new JSONArray(
                   new JSONObject(
                        new JSONField("result-code-value", 0),
                        new JSONField("result-code-name", "COMPLETE"),
                        new JSONField("unrecognized", "foo")))))));

    final AssuredReplicationResponseControl decodedControl =
         AssuredReplicationResponseControl.decodeJSONControl(controlObject,
              false);

    assertEquals(decodedControl.getLocalLevel(),
         AssuredReplicationLocalLevel.NONE);

    assertTrue(decodedControl.localAssuranceSatisfied());

    assertNull(decodedControl.getLocalAssuranceMessage());

    assertEquals(decodedControl.getRemoteLevel(),
         AssuredReplicationRemoteLevel.NONE);

    assertTrue(decodedControl.remoteAssuranceSatisfied());

    assertNull(decodedControl.getRemoteAssuranceMessage());

    assertNull(decodedControl.getCSN());

    assertEquals(decodedControl.getServerResults().size(), 1);

    final AssuredReplicationServerResult serverResult =
         decodedControl.getServerResults().get(0);
    assertEquals(serverResult.getResultCode(),
         AssuredReplicationServerResultCode.COMPLETE);
    assertNull(serverResult.getReplicationServerID());
    assertNull(serverResult.getReplicaID());
  }
}
