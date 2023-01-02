/*
 * Copyright 2014-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2023 Ping Identity Corporation
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
 * Copyright (C) 2014-2023 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the get matching entry count
 * response control.
 */
public final class MatchingEntryCountResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the control for an examined response created with a
   * minimal set of fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalExaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(0, true,
              Arrays.asList("debug1", "debug2"));
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.EXAMINED_COUNT);

    assertEquals(c.getCountValue(), 0);

    assertTrue(c.searchIndexed());

    assertNull(c.getShortCircuited());

    assertNull(c.getFullyIndexed());

    assertNull(c.getCandidatesAreInScope());

    assertNull(c.getRemainingFilter());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 2);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an examined response created with an
   * extended set of fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedExaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(1, true,
              true, true, false, true,
              Filter.createEqualityFilter("objectClass", "person"),
              Arrays.asList("debug1", "debug2"));
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.EXAMINED_COUNT);

    assertEquals(c.getCountValue(), 1);

    assertTrue(c.searchIndexed());

    assertNotNull(c.getShortCircuited());
    assertTrue(c.getShortCircuited());

    assertNotNull(c.getFullyIndexed());
    assertFalse(c.getFullyIndexed());

    assertNotNull(c.getCandidatesAreInScope());
    assertTrue(c.getCandidatesAreInScope());

    assertNotNull(c.getRemainingFilter());
    assertEquals(c.getRemainingFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 2);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an unexamined response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalUnexaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(123, false,
              null);
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(c.getCountValue(), 123);

    assertTrue(c.searchIndexed());

    assertNull(c.getShortCircuited());

    assertNull(c.getFullyIndexed());

    assertNull(c.getCandidatesAreInScope());

    assertNull(c.getRemainingFilter());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an unexamined response for search
   * criteria that the server considers unindexed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnindexedUnexaminedCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(123, false,
              false, false, false, true,
              Filter.createEqualityFilter("objectClass", "person"), null);
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(c.getCountValue(), 123);

    assertFalse(c.searchIndexed());

    assertNotNull(c.getShortCircuited());
    assertFalse(c.getShortCircuited());

    assertNotNull(c.getFullyIndexed());
    assertFalse(c.getFullyIndexed());

    assertNotNull(c.getCandidatesAreInScope());
    assertTrue(c.getCandidatesAreInScope());

    assertNotNull(c.getRemainingFilter());
    assertEquals(c.getRemainingFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an upper bound response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalUpperBoundResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUpperBoundResponse(456,
              Arrays.<String>asList());
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UPPER_BOUND);

    assertEquals(c.getCountValue(), 456);

    assertTrue(c.searchIndexed());

    assertNull(c.getShortCircuited());

    assertNull(c.getFullyIndexed());

    assertNull(c.getCandidatesAreInScope());

    assertNull(c.getRemainingFilter());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an upper bound response for search
   * criteria that the server considers unindexed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnindexedUpperBoundResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUpperBoundResponse(456, false,
              false, false, false, Filter.createPresenceFilter("objectClass"),
              Arrays.<String>asList());
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UPPER_BOUND);

    assertEquals(c.getCountValue(), 456);

    assertFalse(c.searchIndexed());

    assertNotNull(c.getShortCircuited());
    assertFalse(c.getShortCircuited());

    assertNotNull(c.getFullyIndexed());
    assertFalse(c.getFullyIndexed());

    assertNotNull(c.getCandidatesAreInScope());
    assertFalse(c.getCandidatesAreInScope());

    assertNotNull(c.getRemainingFilter());
    assertEquals(c.getRemainingFilter(),
         Filter.createPresenceFilter("objectClass"));

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 0);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the control for an unknown count response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnknownCountResponse()
         throws Exception
  {
    MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(
              Arrays.asList("debug"));
    c = new MatchingEntryCountResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.37");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getCountType());
    assertEquals(c.getCountType(), MatchingEntryCountType.UNKNOWN);

    assertEquals(c.getCountValue(), -1);

    assertFalse(c.searchIndexed());

    assertNull(c.getShortCircuited());

    assertNull(c.getFullyIndexed());

    assertNull(c.getCandidatesAreInScope());

    assertNull(c.getRemainingFilter());

    assertNotNull(c.getDebugInfo());
    assertEquals(c.getDebugInfo().size(), 1);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the {@code get} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGet()
         throws Exception
  {
    SearchResult r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, null);
    assertNull(MatchingEntryCountResponseControl.get(r));

    Control[] controls =
    {
      new Control("1.2.3.4")
    };
    r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, controls);
    assertNull(MatchingEntryCountResponseControl.get(r));

    controls = new Control[]
    {
      MatchingEntryCountResponseControl.createUnknownCountResponse(null)
    };
    r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, controls);
    assertNotNull(MatchingEntryCountResponseControl.get(r));

    controls = new Control[]
    {
      new Control("1.2.3.4"),
      new Control("1.3.6.1.4.1.30221.2.5.37", false,
           MatchingEntryCountResponseControl.createUnknownCountResponse(null).
                getValue())
    };
    r = new SearchResult(-1, ResultCode.SUCCESS, null, null, null,
         0, 0, controls);
    assertNotNull(MatchingEntryCountResponseControl.get(r));
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value cannot be
   * parsed as an ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString("foo"));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an invalid count type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueInvalidCountType()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x84, 12345));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a negative exact count value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNegativeExactCount()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x80, -1));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains an upper bound value of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNegativeZeroUpperBound()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x82, -1));

    new MatchingEntryCountResponseControl("1.3.6.1.4.1.30221.2.5.37", false,
         new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a minimal set of elements for an examined count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalElementsExaminedCount()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(1234, true,
              null);

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

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("count-type", "examined-count"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true)));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.EXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.EXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a minimal set of elements for an unexamined count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalElementsUnexaminedCount()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(1234, false,
              null);

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

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("count-type", "unexamined-count"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true)));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a minimal set of elements for an upper-bound count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalElementsUpperBoundCount()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUpperBoundResponse(1234, true,
              null);

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

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("count-type", "upper-bound"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true)));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UPPER_BOUND);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UPPER_BOUND);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a minimal set of elements for an unknown count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalElementsUnknownCount()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);

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

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("search-indexed", false)));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a complete set of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllElements()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createExactCountResponse(1234,
              false, true, true, false, true,
              Filter.createEqualityFilter("objectClass", "person"),
              Arrays.asList(
                   "debug-string-1",
                   "debug-string-2"));

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

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("count-type", "unexamined-count"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true),
              new JSONField("fully-indexed", false),
              new JSONField("short-circuited", true),
              new JSONField("candidates-are-in-scope", true),
              new JSONField("remaining-filter", "(objectClass=person)"),
              new JSONField("debug-info", new JSONArray(
                   new JSONString("debug-string-1"),
                   new JSONString("debug-string-2")))));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertEquals(decodedControl.getFullyIndexed(), Boolean.FALSE);

    assertEquals(decodedControl.getShortCircuited(), Boolean.TRUE);

    assertEquals(decodedControl.getCandidatesAreInScope(), Boolean.TRUE);

    assertEquals(decodedControl.getRemainingFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertEquals(decodedControl.getDebugInfo(),
         Arrays.asList(
              "debug-string-1",
              "debug-string-2"));


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertEquals(decodedControl.getFullyIndexed(), Boolean.FALSE);

    assertEquals(decodedControl.getShortCircuited(), Boolean.TRUE);

    assertEquals(decodedControl.getCandidatesAreInScope(), Boolean.TRUE);

    assertEquals(decodedControl.getRemainingFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertEquals(decodedControl.getDebugInfo(),
         Arrays.asList(
              "debug-string-1",
              "debug-string-2"));
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
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());
  }



  /**
   * Tests the behavior when trying to decode controls with a variety of
   * count type values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlCountTypes()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);


    // An examined count with a count value.
    JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "examined-count"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true))));

    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.EXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    // An unexamined count with a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unexamined-count"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true))));

    decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNEXAMINED_COUNT);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    // An upper-bound count with a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "upper-bound"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", true))));

    decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UPPER_BOUND);

    assertEquals(decodedControl.getCountValue(), 1234);

    assertTrue(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    // An unknown count without a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("search-indexed", false))));

    decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    // An examined count without a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "examined-count"),
              new JSONField("search-indexed", false))));

    try
    {
      MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an examined count with no value");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // An unexamined count without a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unexamined-count"),
              new JSONField("search-indexed", false))));

    try
    {
      MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unexamined count with no value");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // An upper-bound count without a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "upper-bound"),
              new JSONField("search-indexed", false))));

    try
    {
      MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an upper-bound count with no value");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // An unknown count with a count value.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", false))));

    try
    {
      MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unknown count with a value");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // A unrecognized count type.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unrecognized"),
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", false))));

    try
    {
      MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unrecognized count type");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // A missing count type.
    controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-value", 1234),
              new JSONField("search-indexed", false))));

    try
    {
      MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with a missing count type");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when trying to decode a control with a missing
   * search-indexed value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingSearchIndexed()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);


    // An examined count with a count value.
    JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"))));

    MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a malformed
   * remaining filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMalformedRemainingFilter()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);


    // An examined count with a count value.
    JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("search-indexed", false),
              new JSONField("remaining-filter", "malformed"))));

    MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a debug-info value
   * that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlDebugInfoValueNotString()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);


    // An examined count with a count value.
    JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("search-indexed", false),
              new JSONField("debug-info", new JSONArray(
                   new JSONNumber(1234))))));

    MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control when the value has an
   * unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldStrict()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);


    // An examined count with a count value.
    JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("search-indexed", false),
              new JSONField("unrecognized", "foo"))));

    MatchingEntryCountResponseControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control when the value has an
   * unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlUnrecognizedFieldNOnStrict()
          throws Exception
  {
    final MatchingEntryCountResponseControl c =
         MatchingEntryCountResponseControl.createUnknownCountResponse(null);


    // An examined count with a count value.
    JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("count-type", "unknown"),
              new JSONField("search-indexed", false),
              new JSONField("unrecognized", "foo"))));


    MatchingEntryCountResponseControl decodedControl =
         MatchingEntryCountResponseControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());


    decodedControl =
         (MatchingEntryCountResponseControl)
         Control.decodeJSONControl(controlObject, false, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getCountType(),
         MatchingEntryCountType.UNKNOWN);

    assertEquals(decodedControl.getCountValue(), -1);

    assertFalse(decodedControl.searchIndexed());

    assertNull(decodedControl.getFullyIndexed());

    assertNull(decodedControl.getShortCircuited());

    assertNull(decodedControl.getCandidatesAreInScope());

    assertNull(decodedControl.getRemainingFilter());

    assertTrue(decodedControl.getDebugInfo().isEmpty());
  }
}
