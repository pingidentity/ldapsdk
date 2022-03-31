/*
 * Copyright 2014-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2022 Ping Identity Corporation
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
 * Copyright (C) 2014-2022 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the matching entry count request
 * control.
 */
public final class MatchingEntryCountRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of a matching entry count request control created with
   * the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    MatchingEntryCountRequestControl c = new MatchingEntryCountRequestControl();
    c = new MatchingEntryCountRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.36");
    assertEquals(c.getOID(),
         MatchingEntryCountRequestControl.MATCHING_ENTRY_COUNT_REQUEST_OID);

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertEquals(c.getMaxCandidatesToExamine(), 0);

    assertFalse(c.alwaysExamineCandidates());

    assertFalse(c.processSearchIfUnindexed());

    assertFalse(c.skipResolvingExplodedIndexes());

    assertNull(c.getFastShortCircuitThreshold());

    assertNull(c.getSlowShortCircuitThreshold());

    assertFalse(c.includeExtendedResponseData());

    assertFalse(c.includeDebugInfo());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of a matching entry count request control created with
   * all non-default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultConstructor()
         throws Exception
  {
    MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, 123, true, true, true, 5L,
              20L, true);
    c = new MatchingEntryCountRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.36");
    assertEquals(c.getOID(),
         MatchingEntryCountRequestControl.MATCHING_ENTRY_COUNT_REQUEST_OID);

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertEquals(c.getMaxCandidatesToExamine(), 123);

    assertTrue(c.alwaysExamineCandidates());

    assertTrue(c.processSearchIfUnindexed());

    assertTrue(c.skipResolvingExplodedIndexes());

    assertNotNull(c.getFastShortCircuitThreshold());
    assertEquals(c.getFastShortCircuitThreshold().longValue(), 5L);

    assertNotNull(c.getSlowShortCircuitThreshold());
    assertEquals(c.getSlowShortCircuitThreshold().longValue(), 20L);

    assertFalse(c.includeExtendedResponseData());

    assertTrue(c.includeDebugInfo());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of a matching entry count request control when created
   * from properties with all default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(true, properties);
    c = new MatchingEntryCountRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.36");
    assertEquals(c.getOID(),
         MatchingEntryCountRequestControl.MATCHING_ENTRY_COUNT_REQUEST_OID);

    assertTrue(c.isCritical());

    assertNotNull(c.getValue());

    assertEquals(c.getMaxCandidatesToExamine(), 0);

    assertFalse(c.alwaysExamineCandidates());

    assertFalse(c.processSearchIfUnindexed());

    assertFalse(c.skipResolvingExplodedIndexes());

    assertNull(c.getFastShortCircuitThreshold());

    assertNull(c.getSlowShortCircuitThreshold());

    assertFalse(c.includeExtendedResponseData());

    assertFalse(c.includeDebugInfo());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of a matching entry count request control when created
   * from properties with all non-default settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonDefaultProperties()
         throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();
    properties.setMaxCandidatesToExamine(123);
    properties.setAlwaysExamineCandidates(true);
    properties.setProcessSearchIfUnindexed(true);
    properties.setSkipResolvingExplodedIndexes(true);
    properties.setFastShortCircuitThreshold(5L);
    properties.setSlowShortCircuitThreshold(20L);
    properties.setIncludeExtendedResponseData(true);
    properties.setIncludeDebugInfo(true);

    MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);
    c = new MatchingEntryCountRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.36");
    assertEquals(c.getOID(),
         MatchingEntryCountRequestControl.MATCHING_ENTRY_COUNT_REQUEST_OID);

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertEquals(c.getMaxCandidatesToExamine(), 123);

    assertTrue(c.alwaysExamineCandidates());

    assertTrue(c.processSearchIfUnindexed());

    assertTrue(c.skipResolvingExplodedIndexes());

    assertNotNull(c.getFastShortCircuitThreshold());
    assertEquals(c.getFastShortCircuitThreshold().longValue(), 5L);

    assertNotNull(c.getSlowShortCircuitThreshold());
    assertEquals(c.getSlowShortCircuitThreshold().longValue(), 20L);

    assertTrue(c.includeExtendedResponseData());

    assertTrue(c.includeDebugInfo());

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
  public void testDecodeMissingValue()
         throws Exception
  {
    new MatchingEntryCountRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.36", true, null));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new MatchingEntryCountRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.36", true,
              new ASN1OctetString("foo")));
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * includes a max candidates to examine element with a negative value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceNegativeMaxCandidatesToExamine()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Integer((byte) 0x80, -1));

    new MatchingEntryCountRequestControl(
         new Control("1.3.6.1.4.1.30221.2.5.36", true,
              new ASN1OctetString(valueSequence.encode())));
  }



  /**
   * Provides test coverage for the methods used to determine whether a server
   * supports including extended response data in the matching entry count
   * response control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerSupportsExtendedResponseData()
         throws Exception
  {
    final RootDSE rootDSEWithoutSupport;
    final InMemoryDirectoryServer ds = getTestDS();
    try (LDAPConnection conn = ds.getConnection())
    {
      rootDSEWithoutSupport = conn.getRootDSE();
      assertNotNull(rootDSEWithoutSupport);
      assertFalse(rootDSEWithoutSupport.supportsFeature(
           "1.3.6.1.4.1.30221.2.12.7"));

      assertFalse(MatchingEntryCountRequestControl.
           serverSupportsExtendedResponseData(conn));
      assertFalse(MatchingEntryCountRequestControl.
           serverSupportsExtendedResponseData(rootDSEWithoutSupport));
    }


    final Entry rootDSEEntryWithSupport = rootDSEWithoutSupport.duplicate();
    rootDSEEntryWithSupport.addAttribute("supportedFeatures",
         "1.3.6.1.4.1.30221.2.12.7");
    final RootDSE rootDSEWithSupport = new RootDSE(rootDSEEntryWithSupport);
    assertTrue(MatchingEntryCountRequestControl.
         serverSupportsExtendedResponseData(rootDSEWithSupport));
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when the control uses a default set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlDefaultProperties()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

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
              new JSONField("maximum-candidates-to-examine", 0),
              new JSONField("always-examine-candidates", false),
              new JSONField("process-search-if-unindexed", false),
              new JSONField("include-debug-info", false),
              new JSONField("skip-resolving-exploded-indexes", false),
              new JSONField("include-extended-response-data", false)));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object when all properties use a non-default set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlNonDefaultProperties()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();
    properties.setMaxCandidatesToExamine(1234);
    properties.setAlwaysExamineCandidates(true);
    properties.setProcessSearchIfUnindexed(true);
    properties.setIncludeDebugInfo(true);
    properties.setSkipResolvingExplodedIndexes(true);
    properties.setFastShortCircuitThreshold(5678L);
    properties.setSlowShortCircuitThreshold(8765L);
    properties.setIncludeExtendedResponseData(true);

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

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
              new JSONField("maximum-candidates-to-examine", 1234),
              new JSONField("always-examine-candidates", true),
              new JSONField("process-search-if-unindexed", true),
              new JSONField("include-debug-info", true),
              new JSONField("skip-resolving-exploded-indexes", true),
              new JSONField("fast-short-circuit-threshold", 5678),
              new JSONField("slow-short-circuit-threshold", 8765),
              new JSONField("include-extended-response-data", true)));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 1234);

    assertTrue(decodedControl.alwaysExamineCandidates());

    assertTrue(decodedControl.processSearchIfUnindexed());

    assertTrue(decodedControl.includeDebugInfo());

    assertTrue(decodedControl.skipResolvingExplodedIndexes());

    assertEquals(decodedControl.getFastShortCircuitThreshold(),
         Long.valueOf(5678L));

    assertEquals(decodedControl.getSlowShortCircuitThreshold(),
         Long.valueOf(8765L));

    assertTrue(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 1234);

    assertTrue(decodedControl.alwaysExamineCandidates());

    assertTrue(decodedControl.processSearchIfUnindexed());

    assertTrue(decodedControl.includeDebugInfo());

    assertTrue(decodedControl.skipResolvingExplodedIndexes());

    assertEquals(decodedControl.getFastShortCircuitThreshold(),
         Long.valueOf(5678L));

    assertEquals(decodedControl.getSlowShortCircuitThreshold(),
         Long.valueOf(8765L));

    assertTrue(decodedControl.includeExtendedResponseData());
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
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();
    properties.setMaxCandidatesToExamine(1234);
    properties.setAlwaysExamineCandidates(true);
    properties.setProcessSearchIfUnindexed(true);
    properties.setIncludeDebugInfo(true);
    properties.setSkipResolvingExplodedIndexes(true);
    properties.setFastShortCircuitThreshold(5678L);
    properties.setSlowShortCircuitThreshold(8765L);
    properties.setIncludeExtendedResponseData(true);

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 1234);

    assertTrue(decodedControl.alwaysExamineCandidates());

    assertTrue(decodedControl.processSearchIfUnindexed());

    assertTrue(decodedControl.includeDebugInfo());

    assertTrue(decodedControl.skipResolvingExplodedIndexes());

    assertEquals(decodedControl.getFastShortCircuitThreshold(),
         Long.valueOf(5678L));

    assertEquals(decodedControl.getSlowShortCircuitThreshold(),
         Long.valueOf(8765L));

    assertTrue(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 1234);

    assertTrue(decodedControl.alwaysExamineCandidates());

    assertTrue(decodedControl.processSearchIfUnindexed());

    assertTrue(decodedControl.includeDebugInfo());

    assertTrue(decodedControl.skipResolvingExplodedIndexes());

    assertEquals(decodedControl.getFastShortCircuitThreshold(),
         Long.valueOf(5678L));

    assertEquals(decodedControl.getSlowShortCircuitThreshold(),
         Long.valueOf(8765L));

    assertTrue(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value is an empty object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueEmpty()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", JSONObject.EMPTY_OBJECT));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the maximum-entries-to-examine field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlyMaximumEntriesToExamine()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("maximum-candidates-to-examine", 12345))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 12345);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 12345);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the always-examine-candidates field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlyAlwaysExamineCandidates()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("always-examine-candidates", true))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertTrue(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertTrue(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the process-search-if-unindexed field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlyProcessSearchIfUnindexed()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("process-search-if-unindexed", true))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertTrue(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertTrue(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the include-debug-info field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlyIncludeDebugInfo()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-debug-info", true))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertTrue(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertTrue(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the skip-resolving-exploded-indexes field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlySkipResolvingExplodedIndexes()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("skip-resolving-exploded-indexes", true))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertTrue(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertTrue(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the fast-short-circuit-threshold field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlyFastShortCircuitThreshold()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("fast-short-circuit-threshold", 1234))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertEquals(decodedControl.getFastShortCircuitThreshold(),
         Long.valueOf(1234L));

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertEquals(decodedControl.getFastShortCircuitThreshold(),
         Long.valueOf(1234L));

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the slow-short-circuit-threshold field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlySlowShortCircuitThreshold()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("slow-short-circuit-threshold", 1234))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertEquals(decodedControl.getSlowShortCircuitThreshold(),
         Long.valueOf(1234L));

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertEquals(decodedControl.getSlowShortCircuitThreshold(),
         Long.valueOf(1234L));

    assertFalse(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains only the include-extended-response-data field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueOnlyIncludeExtendedResponseData()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("include-extended-response-data", true))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertTrue(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertTrue(decodedControl.includeExtendedResponseData());
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlValueUnrecognizedFieldStrict()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("unrecognized", "foo"))));

    MatchingEntryCountRequestControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a JSON object as a control when
   * the value object contains an unrecognized field in non-strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueUnrecognizedFieldNonStrict()
          throws Exception
  {
    final MatchingEntryCountRequestControlProperties properties =
         new MatchingEntryCountRequestControlProperties();

    final MatchingEntryCountRequestControl c =
         new MatchingEntryCountRequestControl(false, properties);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("unrecognized", "foo"))));


    MatchingEntryCountRequestControl decodedControl =
         MatchingEntryCountRequestControl.decodeJSONControl(controlObject,
              false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());


    decodedControl =
         (MatchingEntryCountRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getMaxCandidatesToExamine(), 0);

    assertFalse(decodedControl.alwaysExamineCandidates());

    assertFalse(decodedControl.processSearchIfUnindexed());

    assertFalse(decodedControl.includeDebugInfo());

    assertFalse(decodedControl.skipResolvingExplodedIndexes());

    assertNull(decodedControl.getFastShortCircuitThreshold());

    assertNull(decodedControl.getSlowShortCircuitThreshold());

    assertFalse(decodedControl.includeExtendedResponseData());
  }
}
