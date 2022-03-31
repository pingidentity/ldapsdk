/*
 * Copyright 2009-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2022 Ping Identity Corporation
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
 * Copyright (C) 2009-2022 Ping Identity Corporation
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
import java.util.LinkedList;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code JoinResultControl}
 * class.
 */
public class JoinResultControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a set of tests that cover the simple "success" constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessConstructor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: ou=match1,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: match1");

    LinkedList<JoinedEntry> joinResults = new LinkedList<JoinedEntry>();
    joinResults.add(new JoinedEntry(e, null));

    e = new Entry(
         "dn: ou=match2,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: match2");
    joinResults.add(new JoinedEntry(e, null));

    JoinResultControl c = new JoinResultControl(joinResults);
    c = new JoinResultControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.SUCCESS);

    assertNull(c.getDiagnosticMessage());

    assertNull(c.getMatchedDN());

    assertNotNull(c.getReferralURLs());
    assertTrue(c.getReferralURLs().isEmpty());

    assertNotNull(c.getJoinResults());
    assertFalse(c.getJoinResults().isEmpty());
    assertEquals(c.getJoinResults().size(), 2);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides a set of tests that cover the full constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructor()
         throws Exception
  {
    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    LinkedList<JoinedEntry> joinResults = new LinkedList<JoinedEntry>();
    joinResults.add(new JoinedEntry(e, null));

    LinkedList<String> referralURLs = new LinkedList<String>();
    referralURLs.add("ldap://server1.example.com:389/dc=example,dc=com");
    referralURLs.add("ldap://server2.example.com:389/dc=example,dc=com");

    JoinResultControl c = new JoinResultControl(ResultCode.NO_SUCH_OBJECT,
         "diagnosticMessage", "cn=matched,cn=dn", referralURLs, joinResults);
    c = new JoinResultControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(c.getDiagnosticMessage());
    assertEquals(c.getDiagnosticMessage(), "diagnosticMessage");

    assertNotNull(c.getMatchedDN());
    assertEquals(new DN(c.getMatchedDN()),
                 new DN("cn=matched,cn=dn"));

    assertNotNull(c.getReferralURLs());
    assertFalse(c.getReferralURLs().isEmpty());
    assertEquals(c.getReferralURLs().size(), 2);

    assertNotNull(c.getJoinResults());
    assertFalse(c.getJoinResults().isEmpty());
    assertEquals(c.getJoinResults().size(), 1);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides a set of tests that cover the full constructor with no join
   * results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConstructorNoResults()
         throws Exception
  {
    JoinResultControl c = new JoinResultControl(ResultCode.NO_SUCH_OBJECT,
         "diagnosticMessage", "cn=matched,cn=dn", null, null);
    c = new JoinResultControl().decodeControl(c.getOID(), c.isCritical(),
         c.getValue());

    assertNotNull(c);

    assertNotNull(c.getResultCode());
    assertEquals(c.getResultCode(), ResultCode.NO_SUCH_OBJECT);

    assertNotNull(c.getDiagnosticMessage());
    assertEquals(c.getDiagnosticMessage(), "diagnosticMessage");

    assertNotNull(c.getMatchedDN());
    assertEquals(new DN(c.getMatchedDN()),
                 new DN("cn=matched,cn=dn"));

    assertNotNull(c.getReferralURLs());
    assertTrue(c.getReferralURLs().isEmpty());

    assertNotNull(c.getJoinResults());
    assertTrue(c.getJoinResults().isEmpty());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior when trying to decode a control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new JoinResultControl(JoinResultControl.JOIN_RESULT_OID, false, null);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not a
   * valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new JoinResultControl(JoinResultControl.JOIN_RESULT_OID, false,
                          new ASN1OctetString((byte) 0x00, new byte[1]));
  }



  /**
   * Tests the behavior when trying to decode a control whose value is a
   * sequence containing an invalid element type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceHasInvalidElement()
         throws Exception
  {
    ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(0),
         new ASN1OctetString(),
         new ASN1OctetString(),
         new ASN1OctetString((byte) 0xFF, "invalidType"));

    new JoinResultControl(JoinResultControl.JOIN_RESULT_OID, false,
        new ASN1OctetString(valueSequence.encode()));
  }



  /**
   * Tests the {@code get} method with an entry that does not contain a join
   * result control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetMissing()
         throws Exception
  {
    final Control[] controls = new Control[0];

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final JoinResultControl c = JoinResultControl.get(e);
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
    final LinkedList<JoinedEntry> entryList = new LinkedList<JoinedEntry>();
    entryList.add(new JoinedEntry(generateOrgEntry("example.com", null), null));

    final Control[] controls =
    {
      new JoinResultControl(entryList)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final JoinResultControl c = JoinResultControl.get(e);
    assertNotNull(c);

    assertNotNull(c.getJoinResults());
    assertEquals(c.getJoinResults().size(), 1);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that can be parsed as a join result control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValidGenericType()
         throws Exception
  {
    final LinkedList<JoinedEntry> entryList = new LinkedList<JoinedEntry>();
    entryList.add(new JoinedEntry(generateOrgEntry("example.com", null), null));

    final Control tmp = new JoinResultControl(entryList);

    final Control[] controls =
    {
      new Control(tmp.getOID(), tmp.isCritical(), tmp.getValue())
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);

    final JoinResultControl c = JoinResultControl.get(e);
    assertNotNull(c);

    assertNotNull(c.getJoinResults());
    assertEquals(c.getJoinResults().size(), 1);
  }



  /**
   * Tests the {@code get} method with a result that contains a response control
   * that is a generic control that cannot be parsed as a join result control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetInvalidGenericType()
         throws Exception
  {
    final Control[] controls =
    {
      new Control(JoinResultControl.JOIN_RESULT_OID, false, null)
    };

    final SearchResultEntry e = new SearchResultEntry(
         generateDomainEntry("example", "dc=com"), controls);


    JoinResultControl.get(e);
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a minimal set of fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalFields()
          throws Exception
  {
    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS, null, null, null, null);

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
              new JSONField("result-code", 0),
              new JSONField("joined-entries", JSONArray.EMPTY_ARRAY)));


    JoinResultControl decodedControl =
         JoinResultControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertNull(decodedControl.getMatchedDN());

    assertNull(decodedControl.getDiagnosticMessage());

    assertTrue(decodedControl.getReferralURLs().isEmpty());

    assertTrue(decodedControl.getJoinResults().isEmpty());


    decodedControl =
         (JoinResultControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertNull(decodedControl.getMatchedDN());

    assertNull(decodedControl.getDiagnosticMessage());

    assertTrue(decodedControl.getReferralURLs().isEmpty());

    assertTrue(decodedControl.getJoinResults().isEmpty());
  }



  /**
   * Tests the behavior when trying to encode and decode the control to and
   * from a JSON object with a complete set of fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllFields()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

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
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2"))))))));


    JoinResultControl decodedControl =
         JoinResultControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getMatchedDN(), "dc=matched,dc=dn");

    assertEquals(decodedControl.getDiagnosticMessage(), "TheDiagnosticMessage");

    assertEquals(decodedControl.getReferralURLs(),
         referralURLs);

    List<JoinedEntry> decodedJoinResults = decodedControl.getJoinResults();
    assertEquals(decodedJoinResults.size(), 2);
    assertEquals(decodedJoinResults.get(0),
         new Entry(
              "dn: ou=test-1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-1"));
    assertEquals(decodedJoinResults.get(1),
         new Entry(
              "dn: ou=test-2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-2"));

    List<JoinedEntry> nestedJoinResults =
         decodedJoinResults.get(0).getNestedJoinResults();
    assertEquals(nestedJoinResults.size(), 2);
    assertEquals(nestedJoinResults.get(0),
         new Entry(
              "dn: ou=nested-1a,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1a"));
    assertEquals(nestedJoinResults.get(1),
         new Entry(
              "dn: ou=nested-1b,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1b"));

    assertTrue(nestedJoinResults.get(0).getNestedJoinResults().isEmpty());
    assertTrue(nestedJoinResults.get(1).getNestedJoinResults().isEmpty());

    assertTrue(decodedJoinResults.get(1).getNestedJoinResults().isEmpty());


    decodedControl =
         (JoinResultControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getMatchedDN(), "dc=matched,dc=dn");

    assertEquals(decodedControl.getDiagnosticMessage(), "TheDiagnosticMessage");

    assertEquals(decodedControl.getReferralURLs(),
         referralURLs);

    decodedJoinResults = decodedControl.getJoinResults();
    assertEquals(decodedJoinResults.size(), 2);
    assertEquals(decodedJoinResults.get(0),
         new Entry(
              "dn: ou=test-1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-1"));
    assertEquals(decodedJoinResults.get(1),
         new Entry(
              "dn: ou=test-2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-2"));

    nestedJoinResults = decodedJoinResults.get(0).getNestedJoinResults();
    assertEquals(nestedJoinResults.size(), 2);
    assertEquals(nestedJoinResults.get(0),
         new Entry(
              "dn: ou=nested-1a,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1a"));
    assertEquals(nestedJoinResults.get(1),
         new Entry(
              "dn: ou=nested-1b,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1b"));

    assertTrue(nestedJoinResults.get(0).getNestedJoinResults().isEmpty());
    assertTrue(nestedJoinResults.get(1).getNestedJoinResults().isEmpty());

    assertTrue(decodedJoinResults.get(1).getNestedJoinResults().isEmpty());
  }



  /**
   * Tests the behavior when trying to decode the control when the value is
   * base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    JoinResultControl decodedControl =
         JoinResultControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getMatchedDN(), "dc=matched,dc=dn");

    assertEquals(decodedControl.getDiagnosticMessage(), "TheDiagnosticMessage");

    assertEquals(decodedControl.getReferralURLs(),
         referralURLs);

    List<JoinedEntry> decodedJoinResults = decodedControl.getJoinResults();
    assertEquals(decodedJoinResults.size(), 2);
    assertEquals(decodedJoinResults.get(0),
         new Entry(
              "dn: ou=test-1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-1"));
    assertEquals(decodedJoinResults.get(1),
         new Entry(
              "dn: ou=test-2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-2"));

    List<JoinedEntry> nestedJoinResults =
         decodedJoinResults.get(0).getNestedJoinResults();
    assertEquals(nestedJoinResults.size(), 2);
    assertEquals(nestedJoinResults.get(0),
         new Entry(
              "dn: ou=nested-1a,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1a"));
    assertEquals(nestedJoinResults.get(1),
         new Entry(
              "dn: ou=nested-1b,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1b"));

    assertTrue(nestedJoinResults.get(0).getNestedJoinResults().isEmpty());
    assertTrue(nestedJoinResults.get(1).getNestedJoinResults().isEmpty());

    assertTrue(decodedJoinResults.get(1).getNestedJoinResults().isEmpty());



    decodedControl =
         (JoinResultControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getMatchedDN(), "dc=matched,dc=dn");

    assertEquals(decodedControl.getDiagnosticMessage(), "TheDiagnosticMessage");

    assertEquals(decodedControl.getReferralURLs(),
         referralURLs);

    decodedJoinResults = decodedControl.getJoinResults();
    assertEquals(decodedJoinResults.size(), 2);
    assertEquals(decodedJoinResults.get(0),
         new Entry(
              "dn: ou=test-1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-1"));
    assertEquals(decodedJoinResults.get(1),
         new Entry(
              "dn: ou=test-2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-2"));

    nestedJoinResults = decodedJoinResults.get(0).getNestedJoinResults();
    assertEquals(nestedJoinResults.size(), 2);
    assertEquals(nestedJoinResults.get(0),
         new Entry(
              "dn: ou=nested-1a,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1a"));
    assertEquals(nestedJoinResults.get(1),
         new Entry(
              "dn: ou=nested-1b,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1b"));

    assertTrue(nestedJoinResults.get(0).getNestedJoinResults().isEmpty());
    assertTrue(nestedJoinResults.get(1).getNestedJoinResults().isEmpty());

    assertTrue(decodedJoinResults.get(1).getNestedJoinResults().isEmpty());
  }



  /**
   * Tests the behavior when trying to decode a control that is missing the
   * result code field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlMissingResultCode()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a referral-urls
   * value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlReferralURLNotString()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONNumber(1234),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that is missing the joined entry values field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJoinedMissingJoinedEntryValues()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has a joined entry value that is not an object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJoinedJoinedEntryValueNotObject()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONString("foo"),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that is missing a DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJoinedEntryMissingDN()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has a DN that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlJoinedEntryDNNotString()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", 1234),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has a _nested-join-results field whose value is not an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlNestedJoinResultsNotArray()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", "foo")),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has a _nested-join-results array contains a value that is not an
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlNestedJoinResultsValueNotObject()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONString("foo"),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has an attribute field whose value is not an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlAttributeFieldValueNotArray()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONString("test-1")),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has an attribute value that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlAttributeValueNotString()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONNumber(1234),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has an unrecognized field in strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldStrict()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("unrecognized", "foo"),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));

    JoinResultControl.decodeJSONControl(controlObject, true);
  }



  /**
   * Tests the behavior when trying to decode a control with a joined entry
   * that has an unrecognized field in nonstrict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeJSONControlUnrecognizedFieldNonStrict()
          throws Exception
  {
    final List<String> referralURLs = Arrays.asList(
         "ldap://ds1.example.com:389/",
         "ldap://ds2.example.com:389/");

    final List<JoinedEntry> joinResults = Arrays.asList(
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-1,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-1"),
              Arrays.asList(
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1a,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1a"),
                        null),
                   new JoinedEntry(
                        new Entry(
                             "dn: ou=nested-1b,dc=example,dc=com",
                             "objectClass: top",
                             "objectClass: organizationalUnit",
                             "ou: nested-1b"),
                        null))),
         new JoinedEntry(
              new Entry(
                   "dn: ou=test-2,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: test-2"),
              null));

    final JoinResultControl c =
         new JoinResultControl(ResultCode.SUCCESS,
              "TheDiagnosticMessage", "dc=matched,dc=dn", referralURLs,
              joinResults);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("result-code", 0),
              new JSONField("matched-dn", "dc=matched,dc=dn"),
              new JSONField("diagnostic-message", "TheDiagnosticMessage"),
              new JSONField("referral-urls", new JSONArray(
                   new JSONString("ldap://ds1.example.com:389/"),
                   new JSONString("ldap://ds2.example.com:389/"))),
              new JSONField("unrecognized", "foo"),
              new JSONField("joined-entries", new JSONArray(
                   new JSONObject(
                        new JSONField("_dn", "ou=test-1,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-1"))),
                        new JSONField("_nested-join-results", new JSONArray(
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1a," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1a")))),
                             new JSONObject(
                                  new JSONField("_dn", "ou=nested-1b," +
                                       "dc=example,dc=com"),
                                  new JSONField("objectClass", new JSONArray(
                                       new JSONString("top"),
                                       new JSONString("organizationalUnit"))),
                                  new JSONField("ou", new JSONArray(
                                       new JSONString("nested-1b"))))))),
                   new JSONObject(
                        new JSONField("_dn", "ou=test-2,dc=example,dc=com"),
                        new JSONField("objectClass", new JSONArray(
                             new JSONString("top"),
                             new JSONString("organizationalUnit"))),
                        new JSONField("ou", new JSONArray(
                             new JSONString("test-2")))))))));


    JoinResultControl decodedControl =
         JoinResultControl.decodeJSONControl(controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getMatchedDN(), "dc=matched,dc=dn");

    assertEquals(decodedControl.getDiagnosticMessage(), "TheDiagnosticMessage");

    assertEquals(decodedControl.getReferralURLs(),
         referralURLs);

    List<JoinedEntry> decodedJoinResults = decodedControl.getJoinResults();
    assertEquals(decodedJoinResults.size(), 2);
    assertEquals(decodedJoinResults.get(0),
         new Entry(
              "dn: ou=test-1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-1"));
    assertEquals(decodedJoinResults.get(1),
         new Entry(
              "dn: ou=test-2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-2"));

    List<JoinedEntry> nestedJoinResults =
         decodedJoinResults.get(0).getNestedJoinResults();
    assertEquals(nestedJoinResults.size(), 2);
    assertEquals(nestedJoinResults.get(0),
         new Entry(
              "dn: ou=nested-1a,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1a"));
    assertEquals(nestedJoinResults.get(1),
         new Entry(
              "dn: ou=nested-1b,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1b"));

    assertTrue(nestedJoinResults.get(0).getNestedJoinResults().isEmpty());
    assertTrue(nestedJoinResults.get(1).getNestedJoinResults().isEmpty());

    assertTrue(decodedJoinResults.get(1).getNestedJoinResults().isEmpty());


    decodedControl =
         (JoinResultControl)
         Control.decodeJSONControl(controlObject, true, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertFalse(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    assertEquals(decodedControl.getResultCode(), ResultCode.SUCCESS);

    assertEquals(decodedControl.getMatchedDN(), "dc=matched,dc=dn");

    assertEquals(decodedControl.getDiagnosticMessage(), "TheDiagnosticMessage");

    assertEquals(decodedControl.getReferralURLs(),
         referralURLs);

    decodedJoinResults = decodedControl.getJoinResults();
    assertEquals(decodedJoinResults.size(), 2);
    assertEquals(decodedJoinResults.get(0),
         new Entry(
              "dn: ou=test-1,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-1"));
    assertEquals(decodedJoinResults.get(1),
         new Entry(
              "dn: ou=test-2,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test-2"));

    nestedJoinResults = decodedJoinResults.get(0).getNestedJoinResults();
    assertEquals(nestedJoinResults.size(), 2);
    assertEquals(nestedJoinResults.get(0),
         new Entry(
              "dn: ou=nested-1a,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1a"));
    assertEquals(nestedJoinResults.get(1),
         new Entry(
              "dn: ou=nested-1b,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: nested-1b"));

    assertTrue(nestedJoinResults.get(0).getNestedJoinResults().isEmpty());
    assertTrue(nestedJoinResults.get(1).getNestedJoinResults().isEmpty());

    assertTrue(decodedJoinResults.get(1).getNestedJoinResults().isEmpty());
  }
}
