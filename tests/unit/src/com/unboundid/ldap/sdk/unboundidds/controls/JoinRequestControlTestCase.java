/*
 * Copyright 2009-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2023 Ping Identity Corporation
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
 * Copyright (C) 2009-2023 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Base64;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code JoinRequestControl}
 * class.
 */
public class JoinRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests covering the join request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJoinRequestControl()
         throws Exception
  {
    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("member"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"), null, null,
         null, null, null, false, null);

    JoinRequestControl c = new JoinRequestControl(v);
    c = new JoinRequestControl(c);

    assertNotNull(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.9");

    assertTrue(c.isCritical());

    assertNotNull(c.getJoinRequestValue());
    assertEquals(c.getJoinRequestValue().getJoinRule().getType(),
                 JoinRule.JOIN_TYPE_DN);
    assertEquals(c.getJoinRequestValue().getJoinRule().getSourceAttribute(),
                 "member");

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of attempting to decode a control with no value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeNoValue()
         throws Exception
  {
    new JoinRequestControl(new Control("1.3.6.1.4.1.30221.2.5.9", true));
  }



  /**
   * Tests the behavior of attempting to decode a control whose value is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    new JoinRequestControl(new Control("1.3.6.1.4.1.30221.2.5.9", true,
              new ASN1OctetString(new byte[1])));
  }



  /**
   * Tests the behavior with a join request control that has a minimal set of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlMinimalElements()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("require-match", false)));


    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SEARCH_BASE);

    assertNull(decodedValue.getScope());

    assertNull(decodedValue.getDerefPolicy());

    assertNull(decodedValue.getSizeLimit());

    assertNull(decodedValue.getFilter());

    assertEquals(decodedValue.getAttributes().length, 0);

    assertFalse(decodedValue.requireMatch());

    assertNull(decodedValue.getNestedJoin());


    decodedControl =
         (JoinRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SEARCH_BASE);

    assertNull(decodedValue.getScope());

    assertNull(decodedValue.getDerefPolicy());

    assertNull(decodedValue.getSizeLimit());

    assertNull(decodedValue.getFilter());

    assertEquals(decodedValue.getAttributes().length, 0);

    assertFalse(decodedValue.requireMatch());

    assertNull(decodedValue.getNestedJoin());
  }



  /**
   * Tests the behavior with a join request control that has a complete set of
   * elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToJSONControlAllElements()
          throws Exception
  {
    final JoinRequestValue nestedValue = new JoinRequestValue(
         JoinRule.createDNJoin("secretary"),
         JoinBaseDN.createUseSourceEntryDN(), null, null, null, null, null,
         false, null);

    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"),
         SearchScope.SUB, DereferencePolicy.NEVER, 1234,
         Filter.createEqualityFilter("objectClass", "person"),
         new String[] { "uid", "givenName", "sn", "cn", "mail" },
         true, nestedValue);
    final JoinRequestControl c = new JoinRequestControl(v);

    final JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-custom-base-dn"),
              new JSONField("base-dn-value", "dc=example,dc=com"),
              new JSONField("scope", "wholeSubtree"),
              new JSONField("alias-dereferencing-behavior",
                   "neverDerefAliases"),
              new JSONField("size-limit", 1234),
              new JSONField("filter", "(objectClass=person)"),
              new JSONField("attributes", new JSONArray(
                   new JSONString("uid"),
                   new JSONString("givenName"),
                   new JSONString("sn"),
                   new JSONString("cn"),
                   new JSONString("mail"))),
              new JSONField("require-match", true),
              new JSONField("nested-join", new JSONObject(
                   new JSONField("join-rule", new JSONObject(
                        new JSONField("type", "dn"),
                        new JSONField("source-attribute", "secretary"))),
                   new JSONField("base-dn-type", "use-source-entry-dn"),
                   new JSONField("require-match", false)))));


    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_CUSTOM);
    assertEquals(decodedValue.getBaseDN().getCustomBaseDN(),
         "dc=example,dc=com");

    assertEquals(decodedValue.getScope(), SearchScope.SUB);

    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.NEVER);

    assertEquals(decodedValue.getSizeLimit(), Integer.valueOf(1234));

    assertEquals(decodedValue.getFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertEquals(decodedValue.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });

    assertTrue(decodedValue.requireMatch());

    JoinRequestValue nestedJoin = decodedValue.getNestedJoin();
    assertNotNull(nestedJoin);

    assertEquals(nestedJoin.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(nestedJoin.getJoinRule().getSourceAttribute(), "secretary");

    assertEquals(nestedJoin.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN);

    assertNull(nestedJoin.getScope());

    assertNull(nestedJoin.getDerefPolicy());

    assertNull(nestedJoin.getSizeLimit());

    assertNull(nestedJoin.getFilter());

    assertEquals(nestedJoin.getAttributes().length, 0);

    assertFalse(nestedJoin.requireMatch());

    assertNull(nestedJoin.getNestedJoin());


    decodedControl =
         (JoinRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_CUSTOM);
    assertEquals(decodedValue.getBaseDN().getCustomBaseDN(),
         "dc=example,dc=com");

    assertEquals(decodedValue.getScope(), SearchScope.SUB);

    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.NEVER);

    assertEquals(decodedValue.getSizeLimit(), Integer.valueOf(1234));

    assertEquals(decodedValue.getFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertEquals(decodedValue.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });

    assertTrue(decodedValue.requireMatch());

    nestedJoin = decodedValue.getNestedJoin();
    assertNotNull(nestedJoin);

    assertEquals(nestedJoin.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(nestedJoin.getJoinRule().getSourceAttribute(), "secretary");

    assertEquals(nestedJoin.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN);

    assertNull(nestedJoin.getScope());

    assertNull(nestedJoin.getDerefPolicy());

    assertNull(nestedJoin.getSizeLimit());

    assertNull(nestedJoin.getFilter());

    assertEquals(nestedJoin.getAttributes().length, 0);

    assertFalse(nestedJoin.requireMatch());

    assertNull(nestedJoin.getNestedJoin());
  }



  /**
   * Tests the behavior when trying to decode a control when the value is
   * base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONControlValueBase64()
          throws Exception
  {
    final JoinRequestValue nestedValue = new JoinRequestValue(
         JoinRule.createDNJoin("secretary"),
         JoinBaseDN.createUseSourceEntryDN(), null, null, null, null, null,
         false, null);

    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"),
         SearchScope.SUB, DereferencePolicy.NEVER, 1234,
         Filter.createEqualityFilter("objectClass", "person"),
         new String[] { "uid", "givenName", "sn", "cn", "mail" },
         true, nestedValue);
    final JoinRequestControl c = new JoinRequestControl(v);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-base64", Base64.encode(c.getValue().getValue())));


    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_CUSTOM);
    assertEquals(decodedValue.getBaseDN().getCustomBaseDN(),
         "dc=example,dc=com");

    assertEquals(decodedValue.getScope(), SearchScope.SUB);

    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.NEVER);

    assertEquals(decodedValue.getSizeLimit(), Integer.valueOf(1234));

    assertEquals(decodedValue.getFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertEquals(decodedValue.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });

    assertTrue(decodedValue.requireMatch());

    JoinRequestValue nestedJoin = decodedValue.getNestedJoin();
    assertNotNull(nestedJoin);

    assertEquals(nestedJoin.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(nestedJoin.getJoinRule().getSourceAttribute(), "secretary");

    assertEquals(nestedJoin.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN);

    assertNull(nestedJoin.getScope());

    assertNull(nestedJoin.getDerefPolicy());

    assertNull(nestedJoin.getSizeLimit());

    assertNull(nestedJoin.getFilter());

    assertEquals(nestedJoin.getAttributes().length, 0);

    assertFalse(nestedJoin.requireMatch());

    assertNull(nestedJoin.getNestedJoin());


    decodedControl =
         (JoinRequestControl)
         Control.decodeJSONControl(controlObject, true, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_CUSTOM);
    assertEquals(decodedValue.getBaseDN().getCustomBaseDN(),
         "dc=example,dc=com");

    assertEquals(decodedValue.getScope(), SearchScope.SUB);

    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.NEVER);

    assertEquals(decodedValue.getSizeLimit(), Integer.valueOf(1234));

    assertEquals(decodedValue.getFilter(),
         Filter.createEqualityFilter("objectClass", "person"));

    assertEquals(decodedValue.getAttributes(),
         new String[] { "uid", "givenName", "sn", "cn", "mail" });

    assertTrue(decodedValue.requireMatch());

    nestedJoin = decodedValue.getNestedJoin();
    assertNotNull(nestedJoin);

    assertEquals(nestedJoin.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(nestedJoin.getJoinRule().getSourceAttribute(), "secretary");

    assertEquals(nestedJoin.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN);

    assertNull(nestedJoin.getScope());

    assertNull(nestedJoin.getDerefPolicy());

    assertNull(nestedJoin.getSizeLimit());

    assertNull(nestedJoin.getFilter());

    assertEquals(nestedJoin.getAttributes().length, 0);

    assertFalse(nestedJoin.requireMatch());

    assertNull(nestedJoin.getNestedJoin());
  }



  /**
   * Tests the behavior decoding a control with no join rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoJoinRule()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    try
    {
      final JSONObject controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with no join rule");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior decoding a control with a malformed join rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedJoinRule()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    try
    {
      final JSONObject controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", JSONObject.EMPTY_OBJECT),
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with no join rule");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when encoding and decoding controls with various base
   * DN values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSONBaseDN()
          throws Exception
  {
    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    JoinRequestControl c = new JoinRequestControl(v);

    JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("require-match", false)));

    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SEARCH_BASE);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSourceEntryDN(),
         null, null, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-source-entry-dn"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SOURCE_ENTRY_DN);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"),
         null, null, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-custom-base-dn"),
              new JSONField("base-dn-value", "dc=example,dc=com"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_CUSTOM);
    assertEquals(decodedValue.getBaseDN().getCustomBaseDN(),
         "dc=example,dc=com");


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with no base DN type");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "unrecognized"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unrecognized base DN type");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("base-dn-value", "dc=not,dc=allowed"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with a base DN value for use search base DN");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-source-entry-dn"),
                new JSONField("base-dn-value", "dc=not,dc=allowed"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with a base DN value for use source entry " +
           "DN");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-custom-base-dn"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception without a base DN value for use custom " +
           "base DN");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when encoding and decoding controls with various search
   * scope values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSONScope()
          throws Exception
  {
    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         SearchScope.BASE, null, null, null, null, false, null);
    JoinRequestControl c = new JoinRequestControl(v);

    JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("scope", "baseObject"),
              new JSONField("require-match", false)));

    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getScope(), SearchScope.BASE);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         SearchScope.ONE, null, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("scope", "singleLevel"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getScope(), SearchScope.ONE);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         SearchScope.SUB, null, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("scope", "wholeSubtree"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getScope(), SearchScope.SUB);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         SearchScope.SUBORDINATE_SUBTREE, null, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("scope", "subordinateSubtree"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getScope(), SearchScope.SUBORDINATE_SUBTREE);


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("scope", "unrecognized"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unrecognized scope");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when encoding and decoding controls with various alias
   * dereferencing behaviors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSONDerefBehavior()
          throws Exception
  {
    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, DereferencePolicy.NEVER, null, null, null, false, null);
    JoinRequestControl c = new JoinRequestControl(v);

    JSONObject controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("alias-dereferencing-behavior",
                   "neverDerefAliases"),
              new JSONField("require-match", false)));

    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.NEVER);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, DereferencePolicy.SEARCHING, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("alias-dereferencing-behavior",
                   "derefInSearching"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.SEARCHING);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, DereferencePolicy.FINDING, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("alias-dereferencing-behavior",
                   "derefInFindingBaseObj"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.FINDING);


    v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, DereferencePolicy.ALWAYS, null, null, null, false, null);
    c = new JoinRequestControl(v);

    controlObject = c.toJSONControl();

    assertNotNull(controlObject);
    assertEquals(controlObject.getFields().size(), 4);

    assertEquals(controlObject.getFieldAsString("oid"), c.getOID());

    assertNotNull(controlObject.getFieldAsString("control-name"));
    assertFalse(controlObject.getFieldAsString("control-name").isEmpty());
    assertFalse(controlObject.getFieldAsString("control-name").equals(
         controlObject.getFieldAsString("oid")));

    assertEquals(controlObject.getFieldAsBoolean("criticality"),
         Boolean.TRUE);

    assertFalse(controlObject.hasField("value-base64"));

    assertEquals(controlObject.getFieldAsObject("value-json"),
         new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("alias-dereferencing-behavior",
                   "derefAlways"),
              new JSONField("require-match", false)));

    decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, true);
    assertNotNull(decodedControl);

    decodedValue = decodedControl.getJoinRequestValue();
    assertEquals(decodedValue.getDerefPolicy(), DereferencePolicy.ALWAYS);


    try
    {
      controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("alias-dereferencing-behavior", "unrecognized"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unrecognized deref behavior");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior decoding a control with a malformed filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedFilter()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    try
    {
      final JSONObject controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("filter", "malformed"),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with a malformed filter");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior decoding a control with a requested attribute value
   * that is not a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeNotString()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    try
    {
      final JSONObject controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-search-base-dn"),
                new JSONField("attributes", new JSONArray(
                     new JSONNumber(1234))),
                new JSONField("require-match", false))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with non-string attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior decoding a control with a missing require-Match flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingRequireMatch()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    try
    {
      final JSONObject controlObject = new JSONObject(
           new JSONField("oid", c.getOID()),
           new JSONField("criticality", c.isCritical()),
           new JSONField("value-json", new JSONObject(
                new JSONField("join-rule", new JSONObject(
                     new JSONField("type", "dn"),
                     new JSONField("source-attribute", "manager"))),
                new JSONField("base-dn-type", "use-search-base-dn"))));
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with a missing require-match flag");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior decoding a control with an unrecognized field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnrecognizedField()
          throws Exception
  {
    final JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("manager"), JoinBaseDN.createUseSearchBaseDN(),
         null, null, null, null, null, false, null);
    final JoinRequestControl c = new JoinRequestControl(v);

    final JSONObject controlObject = new JSONObject(
         new JSONField("oid", c.getOID()),
         new JSONField("criticality", c.isCritical()),
         new JSONField("value-json", new JSONObject(
              new JSONField("join-rule", new JSONObject(
                   new JSONField("type", "dn"),
                   new JSONField("source-attribute", "manager"))),
              new JSONField("base-dn-type", "use-search-base-dn"),
              new JSONField("require-match", false),
              new JSONField("unrecognized", "foo"))));


    try
    {
      JoinRequestControl.decodeJSONControl(controlObject, true);
      fail("Expected an exception with an unrecognized field");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    JoinRequestControl decodedControl = JoinRequestControl.decodeJSONControl(
         controlObject, false);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    JoinRequestValue decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SEARCH_BASE);

    assertNull(decodedValue.getScope());

    assertNull(decodedValue.getDerefPolicy());

    assertNull(decodedValue.getSizeLimit());

    assertNull(decodedValue.getFilter());

    assertEquals(decodedValue.getAttributes().length, 0);

    assertFalse(decodedValue.requireMatch());

    assertNull(decodedValue.getNestedJoin());


    decodedControl =
         (JoinRequestControl)
         Control.decodeJSONControl(controlObject, false, true);
    assertNotNull(decodedControl);

    assertEquals(decodedControl.getOID(), c.getOID());

    assertTrue(decodedControl.isCritical());

    assertNotNull(decodedControl.getValue());

    decodedValue = decodedControl.getJoinRequestValue();

    assertEquals(decodedValue.getJoinRule().getType(),
         JoinRule.JOIN_TYPE_DN);
    assertEquals(decodedValue.getJoinRule().getSourceAttribute(), "manager");

    assertEquals(decodedValue.getBaseDN().getType(),
         JoinBaseDN.BASE_TYPE_SEARCH_BASE);

    assertNull(decodedValue.getScope());

    assertNull(decodedValue.getDerefPolicy());

    assertNull(decodedValue.getSizeLimit());

    assertNull(decodedValue.getFilter());

    assertEquals(decodedValue.getAttributes().length, 0);

    assertFalse(decodedValue.requireMatch());

    assertNull(decodedValue.getNestedJoin());
  }
}
