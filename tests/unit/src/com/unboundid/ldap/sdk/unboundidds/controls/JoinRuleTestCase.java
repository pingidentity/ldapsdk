/*
 * Copyright 2009-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2024 Ping Identity Corporation
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
 * Copyright (C) 2009-2024 Ping Identity Corporation
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



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;



/**
 * This class provides a set of test cases for the {@code JoinRule} class.
 */
public class JoinRuleTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests involving the "andJoin" type using an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDJoinTypeArray()
         throws Exception
  {
    JoinRule joinRule = JoinRule.createANDRule(
         JoinRule.createEqualityJoin("attr1", "attr2", false),
         JoinRule.createEqualityJoin("attr3", "attr3", true));
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_AND);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 2);

    assertNull(joinRule.getSourceAttribute());

    assertNull(joinRule.getTargetAttribute());

    assertFalse(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Tests the behavior when trying to create an AND join rule from an array
   * with no elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testANDJoinTypeEmptyArray()
         throws Exception
  {
    JoinRule.createANDRule();
  }



  /**
   * Performs a set of tests involving the "andJoin" type using a list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDJoinTypeList()
         throws Exception
  {
    LinkedList<JoinRule> ruleList = new LinkedList<JoinRule>();
    ruleList.add(JoinRule.createEqualityJoin("attr1", "attr2", false));
    ruleList.add(JoinRule.createEqualityJoin("attr3", "attr3", true));

    JoinRule joinRule = JoinRule.createANDRule(ruleList);
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_AND);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 2);

    assertNull(joinRule.getSourceAttribute());

    assertNull(joinRule.getTargetAttribute());

    assertFalse(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Tests the behavior when trying to create an AND join rule from a list
   * with no elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testANDJoinTypeEmptyList()
         throws Exception
  {
    JoinRule.createANDRule(new LinkedList<JoinRule>());
  }



  /**
   * Performs a set of tests involving the "orJoin" type using an array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testORJoinTypeArray()
         throws Exception
  {
    JoinRule joinRule = JoinRule.createORRule(
         JoinRule.createEqualityJoin("attr1", "attr2", false),
         JoinRule.createEqualityJoin("attr3", "attr3", true));
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_OR);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 2);

    assertNull(joinRule.getSourceAttribute());

    assertNull(joinRule.getTargetAttribute());

    assertFalse(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Tests the behavior when trying to create an OR join rule from an array
   * with no elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testORJoinTypeEmptyArray()
         throws Exception
  {
    JoinRule.createORRule();
  }



  /**
   * Performs a set of tests involving the "orJoin" type using a list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testORJoinTypeList()
         throws Exception
  {
    LinkedList<JoinRule> ruleList = new LinkedList<JoinRule>();
    ruleList.add(JoinRule.createEqualityJoin("attr1", "attr2", false));
    ruleList.add(JoinRule.createEqualityJoin("attr3", "attr3", true));

    JoinRule joinRule = JoinRule.createORRule(ruleList);
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_OR);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 2);

    assertNull(joinRule.getSourceAttribute());

    assertNull(joinRule.getTargetAttribute());

    assertFalse(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Tests the behavior when trying to create an OR join rule from a list
   * with no elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testORJoinTypeEmptyList()
         throws Exception
  {
    JoinRule.createORRule(new LinkedList<JoinRule>());
  }



  /**
   * Performs a set of tests involving the "dnJoin" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNJoinType()
         throws Exception
  {
    JoinRule joinRule = JoinRule.createDNJoin("member");
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_DN);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 0);

    assertNotNull(joinRule.getSourceAttribute());
    assertEquals(joinRule.getSourceAttribute(), "member");

    assertNull(joinRule.getTargetAttribute());

    assertFalse(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Performs a set of tests involving the "equalityJoin" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualityJoinType()
         throws Exception
  {
    JoinRule joinRule = JoinRule.createEqualityJoin("attr1", "attr2", true);
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_EQUALITY);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 0);

    assertNotNull(joinRule.getSourceAttribute());
    assertEquals(joinRule.getSourceAttribute(), "attr1");

    assertNotNull(joinRule.getTargetAttribute());
    assertEquals(joinRule.getTargetAttribute(), "attr2");

    assertTrue(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Performs a set of tests involving the "containsJoin" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testContainsJoinType()
         throws Exception
  {
    JoinRule joinRule = JoinRule.createContainsJoin("attr1", "attr2", true);
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_CONTAINS);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 0);

    assertNotNull(joinRule.getSourceAttribute());
    assertEquals(joinRule.getSourceAttribute(), "attr1");

    assertNotNull(joinRule.getTargetAttribute());
    assertEquals(joinRule.getTargetAttribute(), "attr2");

    assertTrue(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Performs a set of tests involving the "reverseDNJoin" type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReverseDNJoinType()
         throws Exception
  {
    JoinRule joinRule = JoinRule.createReverseDNJoin("manager");
    joinRule = JoinRule.decode(joinRule.encode());

    assertNotNull(joinRule);

    assertEquals(joinRule.getType(), JoinRule.JOIN_TYPE_REVERSE_DN);

    assertNotNull(joinRule.getComponents());
    assertEquals(joinRule.getComponents().length, 0);

    assertNull(joinRule.getSourceAttribute());

    assertNotNull(joinRule.getTargetAttribute());
    assertEquals(joinRule.getTargetAttribute(), "manager");

    assertFalse(joinRule.matchAll());

    assertNotNull(joinRule.toString());
  }



  /**
   * Tests the behavior when attempting to decode a rule with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidType()
         throws Exception
  {
    JoinRule.decode(new ASN1Element((byte) 0x00));
  }



  /**
   * Tests the behavior when attempting to decode an AND join rule whose value
   * is not a valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeANDValueNotSequence()
         throws Exception
  {
    JoinRule.decode(new ASN1Element((byte) 0xA0, new byte[1]));
  }



  /**
   * Tests the behavior when attempting to decode an OR join rule whose value
   * is not a valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeORValueNotSequence()
         throws Exception
  {
    JoinRule.decode(new ASN1Element((byte) 0xA1, new byte[1]));
  }



  /**
   * Tests the behavior when attempting to decode an equality join rule whose
   * value is not a valid sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeEqualityValueNotSequence()
         throws Exception
  {
    JoinRule.decode(new ASN1Element((byte) 0xA3, new byte[1]));
  }



  /**
   * Tests the behavior when trying to encode and decode a DN join rule to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNJoinRuleJSON()
          throws Exception
  {
    JoinRule rule = JoinRule.createDNJoin("sourceAttr");

    JSONObject o = rule.toJSON();
    assertNotNull(o);
    assertEquals(o,
         new JSONObject(
              new JSONField("type", "dn"),
              new JSONField("source-attribute", "sourceAttr")));

    rule = JoinRule.decodeJSONJoinRule(o, true);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_DN);
    assertEquals(rule.getSourceAttribute(), "sourceAttr");


    // Test decoding with a missing source attribute.
    o = new JSONObject(
         new JSONField("type", "dn"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no source attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in strict mode.
    o = new JSONObject(
         new JSONField("type", "dn"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("unrecognized", "foo"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an unrecognized attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in non-strict mode.
    rule = JoinRule.decodeJSONJoinRule(o, false);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_DN);
    assertEquals(rule.getSourceAttribute(), "sourceAttr");
  }



  /**
   * Tests the behavior when trying to encode and decode a reverse DN join rule
   * to and from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReverseDNJoinRuleJSON()
          throws Exception
  {
    JoinRule rule = JoinRule.createReverseDNJoin("targetAttr");

    JSONObject o = rule.toJSON();
    assertNotNull(o);
    assertEquals(o,
         new JSONObject(
              new JSONField("type", "reverse-dn"),
              new JSONField("target-attribute", "targetAttr")));

    rule = JoinRule.decodeJSONJoinRule(o, true);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_REVERSE_DN);
    assertEquals(rule.getTargetAttribute(), "targetAttr");


    // Test decoding with a missing source attribute.
    o = new JSONObject(
         new JSONField("type", "reverse-dn"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no target attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in strict mode.
    o = new JSONObject(
         new JSONField("type", "reverse-dn"),
         new JSONField("target-attribute", "targetAttr"),
         new JSONField("unrecognized", "foo"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an unrecognized attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in non-strict mode.
    rule = JoinRule.decodeJSONJoinRule(o, false);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_REVERSE_DN);
    assertEquals(rule.getTargetAttribute(), "targetAttr");
  }



  /**
   * Tests the behavior when trying to encode and decode an equality join rule
   * to and from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualityJoinRuleJSON()
          throws Exception
  {
    JoinRule rule =
         JoinRule.createEqualityJoin("sourceAttr", "targetAttr", true);

    JSONObject o = rule.toJSON();
    assertNotNull(o);
    assertEquals(o,
         new JSONObject(
              new JSONField("type", "equality"),
              new JSONField("source-attribute", "sourceAttr"),
              new JSONField("target-attribute", "targetAttr"),
              new JSONField("match-all", true)));

    rule = JoinRule.decodeJSONJoinRule(o, true);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getSourceAttribute(), "sourceAttr");
    assertEquals(rule.getTargetAttribute(), "targetAttr");
    assertEquals(rule.matchAll(), true);


    // Test decoding with a missing source attribute.
    o = new JSONObject(
         new JSONField("type", "equality"),
         new JSONField("target-attribute", "targetAttr"),
         new JSONField("match-all", true));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no source attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with a missing target attribute.
    o = new JSONObject(
         new JSONField("type", "equality"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("match-all", true));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no target attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with a missing match-all field.
    o = new JSONObject(
         new JSONField("type", "equality"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("target-attribute", "targetAttr"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no match-all field");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in strict mode.
    o = new JSONObject(
         new JSONField("type", "equality"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("target-attribute", "targetAttr"),
         new JSONField("match-all", true),
         new JSONField("unrecognized", "foo"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an unrecognized attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in non-strict mode.
    rule = JoinRule.decodeJSONJoinRule(o, false);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getSourceAttribute(), "sourceAttr");
    assertEquals(rule.getTargetAttribute(), "targetAttr");
    assertEquals(rule.matchAll(), true);
  }



  /**
   * Tests the behavior when trying to encode and decode a contains join rule
   * to and from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testContainsJoinRuleJSON()
          throws Exception
  {
    JoinRule rule =
         JoinRule.createContainsJoin("sourceAttr", "targetAttr", true);

    JSONObject o = rule.toJSON();
    assertNotNull(o);
    assertEquals(o,
         new JSONObject(
              new JSONField("type", "contains"),
              new JSONField("source-attribute", "sourceAttr"),
              new JSONField("target-attribute", "targetAttr"),
              new JSONField("match-all", true)));

    rule = JoinRule.decodeJSONJoinRule(o, true);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_CONTAINS);
    assertEquals(rule.getSourceAttribute(), "sourceAttr");
    assertEquals(rule.getTargetAttribute(), "targetAttr");
    assertEquals(rule.matchAll(), true);


    // Test decoding with a missing source attribute.
    o = new JSONObject(
         new JSONField("type", "contains"),
         new JSONField("target-attribute", "targetAttr"),
         new JSONField("match-all", true));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no source attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with a missing target attribute.
    o = new JSONObject(
         new JSONField("type", "contains"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("match-all", true));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no target attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with a missing match-all field.
    o = new JSONObject(
         new JSONField("type", "contains"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("target-attribute", "targetAttr"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no match-all field");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in strict mode.
    o = new JSONObject(
         new JSONField("type", "contains"),
         new JSONField("source-attribute", "sourceAttr"),
         new JSONField("target-attribute", "targetAttr"),
         new JSONField("match-all", true),
         new JSONField("unrecognized", "foo"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an unrecognized attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in non-strict mode.
    rule = JoinRule.decodeJSONJoinRule(o, false);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_CONTAINS);
    assertEquals(rule.getSourceAttribute(), "sourceAttr");
    assertEquals(rule.getTargetAttribute(), "targetAttr");
    assertEquals(rule.matchAll(), true);
  }



  /**
   * Tests the behavior when trying to encode and decode an AND join rule to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDJoinRuleJSON()
          throws Exception
  {
    JoinRule rule = JoinRule.createANDRule(
         JoinRule.createEqualityJoin("source1", "target1", true),
         JoinRule.createEqualityJoin("source2", "target2", false));

    JSONObject o = rule.toJSON();
    assertNotNull(o);
    assertEquals(o,
         new JSONObject(
              new JSONField("type", "and"),
              new JSONField("rules", new JSONArray(
                   new JSONObject(
                        new JSONField("type", "equality"),
                        new JSONField("source-attribute", "source1"),
                        new JSONField("target-attribute", "target1"),
                        new JSONField("match-all", true)),
                   new JSONObject(
                        new JSONField("type", "equality"),
                        new JSONField("source-attribute", "source2"),
                        new JSONField("target-attribute", "target2"),
                        new JSONField("match-all", false))))));

    rule = JoinRule.decodeJSONJoinRule(o, true);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_AND);
    assertEquals(rule.getComponents().length, 2);
    assertEquals(rule.getComponents()[0].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[0].getSourceAttribute(), "source1");
    assertEquals(rule.getComponents()[0].getTargetAttribute(), "target1");
    assertEquals(rule.getComponents()[0].matchAll(), true);
    assertEquals(rule.getComponents()[1].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[1].getSourceAttribute(), "source2");
    assertEquals(rule.getComponents()[1].getTargetAttribute(), "target2");
    assertEquals(rule.getComponents()[1].matchAll(), false);


    // Test decoding with no rules field.
    o = new JSONObject(
         new JSONField("type", "and"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no rules field");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an empty rules array.
    o = new JSONObject(
         new JSONField("type", "and"),
         new JSONField("rules", new JSONArray()));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an empty rules array");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with a rules array that contains something other than an
    // object.
    o = new JSONObject(
         new JSONField("type", "and"),
         new JSONField("rules", new JSONArray(
              new JSONString("foo"))));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with a non-object rule");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in strict mode.
    o = new JSONObject(
         new JSONField("type", "and"),
         new JSONField("rules", new JSONArray(
              new JSONObject(
                   new JSONField("type", "equality"),
                   new JSONField("source-attribute", "source1"),
                   new JSONField("target-attribute", "target1"),
                   new JSONField("match-all", true)),
              new JSONObject(
                   new JSONField("type", "equality"),
                   new JSONField("source-attribute", "source2"),
                   new JSONField("target-attribute", "target2"),
                   new JSONField("match-all", false)))),
         new JSONField("unrecognized", "foo"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an unrecognized attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in non-strict mode.
    rule = JoinRule.decodeJSONJoinRule(o, false);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_AND);
    assertEquals(rule.getComponents().length, 2);
    assertEquals(rule.getComponents()[0].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[0].getSourceAttribute(), "source1");
    assertEquals(rule.getComponents()[0].getTargetAttribute(), "target1");
    assertEquals(rule.getComponents()[0].matchAll(), true);
    assertEquals(rule.getComponents()[1].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[1].getSourceAttribute(), "source2");
    assertEquals(rule.getComponents()[1].getTargetAttribute(), "target2");
    assertEquals(rule.getComponents()[1].matchAll(), false);
  }



  /**
   * Tests the behavior when trying to encode and decode an OR join rule to and
   * from a JSON object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testORJoinRuleJSON()
          throws Exception
  {
    JoinRule rule = JoinRule.createORRule(
         JoinRule.createEqualityJoin("source1", "target1", true),
         JoinRule.createEqualityJoin("source2", "target2", false));

    JSONObject o = rule.toJSON();
    assertNotNull(o);
    assertEquals(o,
         new JSONObject(
              new JSONField("type", "or"),
              new JSONField("rules", new JSONArray(
                   new JSONObject(
                        new JSONField("type", "equality"),
                        new JSONField("source-attribute", "source1"),
                        new JSONField("target-attribute", "target1"),
                        new JSONField("match-all", true)),
                   new JSONObject(
                        new JSONField("type", "equality"),
                        new JSONField("source-attribute", "source2"),
                        new JSONField("target-attribute", "target2"),
                        new JSONField("match-all", false))))));

    rule = JoinRule.decodeJSONJoinRule(o, true);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_OR);
    assertEquals(rule.getComponents().length, 2);
    assertEquals(rule.getComponents()[0].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[0].getSourceAttribute(), "source1");
    assertEquals(rule.getComponents()[0].getTargetAttribute(), "target1");
    assertEquals(rule.getComponents()[0].matchAll(), true);
    assertEquals(rule.getComponents()[1].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[1].getSourceAttribute(), "source2");
    assertEquals(rule.getComponents()[1].getTargetAttribute(), "target2");
    assertEquals(rule.getComponents()[1].matchAll(), false);


    // Test decoding with no rules field.
    o = new JSONObject(
         new JSONField("type", "or"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with no rules field");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an empty rules array.
    o = new JSONObject(
         new JSONField("type", "or"),
         new JSONField("rules", new JSONArray()));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an empty rules array");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with a rules array that contains something other than an
    // object.
    o = new JSONObject(
         new JSONField("type", "or"),
         new JSONField("rules", new JSONArray(
              new JSONString("foo"))));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with a non-object rule");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in strict mode.
    o = new JSONObject(
         new JSONField("type", "or"),
         new JSONField("rules", new JSONArray(
              new JSONObject(
                   new JSONField("type", "equality"),
                   new JSONField("source-attribute", "source1"),
                   new JSONField("target-attribute", "target1"),
                   new JSONField("match-all", true)),
              new JSONObject(
                   new JSONField("type", "equality"),
                   new JSONField("source-attribute", "source2"),
                   new JSONField("target-attribute", "target2"),
                   new JSONField("match-all", false)))),
         new JSONField("unrecognized", "foo"));
    try
    {
      JoinRule.decodeJSONJoinRule(o, true);
      fail("Expected an exception with an unrecognized attribute");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }


    // Test decoding with an unrecognized field in non-strict mode.
    rule = JoinRule.decodeJSONJoinRule(o, false);
    assertNotNull(rule);
    assertEquals(rule.getType(), JoinRule.JOIN_TYPE_OR);
    assertEquals(rule.getComponents().length, 2);
    assertEquals(rule.getComponents()[0].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[0].getSourceAttribute(), "source1");
    assertEquals(rule.getComponents()[0].getTargetAttribute(), "target1");
    assertEquals(rule.getComponents()[0].matchAll(), true);
    assertEquals(rule.getComponents()[1].getType(),
         JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(rule.getComponents()[1].getSourceAttribute(), "source2");
    assertEquals(rule.getComponents()[1].getTargetAttribute(), "target2");
    assertEquals(rule.getComponents()[1].matchAll(), false);
  }



  /**
   * Tests the behavior when trying to decode a join rule that doesn't have a
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONObjectWithoutType()
          throws Exception
  {
    try
    {
      JoinRule.decodeJSONJoinRule(
           new JSONObject(
                new JSONField("source-attribute", "sourceAttr")),
           true);
      fail("Expected an exception due to a missing type");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }



  /**
   * Tests the behavior when trying to decode a join rule that has an
   * unrecognized type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeJSONObjectWithUnrecognizedType()
          throws Exception
  {
    try
    {
      JoinRule.decodeJSONJoinRule(
           new JSONObject(
                new JSONField("type", "unrecognized"),
                new JSONField("source-attribute", "sourceAttr")),
           true);
      fail("Expected an exception due to an unrecognized type");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.DECODING_ERROR);
    }
  }
}
