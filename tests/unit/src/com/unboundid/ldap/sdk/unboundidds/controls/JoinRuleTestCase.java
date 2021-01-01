/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
import com.unboundid.util.LDAPSDKUsageException;



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
}
