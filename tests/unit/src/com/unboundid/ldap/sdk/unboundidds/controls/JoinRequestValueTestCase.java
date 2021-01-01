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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides a set of test cases for the {@code JoinRequestValue}
 * class.
 */
public class JoinRequestValueTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests with a join request value containing a minimal set
   * of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalRequestValue()
         throws Exception
  {
    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createEqualityJoin("attr1", "attr2", false),
         JoinBaseDN.createUseSearchBaseDN(), null, null, null, null, null,
         false, null);
    v = JoinRequestValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getJoinRule());
    assertEquals(v.getJoinRule().getType(), JoinRule.JOIN_TYPE_EQUALITY);
    assertEquals(v.getJoinRule().getSourceAttribute(), "attr1");
    assertEquals(v.getJoinRule().getTargetAttribute(), "attr2");

    assertNotNull(v.getBaseDN());
    assertEquals(v.getBaseDN().getType(), JoinBaseDN.BASE_TYPE_SEARCH_BASE);

    assertNull(v.getScope());

    assertNull(v.getDerefPolicy());

    assertNull(v.getSizeLimit());

    assertNull(v.getFilter());

    assertNotNull(v.getAttributes());
    assertEquals(v.getAttributes().length, 0);

    assertFalse(v.requireMatch());

    assertNull(v.getNestedJoin());

    assertNotNull(v.toString());
  }



  /**
   * Performs a set of tests with a join request value containing a full set of
   * information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullRequestValue()
         throws Exception
  {
    JoinRequestValue managerValue = new JoinRequestValue(
         JoinRule.createDNJoin("manager"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"), SearchScope.SUB,
         DereferencePolicy.NEVER, 1, null, new String[] { "*", "+" }, false,
         null);

    JoinRequestValue v = new JoinRequestValue(
         JoinRule.createDNJoin("member"),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com"),
         SearchScope.SUB, DereferencePolicy.NEVER, 1000,
         Filter.createEqualityFilter("objectClass", "person"),
         new String[] { "*", "+" }, true, managerValue);
    v = JoinRequestValue.decode(v.encode());

    assertNotNull(v);

    assertNotNull(v.getJoinRule());
    assertEquals(v.getJoinRule().getType(), JoinRule.JOIN_TYPE_DN);
    assertEquals(v.getJoinRule().getSourceAttribute(), "member");

    assertNotNull(v.getBaseDN());
    assertEquals(v.getBaseDN().getType(), JoinBaseDN.BASE_TYPE_CUSTOM);
    assertEquals(new DN(v.getBaseDN().getCustomBaseDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(v.getScope());
    assertEquals(v.getScope(), SearchScope.SUB);

    assertNotNull(v.getDerefPolicy());
    assertEquals(v.getDerefPolicy(), DereferencePolicy.NEVER);

    assertNotNull(v.getSizeLimit());
    assertEquals(v.getSizeLimit(), Integer.valueOf(1000));

    assertNotNull(v.getFilter());
    assertEquals(v.getFilter(), Filter.create("(objectClass=person)"));

    assertNotNull(v.getAttributes());
    assertEquals(v.getAttributes().length, 2);
    assertEquals(v.getAttributes()[0], "*");
    assertEquals(v.getAttributes()[1], "+");

    assertTrue(v.requireMatch());

    assertNotNull(v.getNestedJoin());
    assertEquals(v.getNestedJoin().getJoinRule().getType(),
                 JoinRule.JOIN_TYPE_DN);
    assertEquals(v.getNestedJoin().getJoinRule().getSourceAttribute(),
                 "manager");

    assertNotNull(v.toString());
  }



  /**
   * Tests the behavior of the decode method with a value that is not a
   * sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueNotSequence()
         throws Exception
  {
    JoinRequestValue.decode(new ASN1Element((byte) 0x30, new byte[1]));
  }



  /**
   * Tests the behavior of the decode method with a value sequence containing an
   * element with an invalid type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeValueSequenceInvalidType()
         throws Exception
  {
    ASN1Sequence valueSequence = new ASN1Sequence(
         JoinRule.createDNJoin("member").encode(),
         JoinBaseDN.createUseCustomBaseDN("dc=example,dc=com").encode(),
         new ASN1Element((byte) 0x00, new byte[0]));

    JoinRequestValue.decode(valueSequence);
  }
}
