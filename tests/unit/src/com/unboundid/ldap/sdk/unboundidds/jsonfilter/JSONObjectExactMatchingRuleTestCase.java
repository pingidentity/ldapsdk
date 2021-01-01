/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.jsonfilter;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a set of test cases for the
 * {@code JSONObjectExactMatchingRule} matching rule implementation.
 */
public final class JSONObjectExactMatchingRuleTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the matching rule class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    final JSONObjectExactMatchingRule mr =
         JSONObjectExactMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "jsonObjectExactMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "1.3.6.1.4.1.30221.2.4.12");

    assertNull(mr.getOrderingMatchingRuleName());
    assertNull(mr.getOrderingMatchingRuleOID());

    assertNull(mr.getSubstringMatchingRuleName());
    assertNull(mr.getSubstringMatchingRuleOID());

    final JSONObject o1 = new JSONObject(
         new JSONField("one", 1),
         new JSONField("two", "2"));
    final JSONObject o2 = new JSONObject(
         new JSONField("two", "2"),
         new JSONField("one", 1));
    final JSONObject o3 = new JSONObject(
         new JSONField("one", "1"),
         new JSONField("two", 2));
    assertTrue(mr.valuesMatch(new ASN1OctetString(o1.toString()),
         new ASN1OctetString(o1.toString())));
    assertTrue(mr.valuesMatch(new ASN1OctetString(o1.toString()),
         new ASN1OctetString(o2.toString())));
    assertFalse(mr.valuesMatch(new ASN1OctetString(o1.toString()),
         new ASN1OctetString(o3.toString())));

    try
    {
      mr.valuesMatch(new ASN1OctetString("not a valid JSON object"),
           new ASN1OctetString(o1.toString()));
      fail("Expected a valuesMatch exception with an invalid first value");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.valuesMatch(new ASN1OctetString(o1.toString()),
           new ASN1OctetString("not a valid JSON object"));
      fail("Expected a valuesMatch exception with an invalid second value");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.matchesSubstring(new ASN1OctetString(o1.toString()),
           new ASN1OctetString("{"), new ASN1OctetString[0], null);
      fail("Expected a matchesSubstring exception");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.compareValues(new ASN1OctetString(o1.toString()),
           new ASN1OctetString(o2.toString()));
      fail("Expected a compareValues exception");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    assertNotNull(mr.normalize(new ASN1OctetString(o1.toString())));
    assertEquals(mr.normalize(new ASN1OctetString(o1.toString())),
         new ASN1OctetString(o1.toNormalizedString()));

    try
    {
      mr.normalize(new ASN1OctetString("not a valid JSON object"));
      fail("Expected a normalize exception with an invalid object");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      mr.normalizeSubstring(new ASN1OctetString("{"), (byte) 0x80);
      fail("Expected a normalizeSubstring exception");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }
}
