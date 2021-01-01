/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.matchingrules;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;

import static com.unboundid.ldap.matchingrules.MatchingRule.*;



/**
 * This class provides a set of test cases for the telephone number matching
 * rule.
 */
public class TelephoneNumberMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the telephone number matching rule with a number of value pairs
   * that should be considered matches.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues")
  public void testMatchingValues(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1);
    ASN1OctetString value2OS = new ASN1OctetString(value2);

    TelephoneNumberMatchingRule matchingRule =
         TelephoneNumberMatchingRule.getInstance();
    assertTrue(matchingRule.valuesMatch(value1OS, value2OS),
               value1 + ", " + value2);
  }



  /**
   * Tests the telephone number matching rule with a number of value pairs
   * that should not be considered matches.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testNonMatchingValues")
  public void testNonMatchingValues(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1);
    ASN1OctetString value2OS = new ASN1OctetString(value2);

    TelephoneNumberMatchingRule matchingRule =
         TelephoneNumberMatchingRule.getInstance();
    assertFalse(matchingRule.valuesMatch(value1OS, value2OS));
  }



  /**
   * Tests the telephone number matching rule with a number of invalid values.
   *
   * @param  invalidValue  An invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidValues",
        expectedExceptions = { LDAPException.class })
  public void testNormalizeInvalid(String invalidValue)
         throws Exception
  {
    TelephoneNumberMatchingRule matchingRule =
         TelephoneNumberMatchingRule.getInstance();
    matchingRule.normalize(new ASN1OctetString(invalidValue));
  }



  /**
   * Tests the {@code normalizeSubstring} method with the provided information.
   *
   * @param  rawValue         The raw value to be normalized.
   * @param  normalizedValue  The expected normalized representation of the
   *                          provided value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues")
  public void testNormalizeSubstring(String rawValue, String normalizedValue)
         throws Exception
  {
    ASN1OctetString rawOS = new ASN1OctetString(rawValue);

    TelephoneNumberMatchingRule matchingRule =
         TelephoneNumberMatchingRule.getInstance();

    assertEquals(matchingRule.normalizeSubstring(rawOS,
         SUBSTRING_TYPE_SUBINITIAL).stringValue(), normalizedValue);
    assertEquals(matchingRule.normalizeSubstring(rawOS,
         SUBSTRING_TYPE_SUBANY).stringValue(), normalizedValue);
    assertEquals(matchingRule.normalizeSubstring(rawOS,
         SUBSTRING_TYPE_SUBFINAL).stringValue(), normalizedValue);
  }



  /**
   * Tests the telephone number matching rule to ensure that it does not allow
   * ordering matching.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues",
        expectedExceptions = { LDAPException.class })
  public void testOrderingMatching(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1);
    ASN1OctetString value2OS = new ASN1OctetString(value2);

    TelephoneNumberMatchingRule matchingRule =
         TelephoneNumberMatchingRule.getInstance();
    matchingRule.compareValues(value1OS, value2OS);
  }



  /**
   * Retrieves a set of value pairs that should be considered equal according to
   * the matching rule.
   *
   * @return  A set of value pairs that should be considered equal according to
   *          the matching rule.
   */
  @DataProvider(name = "testMatchingValues")
  public Object[][] getTestMatchingValues()
  {
    return new Object[][]
    {
      new Object[] { "+1 123 456 7890", "+11234567890" },
      new Object[] { "+1 123-456-7890", "+11234567890" },
      new Object[] { "", "" },
      new Object[] { " ", "" },
      new Object[] { "  ", "" },
      new Object[] { "1", "1" },
      new Object[] { " 1 ", "1" },
      new Object[] { "0123456789", "0123456789" },
      new Object[] { " 0 1 2 3 4    5 6 7 8 9 ", "0123456789" },
      new Object[] { "+1", "+1" },
      new Object[] { " +1 ", "+1" },
      new Object[] { "+0123456789", "+0123456789" },
      new Object[] { " +0-1-2-3-4    5-6-7-8-9 ", "+0123456789" },
      new Object[] { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                          "0123456789'()+,-.=/:? ",
                     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                          "0123456789'()+,.=/:?"},
    };
  }



  /**
   * Retrieves a set of value pairs that should not be considered equal
   * according to the matching rule.
   *
   * @return  A set of value pairs that not should be considered equal according
   *          to the matching rule.
   */
  @DataProvider(name = "testNonMatchingValues")
  public Object[][] getTestNonMatchingValues()
  {
    return new Object[][]
    {
      new Object[] { "0", "1" },
      new Object[] { "0 1 2 3 4 5   6 7 8 9", "12345" },
    };
  }



  /**
   * Retrieves a set of invalid values that cannot be parsed as telephone
   * numbers.
   *
   * @return  A set of invalid values that cannot be parsed as telephone
   *          numbers.
   */
  @DataProvider(name = "testInvalidValues")
  public Object[][] getTestInvalidValues()
  {
    return new Object[][]
    {
      new Object[] { "\"" },
      new Object[] { "`" },
      new Object[] { "~" },
      new Object[] { "!" },
      new Object[] { "@" },
      new Object[] { "#" },
      new Object[] { "$" },
      new Object[] { "%" },
      new Object[] { "^" },
      new Object[] { "&" },
      new Object[] { "*" },
      new Object[] { "_" },
      new Object[] { "[" },
      new Object[] { "]" },
      new Object[] { "{" },
      new Object[] { "}" },
      new Object[] { "\\" },
      new Object[] { "|" },
      new Object[] { ";" },
      new Object[] { "<" },
      new Object[] { ">" }
    };
  }



  /**
   * Provides test coverage for the methods used to retrieve the names and OIDs
   * for the matching rules.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNamesAndOIDs()
         throws Exception
  {
    TelephoneNumberMatchingRule mr = TelephoneNumberMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "telephoneNumberMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.20");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "telephoneNumberMatch");

    assertNull(mr.getOrderingMatchingRuleName());

    assertNull(mr.getOrderingMatchingRuleOID());

    assertNull(mr.getOrderingMatchingRuleNameOrOID());

    assertNotNull(mr.getSubstringMatchingRuleName());
    assertEquals(mr.getSubstringMatchingRuleName(),
         "telephoneNumberSubstringsMatch");

    assertNotNull(mr.getSubstringMatchingRuleOID());
    assertEquals(mr.getSubstringMatchingRuleOID(), "2.5.13.21");

    assertNotNull(mr.getSubstringMatchingRuleNameOrOID());
    assertEquals(mr.getSubstringMatchingRuleNameOrOID(),
         "telephoneNumberSubstringsMatch");
  }
}
