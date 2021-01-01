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

import static com.unboundid.ldap.matchingrules.MatchingRule.*;



/**
 * This class provides a set of test cases for the octet string matching
 * rule.
 */
public class OctetStringMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the octet string matching rule with a number of value pairs
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

    OctetStringMatchingRule matchingRule =
         OctetStringMatchingRule.getInstance();
    assertTrue(matchingRule.valuesMatch(value1OS, value2OS),
               value1 + ", " + value2);
  }



  /**
   * Tests the octet string matching rule with a number of value pairs
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

    OctetStringMatchingRule matchingRule =
         OctetStringMatchingRule.getInstance();
    assertFalse(matchingRule.valuesMatch(value1OS, value2OS));
  }



  /**
   * Tests the {@code normalizeSubstring} method with the provided information.
   *
   * @param  rawValue         The raw value to be normalized.
   * @param  substringType    The substring type to use when performing the
   *                          normalization.
   * @param  normalizedValue  The expected normalized representation of the
   *                          provided value.
   */
  @Test(dataProvider = "testNormalizeSubstringValues")
  public void testNormalizeSubstring(String rawValue, byte substringType,
                                     String normalizedValue)
  {
    ASN1OctetString rawOS = new ASN1OctetString(rawValue);

    OctetStringMatchingRule matchingRule =
         OctetStringMatchingRule.getInstance();
    ASN1OctetString gotOS = matchingRule.normalizeSubstring(rawOS,
                                                            substringType);
    assertEquals(gotOS.stringValue(), normalizedValue);
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
      new Object[] { "foo", "foo" },
      new Object[] { "Foo", "Foo" },
      new Object[] { "fOo", "fOo" },
      new Object[] { "foO", "foO" },
      new Object[] { "FOO", "FOO" },
      new Object[] { "foo ", "foo " },
      new Object[] { " foo", " foo" },
      new Object[] { "\u00F1", "\u00F1" }, // \u00F1 = Lowercase n with a tilde
      new Object[] { "\u00D1", "\u00D1" }, // \u00D1 = Uppercase n with a tilde
      new Object[] { "jalape\u00F1o", "jalape\u00F1o" },
      new Object[] { "Jalape\u00F1o", "Jalape\u00F1o" },
      new Object[] { "", "" },
      new Object[] { " ", " " },
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
      new Object[] { "foo", "Foo" },
      new Object[] { "Foo", "foo" },
      new Object[] { "foo", "FOO" },
      new Object[] { "FOO", "foo" },
      new Object[] { "fOo", "FoO" },
      new Object[] { "foo", "bar" },
      new Object[] { "foo", "Boo" },
      new Object[] { "Foo", "boo" },
      new Object[] { "foo", "fooo" },
      new Object[] { "fooo", "foo" },
      new Object[] { "foo", "fo" },
      new Object[] { "fo", "foo" },
      new Object[] { "foo ", " Boo" },
      new Object[] {  "Foo", "boo " },
      new Object[] { "foo", "foo " },
      new Object[] { "foo ", "foo" },
      new Object[] { "foo", "foo  " },
      new Object[] { "", " " },
      new Object[] { " ", "" },
      new Object[] { "foo bar", "   FoO bAr  " },
      new Object[] { " foo", "foo" },
      new Object[] { "foo ", " foo" },
      new Object[] { " foo", "foo " },
      new Object[] { "foo bar", "foo  bar" },
      new Object[] { "foo bar", "foo     bar" },
      new Object[] { "foo  bar", "foo     bar" },
      new Object[] { "abcdefghijklmnopqrstuvwxyz",
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
      new Object[] { "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                     "abcdefghijklmnopqrstuvwxyz" },
      new Object[] { "abcdefghijklmnopqrstuvwxyz0123456789",
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" },
      new Object[] { "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                     "abcdefghijklmnopqrstuvwxyz0123456789" },
      new Object[] { " abcdefghijklmnopqrstuvwxyz0123456789",
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 " },
      new Object[] { "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ",
                     " abcdefghijklmnopqrstuvwxyz0123456789" },
      new Object[] { "jalape\u00F1o", "jalape\u00D1o" },
      new Object[] { "jalape\u00F1o ", " jalape\u00D1o" },
      new Object[] { "jalape\u00F1o ", " jalape\u00F1o" },
      new Object[] { "Jalape\u00F1o on a stick",
                     "Jalape\u00F1o  on  a  stick   " },
      new Object[] { " ", "    " },
      new Object[] { "    ", " " },
      new Object[] { "  ", "    " },
    };
  }



  /**
   * Retrieves a set of data that can be used to test the
   * {@code normalizeSubstring} method.
   *
   * @return  A set of data that can be used to test the
   *          {@code normalizeSubstring} method.
   */
  @DataProvider(name = "testNormalizeSubstringValues")
  public Object[][] getTestNormalizeSubstringValues()
  {
    return new Object[][]
    {
      new Object[] { "foo", SUBSTRING_TYPE_SUBINITIAL, "foo" },
      new Object[] { "FOO", SUBSTRING_TYPE_SUBINITIAL, "FOO" },
      new Object[] { " foo ", SUBSTRING_TYPE_SUBINITIAL, " foo " },
      new Object[] { "  foo  ", SUBSTRING_TYPE_SUBINITIAL, "  foo  " },
      new Object[] { " FOO ", SUBSTRING_TYPE_SUBINITIAL, " FOO " },
      new Object[] { "  FOO  ", SUBSTRING_TYPE_SUBINITIAL, "  FOO  " },
      new Object[] { "foo", SUBSTRING_TYPE_SUBANY, "foo" },
      new Object[] { "FOO", SUBSTRING_TYPE_SUBANY, "FOO" },
      new Object[] { " foo ", SUBSTRING_TYPE_SUBANY, " foo " },
      new Object[] { "  foo  ", SUBSTRING_TYPE_SUBANY, "  foo  " },
      new Object[] { " FOO ", SUBSTRING_TYPE_SUBANY, " FOO " },
      new Object[] { "  FOO  ", SUBSTRING_TYPE_SUBANY, "  FOO  " },
      new Object[] { "foo", SUBSTRING_TYPE_SUBFINAL, "foo" },
      new Object[] { "FOO", SUBSTRING_TYPE_SUBFINAL, "FOO" },
      new Object[] { " foo ", SUBSTRING_TYPE_SUBFINAL, " foo " },
      new Object[] { "  foo  ", SUBSTRING_TYPE_SUBFINAL, "  foo  " },
      new Object[] { " FOO ", SUBSTRING_TYPE_SUBFINAL, " FOO " },
      new Object[] { "  FOO  ", SUBSTRING_TYPE_SUBFINAL, "  FOO  " },

      new Object[]
      {
        "jalape\u00F1o",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o"
      },

      new Object[]
      {
        "JALAPE\u00D1O",
        SUBSTRING_TYPE_SUBINITIAL,
        "JALAPE\u00D1O"
      },

      new Object[]
      {
        " jalape\u00F1o ",
        SUBSTRING_TYPE_SUBINITIAL,
        " jalape\u00F1o "
      },

      new Object[]
      {
        " JALAPE\u00D1O ",
        SUBSTRING_TYPE_SUBINITIAL,
        " JALAPE\u00D1O "
      },

      new Object[]
      {
        "  jalape\u00F1o  ",
        SUBSTRING_TYPE_SUBINITIAL,
        "  jalape\u00F1o  "
      },

      new Object[]
      {
        "  JALAPE\u00D1O  ",
        SUBSTRING_TYPE_SUBINITIAL,
        "  JALAPE\u00D1O  "
      },

      new Object[]
      {
        "jalape\u00F1o on a stick",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o on a stick"
      },

      new Object[]
      {
        "jalape\u00F1o  on  a  stick",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o  on  a  stick"
      },

      new Object[]
      {
        " jalape\u00F1o  on  a  stick ",
        SUBSTRING_TYPE_SUBINITIAL,
        " jalape\u00F1o  on  a  stick "
      },

      new Object[]
      {
        "  jalape\u00F1o  on  a  stick  ",
        SUBSTRING_TYPE_SUBINITIAL,
        "  jalape\u00F1o  on  a  stick  "
      },

      new Object[]
      {
        "jalape\u00F1o",
        SUBSTRING_TYPE_SUBANY,
        "jalape\u00F1o"
      },

      new Object[]
      {
        "JALAPE\u00D1O",
        SUBSTRING_TYPE_SUBANY,
        "JALAPE\u00D1O"
      },

      new Object[]
      {
        " jalape\u00F1o ",
        SUBSTRING_TYPE_SUBANY,
        " jalape\u00F1o "
      },

      new Object[]
      {
        " JALAPE\u00D1O ",
        SUBSTRING_TYPE_SUBANY,
        " JALAPE\u00D1O "
      },

      new Object[]
      {
        "  jalape\u00F1o  ",
        SUBSTRING_TYPE_SUBANY,
        "  jalape\u00F1o  "
      },

      new Object[]
      {
        "  JALAPE\u00D1O  ",
        SUBSTRING_TYPE_SUBANY,
        "  JALAPE\u00D1O  "
      },

      new Object[]
      {
        "jalape\u00F1o on a stick",
        SUBSTRING_TYPE_SUBANY,
        "jalape\u00F1o on a stick"
      },

      new Object[]
      {
        "jalape\u00F1o  on  a  stick",
        SUBSTRING_TYPE_SUBANY,
        "jalape\u00F1o  on  a  stick"
      },

      new Object[]
      {
        " jalape\u00F1o  on  a  stick ",
        SUBSTRING_TYPE_SUBANY,
        " jalape\u00F1o  on  a  stick "
      },

      new Object[]
      {
        "  jalape\u00F1o  on  a  stick  ",
        SUBSTRING_TYPE_SUBANY,
        "  jalape\u00F1o  on  a  stick  "
      },

      new Object[]
      {
        "jalape\u00F1o",
        SUBSTRING_TYPE_SUBFINAL,
        "jalape\u00F1o"
      },

      new Object[]
      {
        "JALAPE\u00D1O",
        SUBSTRING_TYPE_SUBFINAL,
        "JALAPE\u00D1O"
      },

      new Object[]
      {
        " jalape\u00F1o ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o "
      },

      new Object[]
      {
        " JALAPE\u00D1O ",
        SUBSTRING_TYPE_SUBFINAL,
        " JALAPE\u00D1O "
      },

      new Object[]
      {
        "  jalape\u00F1o  ",
        SUBSTRING_TYPE_SUBFINAL,
        "  jalape\u00F1o  "
      },

      new Object[]
      {
        "  JALAPE\u00D1O  ",
        SUBSTRING_TYPE_SUBFINAL,
        "  JALAPE\u00D1O  "
      },

      new Object[]
      {
        "jalape\u00F1o on a stick",
        SUBSTRING_TYPE_SUBFINAL,
        "jalape\u00F1o on a stick"
      },

      new Object[]
      {
        "jalape\u00F1o  on  a  stick",
        SUBSTRING_TYPE_SUBFINAL,
        "jalape\u00F1o  on  a  stick"
      },

      new Object[]
      {
        " jalape\u00F1o  on  a  stick ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o  on  a  stick "
      },

      new Object[]
      {
        "  jalape\u00F1o  on  a  stick  ",
        SUBSTRING_TYPE_SUBFINAL,
        "  jalape\u00F1o  on  a  stick  "
      },
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
    OctetStringMatchingRule mr = OctetStringMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "octetStringMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.17");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "octetStringMatch");

    assertNotNull(mr.getOrderingMatchingRuleName());
    assertEquals(mr.getOrderingMatchingRuleName(), "octetStringOrderingMatch");

    assertNotNull(mr.getOrderingMatchingRuleOID());
    assertEquals(mr.getOrderingMatchingRuleOID(), "2.5.13.18");

    assertNotNull(mr.getOrderingMatchingRuleNameOrOID());
    assertEquals(mr.getOrderingMatchingRuleNameOrOID(),
         "octetStringOrderingMatch");

    assertNotNull(mr.getSubstringMatchingRuleName());
    assertEquals(mr.getSubstringMatchingRuleName(),
         "octetStringSubstringsMatch");

    assertNotNull(mr.getSubstringMatchingRuleOID());
    assertEquals(mr.getSubstringMatchingRuleOID(), "2.5.13.19");

    assertNotNull(mr.getSubstringMatchingRuleNameOrOID());
    assertEquals(mr.getSubstringMatchingRuleNameOrOID(),
         "octetStringSubstringsMatch");
  }
}
