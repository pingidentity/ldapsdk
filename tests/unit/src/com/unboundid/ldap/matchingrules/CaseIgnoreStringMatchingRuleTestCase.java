/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
 * This class provides a set of test cases for the case ignore string matching
 * rule.
 */
public class CaseIgnoreStringMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the case ignore string matching rule with a number of value pairs
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

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    assertTrue(matchingRule.valuesMatch(value1OS, value2OS));
  }



  /**
   * Tests the case ignore string matching rule with a number of value pairs
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

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
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

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
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
      new Object[] { "foo", "Foo" },
      new Object[] { "Foo", "foo" },
      new Object[] { "foo", "FOO" },
      new Object[] { "FOO", "foo" },
      new Object[] { "fOo", "FoO" },
      new Object[] { "foo", "foo " },
      new Object[] { "foo ", "foo" },
      new Object[] { "foo ", "foo " },
      new Object[] { "foo", "foo  " },
      new Object[] { "foo", " foo" },
      new Object[] { " foo", "foo" },
      new Object[] { " foo", " foo" },
      new Object[] { "foo ", " foo" },
      new Object[] { " foo", "foo " },
      new Object[] { "foo bar", "foo  bar" },
      new Object[] { "foo bar", "foo     bar" },
      new Object[] { "foo  bar", "foo     bar" },
      new Object[] { "foo bar", "   FoO bAr  " },
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
      new Object[] { "\u00F1", "\u00F1" }, // \u00F1 = Lowercase n with a tilde
      new Object[] { "\u00F1", "\u00D1" }, // \u00D1 = Uppercase n with a tilde
      new Object[] { "jalape\u00F1o", "jalape\u00F1o" },
      new Object[] { "jalape\u00F1o", "jalape\u00D1o" },
      new Object[] { "jalape\u00F1o", "Jalape\u00F1o" },
      new Object[] { "jalape\u00F1o ", " jalape\u00F1o" },
      new Object[] { "jalape\u00F1o ", " jalape\u00D1o" },
      new Object[] { "jalape\u00F1o ", " Jalape\u00F1o" },
      new Object[] { "jalape\u00F1o on a stick",
                     "Jalape\u00F1o  on  a  stick   " },
      new Object[] { "", "" },
      new Object[] { " ", " " },
      new Object[] { " ", "    " },
      new Object[] { "    ", " " },
      new Object[] { "  ", "    " },

      new Object[]
      {
        "Latin Capital Letter OO \uA74E",
        "latin capital letter oo \uA74F"
      },

      new Object[]
      {
        "Latin  Capital  Letter  OO \uA74E",
        "latin capital letter oo \uA74F"
      },

      new Object[]
      {
        "Deseret Capital Letter Long I \uD801\uDC00",
        "deseret capital letter long i \uD801\uDC28"
      },

      new Object[]
      {
        "Deseret Capital Letter Long I \uD801\uDC00",
        "deseret  capital  letter  long  i  \uD801\uDC28"
      },

      new Object[]
      {
        "Smiley face emoji \uD83D\uDE00",
        "smiley face emoji \uD83D\uDE00"
      },

      new Object[]
      {
        "United States Flag Emoji \uD83C\uDDFA\uD83C\uDDF8",
        "united states flag emoji \uD83C\uDDFA\uD83C\uDDF8"
      }
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
      new Object[] { "foo", "bar" },
      new Object[] { "foo", "Boo" },
      new Object[] { "Foo", "boo" },
      new Object[] { "foo", "fooo" },
      new Object[] { "fooo", "foo" },
      new Object[] { "foo", "fo" },
      new Object[] { "fo", "foo" },
      new Object[] { "foo ", " Boo" },
      new Object[] {  "Foo", "boo " },
      new Object[] { "", " " },
      new Object[] { " ", "" },
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
      new Object[] { "FOO", SUBSTRING_TYPE_SUBINITIAL, "foo" },
      new Object[] { " foo ", SUBSTRING_TYPE_SUBINITIAL, "foo " },
      new Object[] { "  foo  ", SUBSTRING_TYPE_SUBINITIAL, "foo " },
      new Object[] { " FOO ", SUBSTRING_TYPE_SUBINITIAL, "foo " },
      new Object[] { "  FOO  ", SUBSTRING_TYPE_SUBINITIAL, "foo " },
      new Object[] { "foo", SUBSTRING_TYPE_SUBANY, "foo" },
      new Object[] { "FOO", SUBSTRING_TYPE_SUBANY, "foo" },
      new Object[] { " foo ", SUBSTRING_TYPE_SUBANY, " foo " },
      new Object[] { "  foo  ", SUBSTRING_TYPE_SUBANY, " foo " },
      new Object[] { " FOO ", SUBSTRING_TYPE_SUBANY, " foo " },
      new Object[] { "  FOO  ", SUBSTRING_TYPE_SUBANY, " foo " },
      new Object[] { "foo", SUBSTRING_TYPE_SUBFINAL, "foo" },
      new Object[] { "FOO", SUBSTRING_TYPE_SUBFINAL, "foo" },
      new Object[] { " foo ", SUBSTRING_TYPE_SUBFINAL, " foo" },
      new Object[] { "  foo  ", SUBSTRING_TYPE_SUBFINAL, " foo" },
      new Object[] { " FOO ", SUBSTRING_TYPE_SUBFINAL, " foo" },
      new Object[] { "  FOO  ", SUBSTRING_TYPE_SUBFINAL, " foo" },

      new Object[] { "foo bar", SUBSTRING_TYPE_SUBINITIAL, "foo bar" },
      new Object[] { " foo bar ", SUBSTRING_TYPE_SUBINITIAL, "foo bar " },
      new Object[] { " foo  bar ", SUBSTRING_TYPE_SUBINITIAL, "foo bar " },
      new Object[] { "  foo  bar  ", SUBSTRING_TYPE_SUBINITIAL, "foo bar " },
      new Object[] { "  foo   bar  ", SUBSTRING_TYPE_SUBINITIAL, "foo bar " },
      new Object[] { "foo bar", SUBSTRING_TYPE_SUBANY, "foo bar" },
      new Object[] { " foo bar ", SUBSTRING_TYPE_SUBANY, " foo bar " },
      new Object[] { " foo  bar ", SUBSTRING_TYPE_SUBANY, " foo bar " },
      new Object[] { "  foo  bar  ", SUBSTRING_TYPE_SUBANY, " foo bar " },
      new Object[] { "  foo   bar  ", SUBSTRING_TYPE_SUBANY, " foo bar " },
      new Object[] { "foo bar", SUBSTRING_TYPE_SUBFINAL, "foo bar" },
      new Object[] { " foo bar ", SUBSTRING_TYPE_SUBFINAL, " foo bar" },
      new Object[] { " foo  bar ", SUBSTRING_TYPE_SUBFINAL, " foo bar" },
      new Object[] { "  foo  bar  ", SUBSTRING_TYPE_SUBFINAL, " foo bar" },
      new Object[] { "  foo   bar  ", SUBSTRING_TYPE_SUBFINAL, " foo bar" },

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
        "jalape\u00F1o"
      },

      new Object[]
      {
        " jalape\u00F1o ",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o "
      },

      new Object[]
      {
        " JALAPE\u00D1O ",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o "
      },

      new Object[]
      {
        "  jalape\u00F1o  ",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o "
      },

      new Object[]
      {
        "  JALAPE\u00D1O  ",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o "
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
        "jalape\u00F1o on a stick"
      },

      new Object[]
      {
        " jalape\u00F1o  on  a  stick ",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o on a stick "
      },

      new Object[]
      {
        "  jalape\u00F1o  on  a  stick  ",
        SUBSTRING_TYPE_SUBINITIAL,
        "jalape\u00F1o on a stick "
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
        "jalape\u00F1o"
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
        " jalape\u00F1o "
      },

      new Object[]
      {
        "  jalape\u00F1o  ",
        SUBSTRING_TYPE_SUBANY,
        " jalape\u00F1o "
      },

      new Object[]
      {
        "  JALAPE\u00D1O  ",
        SUBSTRING_TYPE_SUBANY,
        " jalape\u00F1o "
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
        "jalape\u00F1o on a stick"
      },

      new Object[]
      {
        " jalape\u00F1o  on  a  stick ",
        SUBSTRING_TYPE_SUBANY,
        " jalape\u00F1o on a stick "
      },

      new Object[]
      {
        "  jalape\u00F1o  on  a  stick  ",
        SUBSTRING_TYPE_SUBANY,
        " jalape\u00F1o on a stick "
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
        "jalape\u00F1o"
      },

      new Object[]
      {
        " jalape\u00F1o ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o"
      },

      new Object[]
      {
        " JALAPE\u00D1O ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o"
      },

      new Object[]
      {
        "  jalape\u00F1o  ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o"
      },

      new Object[]
      {
        "  JALAPE\u00D1O  ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o"
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
        "jalape\u00F1o on a stick"
      },

      new Object[]
      {
        " jalape\u00F1o  on  a  stick ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o on a stick"
      },

      new Object[]
      {
        "  jalape\u00F1o  on  a  stick  ",
        SUBSTRING_TYPE_SUBFINAL,
        " jalape\u00F1o on a stick"
      },

      new Object[]
      {
        "Latin Capital Letter OO \uA74E",
        SUBSTRING_TYPE_SUBINITIAL,
        "latin capital letter oo \uA74F"
      },

      new Object[]
      {
        "Deseret Capital Letter Long I \uD801\uDC00",
        SUBSTRING_TYPE_SUBINITIAL,
        "deseret capital letter long i \uD801\uDC28"
      },

      new Object[]
      {
        "Smiley face emoji \uD83D\uDE00",
        SUBSTRING_TYPE_SUBINITIAL,
        "smiley face emoji \uD83D\uDE00"
      },

      new Object[]
      {
        "United States Flag Emoji \uD83C\uDDFA\uD83C\uDDF8",
        SUBSTRING_TYPE_SUBINITIAL,
        "united states flag emoji \uD83C\uDDFA\uD83C\uDDF8"
      }
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
    CaseIgnoreStringMatchingRule mr =
         CaseIgnoreStringMatchingRule.getInstance();

    assertNotNull(mr.getEqualityMatchingRuleName());
    assertEquals(mr.getEqualityMatchingRuleName(), "caseIgnoreMatch");

    assertNotNull(mr.getEqualityMatchingRuleOID());
    assertEquals(mr.getEqualityMatchingRuleOID(), "2.5.13.2");

    assertNotNull(mr.getEqualityMatchingRuleNameOrOID());
    assertEquals(mr.getEqualityMatchingRuleNameOrOID(), "caseIgnoreMatch");

    assertNotNull(mr.getOrderingMatchingRuleName());
    assertEquals(mr.getOrderingMatchingRuleName(), "caseIgnoreOrderingMatch");

    assertNotNull(mr.getOrderingMatchingRuleOID());
    assertEquals(mr.getOrderingMatchingRuleOID(), "2.5.13.3");

    assertNotNull(mr.getOrderingMatchingRuleNameOrOID());
    assertEquals(mr.getOrderingMatchingRuleNameOrOID(),
         "caseIgnoreOrderingMatch");

    assertNotNull(mr.getSubstringMatchingRuleName());
    assertEquals(mr.getSubstringMatchingRuleName(),
         "caseIgnoreSubstringsMatch");

    assertNotNull(mr.getSubstringMatchingRuleOID());
    assertEquals(mr.getSubstringMatchingRuleOID(), "2.5.13.4");

    assertNotNull(mr.getSubstringMatchingRuleNameOrOID());
    assertEquals(mr.getSubstringMatchingRuleNameOrOID(),
         "caseIgnoreSubstringsMatch");
  }
}
