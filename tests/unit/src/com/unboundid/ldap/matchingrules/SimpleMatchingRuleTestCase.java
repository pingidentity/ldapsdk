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



/**
 * This class provides a set of test cases for the SimpleMatchingRule class.
 * All tests will be performed with the CaseIgnoreString matching rule.
 */
public class SimpleMatchingRuleTestCase
       extends MatchingRuleTestCase
{
  /**
   * Tests the {@code valuesMatch} method with a number of value pairs
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

    value2OS = new ASN1OctetString(value2 + 'x');
    assertFalse(matchingRule.valuesMatch(value1OS, value2OS));
  }



  /**
   * Tests the {@code valuesMatch} method with a number of value pairs
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
   * Tests the {@code matchesSubstring} method with a number of value pairs
   * that should be considered matches using a subInitial element.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues")
  public void testMatchesSubInitial(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1.trim());
    ASN1OctetString value2OS = new ASN1OctetString(value2.trim());

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    assertTrue(matchingRule.matchesSubstring(value1OS, value2OS, null, null));

    if (matchingRule.normalize(value1OS).getValue().length == 0)
    {
      return;
    }

    value2OS = new ASN1OctetString(value2.trim() + 'x');
    assertFalse(matchingRule.matchesSubstring(value1OS, value2OS, null, null));

    value1OS = new ASN1OctetString(value1.trim() + 'x');
    value2OS = new ASN1OctetString(value2.trim());
    assertTrue(matchingRule.matchesSubstring(value1OS, value2OS, null, null));

    value1OS = new ASN1OctetString('x' + value1.trim());
    assertFalse(matchingRule.matchesSubstring(value1OS, value2OS, null, null));

    value1OS = new ASN1OctetString('x' + value1.trim() + 'x');
    assertFalse(matchingRule.matchesSubstring(value1OS, value2OS, null, null));
  }



  /**
   * Tests the {@code matchesSubstring} method with a number of value pairs
   * that should be considered matches using a subAny element.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues")
  public void testMatchesSubAny(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1.trim());
    ASN1OctetString value2OS = new ASN1OctetString(value2.trim());

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    assertTrue(matchingRule.matchesSubstring(value1OS, null,
         new ASN1OctetString[] { value2OS }, null));

    if (matchingRule.normalize(value1OS).getValue().length == 0)
    {
      return;
    }

    value2OS = new ASN1OctetString(value2.trim() + 'x');
    assertFalse(matchingRule.matchesSubstring(value1OS, null,
         new ASN1OctetString[] { value2OS }, null));

    value1OS = new ASN1OctetString(value1.trim() + 'x');
    value2OS = new ASN1OctetString(value2.trim());
    assertTrue(matchingRule.matchesSubstring(value1OS, null,
         new ASN1OctetString[] { value2OS }, null));

    value1OS = new ASN1OctetString('x' + value1.trim());
    assertTrue(matchingRule.matchesSubstring(value1OS, null,
         new ASN1OctetString[] { value2OS }, null));

    value1OS = new ASN1OctetString('x' + value1.trim() + 'x');
    assertTrue(matchingRule.matchesSubstring(value1OS, null,
         new ASN1OctetString[] { value2OS }, null));

    value1OS = new ASN1OctetString('x' + value1.trim());
    value2OS = new ASN1OctetString(value2.trim() + 'x');
    assertFalse(matchingRule.matchesSubstring(value1OS, null,
         new ASN1OctetString[] { value2OS }, null));
  }



  /**
   * Tests the {@code matchesSubstring} method with a number of value pairs
   * that should be considered matches using a subFinal element.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues")
  public void testMatchesSubFinal(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1.trim());
    ASN1OctetString value2OS = new ASN1OctetString(value2.trim());

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    assertTrue(matchingRule.matchesSubstring(value1OS, null, null, value2OS));

    if (matchingRule.normalize(value1OS).getValue().length == 0)
    {
      return;
    }

    value2OS = new ASN1OctetString(value2.trim() + 'x');
    assertFalse(matchingRule.matchesSubstring(value1OS, null, null, value2OS));

    value1OS = new ASN1OctetString(value1.trim() + 'x');
    value2OS = new ASN1OctetString(value2.trim());
    assertFalse(matchingRule.matchesSubstring(value1OS, null, null, value2OS));

    value1OS = new ASN1OctetString('x' + value1.trim());
    assertTrue(matchingRule.matchesSubstring(value1OS, null, null, value2OS));

    value1OS = new ASN1OctetString('x' + value1.trim() + 'x');
    assertFalse(matchingRule.matchesSubstring(value1OS, null, null, value2OS));
  }



  /**
   * Tests the {@code compareValues} method with values that should be
   * considered matches.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testMatchingValues")
  public void testCompareValuesMatching(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1);
    ASN1OctetString value2OS = new ASN1OctetString(value2);

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    assertEquals(matchingRule.compareValues(value1OS, value2OS), 0);

    if (matchingRule.normalize(value1OS).getValue().length == 0)
    {
      return;
    }

    value1OS = new ASN1OctetString(value1);
    value2OS = new ASN1OctetString(value2.trim() + 'x');
    assertTrue(matchingRule.compareValues(value1OS, value2OS) < 0);

    value1OS = new ASN1OctetString(value1.trim() + 'x');
    value2OS = new ASN1OctetString(value2);
    assertTrue(matchingRule.compareValues(value1OS, value2OS) > 0);

    value1OS = new ASN1OctetString(value1.trim() + 'x');
    value2OS = new ASN1OctetString(value2.trim() + 'y');
    assertTrue(matchingRule.compareValues(value1OS, value2OS) < 0);

    value1OS = new ASN1OctetString(value1.trim() + 'y');
    value2OS = new ASN1OctetString(value2.trim() + 'x');
    assertTrue(matchingRule.compareValues(value1OS, value2OS) > 0);
  }



  /**
   * Tests the {@code compareValues} method with values that should not be
   * considered matches.
   *
   * @param  value1  The first value to compare.
   * @param  value2  The second value to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testNonMatchingValues")
  public void testCompareValuesNonMatching(String value1, String value2)
         throws Exception
  {
    ASN1OctetString value1OS = new ASN1OctetString(value1);
    ASN1OctetString value2OS = new ASN1OctetString(value2);

    CaseIgnoreStringMatchingRule matchingRule =
         CaseIgnoreStringMatchingRule.getInstance();
    assertFalse(matchingRule.compareValues(value1OS, value2OS) == 0);
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
}
