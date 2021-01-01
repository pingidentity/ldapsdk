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
package com.unboundid.ldap.sdk.unboundidds.examples;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code FilterComparator}
 * class.
 */
public class FilterComparatorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests with a number of equivalent filters.
   *
   * @param  f1  The first filter to compare.
   * @param  f2  The second filter to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "equivalentFilters")
  public void testEquivalentFilters(final String f1, final String f2)
         throws Exception
  {
    FilterComparator c = FilterComparator.getInstance();
    assertNotNull(c);

    c.hashCode();

    Filter filter1 = Filter.create(f1);
    Filter filter2 = Filter.create(f2);

    assertEquals(filter1, filter2);
    assertEquals(c.compare(filter1, filter2), 0);
    assertEquals(c.compare(filter2, filter1), 0);
  }



  /**
   * Tests to ensure that an AND filter is ordered before an OR filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDBeforeOR()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(|(a=b)(c=d))");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an OR filter is ordered before a NOT filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testORBeforeNOT()
         throws Exception
  {
    Filter f1 = Filter.create("(|(a=b)(c=d))");
    Filter f2 = Filter.create("(!(a=b))");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a NOT filter is ordered before an equality filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNOTBeforeEquality()
         throws Exception
  {
    Filter f1 = Filter.create("(!(a=b))");
    Filter f2 = Filter.create("(a=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an equality filter is ordered before a substring
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualityBeforeSubstring()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b)");
    Filter f2 = Filter.create("(a=b*)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a substring filter is ordered before a
   * greater-or-equal filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubstringBeforeGreaterOrEqual()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*)");
    Filter f2 = Filter.create("(a>=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a greater-or-equal filter is ordered before a
   * less-or-equal filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGreaterOrEqualBeforeLessOrEqual()
         throws Exception
  {
    Filter f1 = Filter.create("(a>=b)");
    Filter f2 = Filter.create("(a<=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a less-or-equal filter is ordered before a presence
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLessOrEqualBeforePresence()
         throws Exception
  {
    Filter f1 = Filter.create("(a<=b)");
    Filter f2 = Filter.create("(a=*)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a presence filter is ordered before an approximate
   * match filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPresenceBeforeApproximate()
         throws Exception
  {
    Filter f1 = Filter.create("(a=*)");
    Filter f2 = Filter.create("(a~=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an approximate match filter is ordered before an
   * extensible match filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApproximiateBeforeExtensible()
         throws Exception
  {
    Filter f1 = Filter.create("(a~=b)");
    Filter f2 = Filter.create("(a:=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an AND filters with elements that differ by attribute
   * name (but the same number of elements) are ordered correctly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDDifferentAttributeName()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(&(a=b)(e=d))");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an AND filters with elements that differ by assertion
   * value (but the same number of elements) are ordered correctly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDDifferentAssertionValue()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(&(a=b)(c=e))");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an AND filter with fewer elements is ordered before an
   * AND filter with more elements if all other things are considered equal.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDElementCountMismatch()
         throws Exception
  {
    Filter f1 = Filter.create("(&(a=b)(c=d))");
    Filter f2 = Filter.create("(&(a=b)(c=d)(e=f))");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that an AND filter with fewer elements is ordered before an
   * AND filter with more elements if all other things are considered equal and
   * one of them is an LDAP TRUE filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testANDElementCountMismatchTRUEFilter()
         throws Exception
  {
    Filter f1 = Filter.create("(&)");
    Filter f2 = Filter.create("(&(a=b))");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests the behavior with filters that differ only in the length of the
   * assertion value (but the portion of the assertion value they have in common
   * is equivalent).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualityLengthMismatch()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b)");
    Filter f2 = Filter.create("(a=bar)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a substring filter without a subInitial element is
   * ordered before one with a subInitial element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubInitialPresence()
         throws Exception
  {
    Filter f1 = Filter.create("(a=*a*r)");
    Filter f2 = Filter.create("(a=b*a*r)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of the values of subInitial elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubInitialValues()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*a*r)");
    Filter f2 = Filter.create("(a=c*a*r)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a substring filter without a subAny element is ordered
   * before one with a subAny element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubAnyPresence()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*r)");
    Filter f2 = Filter.create("(a=b*a*r)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of the number of subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubAnyCountMismatch()
         throws Exception
  {
    Filter f1 = Filter.create("(a=*a*c)");
    Filter f2 = Filter.create("(a=*a*b*c)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of the values of subAny elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubAnyValueMismatch()
         throws Exception
  {
    Filter f1 = Filter.create("(a=*a*b*c)");
    Filter f2 = Filter.create("(a=*a*d*c)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests to ensure that a substring filter without a subFinal element is
   * ordered before one with a subFinal element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubFinalPresence()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*)");
    Filter f2 = Filter.create("(a=b*a)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of the values of subFinal elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubFinalValues()
         throws Exception
  {
    Filter f1 = Filter.create("(a=b*c*d)");
    Filter f2 = Filter.create("(a=b*c*e)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of an extensible match filter with an attribute name with
   * one without an attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensibleAttributeNamePresence()
         throws Exception
  {
    Filter f1 = Filter.create("(:1.2.3.4:=b)");
    Filter f2 = Filter.create("(a:=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of an extensible match filter with a dnAttributes flag
   * with one without a dnAttributes flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensibleDNAttributesPresence()
         throws Exception
  {
    Filter f1 = Filter.create("(a:=b)");
    Filter f2 = Filter.create("(a:dn:=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of an extensible match filter with a matching rule ID
   * with one without a matching rule ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensibleMatchingRuleIDPresence()
         throws Exception
  {
    Filter f1 = Filter.create("(a:=b)");
    Filter f2 = Filter.create("(a:1.2.3.4:=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests comparison of extensible match filters with different matching rule
   * IDs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensibleDifferentMatchingRuleIDs()
         throws Exception
  {
    Filter f1 = Filter.create("(a:1.2.3.4:=b)");
    Filter f2 = Filter.create("(a:1.2.3.5:=b)");

    FilterComparator c = FilterComparator.getInstance();
    assertTrue(c.compare(f1, f2) < 0);
    assertTrue(c.compare(f2, f1) > 0);
  }



  /**
   * Tests the {@code equals} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    assertFalse(FilterComparator.getInstance().equals(null));
  }



  /**
   * Tests the {@code equals} method with the same instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    assertTrue(FilterComparator.getInstance().equals(
         FilterComparator.getInstance()));
  }



  /**
   * Tests the {@code equals} method with an object that is not a filter
   * comparator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentObjectType()
         throws Exception
  {
    assertFalse(FilterComparator.getInstance().equals("foo"));
  }



  /**
   * Retrieves a set of equivalent filters for testing.
   *
   * @return  A set of equivalent filters for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "equivalentFilters")
  public Object[][] getEquivalentFilters()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "(&(a=b)(c=d))",
        "(&(A=b)(C=d))"
      },

      new Object[]
      {
        "(&(a=b)(c=d))",
        "(&(C=d)(A=b))"
      },

      new Object[]
      {
        "(&(a=b)(c=d)(e=f))",
        "(&(C=d)(E=f)(A=b))"
      },

      new Object[]
      {
        "(|(a=b)(c=d))",
        "(|(A=b)(C=d))"
      },

      new Object[]
      {
        "(|(a=b)(c=d))",
        "(|(c=d)(a=b))"
      },

      new Object[]
      {
        "(!(a=b))",
        "(!(a=b))"
      },

      new Object[]
      {
        "(a=b)",
        "(a=b)"
      },

      new Object[]
      {
        "(a=b*)",
        "(a=b*)"
      },

      new Object[]
      {
        "(a=*b*)",
        "(a=*b*)"
      },

      new Object[]
      {
        "(a=*b)",
        "(a=*b)"
      },

      new Object[]
      {
        "(a=b*c)",
        "(a=b*c)"
      },

      new Object[]
      {
        "(a=*b*c*)",
        "(a=*b*c*)"
      },

      new Object[]
      {
        "(a=b*c*d)",
        "(a=b*c*d)"
      },

      new Object[]
      {
        "(a=b*c*d*e)",
        "(a=b*c*d*e)"
      },

      new Object[]
      {
        "(a>=b)",
        "(a>=b)"
      },

      new Object[]
      {
        "(a<=b)",
        "(a<=b)"
      },

      new Object[]
      {
        "(a=*)",
        "(a=*)"
      },

      new Object[]
      {
        "(a~=b)",
        "(a~=b)"
      },

      new Object[]
      {
        "(a:=b)",
        "(a:=b)"
      },

      new Object[]
      {
        "(a:dn:=b)",
        "(a:dn:=b)"
      },

      new Object[]
      {
        "(:dn:1.2.3.4:=b)",
        "(:dn:1.2.3.4:=b)"
      },

      new Object[]
      {
        "(a:dn:1.2.3.4:=b)",
        "(a:dn:1.2.3.4:=b)"
      },
    };
  }
}
