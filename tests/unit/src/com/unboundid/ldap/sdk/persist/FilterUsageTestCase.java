/*
 * Copyright 2009-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.persist;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases that cover the ability to generate
 * search filters from objects using the LDAP SDK persistence framework.
 */
public final class FilterUsageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the {@code values} and {@code valueOf} methods
   * in the {@code FilterUsage} class.
   */
  @Test()
  public void testFilterUsageValueMethods()
  {
    for (final FilterUsage valuesUsage : FilterUsage.values())
    {
      final FilterUsage valueOfUsage = FilterUsage.valueOf(valuesUsage.name());
      assertNotNull(valueOfUsage);
      assertEquals(valueOfUsage, valuesUsage);
    }
  }



  /**
   * Tests the behavior when trying to generate a filter from a class with all
   * types of filter usages and values for all fields and getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllUsagesAllPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestAllFilterUsages> h =
         new LDAPObjectHandler<TestAllFilterUsages>(TestAllFilterUsages.class);

    final TestAllFilterUsages t = new TestAllFilterUsages();
    t.setRF("1");
    t.setAAF("2");
    t.setCAF("3");
    t.setEF("4");
    t.setRM("5");
    t.setAAM("6");
    t.setCAM("7");
    t.setEM("8");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testAllFilterUsages)" +
         "(rF=1)" +
         "(rM=5)" +
         "(aAF=2)" +
         "(aAM=6)" +
         "(cAF=3)" +
         "(cAM=7)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class with all
   * types of filter usages and values for only the required fields and getter
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllUsagesOnlyRequiredPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestAllFilterUsages> h =
         new LDAPObjectHandler<TestAllFilterUsages>(TestAllFilterUsages.class);

    final TestAllFilterUsages t = new TestAllFilterUsages();
    t.setRF("1");
    t.setRM("5");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testAllFilterUsages)" +
         "(rF=1)" +
         "(rM=5)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class with all
   * types of filter usages and values for only the required and always allowed
   * fields and getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllUsagesOnlyRequiredAndAlwaysAllowedPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestAllFilterUsages> h =
         new LDAPObjectHandler<TestAllFilterUsages>(TestAllFilterUsages.class);

    final TestAllFilterUsages t = new TestAllFilterUsages();
    t.setRF("1");
    t.setAAF("2");
    t.setRM("5");
    t.setAAM("6");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testAllFilterUsages)" +
         "(rF=1)" +
         "(rM=5)" +
         "(aAF=2)" +
         "(aAM=6)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class with all
   * types of filter usages and values for only the required and conditionally
   * allowed fields and getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllUsagesOnlyRequiredAndConditionallyAllowedPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestAllFilterUsages> h =
         new LDAPObjectHandler<TestAllFilterUsages>(TestAllFilterUsages.class);

    final TestAllFilterUsages t = new TestAllFilterUsages();
    t.setRF("1");
    t.setCAF("3");
    t.setRM("5");
    t.setCAM("7");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testAllFilterUsages)" +
         "(rF=1)" +
         "(rM=5)" +
         "(cAF=3)" +
         "(cAM=7)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class with all
   * types of filter usages that is missing a value for a required field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testAllUsagesMissingRequiredField()
         throws  Exception
  {
    final LDAPObjectHandler<TestAllFilterUsages> h =
         new LDAPObjectHandler<TestAllFilterUsages>(TestAllFilterUsages.class);

    final TestAllFilterUsages t = new TestAllFilterUsages();
    t.setAAF("2");
    t.setCAF("3");
    t.setEF("4");
    t.setRM("5");
    t.setAAM("6");
    t.setCAM("7");
    t.setEM("8");

    h.createFilter(t);
  }



  /**
   * Tests the behavior when trying to generate a filter from a class with all
   * types of filter usages that is missing a value for a required getter
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testAllUsagesMissingRequiredGetter()
         throws  Exception
  {
    final LDAPObjectHandler<TestAllFilterUsages> h =
         new LDAPObjectHandler<TestAllFilterUsages>(TestAllFilterUsages.class);

    final TestAllFilterUsages t = new TestAllFilterUsages();
    t.setRF("1");
    t.setAAF("2");
    t.setCAF("3");
    t.setEF("4");
    t.setAAM("6");
    t.setCAM("7");
    t.setEM("8");

    h.createFilter(t);
  }



  /**
   * Tests the behavior when trying to generate a filter from a class without
   * any required filter usages and values for all fields and getter methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoRequiredUsagesAllPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestNoRequiredFilterUsages> h =
         new LDAPObjectHandler<TestNoRequiredFilterUsages>(
              TestNoRequiredFilterUsages.class);

    final TestNoRequiredFilterUsages t = new TestNoRequiredFilterUsages();
    t.setAAF("1");
    t.setCAF("2");
    t.setEF("3");
    t.setAAM("4");
    t.setCAM("5");
    t.setEM("6");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testNoRequiredFilterUsages)" +
         "(aAF=1)" +
         "(aAM=4)" +
         "(cAF=2)" +
         "(cAM=5)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class without
   * any required filter usages and values for all fields and getter methods
   * except the always allowed field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoRequiredUsagesAllExceptAAFPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestNoRequiredFilterUsages> h =
         new LDAPObjectHandler<TestNoRequiredFilterUsages>(
              TestNoRequiredFilterUsages.class);

    final TestNoRequiredFilterUsages t = new TestNoRequiredFilterUsages();
    t.setCAF("2");
    t.setEF("3");
    t.setAAM("4");
    t.setCAM("5");
    t.setEM("6");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testNoRequiredFilterUsages)" +
         "(aAM=4)" +
         "(cAF=2)" +
         "(cAM=5)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class without
   * any required filter usages and values for all fields and getter methods
   * except the always allowed getter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoRequiredUsagesAllExceptAAMPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestNoRequiredFilterUsages> h =
         new LDAPObjectHandler<TestNoRequiredFilterUsages>(
              TestNoRequiredFilterUsages.class);

    final TestNoRequiredFilterUsages t = new TestNoRequiredFilterUsages();
    t.setAAF("1");
    t.setCAF("2");
    t.setEF("3");
    t.setCAM("5");
    t.setEM("6");

    final Filter f = h.createFilter(t);
    assertNotNull(f);
    assertEquals(f, Filter.create("(&" +
         "(objectClass=testNoRequiredFilterUsages)" +
         "(aAF=1)" +
         "(cAF=2)" +
         "(cAM=5)" +
         ')'));
  }



  /**
   * Tests the behavior when trying to generate a filter from a class without
   * any required filter usages and values for only the conditionally-allowed
   * fields and methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={LDAPPersistException.class})
  public void testNoRequiredUsagesOnlyConditionalPopulated()
         throws  Exception
  {
    final LDAPObjectHandler<TestNoRequiredFilterUsages> h =
         new LDAPObjectHandler<TestNoRequiredFilterUsages>(
              TestNoRequiredFilterUsages.class);

    final TestNoRequiredFilterUsages t = new TestNoRequiredFilterUsages();
    t.setCAF("2");
    t.setEF("3");
    t.setCAM("5");
    t.setEM("6");

    h.createFilter(t);
  }
}
