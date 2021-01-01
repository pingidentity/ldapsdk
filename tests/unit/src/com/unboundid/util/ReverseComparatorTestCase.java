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
package com.unboundid.util;



import java.util.Arrays;
import java.util.LinkedList;
import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;



/**
 * This class provides a set of test cases for the {@code ReverseComparator}
 * class.
 */
public class ReverseComparatorTestCase
       extends UtilTestCase
{
  /**
   * Tests the default constructor with a set of long values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefault()
         throws Exception
  {
    ReverseComparator<Long> rc = new ReverseComparator<Long>();
    assertNotNull(rc);

    rc.hashCode();

    TreeSet<Long> forwardSet = new TreeSet<Long>();
    TreeSet<Long> reverseSet = new TreeSet<Long>(rc);

    long[] values = { 1, 0, 2, 9, 3, 8, 4, 7, 5, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                      9, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    for (long l : values)
    {
      forwardSet.add(l);
      reverseSet.add(l);
    }

    LinkedList<Long> forwardList = new LinkedList<Long>(forwardSet);
    assertEquals(forwardList,
                 Arrays.asList(0L, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L));

    LinkedList<Long> reverseList = new LinkedList<Long>(reverseSet);
    assertEquals(reverseList,
                 Arrays.asList(9L, 8L, 7L, 6L, 5L, 4L, 3L, 2L, 1L, 0L));
  }



  /**
   * Tests the constructor which takes an explicit comparator with a set of long
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithComparator()
         throws Exception
  {
    TestLongComparator c = new TestLongComparator();

    ReverseComparator<Long> rc = new ReverseComparator<Long>(c);
    assertNotNull(rc);

    rc.hashCode();

    TreeSet<Long> forwardSet = new TreeSet<Long>(c);
    TreeSet<Long> reverseSet = new TreeSet<Long>(rc);

    long[] values = { 1, 0, 2, 9, 3, 8, 4, 7, 5, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                      9, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    for (long l : values)
    {
      forwardSet.add(l);
      reverseSet.add(l);
    }

    LinkedList<Long> forwardList = new LinkedList<Long>(forwardSet);
    assertEquals(forwardList,
                 Arrays.asList(0L, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L));

    LinkedList<Long> reverseList = new LinkedList<Long>(reverseSet);
    assertEquals(reverseList,
                 Arrays.asList(9L, 8L, 7L, 6L, 5L, 4L, 3L, 2L, 1L, 0L));
  }



  /**
   * Tests a doubly-reversed comparator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublyReversed()
         throws Exception
  {
    ReverseComparator<Long> c = new ReverseComparator<Long>();

    ReverseComparator<Long> rc = new ReverseComparator<Long>(c);
    assertNotNull(rc);

    rc.hashCode();

    TreeSet<Long> forwardSet = new TreeSet<Long>(c);
    TreeSet<Long> reverseSet = new TreeSet<Long>(rc);

    long[] values = { 1, 0, 2, 9, 3, 8, 4, 7, 5, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                      9, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    for (long l : values)
    {
      forwardSet.add(l);
      reverseSet.add(l);
    }

    LinkedList<Long> forwardList = new LinkedList<Long>(forwardSet);
    assertEquals(forwardList,
                 Arrays.asList(9L, 8L, 7L, 6L, 5L, 4L, 3L, 2L, 1L, 0L));

    LinkedList<Long> reverseList = new LinkedList<Long>(reverseSet);
    assertEquals(reverseList,
                 Arrays.asList(0L, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L));
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
    ReverseComparator<Long> rc = new ReverseComparator<Long>();
    assertFalse(rc.equals(null));

    rc = new ReverseComparator<Long>(new TestLongComparator());
    assertFalse(rc.equals(null));
  }



  /**
   * Tests the {@code equals} method with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    ReverseComparator<Long> rc = new ReverseComparator<Long>();
    assertTrue(rc.equals(rc));

    rc = new ReverseComparator<Long>(new TestLongComparator());
    assertTrue(rc.equals(rc));
  }



  /**
   * Tests the {@code equals} method with an equivalent object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalent()
         throws Exception
  {
    ReverseComparator<Long> rc = new ReverseComparator<Long>();
    assertTrue(rc.equals(new ReverseComparator<Long>()));

    rc = new ReverseComparator<Long>(new TestLongComparator());
    assertTrue(rc.equals(new ReverseComparator<Long>(
         new TestLongComparator())));
  }



  /**
   * Tests the {@code equals} method with an object that is not a reverse
   * comparator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotReverseComparator()
         throws Exception
  {
    ReverseComparator<Long> rc = new ReverseComparator<Long>();
    assertFalse(rc.equals("foo"));

    rc = new ReverseComparator<Long>(new TestLongComparator());
    assertFalse(rc.equals("foo"));
  }



  /**
   * Tests the {@code equals} method in which the first comparator was created
   * without a comparator and the second was created with a comparator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsOneWithComparatorOneWithout()
         throws Exception
  {
    ReverseComparator<Long> rc1 = new ReverseComparator<Long>();
    ReverseComparator<Long> rc2 =
         new ReverseComparator<Long>(new TestLongComparator());

    assertFalse(rc1.equals(rc2));
    assertFalse(rc2.equals(rc1));
  }



  /**
   * Tests the {@code equals} method with reverse comparators created with
   * non-equal comparators.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonEqualComparators()
         throws Exception
  {
    ReverseComparator<Long> rc1 =
         new ReverseComparator<Long>(new TestLongComparator());
    ReverseComparator<DN> rc2 = new ReverseComparator<DN>(DN.NULL_DN);

    assertFalse(rc1.equals(rc2));
    assertFalse(rc2.equals(rc1));
  }
}
