/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code WeakHashSet} class.
 */
public final class WeakHashSetTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for weak hash set methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperations()
         throws Exception
  {
    final WeakHashSet<String> set = new WeakHashSet<String>();
    assertTrue(set.isEmpty());
    assertEquals(set.size(), 0);
    assertNotNull(set.toString());
    set.hashCode();

    assertNotNull(set.toArray());
    assertEquals(set.toArray().length, 0);

    assertNotNull(set.toArray(new String[0]));
    assertEquals(set.toArray(new String[0]).length, 0);


    final String foo1 = new String("foo");
    final String foo2 = new String("foo");
    final String bar1 = new String("bar");
    final String bar2 = new String("bar");

    assertSame(foo1, foo1);
    assertSame(foo2, foo2);
    assertNotSame(foo1, foo2);

    assertTrue(set.add(foo1));
    assertTrue(set.contains(foo1));
    assertTrue(set.contains(foo2));
    assertFalse(set.contains(bar1));
    assertFalse(set.contains(bar2));

    assertFalse(set.isEmpty());
    assertEquals(set.size(), 1);
    assertNotNull(set.toString());

    assertNotNull(set.toArray());
    assertEquals(set.toArray().length, 1);

    assertNotNull(set.toArray(new String[0]));
    assertEquals(set.toArray(new String[0]).length, 1);


    assertSame(set.get(foo1), foo1);
    assertSame(set.get(foo2), foo1);
    assertNull(set.get(bar1));
    assertNull(set.get(bar2));

    assertFalse(set.add(foo2));
    assertTrue(set.contains(foo1));
    assertTrue(set.contains(foo2));
    assertFalse(set.contains(bar1));
    assertFalse(set.contains(bar2));

    assertSame(set.get(foo1), foo1);
    assertSame(set.get(foo2), foo1);

    assertTrue(set.remove(foo1));
    assertFalse(set.remove(foo1));
    assertFalse(set.remove(foo2));
    assertFalse(set.remove(bar1));
    assertFalse(set.remove(bar2));

    assertSame(set.addAndGet(foo2), foo2);
    assertSame(set.addAndGet(foo1), foo2);
    assertFalse(set.contains(bar1));
    assertFalse(set.contains(bar2));
  }



  /**
   * Provides test coverage for methods that work with collections of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCollectionOperations()
         throws Exception
  {
    final String a1 = new String("a");
    final String b1 = new String("b");
    final String c1 = new String("c");
    final String d1 = new String("d");
    final String e1 = new String("e");
    final List<String> l1 = Arrays.asList(a1, b1, c1, d1, e1);

    final String a2 = new String("a");
    final String b2 = new String("b");
    final String c2 = new String("c");
    final String d2 = new String("d");
    final String e2 = new String("e");
    final List<String> l2 = Arrays.asList(a2, b2, c2, d2, e2);

    final WeakHashSet<String> set = new WeakHashSet<String>(10);
    assertTrue(set.addAll(l1));
    assertFalse(set.addAll(l1));
    assertFalse(set.addAll(l2));
    assertTrue(set.containsAll(l1));
    assertTrue(set.containsAll(l2));

    assertFalse(set.retainAll(l1));
    assertFalse(set.retainAll(l2));

    assertTrue(set.removeAll(l1));
    assertFalse(set.removeAll(l2));

    assertTrue(set.addAll(l2));
    assertFalse(set.retainAll(l1));
    assertFalse(set.retainAll(l2));
    assertFalse(set.isEmpty());
    assertEquals(set.size(), l1.size());

    set.clear();
    assertTrue(set.isEmpty());
    assertEquals(set.size(), 0);

    assertFalse(set.retainAll(l1));
    assertFalse(set.retainAll(l2));


    set.addAll(l1);
    assertEquals(set.size(), l1.size());

    int i=0;
    final Iterator<String> iterator = set.iterator();
    while (iterator.hasNext())
    {
      i++;
      iterator.next();
      iterator.remove();
    }
    assertEquals(i, l1.size());
    assertTrue(set.isEmpty());
    assertEquals(set.size(), 0);


    final String d3 = new String("d");
    final String e3 = new String("e");
    final String f3 = new String("f");
    final String g3 = new String("g");
    final List<String> l3 = Arrays.asList(d3, e3, f3, g3);

    assertTrue(set.addAll(l1));
    assertTrue(set.contains("a"));
    assertTrue(set.contains("b"));
    assertTrue(set.contains("c"));
    assertTrue(set.contains("d"));
    assertTrue(set.contains("e"));
    assertFalse(set.contains("f"));
    assertFalse(set.contains("g"));

    assertTrue(set.removeAll(l3));
    assertTrue(set.contains("a"));
    assertTrue(set.contains("b"));
    assertTrue(set.contains("c"));
    assertFalse(set.contains("d"));
    assertFalse(set.contains("e"));
    assertFalse(set.contains("f"));
    assertFalse(set.contains("g"));
    assertFalse(set.removeAll(l3));

    assertTrue(set.addAll(l1));
    assertTrue(set.contains("a"));
    assertTrue(set.contains("b"));
    assertTrue(set.contains("c"));
    assertTrue(set.contains("d"));
    assertTrue(set.contains("e"));
    assertFalse(set.contains("f"));
    assertFalse(set.contains("g"));

    assertTrue(set.retainAll(l3));
    assertFalse(set.contains("a"));
    assertFalse(set.contains("b"));
    assertFalse(set.contains("c"));
    assertTrue(set.contains("d"));
    assertTrue(set.contains("e"));
    assertFalse(set.contains("f"));
    assertFalse(set.contains("g"));
  }



  /**
   * Provides test coverage for the equals method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    final WeakHashSet<String> set1 = new WeakHashSet<String>();
    set1.addAll(Arrays.asList("a", "b", "c", "d", "e"));

    assertFalse(set1.equals(null));

    assertTrue(set1.equals(set1));

    assertFalse(set1.equals("foo"));

    assertFalse(set1.equals(Arrays.asList("a", "b", "c", "d", "e")));

    final WeakHashSet<String> set2 = new WeakHashSet<String>();
    set2.addAll(Arrays.asList("a", "b", "c", "d", "e"));

    assertTrue(set1.equals(set2));
    assertTrue(set2.equals(set1));

    final HashSet<String> set3 = new HashSet<String>(5);
    set3.addAll(Arrays.asList("a", "b", "c", "d", "e"));
    assertTrue(set1.equals(set3));
    assertTrue(set2.equals(set3));
    assertTrue(set3.equals(set1));
    assertTrue(set3.equals(set2));

    final WeakHashSet<String> set4 = new WeakHashSet<String>();
    set4.addAll(Arrays.asList("f", "g", "h"));

    assertFalse(set1.equals(set4));
    assertFalse(set4.equals(set1));
  }
}
