/*
 * Copyright 2011-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2023 Ping Identity Corporation
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
 * Copyright (C) 2011-2023 Ping Identity Corporation
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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code ObjectTrio} class.
 */
public final class ObjectTrioTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an object trio in which all three elements are
   * non-{@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllNonNull()
         throws Exception
  {
    final ObjectTrio<String,Boolean,Integer> trio =
         new ObjectTrio<>("foo", true, 1234);
    assertNotNull(trio);

    assertNotNull(trio.getFirst());
    assertEquals(trio.getFirst(), "foo");

    assertNotNull(trio.getSecond());
    assertEquals(trio.getSecond(), Boolean.TRUE);

    assertNotNull(trio.getThird());
    assertEquals(trio.getThird(), Integer.valueOf(1234));

    assertEquals(trio.hashCode(),
         ("foo".hashCode() + Boolean.TRUE.hashCode() +
              Integer.valueOf(1234).hashCode()));

    assertTrue(trio.equals(new ObjectTrio<>("foo", true, 1234)));

    assertNotNull(trio.toString());
    assertEquals(trio.toString(), "ObjectTrio(first=foo, second=true, " +
         "third=1234)");
  }



  /**
   * Tests the behavior for an object trio in which all three elements are
   * {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllNull()
         throws Exception
  {
    final ObjectTrio<String,Boolean,Integer> trio =
         new ObjectTrio<>(null, null, null);
    assertNotNull(trio);

    assertNull(trio.getFirst());
    assertNull(trio.getSecond());
    assertNull(trio.getThird());

    assertEquals(trio.hashCode(), 0);

    assertTrue(trio.equals(new ObjectTrio<>(null, null, null)));

    assertNotNull(trio.toString());
    assertEquals(trio.toString(), "ObjectTrio(first=null, second=null, " +
         "third=null)");
  }



  /**
   * Tests the behavior for an object trio in which there are a mix of
   * {@code null} and non-{@code null} elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSomeNull()
         throws Exception
  {
    final ObjectTrio<String,String,String> trio =
         new ObjectTrio<>("foo", null, "bar");
    assertNotNull(trio);

    assertNotNull(trio.getFirst());
    assertEquals(trio.getFirst(), "foo");

    assertNull(trio.getSecond());

    assertNotNull(trio.getThird());
    assertEquals(trio.getThird(), "bar");

    assertEquals(trio.hashCode(),
         ("foo".hashCode() + "bar".hashCode()));

    assertTrue(trio.equals(new ObjectTrio<>("foo", null, "bar")));

    assertNotNull(trio.toString());
    assertEquals(trio.toString(), "ObjectTrio(first=foo, second=null, " +
         "third=bar)");
  }



  /**
   * Tests the behavior of the {@code equals} method.
   *
   * @param  o  The object to use for testing.
   * @param  m  Indicates whether to expect the provided object to match the
   *            given test object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="equalsData")
  public void testEquals(final Object o, final boolean m)
         throws Exception
  {
    final ObjectTrio<String,String,String> t =
         new ObjectTrio<>("foo", "bar", "baz");

    assertTrue(t.equals(t));

    assertEquals(t.equals(o), m);

    if (o != null)
    {
      assertEquals(o.equals(t), m);
    }

    assertFalse(t.equals(null));

    assertFalse(t.equals("foo"));

    assertTrue(t.equals(new ObjectTrio<>("foo", "bar", "baz")));

    assertTrue(t.equals(new ObjectTrio<Object,Object,Object>(
         "foo", "bar", "baz")));

    assertFalse(t.equals(new ObjectTrio<>(1, 2, 3)));

    assertFalse(t.equals(new ObjectTrio<>("different", "bar", "baz")));

    assertFalse(t.equals(new ObjectTrio<>("foo", "different", "baz")));

    assertFalse(t.equals(new ObjectTrio<>("foo", "bar", "different")));

    assertFalse(t.equals(new ObjectTrio<>(null, null, null)));
  }



  /**
   * Provides a set of data for use in testing the {@code equals} method.
   *
   * @return  A set of data for use in testing the {@code equals} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="equalsData")
  public Object[][] getEqualsData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        null,
        false
      },

      new Object[]
      {
        "foo",
        false
      },

      new Object[]
      {
        new ObjectTrio<>("foo", "bar", "baz"),
        true
      },

      new Object[]
      {
        new ObjectTrio<Object,Object,Object>("foo", "bar", "baz"),
        true
      },

      new Object[]
      {
        new ObjectTrio<>("foo", "foo", "baz"),
        false
      },

      new Object[]
      {
        new ObjectTrio<>("foo", "bar", "foo"),
        false
      },

      new Object[]
      {
        new ObjectTrio<>("foo", "bar", "bar"),
        false
      },

      new Object[]
      {
        new ObjectTrio<>(null, "bar", "baz"),
        false
      },

      new Object[]
      {
        new ObjectTrio<>("foo", null, "baz"),
        false
      },

      new Object[]
      {
        new ObjectTrio<>("foo", "bar", null),
        false
      },

      new Object[]
      {
        new ObjectTrio<>(1, 2, 3),
        false
      },
    };
  }
}
