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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code ObjectPair} class.
 */
public final class ObjectPairTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a set of test cases that cover the behavior when both elements are
   * objects.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testObjects()
         throws Exception
  {
    final ObjectPair<String,Object> p =
         new ObjectPair<String,Object>("foo", "bar");

    assertNotNull(p);

    assertNotNull(p.getFirst());
    assertEquals(p.getFirst(), "foo");

    assertNotNull(p.getSecond());
    assertEquals(p.getSecond(), "bar");

    assertEquals(p.hashCode(), ("foo".hashCode() + "bar".hashCode()));

    assertTrue(p.equals(new ObjectPair<String,Object>("foo", "bar")));

    assertNotNull(p.toString());
    assertEquals(p.toString(), "ObjectPair(first=foo, second=bar)");
  }



  /**
   * Provides a set of test cases that cover the behavior when both elements are
   * primitives.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPrimitives()
         throws Exception
  {
    final ObjectPair<Integer,Long> p = new ObjectPair<Integer,Long>(1, 2L);

    assertNotNull(p);

    assertNotNull(p.getFirst());
    assertEquals(p.getFirst(), Integer.valueOf(1));

    assertNotNull(p.getSecond());
    assertEquals(p.getSecond(), Long.valueOf(2L));

    assertEquals(p.hashCode(), 3);

    assertTrue(p.equals(new ObjectPair<Integer,Long>(1, 2L)));

    assertNotNull(p.toString());
    assertEquals(p.toString(), "ObjectPair(first=1, second=2)");
  }



  /**
   * Provides a set of test cases that cover the behavior when both elements are
   * null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNulls()
         throws Exception
  {
    final ObjectPair<Object,Object> p =
         new ObjectPair<Object,Object>(null, null);

    assertNotNull(p);

    assertNull(p.getFirst());

    assertNull(p.getSecond());

    assertEquals(p.hashCode(), 0);

    assertTrue(p.equals(new ObjectPair<Object, Object>(null, null)));

    assertNotNull(p.toString());
    assertEquals(p.toString(), "ObjectPair(first=null, second=null)");
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
    final ObjectPair<String,String> p =
         new ObjectPair<String,String>("foo", "bar");

    assertTrue(p.equals(p));

    assertEquals(p.equals(o), m);

    if (o != null)
    {
      assertEquals(o.equals(p), m);
    }

    assertFalse(p.equals(null));

    assertTrue(p.equals(p));

    assertFalse(p.equals("foo"));

    assertTrue(p.equals(new ObjectPair<String, String>("foo", "bar")));

    assertTrue(p.equals(new ObjectPair<Object, Object>("foo", "bar")));

    assertFalse(p.equals(new ObjectPair<Object, Object>("foo", "foo")));

    assertFalse(p.equals(new ObjectPair<Object, Object>("bar", "bar")));

    assertFalse(p.equals(new ObjectPair<Object, Object>(null, null)));

    assertFalse(p.equals(new ObjectPair<Object, Object>(1, 2L)));
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
        new ObjectPair<String,String>("foo", "bar"),
        true
      },

      new Object[]
      {
        new ObjectPair<Object,Object>("foo", "bar"),
        true
      },

      new Object[]
      {
        new ObjectPair<Object,Object>("foo", "foo"),
        false
      },

      new Object[]
      {
        new ObjectPair<Object,Object>("bar", "bar"),
        false
      },

      new Object[]
      {
        new ObjectPair<Object,Object>("foo", null),
        false
      },

      new Object[]
      {
        new ObjectPair<Object,Object>(null, "bar"),
        false
      },

      new Object[]
      {
        new ObjectPair<Object,Object>(null, null),
        false
      }
    };
  }
}
