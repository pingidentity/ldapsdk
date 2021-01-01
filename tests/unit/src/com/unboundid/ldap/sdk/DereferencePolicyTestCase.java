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
package com.unboundid.ldap.sdk;



import java.lang.reflect.Field;
import java.util.HashSet;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the DereferencePolicy class.
 */
public class DereferencePolicyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code valueOf} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOf()
         throws Exception
  {
    assertEquals(DereferencePolicy.valueOf(0), DereferencePolicy.NEVER);
    assertSame(DereferencePolicy.valueOf(0), DereferencePolicy.NEVER);

    assertEquals(DereferencePolicy.valueOf(1), DereferencePolicy.SEARCHING);
    assertSame(DereferencePolicy.valueOf(1), DereferencePolicy.SEARCHING);

    assertEquals(DereferencePolicy.valueOf(2), DereferencePolicy.FINDING);
    assertSame(DereferencePolicy.valueOf(2), DereferencePolicy.FINDING);

    assertEquals(DereferencePolicy.valueOf(3), DereferencePolicy.ALWAYS);
    assertSame(DereferencePolicy.valueOf(3), DereferencePolicy.ALWAYS);

    DereferencePolicy p1 = DereferencePolicy.valueOf(4);
    DereferencePolicy p2 = DereferencePolicy.valueOf(4);
    assertEquals(p1, p2);
    assertSame(p1, p2);

    p1.hashCode();
  }



  /**
   * Tests to ensure that all predefined dereference policy values are handled
   * by valueOf.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfIncludesAllPredefinedValues()
         throws Exception
  {
    for (Field f : DereferencePolicy.class.getFields())
    {
      if (f.getDeclaringClass().equals(DereferencePolicy.class))
      {
        DereferencePolicy predefined = (DereferencePolicy) f.get(null);
        DereferencePolicy valueOf =
             DereferencePolicy.valueOf(predefined.intValue());

        assertEquals(predefined, valueOf);
        assertEquals(predefined.intValue(), valueOf.intValue());
        assertEquals(predefined.getName(), valueOf.getName());
        assertTrue(predefined == valueOf);

        predefined.hashCode();
        valueOf.hashCode();
      }
    }
  }



  /**
   * Tests to ensure that all predefined dereference policy values are included
   * in the array returned by values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValuesIncludesAllPredefinedValues()
         throws Exception
  {
    final DereferencePolicy[] values = DereferencePolicy.values();
    final HashSet<DereferencePolicy> valueSet =
         new HashSet<DereferencePolicy>(values.length);
    for (DereferencePolicy p : values)
    {
      valueSet.add(p);
    }

    for (Field f : DereferencePolicy.class.getFields())
    {
      if (f.getDeclaringClass().equals(DereferencePolicy.class))
      {
        DereferencePolicy predefined = (DereferencePolicy) f.get(null);
        assertTrue(valueSet.contains(predefined));
      }
    }
  }



  /**
   * Tests the {@code equals} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    assertFalse(DereferencePolicy.NEVER.equals(null));
    assertTrue(DereferencePolicy.NEVER.equals(DereferencePolicy.NEVER));
    assertFalse(DereferencePolicy.NEVER.equals(DereferencePolicy.ALWAYS));
    assertTrue(DereferencePolicy.NEVER.equals(DereferencePolicy.valueOf(0)));
    assertFalse(DereferencePolicy.NEVER.equals("foo"));
  }
}
