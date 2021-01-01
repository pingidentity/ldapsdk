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

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the ModificationType class.
 */
public class ModificationTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that all predefined modification type values are included
   * in the array returned by the values method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValuesIncludesAllPredefinedValues()
         throws Exception
  {
    for (Field f : ModificationType.class.getFields())
    {
      if (f.getDeclaringClass().equals(ModificationType.class) &&
          f.getType().equals(ModificationType.class))
      {
        ModificationType predefined = (ModificationType) f.get(null);

        boolean found = false;
        for (ModificationType t : ModificationType.values())
        {
          if (t == predefined)
          {
            found = true;
            break;
          }
        }

        assertTrue(found,
             "Modification type " + predefined.getName() + " not in values()");
      }
    }
  }



  /**
   * Tests the {@code valueOf} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOf()
         throws Exception
  {
    assertEquals(ModificationType.valueOf(0), ModificationType.ADD);
    assertSame(ModificationType.valueOf(0), ModificationType.ADD);

    assertEquals(ModificationType.valueOf(1), ModificationType.DELETE);
    assertSame(ModificationType.valueOf(1), ModificationType.DELETE);

    assertEquals(ModificationType.valueOf(2), ModificationType.REPLACE);
    assertSame(ModificationType.valueOf(2), ModificationType.REPLACE);

    assertEquals(ModificationType.valueOf(3), ModificationType.INCREMENT);
    assertSame(ModificationType.valueOf(3), ModificationType.INCREMENT);

    ModificationType t1 = ModificationType.valueOf(4);
    ModificationType t2 = ModificationType.valueOf(4);
    assertEquals(t1, t2);
    assertEquals(t1.hashCode(), t2.hashCode());
    assertSame(t1, t2);
  }



  /**
   * Tests to ensure that all predefined modification type values are handled
   * by valueOf.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfIncludesAllPredefinedValues()
         throws Exception
  {
    for (Field f : ModificationType.class.getFields())
    {
      if (f.getDeclaringClass().equals(ModificationType.class) &&
           f.getType().equals(ModificationType.class))
      {
        ModificationType predefined = (ModificationType) f.get(null);
        ModificationType valueOf =
             ModificationType.valueOf(predefined.intValue());
        ModificationType definedValueOf =
             ModificationType.definedValueOf(predefined.intValue());

        assertEquals(predefined, valueOf);
        assertEquals(predefined, definedValueOf);
        assertEquals(predefined.intValue(), valueOf.intValue());
        assertEquals(predefined.intValue(), definedValueOf.intValue());
        assertEquals(predefined.hashCode(), valueOf.hashCode());
        assertEquals(predefined.hashCode(), definedValueOf.hashCode());
        assertEquals(predefined.getName(), valueOf.getName());
        assertEquals(predefined.getName(), definedValueOf.getName());
        assertSame(predefined, valueOf);
        assertSame(predefined, definedValueOf);
      }
    }
  }



  /**
   * Tests to ensure proper valueOf handling for undefined modification type
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfUndeinfedValues()
         throws Exception
  {
    ModificationType valueOf = ModificationType.valueOf(4);
    assertNotNull(valueOf);
    assertEquals(valueOf.intValue(), 4);

    ModificationType definedValueOf = ModificationType.definedValueOf(4);
    assertNull(definedValueOf);
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
    assertFalse(ModificationType.ADD.equals(null));
    assertTrue(ModificationType.ADD.equals(ModificationType.ADD));
    assertFalse(ModificationType.ADD.equals(ModificationType.DELETE));
    assertTrue(ModificationType.ADD.equals(ModificationType.valueOf(0)));
    assertFalse(ModificationType.ADD.equals("foo"));
  }
}
