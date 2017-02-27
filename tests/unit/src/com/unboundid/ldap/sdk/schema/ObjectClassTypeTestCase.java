/*
 * Copyright 2007-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2017 UnboundID Corp.
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
package com.unboundid.ldap.sdk.schema;



import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the ObjectClassType enum.
 */
public class ObjectClassTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code ABSTRACT} element.
   */
  @Test()
  public void testAbstract()
  {
    assertEquals(ObjectClassType.ABSTRACT.getName(), "ABSTRACT");

    assertEquals(ObjectClassType.ABSTRACT.toString(), "ABSTRACT");

    assertEquals(ObjectClassType.valueOf("ABSTRACT"),
                 ObjectClassType.ABSTRACT);

    assertEquals(ObjectClassType.forName("ABSTRACT"),
         ObjectClassType.ABSTRACT);
  }



  /**
   * Tests the {@code AUXILIARY} element.
   */
  @Test()
  public void testAuxiliary()
  {
    assertEquals(ObjectClassType.AUXILIARY.getName(), "AUXILIARY");

    assertEquals(ObjectClassType.AUXILIARY.toString(), "AUXILIARY");

    assertEquals(ObjectClassType.valueOf("AUXILIARY"),
                 ObjectClassType.AUXILIARY);

    assertEquals(ObjectClassType.forName("AUXILIARY"),
         ObjectClassType.AUXILIARY);
  }



  /**
   * Tests the {@code STRUCTURAL} element.
   */
  @Test()
  public void testStructural()
  {
    assertEquals(ObjectClassType.STRUCTURAL.getName(), "STRUCTURAL");

    assertEquals(ObjectClassType.STRUCTURAL.toString(), "STRUCTURAL");

    assertEquals(ObjectClassType.valueOf("STRUCTURAL"),
                 ObjectClassType.STRUCTURAL);

    assertEquals(ObjectClassType.forName("STRUCTURAL"),
         ObjectClassType.STRUCTURAL);
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    TreeSet<ObjectClassType> expectedSet = new TreeSet<ObjectClassType>();
    expectedSet.add(ObjectClassType.ABSTRACT);
    expectedSet.add(ObjectClassType.AUXILIARY);
    expectedSet.add(ObjectClassType.STRUCTURAL);

    TreeSet<ObjectClassType> valuesSet = new TreeSet<ObjectClassType>();
    for (ObjectClassType type : ObjectClassType.values())
    {
      valuesSet.add(type);
    }

    assertEquals(valuesSet, expectedSet);
  }



  /**
   * Tests the behavior of the {@code forName} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForName()
         throws Exception
  {
    for (final ObjectClassType usage : ObjectClassType.values())
    {
      assertEquals(ObjectClassType.forName(usage.getName()), usage);
      assertEquals(ObjectClassType.forName(usage.getName().toLowerCase()),
           usage);
      assertEquals(ObjectClassType.forName(usage.getName().toUpperCase()),
           usage);
    }

    assertNull(ObjectClassType.forName("undefined"));
  }
}
