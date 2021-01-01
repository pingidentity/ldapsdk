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
package com.unboundid.util;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides test coverage for the DebugType class.
 */
public class DebugTypeTestCase
       extends UtilTestCase
{
  /**
   * Provides basic test coverage for the provided {@code DebugType} enumerated
   * element.
   *
   * @param  t  The debug type on which to operate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "debugTypes")
  public void testDebugType(final DebugType t)
         throws Exception
  {
    assertNotNull(t);

    assertNotNull(t.getName());

    assertEquals(DebugType.valueOf(t.name()), t);
    assertEquals(DebugType.forName(t.getName()), t);

    assertNotNull(t.toString());
  }



  /**
   * Ensures that the {@code forName} method works properly in a
   * case-insensitive manner.
   *
   * @param  t  The debug type on which to operate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "debugTypes")
  public void testForNameCaseSensitivity(final DebugType t)
         throws Exception
  {
    String lowerName = t.getName().toLowerCase();
    assertEquals(DebugType.forName(lowerName), t);

    String upperName = t.getName().toUpperCase();
    assertEquals(DebugType.forName(upperName), t);

    StringBuilder mixedName = new StringBuilder(lowerName.length());
    for (int i=0; i < lowerName.length(); i++)
    {
      if ((i & 0x01) == 0x01)
      {
        mixedName.append(lowerName.charAt(i));
      }
      else
      {
        mixedName.append(upperName.charAt(i));
      }
    }

    assertEquals(DebugType.forName(mixedName.toString()), t);
  }



  /**
   * Tests the {@code forName} method with an invalid debug type name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameInvalid()
         throws Exception
  {
    assertNull(DebugType.forName("invalid"));
  }



  /**
   * Provides basic test coverage for the {@code getTypeNameList} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetTypeNameList()
         throws Exception
  {
    assertNotNull(DebugType.getTypeNameList());
  }



  /**
   * Retrieves the set of defined debug types.
   *
   * @return  The set of defined debug types.
   */
  @DataProvider(name = "debugTypes")
  public Object[][] getDebugTypes()
  {
    DebugType[] values = DebugType.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }
}
