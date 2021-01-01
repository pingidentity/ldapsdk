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



import java.util.ArrayList;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides test coverage for the UtilityMessages class.
 */
public class UtilityMessagesTestCase
       extends UtilTestCase
{
  /**
   * Ensures that the specified message is defined and has a format string in
   * the properties file.
   *
   * @param  m  The message key for which to make the determination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "messageKeys")
  public void testMessageDefined(final UtilityMessages m)
         throws Exception
  {
    assertNotNull(m);

    assertEquals(UtilityMessages.valueOf(m.name()), m);

    try
    {
      m.get();
    } catch (final Exception e) {}

    try
    {
      m.get("foo");
    } catch (final Exception e) {}

    assertNotNull(m.toString());
  }



  /**
   * Tests to ensure that message format strings are generated properly without
   * any exceptions when provided with an expected set of arguments.
   *
   * @param  m  The message key for which to make the determination.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "messageKeys")
  public void testMessageGetWithArgsWithoutException(final UtilityMessages m)
         throws Exception
  {
    final String formatString = m.toString();

    final ArrayList<Object> argList = new ArrayList<>(20);
    for (int i=0; i < 20; i++)
    {
      final boolean hasToken;
      if (formatString.contains("{" + i + '}'))
      {
        argList.add("arg" + i);
        hasToken = true;
      }
      else if (formatString.contains("{" + i + ",number,"))
      {
        argList.add(i);
        hasToken = true;
      }
      else
      {
        hasToken = false;
      }

      if (hasToken && ((argList.size() - 1) != i))
      {
        fail("CertMessages." + m.name() + " has a format string that " +
             "contains {" + i + "} without {" + (i-1) + "}:  " +
             m.toString());
      }
    }

    if (argList.isEmpty())
    {
      assertNotNull(m.get());
    }
    else
    {
      final Object[] argArray = new Object[argList.size()];
      argList.toArray(argArray);

      assertNotNull(m.get(argArray));
    }
  }



  /**
   * Retrieves the set of defined message keys.
   *
   * @return  The set of defined message keys.
   */
  @DataProvider(name = "messageKeys")
  public Object[][] getMessageKeys()
  {
    UtilityMessages[] values = UtilityMessages.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }
}
