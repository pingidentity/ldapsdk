/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import java.util.ArrayList;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the LDAPMessages class.
 */
public class ExperimentalMessagesTestCase
       extends LDAPSDKTestCase
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
  public void testMessageDefined(final ExperimentalMessages m)
         throws Exception
  {
    assertNotNull(m);

    assertEquals(ExperimentalMessages.valueOf(m.name()), m);

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
  public void testMessageGetWithArgsWithoutException(
                   final ExperimentalMessages m)
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
    ExperimentalMessages[] values = ExperimentalMessages.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }
}
