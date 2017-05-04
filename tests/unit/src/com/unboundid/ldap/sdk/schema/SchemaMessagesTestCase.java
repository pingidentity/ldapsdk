/*
 * Copyright 2008-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 Ping Identity Corporation
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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the SchemaMessages class.
 */
public class SchemaMessagesTestCase
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
  public void testMessageDefined(final SchemaMessages m)
         throws Exception
  {
    assertNotNull(m);

    assertEquals(SchemaMessages.valueOf(m.name()), m);

    assertNotNull(m.get());

    try
    {
      m.get("foo");
    } catch (final Exception e) {}

    assertNotNull(m.toString());
  }



  /**
   * Retrieves the set of defined message keys.
   *
   * @return  The set of defined message keys.
   */
  @DataProvider(name = "messageKeys")
  public Object[][] getMessageKeys()
  {
    SchemaMessages[] values = SchemaMessages.values();
    Object[][] returnArray = new Object[values.length][1];
    for (int i=0; i < values.length; i++)
    {
      returnArray[i][0] = values[i];
    }

    return returnArray;
  }
}
