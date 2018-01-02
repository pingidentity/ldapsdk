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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code EntryRight} enum.
 */
public class EntryRightTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the getName method.
   *
   * @param  r  The entry right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="entryRights")
  public void testGetName(EntryRight r)
         throws Exception
  {
    assertNotNull(r.getName());
  }



  /**
   * Provides test coverage for the forName method with a valid name.
   *
   * @param  r  The entry right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="entryRights")
  public void testForNameValid(EntryRight r)
         throws Exception
  {
    assertEquals(EntryRight.forName(r.getName()), r);
    assertEquals(EntryRight.forName(r.getName().toUpperCase()), r);
    assertEquals(EntryRight.forName(r.getName().toLowerCase()), r);
  }



  /**
   * Provides test coverage for the forName method with an invalid name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameInvalid()
         throws Exception
  {
    assertNull(EntryRight.forName("invalid"));
  }



  /**
   * Provides test coverage for the toString method.
   *
   * @param  r  The entry right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="entryRights")
  public void testToString(EntryRight r)
         throws Exception
  {
    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the name method.
   *
   * @param  r  The entry right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="entryRights")
  public void testName(EntryRight r)
         throws Exception
  {
    assertNotNull(r.name());
  }



  /**
   * Provides test coverage for the valueOf method with a valid name.
   *
   * @param  r  The entry right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="entryRights")
  public void testValueOfValid(EntryRight r)
         throws Exception
  {
    assertNotNull(EntryRight.valueOf(r.name()));
  }



  /**
   * Provides test coverage for the valueOf method with an invalid name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testValueOfInvalid()
         throws Exception
  {
    EntryRight.valueOf("invalid");
  }



  /**
   * Provides test coverage for the values method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValues()
         throws Exception
  {
    assertNotNull(EntryRight.values());
    assertFalse(EntryRight.values().length == 0);
  }



  /**
   * Retrieves a set of entry rights for testing purposes.
   *
   * @return  A set of entry rights for testing purposes.
   */
  @DataProvider(name = "entryRights")
  public Object[][] getentryRights()
  {
    Object[][] allRights = new Object[EntryRight.values().length][1];
    for (int i=0; i < allRights.length; i++)
    {
      allRights[i][0] = EntryRight.values()[i];
    }

    return allRights;
  }
}
