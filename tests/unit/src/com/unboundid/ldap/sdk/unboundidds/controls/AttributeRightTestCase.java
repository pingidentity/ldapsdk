/*
 * Copyright 2008-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2017 UnboundID Corp.
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
 * This class provides a set of test cases for the {@code AttributeRight} enum.
 */
public class AttributeRightTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the getName method.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testGetName(AttributeRight r)
         throws Exception
  {
    assertNotNull(r.getName());
  }



  /**
   * Provides test coverage for the forName method with a valid name.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testForNameValid(AttributeRight r)
         throws Exception
  {
    assertEquals(AttributeRight.forName(r.getName()), r);
    assertEquals(AttributeRight.forName(r.getName().toUpperCase()), r);
    assertEquals(AttributeRight.forName(r.getName().toLowerCase()), r);
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
    assertNull(AttributeRight.forName("invalid"));
  }



  /**
   * Provides test coverage for the toString method.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testToString(AttributeRight r)
         throws Exception
  {
    assertNotNull(r.toString());
  }



  /**
   * Provides test coverage for the name method.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testName(AttributeRight r)
         throws Exception
  {
    assertNotNull(r.name());
  }



  /**
   * Provides test coverage for the valueOf method with a valid name.
   *
   * @param  r  The attribute right to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="attributeRights")
  public void testValueOfValid(AttributeRight r)
         throws Exception
  {
    assertNotNull(AttributeRight.valueOf(r.name()));
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
    AttributeRight.valueOf("invalid");
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
    assertNotNull(AttributeRight.values());
    assertFalse(AttributeRight.values().length == 0);
  }



  /**
   * Retrieves a set of attribute rights for testing purposes.
   *
   * @return  A set of attribute rights for testing purposes.
   */
  @DataProvider(name = "attributeRights")
  public Object[][] getAttributeRights()
  {
    Object[][] allRights = new Object[AttributeRight.values().length][1];
    for (int i=0; i < allRights.length; i++)
    {
      allRights[i][0] = AttributeRight.values()[i];
    }

    return allRights;
  }
}
