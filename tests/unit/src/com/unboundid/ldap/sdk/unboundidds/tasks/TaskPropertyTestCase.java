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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the TaskProperty class.
 */
public class TaskPropertyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with valid values for all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1AllValues()
         throws Exception
  {
    TaskProperty p = new TaskProperty("attrName", "displayName", "description",
                                      String.class, true, false, false);

    assertNotNull(p);

    assertNotNull(p.getAttributeName());
    assertEquals(p.getAttributeName(), "attrName");

    assertNotNull(p.getDisplayName());
    assertEquals(p.getDisplayName(), "displayName");

    assertNotNull(p.getDescription());
    assertEquals(p.getDescription(), "description");

    assertNotNull(p.getDataType());
    assertEquals(p.getDataType(), String.class);

    assertTrue(p.isRequired());

    assertFalse(p.isMultiValued());

    assertFalse(p.isAdvanced());

    assertNull(p.getAllowedValues());
  }



  /**
   * Tests the first constructor with no attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoAttributeName()
         throws Exception
  {
    new TaskProperty(null,"displayName", "description" ,String.class, true,
                     false, true);
  }



  /**
   * Tests the first constructor with no display name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoDisplayName()
         throws Exception
  {
    new TaskProperty("attrName", null, "description", String.class, true,
                     false, true);
  }



  /**
   * Tests the first constructor with no description.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoDescription()
         throws Exception
  {
    new TaskProperty("attrName", "displayName", null, String.class, true,
                     false, true);
  }



  /**
   * Tests the first constructor with no data type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NoDataType()
         throws Exception
  {
    new TaskProperty("attrName", "displayName", "description", null, true,
                     false, true);
  }



  /**
   * Tests the first constructor with an invalid data type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1InvalidDataType()
         throws Exception
  {
    new TaskProperty("attrName", "displayName", "description",
                     TaskPropertyTestCase.class, true, false, true);
  }



  /**
   * Tests the second constructor with no allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoAllowedValues()
         throws Exception
  {
    TaskProperty p = new TaskProperty("attrName", "displayName", "description",
                                      String.class, false, true, true, null);

    assertNotNull(p);

    assertNotNull(p.getAttributeName());
    assertEquals(p.getAttributeName(), "attrName");

    assertNotNull(p.getDisplayName());
    assertEquals(p.getDisplayName(), "displayName");

    assertNotNull(p.getDescription());
    assertEquals(p.getDescription(), "description");

    assertNotNull(p.getDataType());
    assertEquals(p.getDataType(), String.class);

    assertFalse(p.isRequired());

    assertTrue(p.isMultiValued());

    assertTrue(p.isAdvanced());

    assertNull(p.getAllowedValues());
  }



  /**
   * Tests the second constructor with an empty set of allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2EmptyAllowedValues()
         throws Exception
  {
    TaskProperty p = new TaskProperty("attrName", "displayName", "description",
                                      String.class, false, true, false,
                                      new Object[0]);

    assertNotNull(p);

    assertNotNull(p.getAttributeName());
    assertEquals(p.getAttributeName(), "attrName");

    assertNotNull(p.getDisplayName());
    assertEquals(p.getDisplayName(), "displayName");

    assertNotNull(p.getDescription());
    assertEquals(p.getDescription(), "description");

    assertNotNull(p.getDataType());
    assertEquals(p.getDataType(), String.class);

    assertFalse(p.isRequired());

    assertTrue(p.isMultiValued());

    assertFalse(p.isAdvanced());

    assertNull(p.getAllowedValues());
  }



  /**
   * Tests the second constructor with allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithAllowedValues()
         throws Exception
  {
    TaskProperty p = new TaskProperty("attrName", "displayName", "description",
                                      String.class, false, false, false,
                                      new Object[] { "foo", "bar" });

    assertNotNull(p);

    assertNotNull(p.getAttributeName());
    assertEquals(p.getAttributeName(), "attrName");

    assertNotNull(p.getDisplayName());
    assertEquals(p.getDisplayName(), "displayName");

    assertNotNull(p.getDescription());
    assertEquals(p.getDescription(), "description");

    assertNotNull(p.getDataType());
    assertEquals(p.getDataType(), String.class);

    assertFalse(p.isRequired());

    assertFalse(p.isMultiValued());

    assertFalse(p.isAdvanced());

    assertNotNull(p.getAllowedValues());
    assertEquals(p.getAllowedValues().length, 2);
    assertEquals(p.getAllowedValues()[0], "foo");
    assertEquals(p.getAllowedValues()[1], "bar");
  }



  /**
   * Tests the second constructor with an invalid element in the set of allowed
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2InvalidAllowedValues()
         throws Exception
  {
    new TaskProperty("attrName", "displayName", "description", String.class,
                     false, true, true, new Object[] { "foo", Boolean.TRUE });
  }
}
