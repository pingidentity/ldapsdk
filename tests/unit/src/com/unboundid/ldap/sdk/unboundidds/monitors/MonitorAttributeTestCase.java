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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides test coverage for the MonitorAttribute class.
 */
public class MonitorAttributeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor which accepts a Boolean value with a non-{@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description", Boolean.TRUE);

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Boolean.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertFalse(a.hasMultipleValues());

    assertEquals(a.getBooleanValue(), Boolean.TRUE);
  }



  /**
   * Tests the constructor which accepts a Boolean value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testBooleanNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Boolean) null);
  }



  /**
   * Tests the constructor which accepts a Date value with a non-{@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDateNonNull()
         throws Exception
  {
    Date d = new Date();
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description", d);

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Date.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertFalse(a.hasMultipleValues());

    assertEquals(a.getDateValue(), d);
  }



  /**
   * Tests the constructor which accepts a Date value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDateNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Date) null);
  }



  /**
   * Tests the constructor which accepts a Date array value with a
   * non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDatesNonNull()
         throws Exception
  {
    Date d1 = new Date();
    Date d2 = new Date(d1.getTime() + 1234);

    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              new Date[] { d1, d2 });

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Date.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);

    assertTrue(a.hasMultipleValues());

    assertEquals(a.getDateValue(), d1);

    assertNotNull(a.getDateValues());
    assertEquals(a.getDateValues().size(), 2);
  }



  /**
   * Tests the constructor which accepts a Date array value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDatesNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Date[]) null);
  }



  /**
   * Tests the constructor which accepts a Double value with a non-{@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoubleNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              Double.valueOf(1.5D));

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Double.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertFalse(a.hasMultipleValues());

    assertEquals(a.getDoubleValue(), Double.valueOf(1.5D));
  }



  /**
   * Tests the constructor which accepts a Double value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDoubleNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Double) null);
  }



  /**
   * Tests the constructor which accepts a Double array value with a
   * non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDoublesNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              new Double[] { 1.5D, 2.5D });

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Double.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);

    assertTrue(a.hasMultipleValues());

    assertEquals(a.getDoubleValue(), Double.valueOf(1.5D));

    assertNotNull(a.getDoubleValues());
    assertEquals(a.getDoubleValues().size(), 2);
  }



  /**
   * Tests the constructor which accepts a Double array value with a
   * {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDoublesNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Double[]) null);
  }



  /**
   * Tests the constructor which accepts an Integer value with a
   * non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegerNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              Integer.valueOf(5));

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Integer.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertFalse(a.hasMultipleValues());

    assertEquals(a.getIntegerValue(), Integer.valueOf(5));
  }



  /**
   * Tests the constructor which accepts an Integer value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testIntegerNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Integer) null);
  }



  /**
   * Tests the constructor which accepts an Integer array value with a
   * non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIntegersNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              new Integer[] { 5, 10 });

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Integer.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);

    assertTrue(a.hasMultipleValues());

    assertEquals(a.getIntegerValue(), Integer.valueOf(5));

    assertNotNull(a.getIntegerValues());
    assertEquals(a.getIntegerValues().size(), 2);
  }



  /**
   * Tests the constructor which accepts an Integer array value with a
   * {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testIntegersNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description",
         (Integer[]) null);
  }



  /**
   * Tests the constructor which accepts a Long value with a non-{@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              Long.valueOf(5));

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Long.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertFalse(a.hasMultipleValues());

    assertEquals(a.getLongValue(), Long.valueOf(5));
  }



  /**
   * Tests the constructor which accepts a Long value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testLongNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Long) null);
  }



  /**
   * Tests the constructor which accepts a Long array value with a
   * non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongsNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              new Long[] { 5L, 10L });

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), Long.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);

    assertTrue(a.hasMultipleValues());

    assertEquals(a.getLongValue(), Long.valueOf(5L));

    assertNotNull(a.getLongValues());
    assertEquals(a.getLongValues().size(), 2);
  }



  /**
   * Tests the constructor which accepts a Long array value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testLongsNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (Long[]) null);
  }



  /**
   * Tests the constructor which accepts a String value with a non-{@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description", "foo");

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), String.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertFalse(a.hasMultipleValues());

    assertEquals(a.getStringValue(), "foo");
  }



  /**
   * Tests the constructor which accepts a String value with a {@code null}
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testStringNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (String) null);
  }



  /**
   * Tests the constructor which accepts a String array value with a
   * non-{@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringsNonNull()
         throws Exception
  {
    MonitorAttribute a = new MonitorAttribute("name", "displayName",
                                              "description",
                                              new String[] { "foo", "bar" });

    assertNotNull(a);
    assertNotNull(a.toString());

    assertNotNull(a.getName());
    assertEquals(a.getName(), "name");

    assertNotNull(a.getDisplayName());
    assertEquals(a.getDisplayName(), "displayName");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "description");

    assertNotNull(a.getDataType());
    assertEquals(a.getDataType(), String.class);

    assertNotNull(a.getValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);

    assertTrue(a.hasMultipleValues());

    assertEquals(a.getStringValue(), "foo");

    assertNotNull(a.getStringValues());
    assertEquals(a.getStringValues().size(), 2);
  }



  /**
   * Tests the constructor which accepts a String array value with a
   * {@code null} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testStringsNull()
         throws Exception
  {
    new MonitorAttribute("name", "displayName", "description", (String[]) null);
  }
}
