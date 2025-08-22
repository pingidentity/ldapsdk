/*
 * Copyright 2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2025 Ping Identity Corporation
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
 * Copyright (C) 2025 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * THis clas provides a set of test cases for the {@code PropertyManager} class.
 */
public final class PropertyManagerCacheRecordTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a cache record for an undefined property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedRecord()
         throws Exception
  {
    final PropertyManagerCacheRecord r = new PropertyManagerCacheRecord(
         "test-property-name", null, Integer.MAX_VALUE);

    assertEquals(r.getPropertyName(), "test-property-name");

    assertEquals(r.getExpirationTimeMillis(), Long.MAX_VALUE);

    assertFalse(r.isExpired());

    assertFalse(r.isDefined());

    assertNull(r.stringValue());

    assertNull(r.stringValue(null));

    assertEquals(r.stringValue("test"), "test");

    assertNull(r.booleanValue());

    assertNull(r.booleanValue(null, true));

    assertEquals(r.booleanValue(Boolean.TRUE, true), Boolean.TRUE);

    assertEquals(r.booleanValue(Boolean.FALSE, true), Boolean.FALSE);

    assertNull(r.booleanValue(null, false));

    assertEquals(r.booleanValue(Boolean.TRUE, false), Boolean.TRUE);

    assertEquals(r.booleanValue(Boolean.FALSE, false), Boolean.FALSE);

    assertNull(r.intValue());

    assertNull(r.intValue(null, true));

    assertEquals(r.intValue(1234, true), Integer.valueOf(1234));

    assertNull(r.intValue(null, false));

    assertEquals(r.intValue(5678, false), Integer.valueOf(5678));

    assertNull(r.longValue());

    assertNull(r.longValue(null, true));

    assertEquals(r.longValue(1234L, true), Long.valueOf(1234L));

    assertNull(r.longValue(null, false));

    assertEquals(r.longValue(5678L, false), Long.valueOf(5678L));

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a cache record for a property whose string value
   * cannot be parsed a Boolean or a number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringRecordNotBooleanOrNumber()
         throws Exception
  {
    final PropertyManagerCacheRecord r = new PropertyManagerCacheRecord(
         "test-property-name", "test", 123_456);

    assertEquals(r.getPropertyName(), "test-property-name");

    assertTrue(r.getExpirationTimeMillis() > System.currentTimeMillis());

    assertFalse(r.isExpired());

    assertTrue(r.isDefined());

    assertEquals(r.stringValue(), "test");

    assertEquals(r.stringValue(null), "test");

    assertEquals(r.stringValue("foo"), "test");

    assertNull(r.booleanValue());

    try
    {
      r.booleanValue(null, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "Boolean");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.booleanValue(Boolean.TRUE, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "Boolean");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.booleanValue(Boolean.FALSE, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "Boolean");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    assertNull(r.booleanValue(null, false));

    assertEquals(r.booleanValue(Boolean.TRUE, false), Boolean.TRUE);

    assertEquals(r.booleanValue(Boolean.FALSE, false), Boolean.FALSE);

    assertNull(r.intValue());

    try
    {
      r.intValue(null, true);
      fail("Expected an exception from a string that cannot be parsed as an " +
           "integer");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.intValue(1234, true);
      fail("Expected an exception from a string that cannot be parsed as an " +
           "integer");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    assertNull(r.intValue(null, false));

    assertEquals(r.intValue(5678, false), Integer.valueOf(5678));

    assertNull(r.longValue());

    try
    {
      r.longValue(null, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "long");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.longValue(1234L, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "long");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    assertNull(r.longValue(null, false));

    assertEquals(r.longValue(5678L, false), Long.valueOf(5678L));

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a cache record for a property whose string value
   * can be parsed as both a Boolean and a number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringRecordBothBooleanAndNumber()
         throws Exception
  {
    final PropertyManagerCacheRecord r = new PropertyManagerCacheRecord(
         "test-property-name", "0", -123_456);

    assertEquals(r.getPropertyName(), "test-property-name");

    assertTrue(r.getExpirationTimeMillis() < System.currentTimeMillis());

    assertTrue(r.isExpired());

    assertTrue(r.isDefined());

    assertEquals(r.stringValue(), "0");

    assertEquals(r.stringValue(null), "0");

    assertEquals(r.stringValue("test"), "0");

    assertEquals(r.booleanValue(), Boolean.FALSE);

    assertEquals(r.booleanValue(null, true), Boolean.FALSE);

    assertEquals(r.booleanValue(Boolean.TRUE, true), Boolean.FALSE);

    assertEquals(r.booleanValue(Boolean.FALSE, true), Boolean.FALSE);

    assertEquals(r.booleanValue(null, false), Boolean.FALSE);

    assertEquals(r.booleanValue(Boolean.TRUE, false), Boolean.FALSE);

    assertEquals(r.booleanValue(Boolean.FALSE, false), Boolean.FALSE);

    assertEquals(r.intValue(), Integer.valueOf(0));

    assertEquals(r.intValue(null, true), Integer.valueOf(0));

    assertEquals(r.intValue(1234, true), Integer.valueOf(0));

    assertEquals(r.intValue(null, false), Integer.valueOf(0));

    assertEquals(r.intValue(1234, false), Integer.valueOf(0));

    assertEquals(r.longValue(), Long.valueOf(0));

    assertEquals(r.longValue(null, true), Long.valueOf(0));

    assertEquals(r.longValue(1234L, true), Long.valueOf(0));

    assertEquals(r.longValue(null, false), Long.valueOf(0));

    assertEquals(r.longValue(1234L, false), Long.valueOf(0));

    assertNotNull(r.toString());
  }



  /**
   * Tests the behavior for a cache record for a property whose string value
   * can be parsed as a long, but not a Boolean or an integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringRecordParsableAsLong()
         throws Exception
  {
    final PropertyManagerCacheRecord r = new PropertyManagerCacheRecord(
         "test-property-name", "1234567890123", Integer.MAX_VALUE);

    assertEquals(r.getPropertyName(), "test-property-name");

    assertEquals(r.getExpirationTimeMillis(), Long.MAX_VALUE);

    assertFalse(r.isExpired());

    assertTrue(r.isDefined());

    assertEquals(r.stringValue(), "1234567890123");

    assertEquals(r.stringValue(null), "1234567890123");

    assertEquals(r.stringValue("test"), "1234567890123");

    assertNull(r.booleanValue());

    try
    {
      r.booleanValue(null, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "Boolean");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.booleanValue(Boolean.TRUE, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "Boolean");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.booleanValue(Boolean.FALSE, true);
      fail("Expected an exception from a string that cannot be parsed as a " +
           "Boolean");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    assertNull(r.booleanValue(null, false));

    assertEquals(r.booleanValue(Boolean.TRUE, false), Boolean.TRUE);

    assertEquals(r.booleanValue(Boolean.FALSE, false), Boolean.FALSE);

    assertNull(r.intValue());

    try
    {
      r.intValue(null, true);
      fail("Expected an exception from a string that cannot be parsed as an " +
           "integer");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    try
    {
      r.intValue(1234, true);
      fail("Expected an exception from a string that cannot be parsed as an " +
           "integer");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected
    }

    assertNull(r.intValue(null, false));

    assertEquals(r.intValue(5678, false), Integer.valueOf(5678));

    assertEquals(r.longValue(), Long.valueOf(1234567890123L));

    assertEquals(r.longValue(null, true), Long.valueOf(1234567890123L));

    assertEquals(r.longValue(1234L, true), Long.valueOf(1234567890123L));

    assertEquals(r.longValue(null, false), Long.valueOf(1234567890123L));

    assertEquals(r.longValue(1234L, false), Long.valueOf(1234567890123L));

    assertNotNull(r.toString());
  }
}
