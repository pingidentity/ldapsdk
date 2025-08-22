/*
 * Copyright 2024-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024-2025 Ping Identity Corporation
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
 * Copyright (C) 2024-2025 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.UUID;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of unit tests for the {@link PropertyManager}
 * class.
 */
public final class PropertyManagerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the basic {@code get} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGet()
         throws Exception
  {
    final String propertyName = StaticUtils.randomAlphabeticString(20, true);
    if (StaticUtils.getSystemProperty(propertyName) == null)
    {
      assertNull(PropertyManager.get(propertyName));
      assertNull(PropertyManager.get(propertyName, null));
      assertEquals(PropertyManager.get(propertyName, "a-default-value"),
           "a-default-value");
    }

    StaticUtils.setSystemProperty(propertyName, "a-real-value");
    assertEquals(PropertyManager.get(propertyName), "a-real-value");
    assertEquals(PropertyManager.get(propertyName, null), "a-real-value");
    assertEquals(PropertyManager.get(propertyName, "a-default-value"),
         "a-real-value");

    StaticUtils.setSystemProperty(propertyName, "");
    assertEquals(PropertyManager.get(propertyName), "");
    assertEquals(PropertyManager.get(propertyName, null), "");
    assertEquals(PropertyManager.get(propertyName, "a-default-value"), "");

    assertEquals(PropertyManager.getIdentifierString(propertyName),
         "system property '" + propertyName + '\'');

    StaticUtils.clearSystemProperty(propertyName);
    assertNull(PropertyManager.get(propertyName));
    assertNull(PropertyManager.get(propertyName, null));
    assertEquals(PropertyManager.get(propertyName, "a-default-value"),
         "a-default-value");
  }



  /**
   * Tests to ensure that we can successfully get the values of properties when
   * set as environment variables.  We can't set environment variables in a
   * Java process, but it's almost certainly the case that there will already
   * be environment variables set that we can use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGettingEnvironmentVariables()
         throws Exception
  {
    for (final Map.Entry<String,String> e :
         StaticUtils.getEnvironmentVariables().entrySet())
    {
      final String variableName = e.getKey();
      final String variableValue = e.getValue();

      assertEquals(PropertyManager.get(variableName), variableValue);

      if (StaticUtils.getSystemProperty(variableName) == null)
      {
        assertEquals(PropertyManager.getIdentifierString(variableName),
             "environment variable '" + variableName + '\'');
      }

      final String systemPropertyName =
           variableName.toLowerCase().replace('_', '.');
      if (PropertyManager.generateEnvironmentVariableNameFromPropertyName(
           systemPropertyName).equals(variableName))
      {
        if ((StaticUtils.getSystemProperty(systemPropertyName) == null) &&
             (StaticUtils.getEnvironmentVariable(systemPropertyName) == null))
        {
          assertEquals(PropertyManager.get(systemPropertyName), variableValue);
          assertEquals(PropertyManager.getIdentifierString(systemPropertyName),
               "environment variable '" + variableName + '\'');
        }
      }
    }
  }



  /**
   * Tests the behavior of the {@code getBoolean} methods.
   *
   * @param  stringValue    The string value to parse.  It must not be
   *                        {@code null}.
   * @param  expectedValue  The Boolean value that we expect to retrieve from
   *                        the specified string value.  It may be {@code null}
   *                        if the provided string value cannot be parsed as a
   *                        valid Boolean.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testBooleanValues")
  public void testGetBoolean(final String stringValue,
                             final Boolean expectedValue)
         throws Exception
  {
    final String propertyName = StaticUtils.randomAlphabeticString(20, true);
    if (StaticUtils.getSystemProperty(propertyName) == null)
    {
      assertNull(PropertyManager.getBoolean(propertyName));
      assertNull(PropertyManager.getBoolean(propertyName, null));
      assertEquals(PropertyManager.getBoolean(propertyName, true),
           Boolean.TRUE);
      assertEquals(PropertyManager.getBoolean(propertyName, false),
           Boolean.FALSE);
      assertEquals(PropertyManager.getBoolean(propertyName, true, false),
           Boolean.TRUE);
      assertEquals(PropertyManager.getBoolean(propertyName, false, false),
           Boolean.FALSE);
      assertEquals(PropertyManager.getBoolean(propertyName, true, true),
           Boolean.TRUE);
      assertEquals(PropertyManager.getBoolean(propertyName, false, true),
           Boolean.FALSE);
    }

    StaticUtils.setSystemProperty(propertyName, stringValue);

    assertEquals(PropertyManager.getBoolean(propertyName), expectedValue);
    assertEquals(PropertyManager.getBoolean(propertyName, null), expectedValue);

    if (expectedValue == null)
    {
      assertEquals(PropertyManager.getBoolean(propertyName, true),
           Boolean.TRUE);
      assertEquals(PropertyManager.getBoolean(propertyName, false),
           Boolean.FALSE);

      assertEquals(PropertyManager.getBoolean(propertyName, true, false),
           Boolean.TRUE);
      assertEquals(PropertyManager.getBoolean(propertyName, false, false),
           Boolean.FALSE);

      try
      {
        PropertyManager.getBoolean(propertyName, true, true);
        fail("Expected an exception when testing with an invalid value.");
      }
      catch (final IllegalArgumentException e)
      {
        // This was expected.
      }

      try
      {
        PropertyManager.getBoolean(propertyName, false, true);
        fail("Expected an exception when testing with an invalid value.");
      }
      catch (final IllegalArgumentException e)
      {
        // This was expected.
      }
    }
    else
    {
      assertEquals(PropertyManager.getBoolean(propertyName, true),
           expectedValue);
      assertEquals(PropertyManager.getBoolean(propertyName, false),
           expectedValue);

      assertEquals(PropertyManager.getBoolean(propertyName, true, false),
           expectedValue);
      assertEquals(PropertyManager.getBoolean(propertyName, false, false),
           expectedValue);

      assertEquals(PropertyManager.getBoolean(propertyName, true, true),
           expectedValue);
      assertEquals(PropertyManager.getBoolean(propertyName, false, true),
           expectedValue);
    }
  }



  /**
   * Retrieves a set of values to use when testing the {@code getBoolean}
   * methods.
   *
   * @return  A set of values to use when testing the {@code getBoolean}
   *          methods.
   */
  @DataProvider(name="testBooleanValues")
  public Object[][] getTestBooleanValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "true",
        true
      },
      new Object[]
      {
        "TRUE",
        true
      },
      new Object[]
      {
        "True",
        true
      },
      new Object[]
      {
        " true",
        true
      },
      new Object[]
      {
        "true ",
        true
      },
      new Object[]
      {
        " true ",
        true
      },
      new Object[]
      {
        "    true   ",
        true
      },
      new Object[]
      {
        "t",
        true
      },
      new Object[]
      {
        "T",
        true
      },
      new Object[]
      {
        "yes",
        true
      },
      new Object[]
      {
        "YES",
        true
      },
      new Object[]
      {
        "Yes",
        true
      },
      new Object[]
      {
        "y",
        true
      },
      new Object[]
      {
        "Y",
        true
      },
      new Object[]
      {
        "on",
        true
      },
      new Object[]
      {
        "ON",
        true
      },
      new Object[]
      {
        "On",
        true
      },
      new Object[]
      {
        "1",
        true
      },


      new Object[]
      {
        "false",
        false
      },
      new Object[]
      {
        "FALSE",
        false
      },
      new Object[]
      {
        "False",
        false
      },
      new Object[]
      {
        " false",
        false
      },
      new Object[]
      {
        "false ",
        false
      },
      new Object[]
      {
        " false ",
        false
      },
      new Object[]
      {
        "    false   ",
        false
      },
      new Object[]
      {
        "f",
        false
      },
      new Object[]
      {
        "F",
        false
      },
      new Object[]
      {
        "no",
        false
      },
      new Object[]
      {
        "NO",
        false
      },
      new Object[]
      {
        "No",
        false
      },
      new Object[]
      {
        "n",
        false
      },
      new Object[]
      {
        "N",
        false
      },
      new Object[]
      {
        "off",
        false
      },
      new Object[]
      {
        "OFF",
        false
      },
      new Object[]
      {
        "Off",
        false
      },
      new Object[]
      {
        "0",
        false
      },


      new Object[]
      {
        "",
        null
      },
      new Object[]
      {
        "invalid",
        null
      },
    };
  }



  /**
   * Tests the behavior of the {@code getInt} methods.
   *
   * @param  stringValue    The string value to parse.  It must not be
   *                        {@code null}.
   * @param  expectedValue  The integer value that we expect to retrieve from
   *                        the specified string value.  It may be {@code null}
   *                        if the provided string value cannot be parsed as a
   *                        valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testIntValues")
  public void testGetInt(final String stringValue,
                         final Integer expectedValue)
         throws Exception
  {
    final String propertyName = StaticUtils.randomAlphabeticString(20, true);
    if (StaticUtils.getSystemProperty(propertyName) == null)
    {
      assertNull(PropertyManager.getInt(propertyName));
      assertNull(PropertyManager.getInt(propertyName, null));
      assertEquals(PropertyManager.getInt(propertyName, 1234).intValue(), 1234);
      assertEquals(
           PropertyManager.getInt(propertyName, 1234, false).intValue(), 1234);
      assertEquals(
           PropertyManager.getInt(propertyName, 1234, true).intValue(), 1234);
    }

    StaticUtils.setSystemProperty(propertyName, stringValue);

    assertEquals(PropertyManager.getInt(propertyName), expectedValue);
    assertEquals(PropertyManager.getInt(propertyName, null), expectedValue);

    if (expectedValue == null)
    {
      assertEquals(PropertyManager.getInt(propertyName, 1234).intValue(),
           1234);
      assertEquals(PropertyManager.getInt(propertyName, 5678).intValue(),
           5678);

      assertEquals(PropertyManager.getInt(propertyName, 4321, false).intValue(),
           4321);
      assertEquals(PropertyManager.getInt(propertyName, 8765, false).intValue(),
           8765);

      try
      {
        PropertyManager.getInt(propertyName, 1234, true);
        fail("Expected an exception when testing with an invalid value.");
      }
      catch (final IllegalArgumentException e)
      {
        // This was expected.
      }

      try
      {
        PropertyManager.getInt(propertyName, 1234, true);
        fail("Expected an exception when testing with an invalid value.");
      }
      catch (final IllegalArgumentException e)
      {
        // This was expected.
      }
    }
    else
    {
      assertEquals(PropertyManager.getInt(propertyName, 1234),
           expectedValue);
      assertEquals(PropertyManager.getInt(propertyName, 1234),
           expectedValue);

      assertEquals(PropertyManager.getInt(propertyName, 1234, false),
           expectedValue);
      assertEquals(PropertyManager.getInt(propertyName, 1234, false),
           expectedValue);

      assertEquals(PropertyManager.getInt(propertyName, 1234, true),
           expectedValue);
      assertEquals(PropertyManager.getInt(propertyName, 1234, true),
           expectedValue);
    }
  }



  /**
   * Retrieves a set of values to use when testing the {@code getInt}
   * methods.
   *
   * @return  A set of values to use when testing the {@code getInt}
   *          methods.
   */
  @DataProvider(name="testIntValues")
  public Object[][] getTestIntValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "1",
        1
      },
      new Object[]
      {
        " 1",
        1
      },
      new Object[]
      {
        " 1 ",
        1
      },
      new Object[]
      {
        "   1   ",
        1
      },
      new Object[]
      {
        "0",
        0
      },
      new Object[]
      {
        "-1",
        -1
      },
      new Object[]
      {
        "12345",
        12345
      },
      new Object[]
      {
        String.valueOf(Integer.MAX_VALUE),
        Integer.MAX_VALUE
      },
      new Object[]
      {
        String.valueOf(Integer.MIN_VALUE),
        Integer.MIN_VALUE
      },


      new Object[]
      {
        String.valueOf(Long.MAX_VALUE),
        null
      },
      new Object[]
      {
        String.valueOf(Long.MIN_VALUE),
        null
      },
      new Object[]
      {
        "invalid",
        null
      },
    };
  }



  /**
   * Tests the behavior of the {@code getLong} methods.
   *
   * @param  stringValue    The string value to parse.  It must not be
   *                        {@code null}.
   * @param  expectedValue  The long value that we expect to retrieve from the
   *                        specified string value.  It may be {@code null} if
   *                        the provided string value cannot be parsed as a
   *                        valid long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testLongValues")
  public void testGetLong(final String stringValue,
                          final Long expectedValue)
         throws Exception
  {
    final String propertyName = StaticUtils.randomAlphabeticString(20, true);
    if (StaticUtils.getSystemProperty(propertyName) == null)
    {
      assertNull(PropertyManager.getLong(propertyName));
      assertNull(PropertyManager.getLong(propertyName, null));
      assertEquals(
           PropertyManager.getLong(propertyName, 1234L).longValue(),
           1234L);
      assertEquals(
           PropertyManager.getLong(propertyName, 1234L, false).intValue(),
           1234L);
      assertEquals(
           PropertyManager.getLong(propertyName, 1234L, true).intValue(),
           1234L);
    }

    StaticUtils.setSystemProperty(propertyName, stringValue);

    assertEquals(PropertyManager.getLong(propertyName), expectedValue);
    assertEquals(PropertyManager.getLong(propertyName, null), expectedValue);

    if (expectedValue == null)
    {
      assertEquals(
           PropertyManager.getLong(propertyName, 1234L).longValue(),
           1234L);
      assertEquals(
           PropertyManager.getLong(propertyName, 5678L).longValue(),
           5678L);

      assertEquals(
           PropertyManager.getLong(propertyName, 4321L, false).longValue(),
           4321L);
      assertEquals(
           PropertyManager.getLong(propertyName, 8765L, false).longValue(),
           8765L);

      try
      {
        PropertyManager.getLong(propertyName, 1234L, true);
        fail("Expected an exception when testing with an invalid value.");
      }
      catch (final IllegalArgumentException e)
      {
        // This was expected.
      }

      try
      {
        PropertyManager.getLong(propertyName, 1234L, true);
        fail("Expected an exception when testing with an invalid value.");
      }
      catch (final IllegalArgumentException e)
      {
        // This was expected.
      }
    }
    else
    {
      assertEquals(PropertyManager.getLong(propertyName, 1234L),
           expectedValue);
      assertEquals(PropertyManager.getLong(propertyName, 1234L),
           expectedValue);

      assertEquals(PropertyManager.getLong(propertyName, 1234L, false),
           expectedValue);
      assertEquals(PropertyManager.getLong(propertyName, 1234L, false),
           expectedValue);

      assertEquals(PropertyManager.getLong(propertyName, 1234L, true),
           expectedValue);
      assertEquals(PropertyManager.getLong(propertyName, 1234L, true),
           expectedValue);
    }
  }



  /**
   * Retrieves a set of values to use when testing the {@code getLong}
   * methods.
   *
   * @return  A set of values to use when testing the {@code getLong}
   *          methods.
   */
  @DataProvider(name="testLongValues")
  public Object[][] getTestLongValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "1",
        1L
      },
      new Object[]
      {
        " 1",
        1L
      },
      new Object[]
      {
        " 1 ",
        1L
      },
      new Object[]
      {
        "   1   ",
        1L
      },
      new Object[]
      {
        "0",
        0L
      },
      new Object[]
      {
        "-1",
        -1L
      },
      new Object[]
      {
        "12345",
        12345L
      },
      new Object[]
      {
        String.valueOf(Integer.MAX_VALUE),
        Long.valueOf(Integer.MAX_VALUE)
      },
      new Object[]
      {
        String.valueOf(Integer.MIN_VALUE),
        Long.valueOf(Integer.MIN_VALUE)
      },
      new Object[]
      {
        String.valueOf(Long.MAX_VALUE),
        Long.MAX_VALUE
      },
      new Object[]
      {
        String.valueOf(Long.MIN_VALUE),
        Long.MIN_VALUE
      },


      new Object[]
      {
        "invalid",
        null
      },
    };
  }



  /**
   * Tests the behavior of the {@code getCommaDelimitedList methods.
   *
   * @param  stringValue                  The string value to parse.  It must
   *                                      not be {@code null}.
   * @param  expectedListWithTrimming     The expected list when trimming is
   *                                      enabled.
   * @param  expectedListWithoutTrimming  The expected list when trimming is
   *                                      not enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testCommaDelimitedValues")
  public void testGetCommaDelimitedList(final String stringValue,
                   final List<String> expectedListWithTrimming,
                   final List<String> expectedListWithoutTrimming)
  {
    final String propertyName = StaticUtils.randomAlphabeticString(20, true);
    if (StaticUtils.getSystemProperty(propertyName) == null)
    {
      assertEquals(PropertyManager.getCommaDelimitedList(propertyName),
           Collections.emptyList());
      assertEquals(PropertyManager.getCommaDelimitedList(propertyName, true),
           Collections.emptyList());
      assertEquals(PropertyManager.getCommaDelimitedList(propertyName, false),
           Collections.emptyList());
    }

    StaticUtils.setSystemProperty(propertyName, stringValue);

    assertEquals(PropertyManager.getCommaDelimitedList(propertyName),
         expectedListWithTrimming);
    assertEquals(PropertyManager.getCommaDelimitedList(propertyName, true),
         expectedListWithTrimming);
    assertEquals(PropertyManager.getCommaDelimitedList(propertyName, false),
         expectedListWithoutTrimming);
  }



  /**
   * Retrieves a set of values to use when testing the
   * {@code getCommaDelimitedList} methods.
   *
   * @return  A set of values to use when testing the
   *          {@code getCommaDelimitedList} methods.
   */
  @DataProvider(name="testCommaDelimitedValues")
  public Object[][] getTestCommaDelimitedValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        Collections.singletonList(""),
        Collections.singletonList("")
      },
      new Object[]
      {
        " ",
        Collections.singletonList(""),
        Collections.singletonList(" ")
      },
      new Object[]
      {
        "foo",
        Collections.singletonList("foo"),
        Collections.singletonList("foo")
      },
      new Object[]
      {
        "foo ",
        Collections.singletonList("foo"),
        Collections.singletonList("foo ")
      },
      new Object[]
      {
        " foo ",
        Collections.singletonList("foo"),
        Collections.singletonList(" foo ")
      },
      new Object[]
      {
        "foo,bar",
        Arrays.asList("foo", "bar"),
        Arrays.asList("foo", "bar")
      },
      new Object[]
      {
        "foo, bar",
        Arrays.asList("foo", "bar"),
        Arrays.asList("foo", " bar")
      },
      new Object[]
      {
        "foo,bar, baz",
        Arrays.asList("foo", "bar", "baz"),
        Arrays.asList("foo", "bar", " baz")
      },
      new Object[]
      {
        "foo,,bar",
        Arrays.asList("foo", "", "bar"),
        Arrays.asList("foo", "", "bar")
      },
    };
  }



  /**
   * Tests the behavior of the {@code getProperties} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetProperties()
         throws Exception
  {
    final String[] nameArray = new String[10];
    final Map<String,String> propertyMap = new TreeMap<>();
    while (propertyMap.size() < 10)
    {
      final String propertyName = StaticUtils.randomAlphabeticString(20, true);
      if (PropertyManager.get(propertyName) == null)
      {
        nameArray[propertyMap.size()] = propertyName;
        propertyMap.put(propertyName,
             StaticUtils.randomAlphabeticString(20, true));
      }
    }


    assertNotNull(PropertyManager.getProperties(nameArray));
    assertTrue(PropertyManager.getProperties(nameArray).isEmpty());


    for (int i=0; i < 10; i++)
    {
      final String propertyName = nameArray[i];
      assertNotNull(propertyName);

      final String propertyValue = propertyMap.get(propertyName);
      assertNotNull(propertyValue);

      StaticUtils.setSystemProperty(propertyName, propertyValue);

      final Properties properties = PropertyManager.getProperties(nameArray);
      assertNotNull(properties);
      assertEquals(properties.size(), (i + 1));

      for (int j=0; j < 10; j++)
      {
        if (j <= i)
        {
          assertNotNull(properties.getProperty(nameArray[j]));
          assertEquals(properties.getProperty(nameArray[j]),
               propertyMap.get(nameArray[j]));
        }
        else
        {
          assertNull(properties.getProperty(nameArray[j]));
        }
      }
    }
  }



  /**
   * Tests the behavior when the property manager is configured to use caching.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCaching()
         throws Exception
  {
    // Generate random property names to use for testing.  Make sure that those
    // properties aren't actually defined.
    final String stringPropertyName = UUID.randomUUID().toString();
    final String booleanPropertyName = UUID.randomUUID().toString();
    final String intPropertyName = UUID.randomUUID().toString();
    final String longPropertyName = UUID.randomUUID().toString();

    assertNull(System.getProperty(stringPropertyName));
    assertNull(System.getProperty(booleanPropertyName));
    assertNull(System.getProperty(intPropertyName));
    assertNull(System.getProperty(longPropertyName));


    // Enable caching for 1 second.
    PropertyManager.setCacheDurationMillis(1_000);
    assertEquals(PropertyManager.getCacheDurationMillis(), 1_000);

    try
    {
      // Clear the cache and make sure that it starts empty.
      PropertyManager.clearCache();
      assertTrue(PropertyManager.getCache().isEmpty());


      // Make initial attempts to retrieve the properties using the associated
      // syntax.  Ensure that all of the attempts indicate that the properties
      // aren't defined.
      assertNull(PropertyManager.get(stringPropertyName));
      assertNull(PropertyManager.getBoolean(booleanPropertyName));
      assertNull(PropertyManager.getInt(intPropertyName));
      assertNull(PropertyManager.getLong(longPropertyName));


      // Make sure that the cache is no longer empty.
      assertEquals(PropertyManager.getCache().size(), 4);


      // Set values for each of the system properties.
      System.setProperty(stringPropertyName, "foo");
      System.setProperty(booleanPropertyName, "true");
      System.setProperty(intPropertyName, "1234");
      System.setProperty(longPropertyName, "5678");


      // Make sure that the attempts to retrieve the property values still
      // indicate that they're undefined because the existing cache records
      // aren't yet expired.
      assertNull(PropertyManager.get(stringPropertyName));
      assertNull(PropertyManager.getBoolean(booleanPropertyName));
      assertNull(PropertyManager.getInt(intPropertyName));
      assertNull(PropertyManager.getLong(longPropertyName));


      // Sleep for more than 1 second to ensure that the cache records have
      // time to expire.
      Thread.sleep(1_100L);


      // Try to retrieve the property values again.  This time, it should
      // reflect the new values.
      assertEquals(PropertyManager.get(stringPropertyName), "foo");
      assertEquals(PropertyManager.getBoolean(booleanPropertyName),
           Boolean.TRUE);
      assertEquals(PropertyManager.getInt(intPropertyName),
           Integer.valueOf(1234));
      assertEquals(PropertyManager.getLong(longPropertyName),
           Long.valueOf(5678L));


      // Change the values of the associated system properties to something
      // different.
      System.setProperty(stringPropertyName, "bar");
      System.setProperty(booleanPropertyName, "false");
      System.setProperty(intPropertyName, "4321");
      System.setProperty(longPropertyName, "8765");


      // Re-retrieve the property values.  This should use the values cached
      // from before the most recent change.
      assertEquals(PropertyManager.get(stringPropertyName), "foo");
      assertEquals(PropertyManager.getBoolean(booleanPropertyName),
           Boolean.TRUE);
      assertEquals(PropertyManager.getInt(intPropertyName),
           Integer.valueOf(1234));
      assertEquals(PropertyManager.getLong(longPropertyName),
           Long.valueOf(5678L));


      // Clear the cache.
      PropertyManager.clearCache();
      assertTrue(PropertyManager.getCache().isEmpty());


      // Re-retrieve the property values one more time and verify that we now
      // get the most recent version of the values.
      assertEquals(PropertyManager.get(stringPropertyName), "bar");
      assertEquals(PropertyManager.getBoolean(booleanPropertyName),
           Boolean.FALSE);
      assertEquals(PropertyManager.getInt(intPropertyName),
           Integer.valueOf(4321));
      assertEquals(PropertyManager.getLong(longPropertyName),
           Long.valueOf(8765L));

      assertEquals(PropertyManager.getCache().size(), 4);
    }
    finally
    {
      // Disable caching.
      PropertyManager.setCacheDurationMillis(0);
      assertEquals(PropertyManager.getCacheDurationMillis(), 0);

      PropertyManager.clearCache();
      assertTrue(PropertyManager.getCache().isEmpty());

      System.clearProperty(stringPropertyName);
      System.clearProperty(booleanPropertyName);
      System.clearProperty(intPropertyName);
      System.clearProperty(longPropertyName);
    }
  }


  /**
   * Tests the behavior for caching when cache records are obtained from
   * system properties rather than environment variables.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCachingWithEnvironmentVariables()
         throws Exception
  {
    // Enable caching with no timeout.
    PropertyManager.setCacheDurationMillis(Integer.MAX_VALUE);
    assertEquals(PropertyManager.getCacheDurationMillis(), Integer.MAX_VALUE);

    try
    {
      // Clear the cache and make sure that it starts empty.
      PropertyManager.clearCache();
      assertTrue(PropertyManager.getCache().isEmpty());


      // Iterate through all of the environment variables defined in the JVM
      // process and retrieve their values.
      for (final Map.Entry<String,String> e :
           StaticUtils.getEnvironmentVariables().entrySet())
      {
        final String envVarName = e.getKey();
        final String envVarValue = e.getValue();

        assertEquals(PropertyManager.get(envVarName), envVarValue);
      }


      // Make sure that the cache is no longer empty.
      assertFalse(PropertyManager.getCache().isEmpty());


      // Re-iterate through all of the environment variables again and
      // re-retrieve their values.  The values won't have changed, but at least
      // this time they should have been retrieved from the cache rather than
      // directly from the underlying environment variable.
      for (final Map.Entry<String,String> e :
           StaticUtils.getEnvironmentVariables().entrySet())
      {
        final String envVarName = e.getKey();
        final String envVarValue = e.getValue();

        assertEquals(PropertyManager.get(envVarName), envVarValue);
      }
    }
    finally
    {
      // Disable caching.
      PropertyManager.setCacheDurationMillis(0);
      assertEquals(PropertyManager.getCacheDurationMillis(), 0);

      PropertyManager.clearCache();
      assertTrue(PropertyManager.getCache().isEmpty());
    }
  }



  /**
   * Tests the behavior of the {@code populateCache} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPopulateCache()
         throws Exception
  {
    // Ensure that caching is currently disabled and the cache is empty.
    assertEquals(PropertyManager.getCacheDurationMillis(), 0);
    assertTrue(PropertyManager.getCache().isEmpty());


    // Call the populate cache method.  This shouldn't have any effect when
    // caching is disabled.
    PropertyManager.populateCache();
    assertTrue(PropertyManager.getCache().isEmpty());


    // Enable caching.
    PropertyManager.setCacheDurationMillis(Integer.MAX_VALUE);

    try
    {
      // Make sure that the cache is still empty.
      assertEquals(PropertyManager.getCacheDurationMillis(), Integer.MAX_VALUE);
      assertTrue(PropertyManager.getCache().isEmpty());


      // Make another call to populate the cache.
      PropertyManager.populateCache();


      // Make sure that the cache is no longer empty.
      assertFalse(PropertyManager.getCache().isEmpty());


      // Make sure that the cache has a record for every system property that is
      // currently defined.
      for (final String propertyName :
           System.getProperties().stringPropertyNames())
      {
        assertTrue(PropertyManager.getCache().containsKey(propertyName));
      }


      // Make sure that the cache has a record for every environment variable
      // that is currently defined.
      for (final Map.Entry<String,String> e :
           StaticUtils.getEnvironmentVariables().entrySet())
      {
        final String envVarName = e.getKey();
        assertTrue(PropertyManager.getCache().containsKey(envVarName));
      }
    }
    finally
    {
      // Disable caching.
      PropertyManager.setCacheDurationMillis(0);
      assertEquals(PropertyManager.getCacheDurationMillis(), 0);

      PropertyManager.clearCache();
      assertTrue(PropertyManager.getCache().isEmpty());
    }
  }
}
