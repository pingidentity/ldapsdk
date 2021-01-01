/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.util.args;



import java.util.concurrent.TimeUnit;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.UtilTestCase;



/**
 * This class provides test coverage for the DurationArgument class.
 */
public class DurationArgumentTestCase
       extends UtilTestCase
{
  /**
   * Tests the minimal constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructor()
         throws Exception
  {
    DurationArgument a = new DurationArgument('d', "durationArg", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "durationArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{duration}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNotNull(a.getLowerBound(TimeUnit.NANOSECONDS));
    assertEquals(a.getLowerBound(TimeUnit.NANOSECONDS), 0L);

    assertNotNull(a.getUpperBound(TimeUnit.NANOSECONDS));
    assertEquals(a.getUpperBound(TimeUnit.NANOSECONDS), Long.MAX_VALUE);

    assertNull(a.getValue(TimeUnit.NANOSECONDS));

    assertNull(a.getDefaultValue(TimeUnit.NANOSECONDS));

    assertFalse(a.isRequired());

    assertFalse(a.isPresent());

    assertFalse(a.isHidden());

    assertFalse(a.isRegistered());

    assertFalse(a.isUsageArgument());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getDurationArgument(a.getIdentifierString()));

    assertNull(newParser.getDurationArgument("--noSuchArgument"));
  }



  /**
   * Tests the constructor without a default value or bounds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithoutDefaultOrBounds()
         throws Exception
  {
    DurationArgument a = new DurationArgument('d', "durationArg", false,
         "{value}", "foo");
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "durationArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNotNull(a.getLowerBound(TimeUnit.NANOSECONDS));
    assertEquals(a.getLowerBound(TimeUnit.NANOSECONDS), 0L);

    assertNotNull(a.getUpperBound(TimeUnit.NANOSECONDS));
    assertEquals(a.getUpperBound(TimeUnit.NANOSECONDS), Long.MAX_VALUE);

    assertNull(a.getValue(TimeUnit.NANOSECONDS));

    assertNull(a.getDefaultValue(TimeUnit.NANOSECONDS));

    assertFalse(a.isRequired());

    assertFalse(a.isPresent());

    assertFalse(a.isHidden());

    assertFalse(a.isRegistered());

    assertFalse(a.isUsageArgument());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the constructor with a default value and bounds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDefaultAndBounds()
         throws Exception
  {
    DurationArgument a = new DurationArgument('d', "durationArg", true,
         "{value}", "foo", 1000L, TimeUnit.MILLISECONDS, 1L,
         TimeUnit.MILLISECONDS, 60L, TimeUnit.SECONDS);
    a = a.getCleanCopy();

    assertNotNull(a);

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('d'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "durationArg");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "{value}");

    assertNotNull(a.getDescription());
    assertEquals(a.getDescription(), "foo");

    assertNotNull(a.getLowerBound(TimeUnit.NANOSECONDS));
    assertEquals(a.getLowerBound(TimeUnit.NANOSECONDS), 1000000L);
    assertEquals(a.getLowerBound(TimeUnit.MICROSECONDS), 1000L);
    assertEquals(a.getLowerBound(TimeUnit.MILLISECONDS), 1L);
    assertEquals(a.getLowerBound(TimeUnit.SECONDS), 0L);
    assertEquals(a.getLowerBound(TimeUnit.MINUTES), 0L);
    assertEquals(a.getLowerBound(TimeUnit.HOURS), 0L);
    assertEquals(a.getLowerBound(TimeUnit.DAYS), 0L);

    assertNotNull(a.getUpperBound(TimeUnit.NANOSECONDS));
    assertEquals(a.getUpperBound(TimeUnit.NANOSECONDS), 60000000000L);
    assertEquals(a.getUpperBound(TimeUnit.MICROSECONDS), 60000000L);
    assertEquals(a.getUpperBound(TimeUnit.MILLISECONDS), 60000L);
    assertEquals(a.getUpperBound(TimeUnit.SECONDS), 60L);
    assertEquals(a.getUpperBound(TimeUnit.MINUTES), 1L);
    assertEquals(a.getUpperBound(TimeUnit.HOURS), 0L);
    assertEquals(a.getUpperBound(TimeUnit.DAYS), 0L);

    assertNotNull(a.getValue(TimeUnit.NANOSECONDS));
    assertEquals(a.getValue(TimeUnit.NANOSECONDS),
         Long.valueOf(1000000000L));

    assertNotNull(a.getDefaultValue(TimeUnit.NANOSECONDS));
    assertEquals(a.getDefaultValue(TimeUnit.NANOSECONDS),
         Long.valueOf(1000000000L));

    assertTrue(a.isRequired());

    assertTrue(a.isPresent());

    assertFalse(a.isHidden());

    assertFalse(a.isRegistered());

    assertFalse(a.isUsageArgument());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the constructor with different units for the duration, lower bound,
   * and upper bound values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithDifferentUnits()
         throws Exception
  {
    for (final TimeUnit u : TimeUnit.values())
    {
      new DurationArgument('d', "durationArg", false, "{value}", "foo",
           1234L, u, 0L, u, 5678L, u);
    }
  }



  /**
   * Tests the constructor with a default value but no corresponding unit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructorDefaultValueWithoutUnit()
         throws Exception
  {
    new DurationArgument('d', "durationArg", false, "{value}", "foo", 1234L,
         null, null, null, null, null);
  }



  /**
   * Tests the constructor with a lower bound value but no corresponding unit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructorLowerBoundWithoutUnit()
         throws Exception
  {
    new DurationArgument('d', "durationArg", false, "{value}", "foo", null,
         null, 1234L, null, null, null);
  }



  /**
   * Tests the constructor with an upper bound value but no corresponding unit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructorUpperBoundWithoutUnit()
         throws Exception
  {
    new DurationArgument('d', "durationArg", false, "{value}", "foo", null,
         null, null, null, 1234L, null);
  }



  /**
   * Tests the constructor with a lower bound that is greater than the upper
   * bound.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = ArgumentException.class)
  public void testConstructorLowerBoundGreaterThanUpper()
         throws Exception
  {
    new DurationArgument('d', "durationArg", false, "{value}", "foo", null,
         null, 5678L, TimeUnit.NANOSECONDS, 1234L, TimeUnit.NANOSECONDS);
  }



  /**
   * Tests the argument's behavior with an argument value validator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithArgumentValueValidator()
         throws Exception
  {
    DurationArgument a = new DurationArgument('d', "durationArg", false,
         "{value}", "foo");
    a.addValueValidator(new TestArgumentValueValidator("5 seconds"));

    assertNull(a.getValue(TimeUnit.SECONDS));

    try
    {
      a.addValue("5000 milliseconds");
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue(TimeUnit.SECONDS));

    a.addValue("5 seconds");

    assertNotNull(a.getValue(TimeUnit.SECONDS));
    assertEquals(a.getValue(TimeUnit.SECONDS), Long.valueOf(5L));
  }



  /**
   * Tests the {@code addValue} method with a set of valid data.
   *
   * @param  valueStr       The value string to be parsed.
   * @param  expectedValue  The expected parsed value.
   * @param  expectedUnit   The unit to use for the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validValues")
  public void testValidValues(final String valueStr, final long expectedValue,
                              final TimeUnit expectedUnit)
         throws Exception
  {
    DurationArgument a = new DurationArgument('d', "durationArg", false,
         "{value}", "foo");
    a = a.getCleanCopy();

    assertNull(a.getValue(expectedUnit));

    a.addValue(valueStr);

    assertNotNull(a.getValue(expectedUnit));
    assertEquals(a.getValue(expectedUnit), Long.valueOf(expectedValue));

    try
    {
      // Verify that we can't set a second value.
      a.addValue("0s");
      fail("Expected an exception when adding a second value");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the {@code addValue} method with a set of invalid data.
   *
   * @param  valueStr  The value string to be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidValues",
        expectedExceptions = { ArgumentException.class })
  public void testInvalidValues(final String valueStr)
         throws Exception
  {
    DurationArgument a = new DurationArgument('d', "durationArg", false,
         "{value}", "foo", null, null, 1L, TimeUnit.MILLISECONDS, 1L,
         TimeUnit.MINUTES);
    a = a.getCleanCopy();

    assertNull(a.getValue(TimeUnit.NANOSECONDS));

    a.addValue(valueStr);
  }



  /**
   * Tests the {@code nanosToDuration} method with the provided values.
   *
   * @param  nanos             The value to provide to the method.
   * @param  expectedDuration  The expected return value from the method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "nanosToDurationValues")
  public void testNanosToDuration(final long nanos,
                                  final String expectedDuration)
         throws Exception
  {
    assertEquals(DurationArgument.nanosToDuration(nanos), expectedDuration);
  }



  /**
   * Retrieves a set of valid values that may be used for testing.
   *
   * @return  A set of valid values that may be used for testing.
   */
  @DataProvider(name = "validValues")
  public Object[][] getValidValues()
  {
    return new Object[][]
    {
      new Object[] { "1234ns", 1234L, TimeUnit.NANOSECONDS },
      new Object[] { "1234 ns", 1234L, TimeUnit.NANOSECONDS },
      new Object[] { "1234 nano", 1234L, TimeUnit.NANOSECONDS },
      new Object[] { "1234 nanos", 1234L, TimeUnit.NANOSECONDS },
      new Object[] { "1234 nanosecond", 1234L, TimeUnit.NANOSECONDS },
      new Object[] { "1234 nanoseconds", 1234L, TimeUnit.NANOSECONDS },

      new Object[] { "2345us", 2345L, TimeUnit.MICROSECONDS },
      new Object[] { "2345 us", 2345L, TimeUnit.MICROSECONDS },
      new Object[] { "2345 micro", 2345L, TimeUnit.MICROSECONDS },
      new Object[] { "2345 micros", 2345L, TimeUnit.MICROSECONDS },
      new Object[] { "2345 microsecond", 2345L, TimeUnit.MICROSECONDS },
      new Object[] { "2345 microseconds", 2345L, TimeUnit.MICROSECONDS },

      new Object[] { "3456ms", 3456L, TimeUnit.MILLISECONDS },
      new Object[] { "3456 ms", 3456L, TimeUnit.MILLISECONDS },
      new Object[] { "3456 milli", 3456L, TimeUnit.MILLISECONDS },
      new Object[] { "3456 millis", 3456L, TimeUnit.MILLISECONDS },
      new Object[] { "3456 millisecond", 3456L, TimeUnit.MILLISECONDS },
      new Object[] { "3456 milliseconds", 3456L, TimeUnit.MILLISECONDS },

      new Object[] { "4567s", 4567L, TimeUnit.SECONDS },
      new Object[] { "4567 s", 4567L, TimeUnit.SECONDS },
      new Object[] { "4567 sec", 4567L, TimeUnit.SECONDS },
      new Object[] { "4567 secs", 4567L, TimeUnit.SECONDS },
      new Object[] { "4567 second", 4567L, TimeUnit.SECONDS },
      new Object[] { "4567 seconds", 4567L, TimeUnit.SECONDS },

      new Object[] { "5678m", 5678L, TimeUnit.MINUTES },
      new Object[] { "5678 m", 5678L, TimeUnit.MINUTES },
      new Object[] { "5678 min", 5678L, TimeUnit.MINUTES },
      new Object[] { "5678 mins", 5678L, TimeUnit.MINUTES },
      new Object[] { "5678 minute", 5678L, TimeUnit.MINUTES },
      new Object[] { "5678 minutes", 5678L, TimeUnit.MINUTES },

      new Object[] { "6789h", 6789L, TimeUnit.HOURS },
      new Object[] { "6789 h", 6789L, TimeUnit.HOURS },
      new Object[] { "6789 hr", 6789L, TimeUnit.HOURS },
      new Object[] { "6789 hrs", 6789L, TimeUnit.HOURS },
      new Object[] { "6789 hour", 6789L, TimeUnit.HOURS },
      new Object[] { "6789 hours", 6789L, TimeUnit.HOURS },

      new Object[] { "7890d", 7890L, TimeUnit.DAYS },
      new Object[] { "7890 d", 7890L, TimeUnit.DAYS },
      new Object[] { "7890 day", 7890L, TimeUnit.DAYS },
      new Object[] { "7890 days", 7890L, TimeUnit.DAYS },

      new Object[] { "1w", 7L, TimeUnit.DAYS },
      new Object[] { "2 w", 14L, TimeUnit.DAYS },
      new Object[] { "3 week", 21L, TimeUnit.DAYS },
      new Object[] { "4 weeks", 28L, TimeUnit.DAYS },
    };
  }



  /**
   * Retrieves a set of invalid values that cannot be used as durations.
   *
   * @return  A set of invalid values that cannot be used as durations.
   */
  @DataProvider(name = "invalidValues")
  public Object[][] getInvalidValues()
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { "1234" }, // No unit
      new Object[] { "seconds" }, // No integer portion
      new Object[] { "1234inv" }, // Invalid unit.
      new Object[] { " 1234s" }, // Space before integer portion
      new Object[] { "0s" }, // Below the minimum
      new Object[] { "5m" }, // Above the maximum
    };
  }



  /**
   * Retrieves a set of values that can be used for testing the
   * {@code nanosToDuration} method.
   *
   * @return  A set of values that can be used for testing the
   *          {@code nanosToDuration} method.
   */
  @DataProvider(name = "nanosToDurationValues")
  public Object[][] getNanosToDurationValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(7L, TimeUnit.DAYS),
        "1 week"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(14L, TimeUnit.DAYS),
        "2 weeks"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.DAYS),
        "1 day"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.DAYS),
        "2 days"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.HOURS),
        "1 hour"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.HOURS),
        "2 hours"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.MINUTES),
        "1 minute"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.MINUTES),
        "2 minutes"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.SECONDS),
        "1 second"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.SECONDS),
        "2 seconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.MILLISECONDS),
        "1 millisecond"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.MILLISECONDS),
        "2 milliseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.MICROSECONDS),
        "1 microsecond"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.MICROSECONDS),
        "2 microseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(1L, TimeUnit.NANOSECONDS),
        "1 nanosecond"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(2L, TimeUnit.NANOSECONDS),
        "2 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.DAYS),
        "0 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.HOURS),
        "0 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.MINUTES),
        "0 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.SECONDS),
        "0 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.MILLISECONDS),
        "0 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.MICROSECONDS),
        "0 nanoseconds"
      },
      new Object[]
      {
        TimeUnit.NANOSECONDS.convert(0L, TimeUnit.NANOSECONDS),
        "0 nanoseconds"
      }
    };
  }
}
