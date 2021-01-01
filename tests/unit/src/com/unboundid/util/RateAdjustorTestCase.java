/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests for the RateAdjustor class.
 */
public class RateAdjustorTestCase extends UtilTestCase
{
  /**
   * Tests the calculatePerInterval method.
   *
   * @param  intervalMillis       The interval duration.
   * @param  ratePerSecond        The target rate per second.
   * @param  expectedPerInterval  The expected rate per interval.
   */
  @Test(dataProvider = "getTestCalculatePerInterval")
  public void testCalculatePerInterval(final long intervalMillis,
                                       final double ratePerSecond,
                                       final int expectedPerInterval)
  {
    final int actualPerInterval = RateAdjustor.calculatePerInterval(
            intervalMillis, ratePerSecond);
    assertEquals(actualPerInterval, expectedPerInterval);
  }



  /**
   * Data provider for testCalculatePerInterval.
   *
   * @return  Parameters for the testCalculatePerInterval method.
   */
  @DataProvider
  public Object[][] getTestCalculatePerInterval()
  {
    return new Object[][]{
         //          intervalMillis    ratePerSecond   expectedPerInterval
         new Object[]{          100,             100,                  10},
         // Needs to be at least 1 per interval.
         new Object[]{          100,             0.5,                   1},
         new Object[]{    10 * 1000,             0.5,                   5},
    };
  }



  /**
   * Tests RateAdjustor#consumeHeader.
   *
   * @param  originalLines        The lines with the header.
   * @param  expectedHeader       The expected header map.
   * @param  expectedHeaderLines  The number of lines expected to be consumed.
   */
  @Test(dataProvider = "getTestConsumerHeaderParams")
  public void testConsumerHeader(final List<String> originalLines,
                                 final Map<String,String> expectedHeader,
                                 final int expectedHeaderLines)
  {
    final List<String> lines = new ArrayList<String>(originalLines);

    final Map<String,String> header = RateAdjustor.consumeHeader(lines);

    final int removedLines = originalLines.size() - lines.size();
    assertEquals(removedLines, expectedHeaderLines);

    final List<String> expectedRemaining = originalLines.subList(
            removedLines, originalLines.size());
    assertEquals(lines, expectedRemaining);

    assertEquals(header, expectedHeader);
  }



  /**
   * DataProvider for testConsumerHeader.
   *
   * @return  Parameters for testConsumerHeader.
   */
  @DataProvider
  public Object[][] getTestConsumerHeaderParams()
  {
    final Map<String,String> emptyMap = Collections.emptyMap();

    final Map<String,String> singletonMap = Collections.singletonMap("k", "v");
    final Map<String,String> complexMap = new LinkedHashMap<String,String>();
    complexMap.put("k0", "");
    complexMap.put("k1", "value with space");
    complexMap.put("k2", "value with =");

    return new Object[][]
    {
        new Object[]
        {
            lines("END HEADER"),
            emptyMap,
            1
        },

        new Object[]
        {
            lines("end header"),
            emptyMap,
            1
        },

        new Object[]
        {
            lines("# This is a comment not a header.",
                  "END HEADER"),
            emptyMap,
            2
        },

        new Object[]
        {
            lines("# This is a comment.",
                  " # This is another comment.",
                  "END HEADER"),
            emptyMap,
            3
        },

        new Object[]
        {
            lines("k=v",
                  "END HEADER"),
            singletonMap,
            2
        },

        new Object[]
        {
            lines(" k = v ",
                  "END HEADER"),
            singletonMap,
            2
        },

        new Object[]
        {
            lines("#",
                  "k = v ",
                  "#",
                  "END HEADER",
                  "Not a comment"),
            singletonMap,
            4
        },

        new Object[]
        {
            lines("k0=",
                  "k1=value with space",
                  "k2=value with =",
                  "END HEADER"),
            complexMap,
            4
        },
    };
  }



  /**
   * Tests that RateAdjustor#consumeHeader should throw when a key value
   * is redefined.
   */
  @Test(expectedExceptions = { IllegalArgumentException.class })
  public void testRedefinedKeyInHeader()
  {
    RateAdjustor.consumeHeader(new ArrayList<String>(lines(
         "k1=v1",
         "k2=v2",
         "k1=v3",
         "END HEADER")));
  }



  /**
   * Tests that the rate and durations are parsed properly from the file.
   *
   * @param  baseRatePerSecond  The base rate per second.
   * @param  rates              The Reader used to initialize a RateAdjustor.
   * @param  expected           The expected generated rate and durations.
   *
   * @throws  Exception  If there is a problem.
   */
  @Test(dataProvider = "getTestRatesAndDurationsParams")
  public void testRatesAndDurations(final long baseRatePerSecond,
       final Reader rates, final List<ObjectPair<Double, Long>> expected)
       throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(1, 1);

    final RateAdjustor adjustor = new RateAdjustor(barrier,
                                                   baseRatePerSecond,
                                                   rates);

    assertEquals(adjustor.getRatesAndDurations(), expected);
  }



  /**
   * Returns parameters for testRatesAndDurations.
   *
   * @return  Parameters for testRatesAndDurations.
   */
  @DataProvider
  public Object[][] getTestRatesAndDurationsParams()
  {
    return new Object[][]
    {
        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER"),
            ratesAndDurations()
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,10ms"),
            ratesAndDurations(1000, 10)
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,10ms",
                   "# This comment and the next two lines are skipped",
                   "",
                   "   \t",
                   "2000,1minute"),
            ratesAndDurations(1000, 10,
                              2000, 60 * 1000)
        },

        new Object[]
        {
            100,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "10X,10ms",
                   "0.5x,10ms"),
            ratesAndDurations(1000, 10,
                              50, 10)
        },

        new Object[]
        {
            100,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "10X,10ms",
                   "1000,2h"),
            ratesAndDurations(1000, 10,
                              1000, 2 * 60 * 60 * 1000)
        },

        new Object[]
        {
            100,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "10X,10ms# Comment",
                   "1000,2h # Another comment"),
            ratesAndDurations(1000, 10,
                              1000, 2 * 60 * 60 * 1000)
        },

        new Object[]
        {
            100,
            reader("format=rate-and-duration",
                   "default-duration=1s",
                   "END HEADER",
                   "10X,10ms",
                   "1000",
                   "10X"),
            ratesAndDurations(1000, 10,
                              1000, 1000,
                              1000, 1000)
        },
    };
  }



  /**
   * Tests RateAdjustor when it is constructed with invalid input.
   *
   * @param  baseRatePerSecond  The base rate.
   * @param  rates              The rates.
   * @param  failureSnippet     A String expected to appear in the output.
   *
   * @throws  Exception  If there is a problem.
   */
  @Test(dataProvider = "getTestInvalidInputParams")
  public void testInvalidInput(final long baseRatePerSecond,
                               final Reader rates,
                               final String failureSnippet)
          throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(1, 1);

    try
    {
      final RateAdjustor adjustor = new RateAdjustor(barrier,
                                                     baseRatePerSecond,
                                                     rates);
      fail("Expected an exception to be thrown.");
    }
    catch (IllegalArgumentException e)
    {
      if (! e.getMessage().contains(failureSnippet))
      {
        fail("Expected '" + e.getMessage() + "' to contain '" +
             failureSnippet + "'.");
      }
    }
  }



  /**
   * Returns parameters for testInvalidInput.
   *
   * @return  Parameters for testInvalidInput.
   */
  @DataProvider
  public Object[][] getTestInvalidInputParams()
  {
    return new Object[][]
    {
        new Object[]
        {
            0,
            reader(),
            "END HEADER"
        },

        new Object[]
        {
            0,
            reader("END HEADER"),
            "did not include a value for the 'format' property in the header"
        },

        new Object[]
        {
            0,
            reader("repeat=true",
                   "END HEADER"),
            "did not include a value for the 'format' property in the header"
        },

        new Object[]
        {
            0,
            reader("format=unknown",
                   "END HEADER"),
            "included an invalid value, 'unknown', for the 'format' property"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "unknown-key=value",
                   "END HEADER"),
            "invalid keys"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "key-not-followed-by-equal",
                   "END HEADER"),
            "equal sign"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "=zero-length key",
                   "END HEADER"),
            "empty string"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "2X,1000ms"),
            "the target rate per second was not provided"
        },

        new Object[]
        {
            1000,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "tenX,1000ms"),
            "could not be parsed as a floating point value"
        },

        new Object[]
        {
            1000,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "X,1000ms"),
            "could not be parsed as a floating point value"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,ten-seconds"),
            "could not be parsed as a duration value"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000"),
            "invalid format"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,"),
            "invalid format"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,1d,2"),
            "invalid format"
        },

        new Object[]
        {
            0,
            reader("format=rate-and-duration",
                   "default-duration=one second",
                   "END HEADER"),
            "could not be parsed as a duration value"
        },
    };
  }



  /**
   * Tests that the RateAdjustor actually changes the rates.  We are
   * conservative in the timing here to avoid failures due to low CPU
   * availability or other timing issues.
   *
   * @throws Exception  If there is a problem.
   */
  @Test
  public void testBasics() throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(10000, 100);
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 100);

    final RateAdjustor adjustor = new RateAdjustor(barrier, 1000,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,100ms",
                   "100,100ms"));

    adjustor.start();

    // The new rate should be in effect once start returns.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 10000);

    Thread.sleep(150);

    // We should be in the middle of the second interval now.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 1000);

    Thread.sleep(100);

    // All intervals should be done now.
    assertFalse(adjustor.isAlive());
  }



  /**
   * Tests repeating the intervals.
   *
   * @throws Exception  If there is a problem.
   */
  @Test
  public void testRepeat() throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(10000, 100);
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 100);

    final RateAdjustor adjustor = new RateAdjustor(barrier, 1000,
            reader("format=rate-and-duration",
                   "repeat=true",
                   "END HEADER",
                   "1000,100ms",
                   "100,100ms"));

    adjustor.start();

    // The new rate should be in effect once start returns.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 10000);

    Thread.sleep(150);

    // We should be in the middle of the second interval now.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 1000);

    Thread.sleep(100);

    // We should be back into the first interval now.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 10000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 10000);

    adjustor.shutDown();
  }



  /**
   * Tests that the RateAdjustor behaves if it is shut down before it's started.
   *
   * @throws  Exception  If there is a problem.
   */
  @Test(timeOut = 10000)
  public void testShutDownBeforeStart() throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(1000, 1);
    final RateAdjustor adjustor = new RateAdjustor(barrier, 1000,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "1000,1d"));

    // If we shut it down before starting it, then the rate shouldn't change.
    adjustor.shutDown();
    adjustor.start();
    adjustor.join();

    assertEquals(barrier.getTargetRate().getFirst().longValue(), 1000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 1);
  }



  /**
   * Tests shutDown.
   *
   * @throws  Exception  If there is a problem.
   */
  @Test(timeOut = 10000)
  public void testShutDown() throws Exception
  {
    final FixedRateBarrier barrier = new FixedRateBarrier(1000, 1);
    final RateAdjustor adjustor = new RateAdjustor(barrier, 1000,
            reader("format=rate-and-duration",
                   "END HEADER",
                   "100,1d",
                   "1000,1d"));

    adjustor.start();

    // The new rate should be in effect once start returns.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 1000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 100);

    // Shutting it down should not wait for the interval to expire.
    adjustor.shutDown();
    adjustor.join();

    // The initial rate should still be in effect.
    assertEquals(barrier.getTargetRate().getFirst().longValue(), 1000);
    assertEquals(barrier.getTargetRate().getSecond().intValue(), 100);
  }



  /**
   * Returns a list of rates and durations from the provided alternating array
   * of rates and durations.
   *
   * @param  pairs  An alternating list of rates and durations (in
   *                milliseconds.)
   *
   * @return  A list of rates and durations from the list of values.
   */
  private List<ObjectPair<Double,Long>> ratesAndDurations(Object... pairs)
  {
    final List<ObjectPair<Double,Long>> list =
            new ArrayList<ObjectPair<Double,Long>>();

    for (int i = 0; i < pairs.length; i+= 2)
    {
      final Double rate = ((Number)pairs[i]).doubleValue();
      final Long duration = ((Number)pairs[i + 1]).longValue();

      list.add(new ObjectPair<Double, Long>(rate, duration));
    }

    return list;
  }



  /**
   * Constructs an immutable list of Strings from the parameter.
   *
   * @param  lines  The Strings to return as an immutable list.
   *
   * @return  lines in an immutable list of Strings.
   */
  private List<String> lines(String... lines)
  {
    return Arrays.asList(lines);
  }



  /**
   * Return a Reader for the specified lines.
   *
   * @param  lines  The lines to initialize the Reader.
   *
   * @return  A Reader containing each value of lines followed by a EOL.
   */
  private Reader reader(String... lines)
  {
    final StringBuilder buffer = new StringBuilder();

    for (String line: lines)
    {
      buffer.append(line).append(StaticUtils.EOL);
    }

    return new StringReader(buffer.toString())
      {
        /**
         * Override toString() so that the output on a failure is helpful.
         *
         * @return  The String that this wraps.
         */
        @Override
        public String toString()
        {
          return buffer.toString();
        }
      };
  }
}

