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
package com.unboundid.util;



import java.io.File;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the ValuePattern class and its
 *  supporting classes.
 */
public class ValuePatternTestCase
       extends UtilTestCase
{
  /**
   * Tests the value pattern with a {@code null} string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullString()
         throws Exception
  {
    new ValuePattern(null);
  }



  /**
   * Tests the value pattern with an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyString()
         throws Exception
  {
    ValuePattern p = new ValuePattern("");

    assertNotNull(p);

    assertEquals(p.nextValue(), "");

    assertEquals(p.toString(), "");
  }



  /**
   * Tests the value pattern with a static text string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStaticString()
         throws Exception
  {
    ValuePattern p = new ValuePattern("dc=example,dc=com");

    assertNotNull(p);

    assertEquals(p.nextValue(), "dc=example,dc=com");

    assertEquals(p.toString(), "dc=example,dc=com");
  }



  /**
   * Tests the value pattern with a static text string that contains double
   * brackets.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStaticStringWithDoubleBrackets()
         throws Exception
  {
    ValuePattern p = new ValuePattern("]][[dc]]=[[example]],[[dc]]=[[com]][[");

    assertNotNull(p);

    assertEquals(p.nextValue(), "][dc]=[example],[dc]=[com][");

    assertEquals(p.toString(), "]][[dc]]=[[example]],[[dc]]=[[com]][[");
  }



  /**
   * Tests the value pattern with a simple sequential numeric value component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleSequentialValue()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:10]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "1");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "3");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "5");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "7");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "9");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "1");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "3");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "5");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "7");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "9");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "0");

    assertEquals(p.toString(), "[0:10]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component in
   * reverse order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleSequentialValueReverse()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[10:0]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "9");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "7");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "5");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "3");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "1");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "9");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "7");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "5");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "3");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "1");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "10");

    assertEquals(p.toString(), "[10:0]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component
   * containing an increment.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleSequentialValueWithIncrement()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:10x2]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "0");

    assertEquals(p.toString(), "[0:10x2]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component
   * containing a negative increment.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleSequentialValueWithNegativeIncrement()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:10x-2]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "8");
    assertEquals(p.nextValue(), "6");
    assertEquals(p.nextValue(), "4");
    assertEquals(p.nextValue(), "2");
    assertEquals(p.nextValue(), "0");

    assertEquals(p.toString(), "[0:10x-2]");
  }



  /**
   * Tests the value pattern with a simple sequential numeric value component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleSequentialValueWithFormat()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:10%00]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "00");
    assertEquals(p.nextValue(), "01");
    assertEquals(p.nextValue(), "02");
    assertEquals(p.nextValue(), "03");
    assertEquals(p.nextValue(), "04");
    assertEquals(p.nextValue(), "05");
    assertEquals(p.nextValue(), "06");
    assertEquals(p.nextValue(), "07");
    assertEquals(p.nextValue(), "08");
    assertEquals(p.nextValue(), "09");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "00");
    assertEquals(p.nextValue(), "01");
    assertEquals(p.nextValue(), "02");
    assertEquals(p.nextValue(), "03");
    assertEquals(p.nextValue(), "04");
    assertEquals(p.nextValue(), "05");
    assertEquals(p.nextValue(), "06");
    assertEquals(p.nextValue(), "07");
    assertEquals(p.nextValue(), "08");
    assertEquals(p.nextValue(), "09");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "00");

    assertEquals(p.toString(), "[0:10%00]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component
   * containing an increment and a format string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleSequentialValueWithIncrementAndFormat()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:10x2%00]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "00");
    assertEquals(p.nextValue(), "02");
    assertEquals(p.nextValue(), "04");
    assertEquals(p.nextValue(), "06");
    assertEquals(p.nextValue(), "08");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "00");
    assertEquals(p.nextValue(), "02");
    assertEquals(p.nextValue(), "04");
    assertEquals(p.nextValue(), "06");
    assertEquals(p.nextValue(), "08");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "00");

    assertEquals(p.toString(), "[0:10x2%00]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component in which
   * the upper and lower bound values are equal.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSequentialValueLowerEqualsUpper()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:0]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "0");

    assertEquals(p.toString(), "[0:0]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component in which
   * the increment is larger than the range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSequentialValueIncrementLargerThanRange()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[0:10x20]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "0");
    assertEquals(p.nextValue(), "0");

    assertEquals(p.toString(), "[0:10x20]");
  }



  /**
   * Tests the value pattern with a sequential numeric value component in
   * reverse order and in which the increment is larger than the range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSequentialValueReverseIncrementLargerThanRange()
         throws Exception
  {
    ValuePattern p = new ValuePattern("[10:0x20]");

    assertNotNull(p);

    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "10");
    assertEquals(p.nextValue(), "10");

    assertEquals(p.toString(), "[10:0x20]");
  }



  /**
   * Tests the value pattern with a simple random value component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleRandomValue()
         throws Exception
  {
    HashMap<String,AtomicInteger> map = new HashMap<String,AtomicInteger>(11);
    map.put("0",  new AtomicInteger(0));
    map.put("1",  new AtomicInteger(0));
    map.put("2",  new AtomicInteger(0));
    map.put("3",  new AtomicInteger(0));
    map.put("4",  new AtomicInteger(0));
    map.put("5",  new AtomicInteger(0));
    map.put("6",  new AtomicInteger(0));
    map.put("7",  new AtomicInteger(0));
    map.put("8",  new AtomicInteger(0));
    map.put("9",  new AtomicInteger(0));
    map.put("10", new AtomicInteger(0));

    ValuePattern p = new ValuePattern("[0-10]");

    assertNotNull(p);

    for (int i=0; i < 1000; i++)
    {
      AtomicInteger counter = map.get(p.nextValue());
      assertNotNull(counter);
      counter.incrementAndGet();
    }

    assertTrue(map.get("0").intValue() > 25);
    assertTrue(map.get("1").intValue() > 25);
    assertTrue(map.get("2").intValue() > 25);
    assertTrue(map.get("3").intValue() > 25);
    assertTrue(map.get("4").intValue() > 25);
    assertTrue(map.get("5").intValue() > 25);
    assertTrue(map.get("6").intValue() > 25);
    assertTrue(map.get("7").intValue() > 25);
    assertTrue(map.get("8").intValue() > 25);
    assertTrue(map.get("9").intValue() > 25);
    assertTrue(map.get("10").intValue() > 25);

    assertEquals(p.toString(), "[0-10]");
  }



  /**
   * Tests the value pattern with a simple random value component with the upper
   * and lower bounds reversed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleRandomValueBoundsReversed()
         throws Exception
  {
    HashMap<String,AtomicInteger> map = new HashMap<String,AtomicInteger>(11);
    map.put("0",  new AtomicInteger(0));
    map.put("1",  new AtomicInteger(0));
    map.put("2",  new AtomicInteger(0));
    map.put("3",  new AtomicInteger(0));
    map.put("4",  new AtomicInteger(0));
    map.put("5",  new AtomicInteger(0));
    map.put("6",  new AtomicInteger(0));
    map.put("7",  new AtomicInteger(0));
    map.put("8",  new AtomicInteger(0));
    map.put("9",  new AtomicInteger(0));
    map.put("10", new AtomicInteger(0));

    ValuePattern p = new ValuePattern("[10-0]");

    assertNotNull(p);

    for (int i=0; i < 1000; i++)
    {
      AtomicInteger counter = map.get(p.nextValue());
      assertNotNull(counter);
      counter.incrementAndGet();
    }

    assertTrue(map.get("0").intValue() > 25);
    assertTrue(map.get("1").intValue() > 25);
    assertTrue(map.get("2").intValue() > 25);
    assertTrue(map.get("3").intValue() > 25);
    assertTrue(map.get("4").intValue() > 25);
    assertTrue(map.get("5").intValue() > 25);
    assertTrue(map.get("6").intValue() > 25);
    assertTrue(map.get("7").intValue() > 25);
    assertTrue(map.get("8").intValue() > 25);
    assertTrue(map.get("9").intValue() > 25);
    assertTrue(map.get("10").intValue() > 25);

    assertEquals(p.toString(), "[10-0]");
  }



  /**
   * Tests the value pattern with a simple random value component in which the
   * upper and lower bounds are the same.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRandomValueLowerEqualsUpper()
         throws Exception
  {
    HashMap<String,AtomicInteger> map = new HashMap<String,AtomicInteger>(11);
    map.put("0",  new AtomicInteger(0));

    ValuePattern p = new ValuePattern("[0-0]");

    assertNotNull(p);

    for (int i=0; i < 1000; i++)
    {
      AtomicInteger counter = map.get(p.nextValue());
      assertNotNull(counter);
      counter.incrementAndGet();
    }

    assertEquals(map.get("0").intValue(), 1000);

    assertEquals(p.toString(), "[0-0]");
  }



  /**
   * Tests the value pattern with a random value component with a format string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRandomValueWithFormat()
         throws Exception
  {
    HashMap<String,AtomicInteger> map = new HashMap<String,AtomicInteger>(11);
    map.put("00",  new AtomicInteger(0));
    map.put("01",  new AtomicInteger(0));
    map.put("02",  new AtomicInteger(0));
    map.put("03",  new AtomicInteger(0));
    map.put("04",  new AtomicInteger(0));
    map.put("05",  new AtomicInteger(0));
    map.put("06",  new AtomicInteger(0));
    map.put("07",  new AtomicInteger(0));
    map.put("08",  new AtomicInteger(0));
    map.put("09",  new AtomicInteger(0));
    map.put("10", new AtomicInteger(0));

    ValuePattern p = new ValuePattern("[0-10%00]");

    assertNotNull(p);

    for (int i=0; i < 1000; i++)
    {
      AtomicInteger counter = map.get(p.nextValue());
      assertNotNull(counter);
      counter.incrementAndGet();
    }

    assertTrue(map.get("00").intValue() > 25);
    assertTrue(map.get("01").intValue() > 25);
    assertTrue(map.get("02").intValue() > 25);
    assertTrue(map.get("03").intValue() > 25);
    assertTrue(map.get("04").intValue() > 25);
    assertTrue(map.get("05").intValue() > 25);
    assertTrue(map.get("06").intValue() > 25);
    assertTrue(map.get("07").intValue() > 25);
    assertTrue(map.get("08").intValue() > 25);
    assertTrue(map.get("09").intValue() > 25);
    assertTrue(map.get("10").intValue() > 25);

    assertEquals(p.toString(), "[0-10%00]");
  }



  /**
   * Tests with a set of deterministic values.
   *
   * @param  pattern  The value pattern to use.
   * @param  first    The expected output from the first invocation.
   * @param  second   The expected output from the second invocation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="deterministicValues")
  public void testDeterministicValues(String pattern, String first,
                                      String second)
         throws Exception
  {
    ValuePattern p = new ValuePattern(pattern);
    assertEquals(p.toString(), pattern);

    assertEquals(p.nextValue(), first);
    assertEquals(p.nextValue(), second);
  }



  /**
   * Tests with a set of invalid values.
   *
   * @param  pattern  The invalid value pattern to use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidValues",
        expectedExceptions={ ParseException.class })
  public void testInvalidValues(String pattern)
         throws Exception
  {
    new ValuePattern(pattern);
    fail("Expected an exception for format string '" + pattern + '\'');
  }



  /**
   * Retrieves a set of data that may be used to test value patterns that have a
   * deterministic behavior.  Arguments that this returns will be the pattern
   * string, the expected first value, and the expected second value.
   *
   * @return  A set of data that may be used to test value patterns that have a
   *          deterministic behavior.
   */
  @DataProvider(name="deterministicValues")
  public Object[][] getDeterministicValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        "",
        ""
      },

      new Object[]
      {
        "[[",
        "[",
        "["
      },

      new Object[]
      {
        "]]",
        "]",
        "]"
      },

      new Object[]
      {
        "a]]",
        "a]",
        "a]"
      },

      new Object[]
      {
        "]]a",
        "]a",
        "]a"
      },

      new Object[]
      {
        "a]]a",
        "a]a",
        "a]a"
      },

      new Object[]
      {
        "[1:10]",
        "1",
        "2"
      },

      new Object[]
      {
        "[-1:10]",
        "-1",
        "0"
      },

      new Object[]
      {
        "[-10:-1]",
        "-10",
        "-9"
      },

      new Object[]
      {
        "[-1:-10]",
        "-1",
        "-2"
      },

      new Object[]
      {
        "[1:10][1:10]",
        "11",
        "22"
      },

      new Object[]
      {
        "(uid=user.[1:10])",
        "(uid=user.1)",
        "(uid=user.2)"
      },

      new Object[]
      {
        "(|(uid=user.[1:10])(uid=user.[30:21]))",
        "(|(uid=user.1)(uid=user.30))",
        "(|(uid=user.2)(uid=user.29))"
      },

      new Object[]
      {
        "cn=[0:10],cn=[1:11],cn=[2:12],cn=[3:13],cn=[4:14],cn=[5:15],cn=[6:16]",
        "cn=0,cn=1,cn=2,cn=3,cn=4,cn=5,cn=6",
        "cn=1,cn=2,cn=3,cn=4,cn=5,cn=6,cn=7"
      },
    };
  }



  /**
   * Retrieves a set of invalid value patterns.
   *
   * @return  A set of invalid value patterns.
   */
  @DataProvider(name="invalidValues")
  public Object[][] getInvalidValues()
  {
    return new Object[][]
    {
      new Object[]
      {
        "[",
      },

      new Object[]
      {
        "]",
      },

      new Object[]
      {
        "[]",
      },

      new Object[]
      {
        "][",
      },

      new Object[]
      {
        "[0]",
      },

      new Object[]
      {
        "[0:]",
      },

      new Object[]
      {
        "[:0]",
      },

      new Object[]
      {
        "[0:0x]",
      },

      new Object[]
      {
        "[0:0%]",
      },

      new Object[]
      {
        "[0:0x1%]",
      },

      new Object[]
      {
        "[0:10][",
      },

      new Object[]
      {
        "[0:10]]",
      },
      new Object[]
      {
        "[[0:10]",
      },

      new Object[]
      {
        "[0-:10]",
      },

      new Object[]
      {
        "[0:1-0]",
      },

      new Object[]
      {
        "[abc]",
      },

      new Object[]
      {
        "[1:1xa]",
      },

      new Object[]
      {
        "[1:x1]",
      },

      new Object[]
      {
        "[1:%0]",
      },

      new Object[]
      {
        "[1:1x0-1]",
      },

      new Object[]
      {
        "[1:1x%0]",
      },

      new Object[]
      {
        "[1:123456789012345678901234567890]",
      },

      new Object[]
      {
        "[1-123456789012345678901234567890]",
      },

      new Object[]
      {
        "[1-123456789012345678901234567890x2]",
      },

      new Object[]
      {
        "[1-123456789012345678901234567890%0]",
      },

      new Object[]
      {
        "[123456789012345678901234567890:1]",
      },

      new Object[]
      {
        "[123456789012345678901234567890-1]",
      },

      new Object[]
      {
        "[1:2x123456789012345678901234567890]",
      },

      new Object[]
      {
        "[1:2x123456789012345678901234567890%0]",
      },
    };
  }



  /**
   * Tests the behavior when trying to generate random characters without
   * specifying a character set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRandomCharactersWithoutCharacterSet()
         throws Exception
  {
    final ValuePattern valuePattern = new ValuePattern("[random:10]");
    for (int i=0; i < 100; i++)
    {
      final String s = valuePattern.nextValue();
      assertNotNull(s);
      assertEquals(s.length(), 10);
      for (int j=0; j < 10; j++)
      {
        final char c = s.charAt(j);
        assertTrue((c >= 'a') && (c <= 'z'));
      }
    }
  }



  /**
   * Tests the behavior when trying to generate random characters that specifies
   * a character set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRandomCharactersWithCharacterSet()
         throws Exception
  {
    final ValuePattern valuePattern =
         new ValuePattern("[random:10:0123456789abcdef]");
    for (int i=0; i < 100; i++)
    {
      final String s = valuePattern.nextValue();
      assertNotNull(s);
      assertEquals(s.length(), 10);
      for (int j=0; j < 10; j++)
      {
        final char c = s.charAt(j);
        assertTrue(((c >= '0') && (c <= '9')) ||
             ((c >= 'a') && (c <= 'f')));
      }
    }
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that does not specify a character set and has a malformed length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithoutSetMalformedLength()
         throws Exception
  {
    new ValuePattern("[random:invalid]");
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that does not specify a character set and has a length of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithoutSetZeroLength()
         throws Exception
  {
    new ValuePattern("[random:0]");
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that does not specify a character set and has a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithoutSetNegativeLength()
         throws Exception
  {
    new ValuePattern("[random:-1]");
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that specifies a character set and has a malformed length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithSetMalformedLength()
         throws Exception
  {
    new ValuePattern("[random:invalid:abcdef]");
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that specifies a character set and has a length of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithSetZeroLength()
         throws Exception
  {
    new ValuePattern("[random:0:abcdef]");
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that specifies a character set and has a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithSetNegativeLength()
         throws Exception
  {
    new ValuePattern("[random:-1:abcdef]");
  }



  /**
   * Tests the behavior when trying to create a random character set pattern
   * that specifies an empty character set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomCharactersWithEmptySet()
         throws Exception
  {
    new ValuePattern("[random:5:]");
  }



  /**
   * Performs a test using a file URL component with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testFileURLEmptyFile()
         throws Exception
  {
    File f = createTempFile();
    String path = f.getAbsolutePath().replace('\\', '/');

    new ValuePattern("[file:" + path + ']');
  }



  /**
   * Performs a test using a file URL component with a missing file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testMissingFile()
         throws Exception
  {
    File f = createTempFile();
    String path = f.getAbsolutePath().replace('\\', '/');
    f.delete();

    new ValuePattern("[file:" + path + ']');
  }



  /**
   * Performs a test using a file URL component with a valid file containing a
   * single line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidFileSingleLine()
         throws Exception
  {
    File f = createTempFile("foo");
    String path = f.getAbsolutePath().replace('\\', '/');

    ValuePattern p = new ValuePattern("[file:" + path + ']');

    for (int i=0; i < 100; i++)
    {
      assertEquals(p.nextValue(), "foo");
    }

    f.delete();
  }



  /**
   * Performs a test using a file URL component with a valid file containing
   * multiple lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidFileMultipleLines()
         throws Exception
  {
    File f = createTempFile(
         "foo",
         "bar",
         "baz");
    String path = f.getAbsolutePath().replace('\\', '/');

    ValuePattern p = new ValuePattern("[file:" + path + ']');

    int fooCount = 0;
    int barCount = 0;
    int bazCount = 0;
    for (int i=0; i < 100; i++)
    {
      String s = p.nextValue();
      if (s.equals("foo"))
      {
        fooCount++;
      }
      else if (s.equals("bar"))
      {
        barCount++;
      }
      else if (s.equals("baz"))
      {
        bazCount++;
      }
      else
      {
        fail("Unexpected value '" + s + '\'');
      }
    }

    assertTrue(fooCount > 0);
    assertTrue(barCount > 0);
    assertTrue(bazCount > 0);

    f.delete();
  }



  /**
   * Performs a test using an explicitly-random file URL component with an
   * empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomFileURLEmptyFile()
         throws Exception
  {
    File f = createTempFile();
    String path = f.getAbsolutePath().replace('\\', '/');

    new ValuePattern("[randomfile:" + path + ']');
  }



  /**
   * Performs a test using an explicitly-random file URL component with a
   * missing file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testRandomMissingFile()
         throws Exception
  {
    File f = createTempFile();
    String path = f.getAbsolutePath().replace('\\', '/');
    f.delete();

    new ValuePattern("[randomfile:" + path + ']');
  }



  /**
   * Performs a test using an explicitly-random file URL component with a valid
   * file containing a single line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRandomFileSingleLine()
         throws Exception
  {
    File f = createTempFile("foo");
    String path = f.getAbsolutePath().replace('\\', '/');

    ValuePattern p = new ValuePattern("[randomfile:" + path + ']');

    for (int i=0; i < 100; i++)
    {
      assertEquals(p.nextValue(), "foo");
    }

    f.delete();
  }



  /**
   * Performs a test using an explicitly-random file URL component with a valid
   * file containing multiple lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidRandomFileMultipleLines()
         throws Exception
  {
    File f = createTempFile(
         "foo",
         "bar",
         "baz");
    String path = f.getAbsolutePath().replace('\\', '/');

    ValuePattern p = new ValuePattern("[randomfile:" + path + ']');

    int fooCount = 0;
    int barCount = 0;
    int bazCount = 0;
    for (int i=0; i < 100; i++)
    {
      String s = p.nextValue();
      if (s.equals("foo"))
      {
        fooCount++;
      }
      else if (s.equals("bar"))
      {
        barCount++;
      }
      else if (s.equals("baz"))
      {
        bazCount++;
      }
      else
      {
        fail("Unexpected value '" + s + '\'');
      }
    }

    assertTrue(fooCount > 0);
    assertTrue(barCount > 0);
    assertTrue(bazCount > 0);

    f.delete();
  }



  /**
   * Performs a test using an explicitly-sequential file URL component with an
   * empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testSequentialFileURLEmptyFile()
         throws Exception
  {
    File f = createTempFile();
    String path = f.getAbsolutePath().replace('\\', '/');

    new ValuePattern("[sequentialfile:" + path + ']');
  }



  /**
   * Performs a test using an explicitly-sequential file URL component with a
   * missing file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testSequentialMissingFile()
         throws Exception
  {
    File f = createTempFile();
    String path = f.getAbsolutePath().replace('\\', '/');
    f.delete();

    new ValuePattern("[sequentialfile:" + path + ']');
  }



  /**
   * Performs a test using an explicitly-sequential file URL component with a
   * valid file containing a single line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSequentialFileSingleLine()
         throws Exception
  {
    File f = createTempFile("foo");
    String path = f.getAbsolutePath().replace('\\', '/');

    ValuePattern p = new ValuePattern("[sequentialfile:" + path + ']');

    for (int i=0; i < 100; i++)
    {
      assertEquals(p.nextValue(), "foo");
    }

    f.delete();
  }



  /**
   * Performs a test using an explicitly-sequential file URL component with a
   * valid file containing multiple lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSequentialFileMultipleLines()
         throws Exception
  {
    File f = createTempFile(
         "foo",
         "bar",
         "baz");
    String path = f.getAbsolutePath().replace('\\', '/');

    ValuePattern p = new ValuePattern("[sequentialfile:" + path + ']');

    for (int i=0; i < 100; i++)
    {
      assertEquals(p.nextValue(), "foo");
      assertEquals(p.nextValue(), "bar");
      assertEquals(p.nextValue(), "baz");
    }

    f.delete();
  }



  /**
   * Tests the behavior when trying to stream a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testStreamNonexistentFile()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    new ValuePattern("[streamfile:" + f.getAbsolutePath() + ']');
  }



  /**
   * Tests the behavior when trying to stream a path that exists but is not a
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testStreamPathNotFile()
         throws Exception
  {
    final File f = createTempDir();

    new ValuePattern("[streamfile:" + f.getAbsolutePath() + ']');
  }



  /**
   * Tests the behavior when trying to stream an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testStreamEmptyFile()
         throws Exception
  {
    final File f = createTempFile();

    new ValuePattern("[streamfile:" + f.getAbsolutePath() + ']');
  }



  /**
   * Tests the behavior when trying to stream a file that has a single line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStreamSingleLineFile()
         throws Exception
  {
    final File f = createTempFile("hello");

    final ValuePattern valuePattern =
         new ValuePattern("[streamfile:" + f.getAbsolutePath() + ']');
    for (int i=0; i < 10; i++)
    {
      assertEquals(valuePattern.nextValue(), "hello");
    }
  }



  /**
   * Tests the behavior when trying to stream a file that has multiple lines,
   * but still fewer lines than the queue size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStreamFromMultiLineFileBelowQueueSize()
         throws Exception
  {
    final File f = createTempFile();
    try (PrintWriter w = new PrintWriter(f))
    {
      for (int i=0; i < 100; i++)
      {
        w.println("Hello " + i);
      }
    }

    final ValuePattern valuePattern =
         new ValuePattern("[streamfile:" + f.getAbsolutePath() + ']');
    for (int i=0; i < 10; i++)
    {
      for (int j=0; j < 100; j++)
      {
        assertEquals(valuePattern.nextValue(), "Hello " + j);
      }
    }
  }



  /**
   * Tests the behavior when trying to stream a file that has multiple lines,
   * and where the number of lines is larger than the queue size.  This will
   * also inject pauses into the reading process to ensure that the reader
   * thread has time to exit so that a new thread must be created to continue
   * reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStreamFromMultiLineFileAboveQueueSizeWithPauses()
         throws Exception
  {
    final File f = createTempFile();
    try (PrintWriter w = new PrintWriter(f))
    {
      for (int i=0; i < 10_000; i++)
      {
        w.println("Hello " + i);
      }
    }

    final StreamFileValuePatternComponent c =
         new StreamFileValuePatternComponent(f.getAbsolutePath(), 100, 1L);

    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < 10; i++)
    {
      for (int j=0; j < 5000; j++)
      {
        buffer.setLength(0);
        c.append(buffer);
        assertEquals(buffer.toString(), "Hello " + j);
      }

      Thread.sleep(100L);

      for (int j=5000; j < 10_000; j++)
      {
        buffer.setLength(0);
        c.append(buffer);
        assertEquals(buffer.toString(), "Hello " + j);
      }
    }
  }



  /**
   * Performs a test using an HTTP URL with an empty file.
   * <BR><BR>
   * To help tests run quickly, this will only be invoked if a Directory Server
   * instance is available for testing.
   * <BR><BR>
   * NOTE:  This test is currently disabled because files.unboundid.com is no
   * longer available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(enabled = false)
  public void testHTTPURLEmptyFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    try
    {
      new ValuePattern("[http://files.unboundid.com/empty]");
    } catch (Exception e) {}
  }



  /**
   * Performs a test using an HTTP URL with a missing file.
   * <BR><BR>
   * To help tests run quickly, this will only be invoked if a Directory Server
   * instance is available for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHTTPURLMissingFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    try
    {
      new ValuePattern("[http://files.unboundid.com/missing]");
    } catch (Exception e) {}
  }



  /**
   * Performs a test using an HTTP URL with a valid file.
   * <BR><BR>
   * To help tests run quickly, this will only be invoked if a Directory Server
   * instance is available for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHTTPURLValidFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    try
    {
      ValuePattern p = new
           ValuePattern("[http://files.unboundid.com/cddl.html]");

      for (int i=0; i < 100; i++)
      {
        p.nextValue();
      }
    } catch (Exception e) {}
  }



  /**
   * Tests the behavior when using the timestamp pattern with the default
   * settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampDefault()
         throws Exception
  {
    final ValuePattern p = new ValuePattern("[timestamp]");

    final long beforeTime = System.currentTimeMillis();
    final String value = p.nextValue();
    final long afterTime = System.currentTimeMillis();

    assertNotNull(value);
    final Date date = StaticUtils.decodeGeneralizedTime(value);
    final long time = date.getTime();

    assertTrue((time >= beforeTime) && (time <= afterTime));
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values but without a timestamp format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithMinAndMaxWithoutFormat()
         throws Exception
  {
    final String minString = "20180101000000.000Z";
    final long minTime = StaticUtils.decodeGeneralizedTime(minString).getTime();

    final String maxString = "20181231235959.999Z";
    final long maxTime = StaticUtils.decodeGeneralizedTime(maxString).getTime();

    final ValuePattern p = new ValuePattern(
         "[timestamp:min=" + minString + ":max=" + maxString + ']');

    for (int i=0; i < 100; i++)
    {
      final String value = p.nextValue();
      assertNotNull(value);

      final Date date = StaticUtils.decodeGeneralizedTime(value);
      final long time = date.getTime();

      assertTrue((time >= minTime) && (time <= maxTime));
    }
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying a
   * format of milliseconds and without min and max values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithFormatMillisWithoutMinAndMax()
         throws Exception
  {
    final ValuePattern p = new ValuePattern("[timestamp:format=milliseconds]");

    final long beforeTime = System.currentTimeMillis();
    final String value = p.nextValue();
    final long afterTime = System.currentTimeMillis();

    assertNotNull(value);
    final long time = Long.parseLong(value);

    assertTrue((time >= beforeTime) && (time <= afterTime));
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying a
   * format of seconds and without min and max values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithFormatSecondsWithoutMinAndMax()
         throws Exception
  {
    final ValuePattern p = new ValuePattern("[timestamp:format=seconds]");

    final long beforeTime = System.currentTimeMillis() / 1000L;
    final String value = p.nextValue();
    final long afterTime = System.currentTimeMillis() / 1000L;

    assertNotNull(value);
    final long time = Long.parseLong(value);

    assertTrue((time >= beforeTime) && (time <= afterTime));
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying a
   * custom format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithFormatCustomWithoutMinAndMax()
         throws Exception
  {
    final String formatString = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

    final ValuePattern p =
         new ValuePattern("[timestamp:format=" + formatString + ']');

    final long beforeTime = System.currentTimeMillis();
    final String value = p.nextValue();
    final long afterTime = System.currentTimeMillis();

    assertNotNull(value);

    final SimpleDateFormat dateFormat = new SimpleDateFormat(formatString);
    dateFormat.setLenient(false);

    final Date date = dateFormat.parse(value);
    final long time = date.getTime();
    assertTrue((time >= beforeTime) && (time <= afterTime));
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min,
   * max, and format components when the format is milliseconds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithMinMaxAndFormatMillis()
         throws Exception
  {
    final String minString = "20180101000000.000Z";
    final long minTime = StaticUtils.decodeGeneralizedTime(minString).getTime();

    final String maxString = "20181231235959.999Z";
    final long maxTime = StaticUtils.decodeGeneralizedTime(maxString).getTime();

    final ValuePattern p = new ValuePattern("[timestamp:min=" + minString +
         ":max=" + maxString + ":format=milliseconds]");

    final String value = p.nextValue();

    assertNotNull(value);
    final long time = Long.parseLong(value);

    assertTrue((time >= minTime) && (time <= maxTime));
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min,
   * max, and format components when the format is seconds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithMinMaxAndFormatSeconds()
         throws Exception
  {
    final String minString = "20180101000000.000Z";
    final long minTime =
         StaticUtils.decodeGeneralizedTime(minString).getTime() / 1000L;

    final String maxString = "20181231235959.999Z";
    final long maxTime =
         StaticUtils.decodeGeneralizedTime(maxString).getTime() / 1000L;

    final ValuePattern p = new ValuePattern("[timestamp:min=" + minString +
         ":max=" + maxString + ":format=seconds]");

    final String value = p.nextValue();

    assertNotNull(value);
    final long time = Long.parseLong(value);

    assertTrue((time >= minTime) && (time <= maxTime));
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min,
   * max, and format components when using a custom format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimestampWithMinMaxAndFormatCustom()
         throws Exception
  {
    final String minString = "20180101000000.000Z";
    final long minTime = StaticUtils.decodeGeneralizedTime(minString).getTime();

    final String maxString = "20181231235959.999Z";
    final long maxTime = StaticUtils.decodeGeneralizedTime(maxString).getTime();

    final String formatString = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

    final ValuePattern p = new ValuePattern("[timestamp:min=" + minString +
         ":max=" + maxString + ":format=" + formatString + ']');

    for (int i=0; i < 100; i++)
    {
      final String value = p.nextValue();
      assertNotNull(value);

      final SimpleDateFormat dateFormat = new SimpleDateFormat(formatString);
      dateFormat.setLenient(false);

      final Date date = dateFormat.parse(value);
      final long time = date.getTime();

      assertTrue((time >= minTime) && (time <= maxTime));
    }
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying a min
   * value but not a max value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMinWithoutMax()
         throws Exception
  {
    new ValuePattern("[timestamp:min=20180101000000.000Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values but without a timestamp format when the min value is
   * malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMalformedMin()
         throws Exception
  {
    new ValuePattern("[timestamp:min=malformed:max=20181231235959.999Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values but without a timestamp format when the max value is
   * malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMalformedMaxWithoutFormat()
         throws Exception
  {
    new ValuePattern("[timestamp:min=20180101000000.000Z:max=malformed]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values and also a format when the max value is malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMalformedMaxWithFormat()
         throws Exception
  {
    new ValuePattern("[timestamp:min=20180101000000.000Z:max=malformed:" +
         "format=milliseconds]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values when the min and max values are equal.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMinEqualsMax()
         throws Exception
  {
    new ValuePattern(
         "[timestamp:min=20180101000000.000Z:max=20180101000000.000Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values when the min value is after the max value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMinAfterMax()
         throws Exception
  {
    new ValuePattern(
         "[timestamp:min=20181231235959.999Z:max=20180101000000.000Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min,
   * max, and format values when the min value is after the max value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMinAfterMaxWithFormat()
         throws Exception
  {
    new ValuePattern("[timestamp:min=20181231235959.999Z:" +
         "max=20180101000000.000Z:format=milliseconds]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min
   * and max values when the min value is chronologically before the max value,
   * but when the max value comes first in the format string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMinAndMaxOrderSwapped()
         throws Exception
  {
    new ValuePattern(
         "[timestamp:max=20180101000000.000Z:min=20181231235959.999Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min,
   * max, and format values when the format comes before the min and max.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithFormatBeforeMinAndMax()
         throws Exception
  {
    new ValuePattern("[timestamp:format=seconds:min=20180101000000.000Z:" +
         "max=20181231235959.999Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern when specifying min,
   * max, and format values when the format comes between the min and max.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithFormatBetweenMinAndMax()
         throws Exception
  {
    new ValuePattern("[timestamp:min=20180101000000.000Z:format=seconds:" +
         "max=20181231235959.999Z]");
  }



  /**
   * Tests the behavior when using the timestamp pattern with a malformed
   * format when not specifying min and max values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithoutMinAndMaxWithMalformedFormat()
         throws Exception
  {
    new ValuePattern("[timestamp:format=malformed]");
  }



  /**
   * Tests the behavior when using the timestamp pattern with a malformed
   * format when also specifying min and max values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testTimestampWithMinAndMaxWithMalformedFormat()
         throws Exception
  {
    new ValuePattern("[timestamp:min=20180101000000.000Z:" +
         "max=20181231235959.999Z:format=malformed]");
  }



  /**
   * Performs a simple test with a simple valid back-reference.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleValidBackReference()
         throws Exception
  {
    final ValuePattern p = new ValuePattern("[1-1000]:[ref:1]");

    for (int i=0; i < 100; i++)
    {
      final String s = p.nextValue();
      final int colonPos = s.indexOf(':');
      assertEquals(s.substring(0, colonPos), s.substring(colonPos+1));
    }
  }



  /**
   * Performs a simple test with a valid back-reference to a value obtained from
   * a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidBackReferenceToFileComponent()
         throws Exception
  {
    final File f = createTempFile(
         "line1",
         "line2",
         "line3",
         "line4",
         "line5");

    final ValuePattern p = new ValuePattern("[sequentialfile:" +
         f.getAbsolutePath() + "][ref:1]");

    for (int i=1; i <= 5; i++)
    {
      final String s = p.nextValue();
      assertEquals(s, "line" + i + "line" + i);
    }
  }



  /**
   * Performs a simple test with a valid back-reference to a value obtained from
   * a file read via streaming.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidBackReferenceToStreamFileComponent()
         throws Exception
  {
    final File f = createTempFile(
         "line1",
         "line2",
         "line3",
         "line4",
         "line5");

    final ValuePattern p = new ValuePattern("[streamfile:" +
         f.getAbsolutePath() + "][ref:1]");

    for (int i=1; i <= 5; i++)
    {
      final String s = p.nextValue();
      assertEquals(s, "line" + i + "line" + i);
    }
  }



  /**
   * Performs a simple test with a valid back-reference to a value obtained from
   * a timestamp component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidBackReferenceToRandomCharactersComponent()
         throws Exception
  {
    final ValuePattern p =
         new ValuePattern("[random:8:0123456789abcdef]:[ref:1]");

    final String s = p.nextValue();
    final int colonPos = s.indexOf(':');
    assertTrue(colonPos > 0);

    final String hexString1 = s.substring(0, colonPos);
    final String hexString2 = s.substring(colonPos+1);
    assertEquals(hexString1, hexString2);
  }



  /**
   * Performs a simple test with a valid back-reference to a value obtained from
   * a timestamp component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidBackReferenceToTimestampComponent()
         throws Exception
  {
    final ValuePattern p = new ValuePattern("[timestamp]:[ref:1]");

    final String s = p.nextValue();
    final int colonPos = s.indexOf(':');
    assertTrue(colonPos > 0);

    final String timestamp1 = s.substring(0, colonPos);
    final String timestamp2 = s.substring(colonPos+1);
    assertEquals(timestamp1, timestamp2);

    assertNotNull(StaticUtils.decodeGeneralizedTime(timestamp1));
  }



  /**
   * Performs a simple test with a valid back-reference to a value obtained from
   * a UUID component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidBackReferenceToUUIDComponent()
         throws Exception
  {
    final ValuePattern p = new ValuePattern("[uuid]:[ref:1]");

    final String s = p.nextValue();
    final int colonPos = s.indexOf(':');
    assertTrue(colonPos > 0);

    final String uuid1 = s.substring(0, colonPos);
    final String uuid2 = s.substring(colonPos+1);
    assertEquals(uuid1, uuid2);

    assertNotNull(UUID.fromString(uuid1));
  }



  /**
   * Performs a simple test with a compound valid back-reference.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompoundValidBackReference()
         throws Exception
  {
    final ValuePattern p = new ValuePattern(
         "a[1-1000]b[1-1000]c[ref:1]d:a[ref:1]b[ref:2]c[ref:1]d");

    for (int i=0; i < 100; i++)
    {
      final String s = p.nextValue();
      final int colonPos = s.indexOf(':');
      assertEquals(s.substring(0, colonPos), s.substring(colonPos+1));
    }
  }



  /**
   * Performs a simple test with an invalid back-reference using a malformed
   * index.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testBackReferenceMalformedIndex()
         throws Exception
  {
    new ValuePattern("[1-1000]:[ref:invalid]");
  }



  /**
   * Performs a simple test with an invalid back-reference with a zero index.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testBackReferenceZeroIndex()
         throws Exception
  {
    new ValuePattern("[1-1000]:[ref:0]");
  }



  /**
   * Performs a simple test with an invalid back-reference with a negative
   * index.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testBackReferenceNegativeIndex()
         throws Exception
  {
    new ValuePattern("[1-1000]:[ref:-1]");
  }



  /**
   * Performs a simple test with an invalid back-reference with an index that
   * is too large.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testBackReferenceIndexTooLarge()
         throws Exception
  {
    new ValuePattern("[1-1000]:[ref:2]");
  }



  /**
   * Provides coverage for the BackReferenceValuePatternComponent.append method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { AssertionError.class })
  public void testBackReferenceValuePatternAppend()
         throws Exception
  {
    final BackReferenceValuePatternComponent c =
         new BackReferenceValuePatternComponent(1);
    c.append(new StringBuilder());
  }
}
