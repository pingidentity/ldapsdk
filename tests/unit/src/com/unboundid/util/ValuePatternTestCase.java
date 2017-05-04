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
package com.unboundid.util;



import java.io.File;
import java.text.ParseException;
import java.util.HashMap;
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
   * Performs a test using an HTTP URL with an empty file.
   * <BR><BR>
   * To help tests run quickly, this will only be invoked if a Directory Server
   * instance is available for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
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
