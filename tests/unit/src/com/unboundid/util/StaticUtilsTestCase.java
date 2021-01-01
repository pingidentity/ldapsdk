/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.InetAddress;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.TimeZone;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the StaticUtils class.
 */
public class StaticUtilsTestCase
       extends UtilTestCase
{
  /**
   * Tests the {@code toLowerCase} method with a {@code null} string.
   */
  @Test()
  public void testToLowerCaseNull()
  {
    assertNull(StaticUtils.toLowerCase(null));
  }



  /**
   * Tests the {@code toLowerCase} method with an empty string.
   */
  @Test()
  public void testToLowerCaseEmpty()
  {
    assertEquals(StaticUtils.toLowerCase(""), "");
  }



  /**
   * Tests the {@code toLowerCase} method with string that already contains only
   * ASCII characters.
   */
  @Test()
  public void testToLowerCaseOnlyASCII()
  {
    String s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    String l = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz";

    assertEquals(StaticUtils.toLowerCase(s), l);
  }



  /**
   * Tests the {@code toLowerCase} method with string that already contains a
   * mix of ASCII and non-ASCII characters.
   */
  @Test()
  public void testToLowerCaseIncludesNonASCII()
  {
    String u = "JOS\u00c9 JALAPE\u00d1O";
    String l = "jos\u00e9 jalape\u00f1o";

    assertEquals(StaticUtils.toLowerCase(u), l);
  }



  /**
   * Tests the {@code toUpperCase} method with a {@code null} string.
   */
  @Test()
  public void testToUpperCaseNull()
  {
    assertNull(StaticUtils.toUpperCase(null));
  }



  /**
   * Tests the {@code toUpperCase} method with an empty string.
   */
  @Test()
  public void testToUpperCaseEmpty()
  {
    assertEquals(StaticUtils.toUpperCase(""), "");
  }



  /**
   * Tests the {@code toUpperCase} method with string that already contains only
   * ASCII characters.
   */
  @Test()
  public void testToUpperCaseOnlyASCII()
  {
    String s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    String l = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    assertEquals(StaticUtils.toUpperCase(s), l);
  }



  /**
   * Tests the {@code toUpperCase} method with string that already contains a
   * mix of ASCII and non-ASCII characters.
   */
  @Test()
  public void testToUpperCaseIncludesNonASCII()
  {
    String l = "jos\u00e9 jalape\u00f1o";
    String u = "JOS\u00c9 JALAPE\u00d1O";

    assertEquals(StaticUtils.toUpperCase(l), u);
  }



  /**
   * Tests the {@code isHex} method to ensure that it works correctly.
   */
  @Test()
  public void testIsHex()
  {
    // Note that this loop must stop before it gets to the maximum character
    // value because otherwise the final increment will cause the counter to
    // wrap around and become less than the maximum value again.  Therefore,
    // we'll test the maximum value separately.
    for (char c = Character.MIN_VALUE; c < Character.MAX_VALUE; c++)
    {
      if ((c >= '0') && (c <= '9'))
      {
        assertTrue(StaticUtils.isHex(c));
      }
      else if ((c >= 'a') && (c <= 'f'))
      {
        assertTrue(StaticUtils.isHex(c));
      }
      else if ((c >= 'A') && (c <= 'F'))
      {
        assertTrue(StaticUtils.isHex(c));
      }
      else
      {
        assertFalse(StaticUtils.isHex(c));
      }
    }

    assertFalse(StaticUtils.isHex(Character.MAX_VALUE));
  }



  /**
   * Tests both variants of the {@code toHex} method.
   *
   * @param  b          The byte for which to obtain the hexadecimal
   *                    representation.
   * @param  hexString  The expected hexadecimal representation for the provdied
   *                    byte.
   */
  @Test(dataProvider = "testToHexData")
  public void testToHex(byte b, String hexString)
  {
    assertEquals(StaticUtils.toHex(b), hexString);

    StringBuilder buffer = new StringBuilder();
    StaticUtils.toHex(b, buffer);
    assertEquals(buffer.toString(), hexString);
  }



  /**
   * Tests the {@code hexEncode} method to ensure that it works correctly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHexEncode()
         throws Exception
  {
    // Note that this loop must stop before it gets to the maximum character
    // value because otherwise the final increment will cause the counter to
    // wrap around and become less than the maximum value again.  Therefore,
    // we'll skip the maximum value.
    for (char c = Character.MIN_VALUE; c < Character.MAX_VALUE; c++)
    {
      byte[] charBytes = ("" + c).getBytes("UTF-8");
      StringBuilder expectedBuffer = new StringBuilder(9);
      for (byte b : charBytes)
      {
        expectedBuffer.append('\\');
        StaticUtils.toHex(b, expectedBuffer);
      }

      StringBuilder gotBuffer = new StringBuilder(9);
      StaticUtils.hexEncode(c, gotBuffer);

      assertEquals(gotBuffer.toString(), expectedBuffer.toString(),
                   "Mismatch for character with int value " + ((int) c));
    }
  }



  /**
   * Retrieves a set of data that can be used to test the {@code toHex} method.
   *
   * @return  A set of data that can be used to test the {@code toHex} method.
   */
  @DataProvider(name = "testToHexData")
  public Object[][] getTestToHexData()
  {
    return new Object[][]
    {
      new Object[] { (byte) 0x00, "00" },
      new Object[] { (byte) 0x01, "01" },
      new Object[] { (byte) 0x02, "02" },
      new Object[] { (byte) 0x03, "03" },
      new Object[] { (byte) 0x04, "04" },
      new Object[] { (byte) 0x05, "05" },
      new Object[] { (byte) 0x06, "06" },
      new Object[] { (byte) 0x07, "07" },
      new Object[] { (byte) 0x08, "08" },
      new Object[] { (byte) 0x09, "09" },
      new Object[] { (byte) 0x0a, "0a" },
      new Object[] { (byte) 0x0b, "0b" },
      new Object[] { (byte) 0x0c, "0c" },
      new Object[] { (byte) 0x0d, "0d" },
      new Object[] { (byte) 0x0e, "0e" },
      new Object[] { (byte) 0x0f, "0f" },
      new Object[] { (byte) 0x10, "10" },
      new Object[] { (byte) 0x11, "11" },
      new Object[] { (byte) 0x12, "12" },
      new Object[] { (byte) 0x13, "13" },
      new Object[] { (byte) 0x14, "14" },
      new Object[] { (byte) 0x15, "15" },
      new Object[] { (byte) 0x16, "16" },
      new Object[] { (byte) 0x17, "17" },
      new Object[] { (byte) 0x18, "18" },
      new Object[] { (byte) 0x19, "19" },
      new Object[] { (byte) 0x1a, "1a" },
      new Object[] { (byte) 0x1b, "1b" },
      new Object[] { (byte) 0x1c, "1c" },
      new Object[] { (byte) 0x1d, "1d" },
      new Object[] { (byte) 0x1e, "1e" },
      new Object[] { (byte) 0x1f, "1f" },
      new Object[] { (byte) 0x20, "20" },
      new Object[] { (byte) 0x21, "21" },
      new Object[] { (byte) 0x22, "22" },
      new Object[] { (byte) 0x23, "23" },
      new Object[] { (byte) 0x24, "24" },
      new Object[] { (byte) 0x25, "25" },
      new Object[] { (byte) 0x26, "26" },
      new Object[] { (byte) 0x27, "27" },
      new Object[] { (byte) 0x28, "28" },
      new Object[] { (byte) 0x29, "29" },
      new Object[] { (byte) 0x2a, "2a" },
      new Object[] { (byte) 0x2b, "2b" },
      new Object[] { (byte) 0x2c, "2c" },
      new Object[] { (byte) 0x2d, "2d" },
      new Object[] { (byte) 0x2e, "2e" },
      new Object[] { (byte) 0x2f, "2f" },
      new Object[] { (byte) 0x30, "30" },
      new Object[] { (byte) 0x31, "31" },
      new Object[] { (byte) 0x32, "32" },
      new Object[] { (byte) 0x33, "33" },
      new Object[] { (byte) 0x34, "34" },
      new Object[] { (byte) 0x35, "35" },
      new Object[] { (byte) 0x36, "36" },
      new Object[] { (byte) 0x37, "37" },
      new Object[] { (byte) 0x38, "38" },
      new Object[] { (byte) 0x39, "39" },
      new Object[] { (byte) 0x3a, "3a" },
      new Object[] { (byte) 0x3b, "3b" },
      new Object[] { (byte) 0x3c, "3c" },
      new Object[] { (byte) 0x3d, "3d" },
      new Object[] { (byte) 0x3e, "3e" },
      new Object[] { (byte) 0x3f, "3f" },
      new Object[] { (byte) 0x40, "40" },
      new Object[] { (byte) 0x41, "41" },
      new Object[] { (byte) 0x42, "42" },
      new Object[] { (byte) 0x43, "43" },
      new Object[] { (byte) 0x44, "44" },
      new Object[] { (byte) 0x45, "45" },
      new Object[] { (byte) 0x46, "46" },
      new Object[] { (byte) 0x47, "47" },
      new Object[] { (byte) 0x48, "48" },
      new Object[] { (byte) 0x49, "49" },
      new Object[] { (byte) 0x4a, "4a" },
      new Object[] { (byte) 0x4b, "4b" },
      new Object[] { (byte) 0x4c, "4c" },
      new Object[] { (byte) 0x4d, "4d" },
      new Object[] { (byte) 0x4e, "4e" },
      new Object[] { (byte) 0x4f, "4f" },
      new Object[] { (byte) 0x50, "50" },
      new Object[] { (byte) 0x51, "51" },
      new Object[] { (byte) 0x52, "52" },
      new Object[] { (byte) 0x53, "53" },
      new Object[] { (byte) 0x54, "54" },
      new Object[] { (byte) 0x55, "55" },
      new Object[] { (byte) 0x56, "56" },
      new Object[] { (byte) 0x57, "57" },
      new Object[] { (byte) 0x58, "58" },
      new Object[] { (byte) 0x59, "59" },
      new Object[] { (byte) 0x5a, "5a" },
      new Object[] { (byte) 0x5b, "5b" },
      new Object[] { (byte) 0x5c, "5c" },
      new Object[] { (byte) 0x5d, "5d" },
      new Object[] { (byte) 0x5e, "5e" },
      new Object[] { (byte) 0x5f, "5f" },
      new Object[] { (byte) 0x60, "60" },
      new Object[] { (byte) 0x61, "61" },
      new Object[] { (byte) 0x62, "62" },
      new Object[] { (byte) 0x63, "63" },
      new Object[] { (byte) 0x64, "64" },
      new Object[] { (byte) 0x65, "65" },
      new Object[] { (byte) 0x66, "66" },
      new Object[] { (byte) 0x67, "67" },
      new Object[] { (byte) 0x68, "68" },
      new Object[] { (byte) 0x69, "69" },
      new Object[] { (byte) 0x6a, "6a" },
      new Object[] { (byte) 0x6b, "6b" },
      new Object[] { (byte) 0x6c, "6c" },
      new Object[] { (byte) 0x6d, "6d" },
      new Object[] { (byte) 0x6e, "6e" },
      new Object[] { (byte) 0x6f, "6f" },
      new Object[] { (byte) 0x70, "70" },
      new Object[] { (byte) 0x71, "71" },
      new Object[] { (byte) 0x72, "72" },
      new Object[] { (byte) 0x73, "73" },
      new Object[] { (byte) 0x74, "74" },
      new Object[] { (byte) 0x75, "75" },
      new Object[] { (byte) 0x76, "76" },
      new Object[] { (byte) 0x77, "77" },
      new Object[] { (byte) 0x78, "78" },
      new Object[] { (byte) 0x79, "79" },
      new Object[] { (byte) 0x7a, "7a" },
      new Object[] { (byte) 0x7b, "7b" },
      new Object[] { (byte) 0x7c, "7c" },
      new Object[] { (byte) 0x7d, "7d" },
      new Object[] { (byte) 0x7e, "7e" },
      new Object[] { (byte) 0x7f, "7f" },
      new Object[] { (byte) 0x80, "80" },
      new Object[] { (byte) 0x81, "81" },
      new Object[] { (byte) 0x82, "82" },
      new Object[] { (byte) 0x83, "83" },
      new Object[] { (byte) 0x84, "84" },
      new Object[] { (byte) 0x85, "85" },
      new Object[] { (byte) 0x86, "86" },
      new Object[] { (byte) 0x87, "87" },
      new Object[] { (byte) 0x88, "88" },
      new Object[] { (byte) 0x89, "89" },
      new Object[] { (byte) 0x8a, "8a" },
      new Object[] { (byte) 0x8b, "8b" },
      new Object[] { (byte) 0x8c, "8c" },
      new Object[] { (byte) 0x8d, "8d" },
      new Object[] { (byte) 0x8e, "8e" },
      new Object[] { (byte) 0x8f, "8f" },
      new Object[] { (byte) 0x90, "90" },
      new Object[] { (byte) 0x91, "91" },
      new Object[] { (byte) 0x92, "92" },
      new Object[] { (byte) 0x93, "93" },
      new Object[] { (byte) 0x94, "94" },
      new Object[] { (byte) 0x95, "95" },
      new Object[] { (byte) 0x96, "96" },
      new Object[] { (byte) 0x97, "97" },
      new Object[] { (byte) 0x98, "98" },
      new Object[] { (byte) 0x99, "99" },
      new Object[] { (byte) 0x9a, "9a" },
      new Object[] { (byte) 0x9b, "9b" },
      new Object[] { (byte) 0x9c, "9c" },
      new Object[] { (byte) 0x9d, "9d" },
      new Object[] { (byte) 0x9e, "9e" },
      new Object[] { (byte) 0x9f, "9f" },
      new Object[] { (byte) 0xa0, "a0" },
      new Object[] { (byte) 0xa1, "a1" },
      new Object[] { (byte) 0xa2, "a2" },
      new Object[] { (byte) 0xa3, "a3" },
      new Object[] { (byte) 0xa4, "a4" },
      new Object[] { (byte) 0xa5, "a5" },
      new Object[] { (byte) 0xa6, "a6" },
      new Object[] { (byte) 0xa7, "a7" },
      new Object[] { (byte) 0xa8, "a8" },
      new Object[] { (byte) 0xa9, "a9" },
      new Object[] { (byte) 0xaa, "aa" },
      new Object[] { (byte) 0xab, "ab" },
      new Object[] { (byte) 0xac, "ac" },
      new Object[] { (byte) 0xad, "ad" },
      new Object[] { (byte) 0xae, "ae" },
      new Object[] { (byte) 0xaf, "af" },
      new Object[] { (byte) 0xb0, "b0" },
      new Object[] { (byte) 0xb1, "b1" },
      new Object[] { (byte) 0xb2, "b2" },
      new Object[] { (byte) 0xb3, "b3" },
      new Object[] { (byte) 0xb4, "b4" },
      new Object[] { (byte) 0xb5, "b5" },
      new Object[] { (byte) 0xb6, "b6" },
      new Object[] { (byte) 0xb7, "b7" },
      new Object[] { (byte) 0xb8, "b8" },
      new Object[] { (byte) 0xb9, "b9" },
      new Object[] { (byte) 0xba, "ba" },
      new Object[] { (byte) 0xbb, "bb" },
      new Object[] { (byte) 0xbc, "bc" },
      new Object[] { (byte) 0xbd, "bd" },
      new Object[] { (byte) 0xbe, "be" },
      new Object[] { (byte) 0xbf, "bf" },
      new Object[] { (byte) 0xc0, "c0" },
      new Object[] { (byte) 0xc1, "c1" },
      new Object[] { (byte) 0xc2, "c2" },
      new Object[] { (byte) 0xc3, "c3" },
      new Object[] { (byte) 0xc4, "c4" },
      new Object[] { (byte) 0xc5, "c5" },
      new Object[] { (byte) 0xc6, "c6" },
      new Object[] { (byte) 0xc7, "c7" },
      new Object[] { (byte) 0xc8, "c8" },
      new Object[] { (byte) 0xc9, "c9" },
      new Object[] { (byte) 0xca, "ca" },
      new Object[] { (byte) 0xcb, "cb" },
      new Object[] { (byte) 0xcc, "cc" },
      new Object[] { (byte) 0xcd, "cd" },
      new Object[] { (byte) 0xce, "ce" },
      new Object[] { (byte) 0xcf, "cf" },
      new Object[] { (byte) 0xd0, "d0" },
      new Object[] { (byte) 0xd1, "d1" },
      new Object[] { (byte) 0xd2, "d2" },
      new Object[] { (byte) 0xd3, "d3" },
      new Object[] { (byte) 0xd4, "d4" },
      new Object[] { (byte) 0xd5, "d5" },
      new Object[] { (byte) 0xd6, "d6" },
      new Object[] { (byte) 0xd7, "d7" },
      new Object[] { (byte) 0xd8, "d8" },
      new Object[] { (byte) 0xd9, "d9" },
      new Object[] { (byte) 0xda, "da" },
      new Object[] { (byte) 0xdb, "db" },
      new Object[] { (byte) 0xdc, "dc" },
      new Object[] { (byte) 0xdd, "dd" },
      new Object[] { (byte) 0xde, "de" },
      new Object[] { (byte) 0xdf, "df" },
      new Object[] { (byte) 0xe0, "e0" },
      new Object[] { (byte) 0xe1, "e1" },
      new Object[] { (byte) 0xe2, "e2" },
      new Object[] { (byte) 0xe3, "e3" },
      new Object[] { (byte) 0xe4, "e4" },
      new Object[] { (byte) 0xe5, "e5" },
      new Object[] { (byte) 0xe6, "e6" },
      new Object[] { (byte) 0xe7, "e7" },
      new Object[] { (byte) 0xe8, "e8" },
      new Object[] { (byte) 0xe9, "e9" },
      new Object[] { (byte) 0xea, "ea" },
      new Object[] { (byte) 0xeb, "eb" },
      new Object[] { (byte) 0xec, "ec" },
      new Object[] { (byte) 0xed, "ed" },
      new Object[] { (byte) 0xee, "ee" },
      new Object[] { (byte) 0xef, "ef" },
      new Object[] { (byte) 0xf0, "f0" },
      new Object[] { (byte) 0xf1, "f1" },
      new Object[] { (byte) 0xf2, "f2" },
      new Object[] { (byte) 0xf3, "f3" },
      new Object[] { (byte) 0xf4, "f4" },
      new Object[] { (byte) 0xf5, "f5" },
      new Object[] { (byte) 0xf6, "f6" },
      new Object[] { (byte) 0xf7, "f7" },
      new Object[] { (byte) 0xf8, "f8" },
      new Object[] { (byte) 0xf9, "f9" },
      new Object[] { (byte) 0xfa, "fa" },
      new Object[] { (byte) 0xfb, "fb" },
      new Object[] { (byte) 0xfc, "fc" },
      new Object[] { (byte) 0xfd, "fd" },
      new Object[] { (byte) 0xfe, "fe" },
      new Object[] { (byte) 0xff, "ff" },
    };
  }



  /**
   * Tests the {@code getStackTrace} method.
   */
  @Test()
  public void testGetStackTrace()
  {
    Exception cause  = new Exception("This is the cause.");
    assertNotNull(StaticUtils.getStackTrace(cause));

    Exception result = new Exception("This is the result.", cause);
    assertNotNull(StaticUtils.getStackTrace(result));

    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    assertNotNull(StaticUtils.getStackTrace(stack));
  }



  /**
   * Tests the {@code encodeGeneralizedTime} and {@code deocdeGeneralizedTime}
   * methods to ensure that a date can be encoded and decoded properly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeAndDecodeGeneralizedTimes()
         throws Exception
  {
    Date d = new Date();

    final String generalizedTimeStr = StaticUtils.encodeGeneralizedTime(d);
    assertNotNull(generalizedTimeStr);

    final Date decoded = StaticUtils.decodeGeneralizedTime(generalizedTimeStr);
    assertEquals(decoded.getTime(), d.getTime());

    assertEquals(StaticUtils.encodeGeneralizedTime(d.getTime()),
         generalizedTimeStr);
  }



  /**
   * Tests the ability to decode valid timestamps in generalized time form.
   *
   * @param  timestamp  The timestamp to be decoded.
   * @param  expected   The value expected to be decoded.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test(dataProvider = "validGeneralizedTimestamps")
  public void testDecodeValidGeneralizedTime(String timestamp,
                                             Date expected)
         throws Exception
  {
    assertEquals(StaticUtils.decodeGeneralizedTime(timestamp), expected);
  }



  /**
   * Tests to ensure that invalid generalized time timestamps are rejected.
   *
   * @param  timestamp  The invalid timestamp to be decoded.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test(dataProvider = "invalidGeneralizedTimestamps",
        expectedExceptions = { LDAPSDKUsageException.class,
                               ParseException.class })
  public void testDecodeInvalidGeneralizedTime(String timestamp)
         throws Exception
  {
    StaticUtils.decodeGeneralizedTime(timestamp);
  }



  /**
   * Retrieves a {@code Date} object that corresponds to the specified time.
   *
   * @param  year    The year to use for the date.
   * @param  month   The month of the year to use for the date.  Note that this
   *                 is zero-based (so January is 0, February is 1, ..., and
   *                 December is 11).
   * @param  day     The day of the month to use for the date.  Note that this
   *                 is 1-based, so values should be between 1 and 31 (or less
   *                 in months with fewer days).
   * @param  hour    The hour of the day to use for the date.  It should be
   *                 between 0 and 23.
   * @param  min     The minute of the hour to use for the date.  It should be
   *                 between 0 and 59.
   * @param  sec     The second of the hour to use for the date.  It should be
   *                 between 0 and 61.
   * @param  msec    The millisecond value to use for the date.  It should be
   *                 between 0 and 999.
   * @param  offset  The number of hours to be offset from GMT.
   *
   * @return  A {@code Date} object that corresponds to the specified time.
   */
  private static Date getDate(int year, int month, int day, int hour, int min,
                              int sec, int msec, int offset)
  {
    return getDate(year, month, day, hour, min, sec, msec, offset, 0);
  }



  /**
   * Retrieves a {@code Date} object that corresponds to the specified time.
   *
   * @param  year          The year to use for the date.
   * @param  month         The month of the year to use for the date.  Note that
   *                       this is zero-based (so January is 0, February is 1,
   *                       ..., and December is 11).
   * @param  day           The day of the month to use for the date.  Note that
   *                       this is 1-based, so values should be between 1 and 31
   *                       (or less in months with fewer days).
   * @param  hour          The hour of the day to use for the date.  It should
   *                       be between 0 and 23.
   * @param  min           The minute of the hour to use for the date.  It
   *                       should be between 0 and 59.
   * @param  sec           The second of the hour to use for the date.  It
   *                       should be between 0 and 61.
   * @param  msec          The millisecond value to use for the date.  It should
   *                       be between 0 and 999.
   * @param  hourOffset    The number of hours to be offset from GMT.
   * @param  minuteOffset  The number of minutes to be offset from GMT.
   *
   * @return  A {@code Date} object that corresponds to the specified time.
   */
  private static Date getDate(int year, int month, int day, int hour, int min,
                              int sec, int msec, int hourOffset,
                              int minuteOffset)
  {
    final GregorianCalendar gc =
         new GregorianCalendar(year, month, day, hour, min, sec);
    gc.set(GregorianCalendar.MILLISECOND, msec);

    String tzID;
    if (hourOffset >= 10)
    {
      tzID = "GMT+" + hourOffset;
    }
    else if (hourOffset >= 0)
    {
      tzID = "GMT+0" + hourOffset;
    }
    else if (hourOffset >= -9)
    {
      tzID = "GMT-0" + Math.abs(hourOffset);
    }
    else
    {
      tzID = "GMT" + hourOffset;
    }

    if (minuteOffset >= 10)
    {
      tzID += ":" + minuteOffset;
    }
    else
    {
      tzID += ":0" + minuteOffset;
    }

    gc.setTimeZone(TimeZone.getTimeZone(tzID));

    return gc.getTime();
  }



  /**
   * Retrieves a set of valid generalized time timestamps and the corresponding
   * date values that are expected when the timestamps are decoded.
   *
   * @return  A set of valid generalized time timestamps and the corresponding
   *          date values that are expected when the timestamps are decoded.
   */
  @DataProvider(name = "validGeneralizedTimestamps")
  public Object[][] getValidGeneralizedTimestamps()
  {
    return new Object[][]
    {
      new Object[] { "2008010101Z",
                     getDate(2008, 0, 1, 1, 0, 0, 0, 0) },
      new Object[] { "200801010101Z",
                     getDate(2008, 0, 1, 1, 1, 0, 0, 0) },
      new Object[] { "20080101010101Z",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.Z",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.0Z",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.00Z",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.000Z",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.0000Z",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.12345Z",
                     getDate(2008, 0, 1, 1, 1, 1, 123, 0) },
      new Object[] { "2008010101-0000",
                     getDate(2008, 0, 1, 1, 0, 0, 0, 0) },
      new Object[] { "200801010101-0000",
                     getDate(2008, 0, 1, 1, 1, 0, 0, 0) },
      new Object[] { "20080101010101-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.0-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.00-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.000-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.0000-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.12345-0000",
                     getDate(2008, 0, 1, 1, 1, 1, 123, 0) },
      new Object[] { "2008010101+0000",
                     getDate(2008, 0, 1, 1, 0, 0, 0, 0) },
      new Object[] { "200801010101+0000",
                     getDate(2008, 0, 1, 1, 1, 0, 0, 0) },
      new Object[] { "20080101010101+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.0+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.00+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.000+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.0000+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 0) },
      new Object[] { "20080101010101.12345+0000",
                     getDate(2008, 0, 1, 1, 1, 1, 123, 0) },
      new Object[] { "2008010101-0500",
                     getDate(2008, 0, 1, 1, 0, 0, 0, -5) },
      new Object[] { "200801010101-0500",
                     getDate(2008, 0, 1, 1, 1, 0, 0, -5) },
      new Object[] { "20080101010101-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, -5) },
      new Object[] { "20080101010101.-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, -5) },
      new Object[] { "20080101010101.0-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, -5) },
      new Object[] { "20080101010101.00-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, -5) },
      new Object[] { "20080101010101.000-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, -5) },
      new Object[] { "20080101010101.0000-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, -5) },
      new Object[] { "20080101010101.12345-0500",
                     getDate(2008, 0, 1, 1, 1, 1, 123, -5) },
      new Object[] { "2008010101+0500",
                     getDate(2008, 0, 1, 1, 0, 0, 0, 5) },
      new Object[] { "200801010101+0500",
                     getDate(2008, 0, 1, 1, 1, 0, 0, 5) },
      new Object[] { "20080101010101+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 5) },
      new Object[] { "20080101010101.+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 5) },
      new Object[] { "20080101010101.0+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 5) },
      new Object[] { "20080101010101.00+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 5) },
      new Object[] { "20080101010101.000+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 5) },
      new Object[] { "20080101010101.0000+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 0, 5) },
      new Object[] { "20080101010101.12345+0500",
                     getDate(2008, 0, 1, 1, 1, 1, 123, 5) },
    };
  }



  /**
   * Retrieves a set of invalid generalized time timestamps.
   *
   * @return  A set of invalid generalized time timestamps.
   */
  @DataProvider(name = "invalidGeneralizedTimestamps")
  public Object[][] getInvalidGeneralizedTimestamps()
  {
    return new Object[][]
    {
      new Object[] { null },
      new Object[] { "" },
      new Object[] { "Z" },
      new Object[] { "-0500" },
      new Object[] { "+0000" },
      new Object[] { "garbage" },
      new Object[] { "garbageZ" },
      new Object[] { "garbage-0500" },
      new Object[] { "2008" },
      new Object[] { "2008Z" },
      new Object[] { "2008.000Z" },
      new Object[] { "2008-1200" },
      new Object[] { "2008.000+1200" },
      new Object[] { "200801Z" },
      new Object[] { "200801.000Z" },
      new Object[] { "200801-1200" },
      new Object[] { "200801.000+1200" },
      new Object[] { "20080101" },
      new Object[] { "20080101Z" },
      new Object[] { "20080101.000Z" },
      new Object[] { "20080101-0600" },
      new Object[] { "20080101.000+0600" },
      new Object[] { "20080101010101.000+060" },
      new Object[] { "20080101010101.000-060" },
    };
  }



  /**
   * Tests the {@code trimLeading} method on an empty string.
   */
  @Test()
  public void testTrimLeadingEmpty()
  {
    assertEquals(StaticUtils.trimLeading(""),
                 "");
  }



  /**
   * Tests the {@code trimLeading} method when there are no leading spaces.
   */
  @Test()
  public void testTrimLeadingNone()
  {
    assertEquals(StaticUtils.trimLeading("no leading spaces   "),
                 "no leading spaces   ");
  }



  /**
   * Tests the {@code trimLeading} method when there is exactly one leading
   * space.
   */
  @Test()
  public void testTrimLeadingOne()
  {
    assertEquals(StaticUtils.trimLeading(" one leading space "),
                 "one leading space ");
  }



  /**
   * Tests the {@code trimLeading} method when there are multiple leading
   * spaces.
   */
  @Test()
  public void testTrimLeadingMultiple()
  {
    assertEquals(StaticUtils.trimLeading("      multiple leading spaces"),
                 "multiple leading spaces");
  }



  /**
   * Tests the {@code trimLeading} method on a string containing only a space.
   */
  @Test()
  public void testTrimLeadingOnlyOneSpace()
  {
    assertEquals(StaticUtils.trimLeading(" "),
                 "");
  }



  /**
   * Tests the {@code trimLeading} method on a string containing only spaces.
   */
  @Test()
  public void testTrimLeadingOnlySpaces()
  {
    assertEquals(StaticUtils.trimLeading("     "),
                 "");
  }



  /**
   * Tests the {@code trimTrailing} method on an empty string.
   */
  @Test()
  public void testTrimTrailingEmpty()
  {
    assertEquals(StaticUtils.trimLeading(""),
                 "");
  }



  /**
   * Tests the {@code trimTrailing} method when there are no trailing spaces.
   */
  @Test()
  public void testTrimTrailingNone()
  {
    assertEquals(StaticUtils.trimTrailing("   no trailing spaces"),
                 "   no trailing spaces");
  }



  /**
   * Tests the {@code trimTrailing} method when there is exactly one trailing
   * space.
   */
  @Test()
  public void testTrimTrailingOne()
  {
    assertEquals(StaticUtils.trimTrailing(" one trailing space "),
                 " one trailing space");
  }



  /**
   * Tests the {@code trimTrailing} method when there are multiple trailing
   * spaces.
   */
  @Test()
  public void testTrimTrailingMultiple()
  {
    assertEquals(StaticUtils.trimTrailing("multiple trailing spaces      "),
                 "multiple trailing spaces");
  }



  /**
   * Tests the {@code trimTrailing} method on a string containing only a space.
   */
  @Test()
  public void testTrimTrailingOnlyOneSpace()
  {
    assertEquals(StaticUtils.trimTrailing(" "),
                 "");
  }



  /**
   * Tests the {@code trimTrailing} method on a string containing only spaces.
   */
  @Test()
  public void testTrimTrailingOnlySpaces()
  {
    assertEquals(StaticUtils.trimTrailing("     "),
                 "");
  }



  /**
   * Tests the {@code wrapLine} method with various parameters.
   *
   * @param  line      The line to process.
   * @param  maxWidth  The column at which long lines should be wrapped.
   * @param  expected  The expected result.
   */
  @Test(dataProvider = "wrapLineData")
  public void testWrapLine(String line, int maxWidth, List<String> expected)
  {
    List<String> resulting = StaticUtils.wrapLine(line, maxWidth);
    assertEquals(resulting, expected, String.valueOf(resulting));
  }



  /**
   * Retrieves data that may be used to test the {@code wrapLine} method.
   *
   * @return  Data that may be used to test the {@code wrapLine} method.
   */
  @DataProvider(name = "wrapLineData")
  public Object[][] getWrapLineData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "short",
        20,
        Arrays.asList("short")
      },

      new Object[]
      {
        "Now is the time for all good men to come to the aid of their country.",
        -1,
        Arrays.asList("Now is the time for all good men to come to the aid " +
                      "of their country.")
      },

      new Object[]
      {
        "reallyreallyreallyreallyreallyreallyreallyreallyreallylong",
        20,
        Arrays.asList("reallyreallyreallyre",
                      "allyreallyreallyreal",
                      "lyreallyreallylong")
      },

      new Object[]
      {
        "Now is the time for all good men to come to the aid of their country.",
        20,
        Arrays.asList("Now is the time for",
                      "all good men to come",
                      "to the aid of their",
                      "country.")
      },

      new Object[]
      {
        "this\nis\r\na\ntest",
        20,
        Arrays.asList("this",
                      "is",
                      "a",
                      "test")
      },

      new Object[]
      {
        "This is another, longer test.\nLines should be wrapped properly.",
        20,
        Arrays.asList("This is another,",
                      "longer test.",
                      "Lines should be",
                      "wrapped properly.")
      },
    };
  }



  /**
   * Provides test coverage for the {@code concatenateStrings} method with no
   * items in the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConcatenateStringsArrayEmpty()
         throws Exception
  {
    String s = StaticUtils.concatenateStrings(new String[0]);
    assertNotNull(s);
    assertEquals(s, "");
  }



  /**
   * Provides test coverage for the {@code concatenateStrings} method with an
   * array containing a single item.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConcatenateStringsArrayOneItem()
         throws Exception
  {
    String[] a = { "foo" };

    String s = StaticUtils.concatenateStrings(a);
    assertNotNull(s);
    assertEquals(s, "foo");
  }



  /**
   * Provides test coverage for the {@code concatenateStrings} method with an
   * array containing multiple items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConcatenateStringsArrayMultipleItems()
         throws Exception
  {
    String[] a = { "foo", "bar" };

    String s = StaticUtils.concatenateStrings(a);
    assertNotNull(s);
    assertEquals(s, "foo  bar");
  }



  /**
   * Provides test coverage for the {@code concatenateStrings} method with no
   * items in the list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConcatenateStringsListEmpty()
         throws Exception
  {
    LinkedList<String> l = new LinkedList<String>();
    String s = StaticUtils.concatenateStrings(l);
    assertNotNull(s);
    assertEquals(s, "");
  }



  /**
   * Provides test coverage for the {@code concatenateStrings} method with a
   * list containing a single item.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConcatenateStringsListOneItem()
         throws Exception
  {
    LinkedList<String> l = new LinkedList<String>();
    l.add("foo");

    String s = StaticUtils.concatenateStrings(l);
    assertNotNull(s);
    assertEquals(s, "foo");
  }



  /**
   * Provides test coverage for the {@code concatenateStrings} method with a
   * list containing multiple items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConcatenateStringsListMultipleItems()
         throws Exception
  {
    LinkedList<String> l = new LinkedList<String>();
    l.add("foo");
    l.add("bar");

    String s = StaticUtils.concatenateStrings(l);
    assertNotNull(s);
    assertEquals(s, "foo  bar");
  }



  /**
   * Provides test coverage for the {@code secondsToHumanReadableDuration}
   * method.
   *
   * @param  d  The duration in seconds.
   * @param  s  The expected string representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "secondsToHumanReadableDurationData")
  public void testSecondsToHumanReadableDuration(long d, String s)
         throws Exception
  {
    assertNotNull(StaticUtils.secondsToHumanReadableDuration(d));
    assertEquals(StaticUtils.secondsToHumanReadableDuration(d), s);
  }



  /**
   * Provides test coverage for the {@code millisToHumanReadableDuration}
   * method.
   *
   * @param  d  The duration in seconds.
   * @param  s  The expected string representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "millisToHumanReadableDurationData")
  public void testMillisToHumanReadableDuration(long d, String s)
         throws Exception
  {
    assertNotNull(StaticUtils.millisToHumanReadableDuration(d));
    assertEquals(StaticUtils.millisToHumanReadableDuration(d), s);
  }



  /**
   * Provides data for use in testing the {@code secondsToHumanReadableDuration}
   * method.
   *
   * @return  Data for use in testing the {@code secondsToHumanReadableDuration}
   *          method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="secondsToHumanReadableDurationData")
  public Object[][] getSecondsToHumanReadableDurationTestData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[] { 0L, "0 seconds" },
      new Object[] { 1L, "1 second" },
      new Object[] { 2L, "2 seconds" },
      new Object[] { 3L, "3 seconds" },
      new Object[] { 4L, "4 seconds" },
      new Object[] { 5L, "5 seconds" },
      new Object[] { 6L, "6 seconds" },
      new Object[] { 7L, "7 seconds" },
      new Object[] { 8L, "8 seconds" },
      new Object[] { 9L, "9 seconds" },
      new Object[] { 10L, "10 seconds" },
      new Object[] { 59L, "59 seconds" },
      new Object[] { 60L, "1 minute" },
      new Object[] { 61L, "1 minute, 1 second" },
      new Object[] { 62L, "1 minute, 2 seconds" },
      new Object[] { 119L, "1 minute, 59 seconds" },
      new Object[] { 120L, "2 minutes" },
      new Object[] { 121L, "2 minutes, 1 second" },
      new Object[] { 122L, "2 minutes, 2 seconds" },
      new Object[] { 3599L, "59 minutes, 59 seconds" },
      new Object[] { 3600L, "1 hour" },
      new Object[] { 3601L, "1 hour, 1 second" },
      new Object[] { 3602L, "1 hour, 2 seconds" },
      new Object[] { 3660L, "1 hour, 1 minute" },
      new Object[] { 3661L, "1 hour, 1 minute, 1 second" },
      new Object[] { 3662L, "1 hour, 1 minute, 2 seconds" },
      new Object[] { 3722L, "1 hour, 2 minutes, 2 seconds" },
      new Object[] { 86399L, "23 hours, 59 minutes, 59 seconds" },
      new Object[] { 86400L, "1 day" },
      new Object[] { 86401L, "1 day, 1 second" },
      new Object[] { 86402L, "1 day, 2 seconds" },
      new Object[] { 90061L, "1 day, 1 hour, 1 minute, 1 second" },
      new Object[] { 172799L, "1 day, 23 hours, 59 minutes, 59 seconds" },
      new Object[] { 172800L, "2 days" },
      new Object[] { 172801L, "2 days, 1 second" },
      new Object[] { 180122L, "2 days, 2 hours, 2 minutes, 2 seconds" },
      new Object[] { 259199L, "2 days, 23 hours, 59 minutes, 59 seconds" },
    };
  }



  /**
   * Provides data for use in testing the {@code millisToHumanReadableDuration}
   * method.
   *
   * @return  Data for use in testing the {@code millisToHumanReadableDuration}
   *          method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="millisToHumanReadableDurationData")
  public Object[][] getMillisToHumanReadableDurationTestData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[] { 0L, "0 seconds" },
      new Object[] { 1L, "0.001 seconds" },
      new Object[] { 12L, "0.012 seconds" },
      new Object[] { 123L, "0.123 seconds" },
      new Object[] { 1000L, "1 second" },
      new Object[] { 2000L, "2 seconds" },
      new Object[] { 3000L, "3 seconds" },
      new Object[] { 4000L, "4 seconds" },
      new Object[] { 5000L, "5 seconds" },
      new Object[] { 6000L, "6 seconds" },
      new Object[] { 7000L, "7 seconds" },
      new Object[] { 8000L, "8 seconds" },
      new Object[] { 9000L, "9 seconds" },
      new Object[] { 10123L, "10.123 seconds" },
      new Object[] { 59000L, "59 seconds" },
      new Object[] { 60000L, "1 minute" },
      new Object[] { 60001L, "1 minute, 0.001 seconds" },
      new Object[] { 60123L, "1 minute, 0.123 seconds" },
      new Object[] { 61000L, "1 minute, 1 second" },
      new Object[] { 62000L, "1 minute, 2 seconds" },
      new Object[] { 119000L, "1 minute, 59 seconds" },
      new Object[] { 120000L, "2 minutes" },
      new Object[] { 121000L, "2 minutes, 1 second" },
      new Object[] { 122000L, "2 minutes, 2 seconds" },
      new Object[] { 3599000L, "59 minutes, 59 seconds" },
      new Object[] { 3600000L, "1 hour" },
      new Object[] { 3600123L, "1 hour, 0.123 seconds" },
      new Object[] { 3601000L, "1 hour, 1 second" },
      new Object[] { 3602000L, "1 hour, 2 seconds" },
      new Object[] { 3660000L, "1 hour, 1 minute" },
      new Object[] { 3661000L, "1 hour, 1 minute, 1 second" },
      new Object[] { 3662000L, "1 hour, 1 minute, 2 seconds" },
      new Object[] { 3722000L, "1 hour, 2 minutes, 2 seconds" },
      new Object[] { 86399000L, "23 hours, 59 minutes, 59 seconds" },
      new Object[] { 86400000L, "1 day" },
      new Object[] { 86401000L, "1 day, 1 second" },
      new Object[] { 86402000L, "1 day, 2 seconds" },
      new Object[] { 90061000L, "1 day, 1 hour, 1 minute, 1 second" },
      new Object[] { 172799000L, "1 day, 23 hours, 59 minutes, 59 seconds" },
      new Object[] { 172800000L, "2 days" },
      new Object[] { 172801000L, "2 days, 1 second" },
      new Object[] { 180122000L, "2 days, 2 hours, 2 minutes, 2 seconds" },
      new Object[] { 259199000L, "2 days, 23 hours, 59 minutes, 59 seconds" },
      new Object[] { 259199999L,
                     "2 days, 23 hours, 59 minutes, 59.999 seconds" },
    };
  }



  /**
   * Provides test coverage for the {@code nanosToMillis} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNanosToMillis()
         throws Exception
  {
    assertEquals(StaticUtils.nanosToMillis(-1L), 0L);
    assertEquals(StaticUtils.nanosToMillis(0L), 0L);
    assertEquals(StaticUtils.nanosToMillis(123L), 0L);
    assertEquals(StaticUtils.nanosToMillis(1234567L), 1L);
    assertEquals(StaticUtils.nanosToMillis(12345678L), 12L);
    assertEquals(StaticUtils.nanosToMillis(123456789L), 123L);
  }



  /**
   * Provides test coverage for the {@code millisToNanos} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMillisToNanos()
         throws Exception
  {
    assertEquals(StaticUtils.millisToNanos(-1L), 0L);
    assertEquals(StaticUtils.millisToNanos(0L), 0L);
    assertEquals(StaticUtils.millisToNanos(1L), 1000000L);
    assertEquals(StaticUtils.millisToNanos(12L), 12000000L);
    assertEquals(StaticUtils.millisToNanos(123L), 123000000L);
  }



  /**
   * Provides test coverage for the {@code encodeUUID} and {@code decodeUUID}
   * methods with valid content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidUUIDs()
         throws Exception
  {
    final UUID randomUUID = UUID.randomUUID();

    final byte[] uuidBytes = StaticUtils.encodeUUID(randomUUID);
    final UUID decodedUUID = StaticUtils.decodeUUID(uuidBytes);

    assertEquals(decodedUUID, randomUUID);
  }



  /**
   * Provides test coverage for the {@code decodeUUID} method with an array that
   * is too short to be a valid UUID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeShortUUID()
         throws Exception
  {
    StaticUtils.decodeUUID(new byte[10]);
  }



  /**
   * Provides test coverage for the {@code decodeUUID} method with an array that
   * is too long to be a valid UUID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeLongUUID()
         throws Exception
  {
    StaticUtils.decodeUUID(new byte[20]);
  }



  /**
   * Provides test coverage for the {@code toArgumentList} method with a valid
   * argument string.
   *
   * @param  s  The string to be parsed.
   * @param  l  The expected argument list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validArgStrings")
  public void testParseValidArgumentString(final String s, final List<String> l)
         throws Exception
  {
    assertEquals(StaticUtils.toArgumentList(s), l);
  }



  /**
   * Retrieves a list of strings which can be parsed as valid argument lists.
   *
   * @return  An array that correlates argument list strings with the expected
   *          parsed argument lists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="validArgStrings")
  public Object[][] getValidArgumentStrings()
         throws Exception
  {
    final LinkedList<String> argStringList = new LinkedList<String>();
    final LinkedList<List<String>> argListList = new LinkedList<List<String>>();

    argStringList.add(null);
    argListList.add(new LinkedList<String>());

    argStringList.add("");
    argListList.add(new LinkedList<String>());

    argStringList.add(" ");
    argListList.add(new LinkedList<String>());

    argStringList.add("-a");
    argListList.add(Arrays.asList("-a"));

    argStringList.add(" -a ");
    argListList.add(Arrays.asList("-a"));

    argStringList.add("-a -b");
    argListList.add(Arrays.asList("-a", "-b"));

    argStringList.add("-a    -b");
    argListList.add(Arrays.asList("-a", "-b"));

    argStringList.add("-a -b \"-c -d -e\"");
    argListList.add(Arrays.asList("-a", "-b", "-c -d -e"));

    argStringList.add("-a -b \"-c -d -e\\\" -f\"");
    argListList.add(Arrays.asList("-a", "-b", "-c -d -e\" -f"));

    int pos = 0;
    final Object[][] returnArray = new Object[argStringList.size()][2];
    final Iterator<String> stringIterator = argStringList.iterator();
    final Iterator<List<String>> listIterator = argListList.iterator();
    while (stringIterator.hasNext())
    {
      returnArray[pos][0] = stringIterator.next();
      returnArray[pos][1] = listIterator.next();
      pos++;
    }

    return returnArray;
  }



  /**
   * Provides test coverage for the {@code toArgumentList} method with an
   * invalid argument string.
   *
   * @param  s  The string to be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidArgStrings",
        expectedExceptions = { ParseException.class})
  public void testParseInvalidArgumentString(final String s)
         throws Exception
  {
    StaticUtils.toArgumentList(s);
  }



  /**
   * Retrieves a list of strings which cannot be parsed as valid argument lists.
   *
   * @return  An array containing invalid argument list strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="invalidArgStrings")
  public Object[][] getInvalidArgumentStrings()
         throws Exception
  {
    final LinkedList<String> argStringList = new LinkedList<String>();

    argStringList.add("-a \"-b -c");

    argStringList.add("-a \"-b -c\"\"");

    argStringList.add("-a \\");

    final Object[][] returnArray = new Object[argStringList.size()][1];
    for (int i=0; i < argStringList.size(); i++)
    {
      returnArray[i][0] = argStringList.get(i);
    }

    return returnArray;
  }



  /**
   * Provides test coverage for the {@code capitalize} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCapitalize()
         throws Exception
  {
    assertNull(StaticUtils.capitalize(null));

    assertNotNull(StaticUtils.capitalize(""));
    assertEquals(StaticUtils.capitalize(""), "");

    assertNotNull(StaticUtils.capitalize("a"));
    assertEquals(StaticUtils.capitalize("a"), "A");

    assertNotNull(StaticUtils.capitalize("A"));
    assertEquals(StaticUtils.capitalize("A"), "A");

    assertNotNull(StaticUtils.capitalize("ab"));
    assertEquals(StaticUtils.capitalize("ab"), "Ab");

    assertNotNull(StaticUtils.capitalize("AB"));
    assertEquals(StaticUtils.capitalize("AB"), "AB");

    assertNotNull(StaticUtils.capitalize("aB"));
    assertEquals(StaticUtils.capitalize("aB"), "AB");

    assertNotNull(StaticUtils.capitalize("abcd efg"));
    assertEquals(StaticUtils.capitalize("abcd efg"), "Abcd efg");

    assertNotNull(StaticUtils.capitalize("abcd efg", true));
    assertEquals(StaticUtils.capitalize("abcd efg", true), "Abcd Efg");

    assertNotNull(StaticUtils.capitalize("this.is.a.test", false));
    assertEquals(StaticUtils.capitalize("this.is.a.test", false),
         "This.is.a.test");

    assertNotNull(StaticUtils.capitalize("this.is.a.test", true));
    assertEquals(StaticUtils.capitalize("this.is.a.test", true),
         "This.Is.A.Test");

    assertNotNull(StaticUtils.capitalize("ab.cd-ef_gh,ij;kl:mn op\"qr'st!uv",
         false));
    assertEquals(
         StaticUtils.capitalize("ab.cd-ef_gh,ij;kl:mn op\"qr'st!uv", false),
         "Ab.cd-ef_gh,ij;kl:mn op\"qr'st!uv");

    assertNotNull(StaticUtils.capitalize("ab.cd-ef_gh,ij;kl:mn op\"qr'st!uv",
         true));
    assertEquals(
         StaticUtils.capitalize("ab.cd-ef_gh,ij;kl:mn op\"qr'st!uv", true),
         "Ab.Cd-Ef_Gh,Ij;Kl:Mn Op\"Qr'St!Uv");
  }



  /**
   * Provides test coverage for the {@code toHexPlusASCII} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToHexPlusASCII()
         throws Exception
  {
    assertNotNull(StaticUtils.toHexPlusASCII(null, 10));
    assertEquals(StaticUtils.toHexPlusASCII(null, 10), "");

    assertNotNull(StaticUtils.toHexPlusASCII(new byte[0], 10));
    assertEquals(StaticUtils.toHexPlusASCII(new byte[0], 10), "");

    for (int i=1; i <= 50; i++)
    {
      final byte b = 0x61;
      final byte[] a = new byte[i];
      Arrays.fill(a, b);

      final String[] lines = parseLines(StaticUtils.toHexPlusASCII(a, 0));

      int expectedLines = a.length / 16;
      if ((a.length % 16) != 0)
      {
        expectedLines++;
      }
      assertEquals(lines.length, expectedLines,
           "Expected " + expectedLines + " for length " + i + " but got " +
                lines.length + " (" + Arrays.toString(lines) + ')');

      for (int j=0; j < lines.length; j++)
      {
        final String line = lines[j];
        if (j == (lines.length - 1))
        {
          switch (a.length % 16)
          {
            case 0:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 " +
                        "61   aaaaaaaaaaaaaaaa");
              break;
            case 1:
              assertEquals(line,
                   "61                                           " +
                        "     a");
              break;
            case 2:
              assertEquals(line,
                   "61 61                                        " +
                        "     aa");
              break;
            case 3:
              assertEquals(line,
                   "61 61 61                                     " +
                        "     aaa");
              break;
            case 4:
              assertEquals(line,
                   "61 61 61 61                                  " +
                        "     aaaa");
              break;
            case 5:
              assertEquals(line,
                   "61 61 61 61 61                               " +
                        "     aaaaa");
              break;
            case 6:
              assertEquals(line,
                   "61 61 61 61 61 61                            " +
                        "     aaaaaa");
              break;
            case 7:
              assertEquals(line,
                   "61 61 61 61 61 61 61                         " +
                        "     aaaaaaa");
              break;
            case 8:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61                      " +
                        "     aaaaaaaa");
              break;
            case 9:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61                   " +
                        "     aaaaaaaaa");
              break;
            case 10:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61                " +
                        "     aaaaaaaaaa");
              break;
            case 11:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61 61             " +
                        "     aaaaaaaaaaa");
              break;
            case 12:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61 61 61          " +
                        "     aaaaaaaaaaaa");
              break;
            case 13:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61 61 61 61       " +
                        "     aaaaaaaaaaaaa");
              break;
            case 14:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61 61 61 61 61    " +
                        "     aaaaaaaaaaaaaa");
              break;
            case 15:
              assertEquals(line,
                   "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 " +
                        "     aaaaaaaaaaaaaaa");
              break;
          }
        }
        else
        {
          assertEquals(line,
               "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 " +
                    "61   aaaaaaaaaaaaaaaa");
        }
      }
    }

    for (int i=1; i <= 50; i++)
    {
      final byte b = 0x00;
      final byte[] a = new byte[i];
      Arrays.fill(a, b);

      final String[] lines = parseLines(StaticUtils.toHexPlusASCII(a, 5));

      int expectedLines = a.length / 16;
      if ((a.length % 16) != 0)
      {
        expectedLines++;
      }
      assertEquals(lines.length, expectedLines,
           "Expected " + expectedLines + " for length " + i + " but got " +
                lines.length + " (" + Arrays.toString(lines) + ')');

      for (int j=0; j < lines.length; j++)
      {
        final String line = lines[j];
        if (j == (lines.length - 1))
        {
          switch (a.length % 16)
          {
            case 0:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
                        "00                   ");
              break;
            case 1:
              assertEquals(line,
                   "     00                                           " +
                        "      ");
              break;
            case 2:
              assertEquals(line,
                   "     00 00                                        " +
                        "       ");
              break;
            case 3:
              assertEquals(line,
                   "     00 00 00                                     " +
                        "        ");
              break;
            case 4:
              assertEquals(line,
                   "     00 00 00 00                                  " +
                        "         ");
              break;
            case 5:
              assertEquals(line,
                   "     00 00 00 00 00                               " +
                        "          ");
              break;
            case 6:
              assertEquals(line,
                   "     00 00 00 00 00 00                            " +
                        "           ");
              break;
            case 7:
              assertEquals(line,
                   "     00 00 00 00 00 00 00                         " +
                        "            ");
              break;
            case 8:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00                      " +
                        "             ");
              break;
            case 9:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00                   " +
                        "              ");
              break;
            case 10:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00                " +
                        "               ");
              break;
            case 11:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00 00             " +
                        "                ");
              break;
            case 12:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00 00 00          " +
                        "                 ");
              break;
            case 13:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00 00 00 00       " +
                        "                  ");
              break;
            case 14:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00 00 00 00 00    " +
                        "                   ");
              break;
            case 15:
              assertEquals(line,
                   "     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
                        "                    ");
              break;
          }
        }
        else
        {
          assertEquals(line,
               "     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
                    "00                   ");
        }
      }
    }
  }



  /**
   * Converts the provided string to an array of lines.
   *
   * @param  s  The string to convert to an array of lines.
   *
   * @return  An array of the lines contained in the provided string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static String[] parseLines(final String s)
          throws Exception
  {
    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(StaticUtils.getBytes(s));
    final BufferedReader reader =
         new BufferedReader(new InputStreamReader(inputStream));

    final LinkedList<String> lineList = new LinkedList<String>();
    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        break;
      }

      lineList.add(line);
    }

    reader.close();

    final String[] lineArray = new String[lineList.size()];
    return lineList.toArray(lineArray);
  }



  /**
   * Provides test coverage for the {@code bothNullOrEqual} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBothNullOrEqual()
         throws Exception
  {
    String s1 = null;
    String s2 = null;
    assertTrue(StaticUtils.bothNullOrEqual(s1, s2));

    s1 = "foo";
    s2 = null;
    assertFalse(StaticUtils.bothNullOrEqual(s1, s2));

    s1 = null;
    s2 = "foo";
    assertFalse(StaticUtils.bothNullOrEqual(s1, s2));

    s1 = "foo";
    s2 = "foo";
    assertTrue(StaticUtils.bothNullOrEqual(s1, s2));

    s1 = "foo";
    s2 = "bar";
    assertFalse(StaticUtils.bothNullOrEqual(s1, s2));

    final Integer i1 = 0;
    assertFalse(StaticUtils.bothNullOrEqual(s1, i1));
  }



  /**
   * Provides test coverage for the {@code bothNullOrEqualIgnoreCase} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBothNullOrEqualIgnoreCase()
         throws Exception
  {
    String s1 = null;
    String s2 = null;
    assertTrue(StaticUtils.bothNullOrEqualIgnoreCase(s1, s2));

    s1 = "foo";
    s2 = null;
    assertFalse(StaticUtils.bothNullOrEqualIgnoreCase(s1, s2));

    s1 = null;
    s2 = "foo";
    assertFalse(StaticUtils.bothNullOrEqualIgnoreCase(s1, s2));

    s1 = "foo";
    s2 = "foo";
    assertTrue(StaticUtils.bothNullOrEqualIgnoreCase(s1, s2));

    s1 = "foo";
    s2 = "FOO";
    assertTrue(StaticUtils.bothNullOrEqualIgnoreCase(s1, s2));

    s1 = "foo";
    s2 = "bar";
    assertFalse(StaticUtils.bothNullOrEqualIgnoreCase(s1, s2));
  }



  /**
   * Provides test coverage for the
   * {@code stringsEqualIgnoreCaseOrderIndependent} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringsEqualIgnoreCaseOrderIndependent()
         throws Exception
  {
    String[] s1 = null;
    String[] s2 = null;
    assertTrue(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[0];
    s2 = new String[0];
    assertTrue(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = null;
    s2 = new String[0];
    assertFalse(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[0];
    s2 = null;
    assertFalse(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[] { "foo" };
    s2 = new String[] { "foo" };
    assertTrue(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[] { "foo" };
    s2 = new String[] { "FOO" };
    assertTrue(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[] { "foo" };
    s2 = new String[] { "bar" };
    assertFalse(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[] { "foo", "bar" };
    s2 = new String[] { "foo" };
    assertFalse(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[] { "foo", "BAR" };
    s2 = new String[] { "FOO", "bar" };
    assertTrue(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));

    s1 = new String[] { "FOO", "bar" };
    s2 = new String[] { "BAR", "foo" };
    assertTrue(StaticUtils.stringsEqualIgnoreCaseOrderIndependent(s1, s2));
  }



  /**
   * Provides test coverage for the {@code arraysEqualOrderIndependent} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArraysEqualOrderIndependent()
         throws Exception
  {
    String[] s1 = null;
    String[] s2 = null;
    assertTrue(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[0];
    s2 = new String[0];
    assertTrue(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = null;
    s2 = new String[0];
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[0];
    s2 = null;
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "foo" };
    s2 = new String[] { "foo" };
    assertTrue(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "foo" };
    s2 = new String[] { "FOO" };
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "foo" };
    s2 = new String[] { "bar" };
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "foo", "bar" };
    s2 = new String[] { "foo" };
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "foo", "BAR" };
    s2 = new String[] { "FOO", "bar" };
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "foo", "BAR" };
    s2 = new String[] { "foo", "BAR" };
    assertTrue(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "FOO", "bar" };
    s2 = new String[] { "BAR", "foo" };
    assertFalse(StaticUtils.arraysEqualOrderIndependent(s1, s2));

    s1 = new String[] { "FOO", "bar" };
    s2 = new String[] { "bar", "FOO" };
    assertTrue(StaticUtils.arraysEqualOrderIndependent(s1, s2));
  }



  /**
   * Provides a set of test cases for the isASCIIString method that takes a byte
   * array argument.
   *
   * @param  b        The array to be examined.
   * @param  isASCII  Indicates whether the contents of the provided array
   *                  represent a valid ASCII string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIsASCII")
  public void testIsByteArrayASCIIString(final byte[] b, final boolean isASCII)
         throws Exception
  {
    assertEquals(StaticUtils.isASCIIString(b), isASCII);
  }



  /**
   * Provides a set of test cases for the isASCIIString method that takes a
   * string argument.
   *
   * @param  b        The array to be examined.
   * @param  isASCII  Indicates whether the contents of the provided array
   *                  represent a valid ASCII string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIsASCII")
  public void testIsStringASCIIString(final byte[] b, final boolean isASCII)
         throws Exception
  {
    assertEquals(StaticUtils.isASCIIString(StaticUtils.toUTF8String(b)),
         isASCII);
  }



  /**
   * Retrieves a set of data that may be used by the testIsASCIIString method.
   *
   * @return  A set of data that may be used by the testIsASCIIString method.
   */
  @DataProvider(name="testIsASCII")
  public Object[][] getTestIsASCIIStringData()
  {
    return new Object[][]
    {
      new Object[]
      {
        StaticUtils.getBytes(""),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("a"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aaa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aaaa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aaaaa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("0123456789"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz" +
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+,-.=/:? "),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz" +
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
             " `~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"),
        true
      },

      new Object[]
      {
        new byte[]
        {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
          0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
          0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
          0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
          0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
          0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
          0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
          0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
          0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
          0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        },
        true
      },

      new Object[]
      {
        new byte[]
        {
          (byte) 0x80
        },
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("jalape\u00F1o"),
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("regular-hyphen"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("en\u2013dash"),
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("em\u2014dash"),
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("\u2018curly single quotes\u2019"),
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("\u201ccurly double quotes\u201d"),
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("Smiley Face Emoji \uD83D\uDE00"),
        false
      },

      new Object[]
      {
        StaticUtils.getBytes(
             "United States Flag Emoji \uD83C\uDDFA\uD83C\uDDF8"),
        false
      }
    };
  }



  /**
   * Provides a set of test cases for the isPrintableString method that takes a
   * byte array argument.
   *
   * @param  b            The array to be examined.
   * @param  isPrintable  Indicates whether the contents of the provided array
   *                      represent a valid LDAP printable string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIsPrintable")
  public void testByteArrayIsPrintableString(final byte[] b,
                                             final boolean isPrintable)
         throws Exception
  {
    assertEquals(StaticUtils.isPrintableString(b), isPrintable);
  }



  /**
   * Provides a set of test cases for the isPrintableString method that takes a
   * string argument.
   *
   * @param  b            The array to be examined.
   * @param  isPrintable  Indicates whether the provided string represents a
   *                      valid LDAP printable string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIsPrintable")
  public void testStringIsPrintableString(final byte[] b,
                                          final boolean isPrintable)
         throws Exception
  {
    assertEquals(StaticUtils.isPrintableString(StaticUtils.toUTF8String(b)),
         isPrintable);
  }



  /**
   * Retrieves a set of data that may be used by the testIsPrintableString
   * method.
   *
   * @return  A set of data that may be used by the testIsPrintableString
   *          method.
   */
  @DataProvider(name="testIsPrintable")
  public Object[][] getTestIsPrintableStringData()
  {
    return new Object[][]
    {
      new Object[]
      {
        StaticUtils.getBytes(""),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("a"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aaa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aaaa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("aaaaa"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("0123456789"),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz" +
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+,-.=/:? "),
        true
      },

      new Object[]
      {
        StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz" +
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
             " `~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"),
        false
      },

      new Object[]
      {
        new byte[]
        {
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
          0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
          0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
          0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
          0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
          0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
          0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
          0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
          0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
          0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
          0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
          0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        },
        false
      },

      new Object[]
      {
        new byte[]
        {
          (byte) 0x80
        },
        false
      },

      new Object[]
      {
        StaticUtils.getBytes("jalape\u00F1o"),
        false
      }
    };
  }



  /**
   * Tests the behavior of the {@code createIOExceptionWithCause} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateIOExceptionWithCause()
         throws Exception
  {
    // NOTE:  The unit tests only run in Java SE 6 or higher, so we don't have
    // to worry about the possibility of a Java SE 5 VM.
    final IOException e1 = StaticUtils.createIOExceptionWithCause(
         "This is the message", new Exception("This is the cause"));
    assertNotNull(e1);

    assertNotNull(e1.getMessage());
    assertEquals(e1.getMessage(), "This is the message");

    assertNotNull(e1.getCause());
    assertEquals(e1.getCause().getMessage(), "This is the cause");


    final IOException e2 = StaticUtils.createIOExceptionWithCause(
         "This is the message for an exception without a cause", null);
    assertNotNull(e2);

    assertNotNull(e2.getMessage());
    assertEquals(e2.getMessage(),
         "This is the message for an exception without a cause");

    assertNull(e2.getCause());


    final IOException e3 = StaticUtils.createIOExceptionWithCause(null,
         new Exception("This is the cause for an exception without a message"));
    assertNotNull(e3);

    assertNotNull(e3.getMessage());
    assertTrue(e3.getMessage().contains(
         "This is the cause for an exception without a message"));

    assertNotNull(e3.getCause());
    assertEquals(e3.getCause().getMessage(),
         "This is the cause for an exception without a message");
  }



  /**
   * Provides test coverage for the methods used to define sensitive attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSensitiveAttributeMethods()
         throws Exception
  {
    final Set<String> defaultSensitiveAttributes =
         StaticUtils.getSensitiveToCodeAttributeBaseNames();

    assertNotNull(defaultSensitiveAttributes);
    assertFalse(defaultSensitiveAttributes.isEmpty());
    assertTrue(defaultSensitiveAttributes.contains("userpassword"));

    StaticUtils.setSensitiveToCodeAttributes();
    assertNotNull(StaticUtils.getSensitiveToCodeAttributeBaseNames());
    assertTrue(StaticUtils.getSensitiveToCodeAttributeBaseNames().isEmpty());

    StaticUtils.setSensitiveToCodeAttributes("socialSecurityNumber");
    assertNotNull(StaticUtils.getSensitiveToCodeAttributeBaseNames());
    assertFalse(StaticUtils.getSensitiveToCodeAttributeBaseNames().isEmpty());
    assertEquals(StaticUtils.getSensitiveToCodeAttributeBaseNames().size(), 1);
    assertTrue(StaticUtils.getSensitiveToCodeAttributeBaseNames().contains(
         "socialsecuritynumber"));

    StaticUtils.setSensitiveToCodeAttributes("userCertificate;binary");
    assertNotNull(StaticUtils.getSensitiveToCodeAttributeBaseNames());
    assertFalse(StaticUtils.getSensitiveToCodeAttributeBaseNames().isEmpty());
    assertEquals(StaticUtils.getSensitiveToCodeAttributeBaseNames().size(), 1);
    assertTrue(StaticUtils.getSensitiveToCodeAttributeBaseNames().contains(
         "usercertificate"));

    StaticUtils.setSensitiveToCodeAttributes(defaultSensitiveAttributes);
    assertEquals(StaticUtils.getSensitiveToCodeAttributeBaseNames(),
         defaultSensitiveAttributes);
  }



  /**
   * Tests the {@code stringToLines} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringToLines()
         throws Exception
  {
    assertNotNull(StaticUtils.stringToLines(null));
    assertTrue(StaticUtils.stringToLines(null).isEmpty());

    assertNotNull(StaticUtils.stringToLines(""));
    assertTrue(StaticUtils.stringToLines(null).isEmpty());

    assertNotNull(StaticUtils.stringToLines("\n"));
    assertEquals(StaticUtils.stringToLines("\n"),
         Collections.singletonList(""));

    assertNotNull(StaticUtils.stringToLines("\r\n"));
    assertEquals(StaticUtils.stringToLines("\r\n"),
         Collections.singletonList(""));

    assertNotNull(StaticUtils.stringToLines("\n\n"));
    assertEquals(StaticUtils.stringToLines("\n\n"),
         Arrays.asList("", ""));

    assertNotNull(StaticUtils.stringToLines("\n\r\n"));
    assertEquals(StaticUtils.stringToLines("\n\r\n"),
         Arrays.asList("", ""));

    assertNotNull(StaticUtils.stringToLines("test"));
    assertEquals(StaticUtils.stringToLines("test"),
         Collections.singletonList("test"));

    assertNotNull(StaticUtils.stringToLines("test\n"));
    assertEquals(StaticUtils.stringToLines("test\n"),
         Collections.singletonList("test"));

    assertNotNull(StaticUtils.stringToLines("test\r\n"));
    assertEquals(StaticUtils.stringToLines("test\r\n"),
         Collections.singletonList("test"));

    assertNotNull(StaticUtils.stringToLines(
         "\r\ntest1\ntest2\r\ntest3\n\ntest4\r\n\r\n"));
    assertEquals(StaticUtils.stringToLines(
         "\r\ntest1\ntest2\r\ntest3\n\ntest4\r\n\r\n"),
         Arrays.asList("", "test1", "test2", "test3", "", "test4", ""));
  }



  /**
   * Tests the {@code linesToString} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLinesToString()
         throws Exception
  {
    final String[] nullStringArray = null;
    assertNotNull(StaticUtils.linesToString(nullStringArray));
    assertEquals(StaticUtils.linesToString(nullStringArray), "");

    final List<String> nullStringList = null;
    assertNotNull(StaticUtils.linesToString(nullStringList));
    assertEquals(StaticUtils.linesToString(nullStringList), "");

    assertNotNull(StaticUtils.linesToString(StaticUtils.NO_STRINGS));
    assertEquals(StaticUtils.linesToString(StaticUtils.NO_STRINGS), "");

    assertNotNull(StaticUtils.linesToString());
    assertEquals(StaticUtils.linesToString(), "");

    assertEquals(StaticUtils.linesToString(""),
         StaticUtils.EOL);

    assertEquals(StaticUtils.linesToString("line1"),
         "line1" + StaticUtils.EOL);

    assertEquals(StaticUtils.linesToString("line1", "line2"),
         "line1" + StaticUtils.EOL +
              "line2" + StaticUtils.EOL);

    assertEquals(StaticUtils.linesToString("line1", "", "line2"),
         "line1" + StaticUtils.EOL +
              StaticUtils.EOL +
              "line2" + StaticUtils.EOL);
  }



  /**
   * Provides coverage for the {@code byteArray} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteArray()
         throws Exception
  {
    assertEquals(StaticUtils.byteArray((int[]) null), StaticUtils.NO_BYTES);

    assertEquals(StaticUtils.byteArray(), StaticUtils.NO_BYTES);

    assertEquals(StaticUtils.byteArray(new int[0]), StaticUtils.NO_BYTES);

    assertEquals(StaticUtils.byteArray(0), new byte[] { 0x00 });

    assertEquals(StaticUtils.byteArray(1), new byte[] { 0x01 });
    assertEquals(StaticUtils.byteArray(127), new byte[] { 0x7F });
    assertEquals(StaticUtils.byteArray(128), new byte[] { (byte) 0x80 });
    assertEquals(StaticUtils.byteArray(255), new byte[] { (byte) 0xFF });

    final int[] intArray = new int[256];
    final byte[] byteArray = new byte[256];
    for (int i=0; i < 256; i++)
    {
      intArray[i] = i;
      byteArray[i] = (byte) (i & 0xFF);
    }
    assertEquals(StaticUtils.byteArray(intArray), byteArray);
  }



  /**
   * Provides coverage for the {@code getExceptionMessage} method with a generic
   * exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExceptionMessageWithGenericException()
         throws Exception
  {
    final Exception e = new Exception("This is the exception",
         new Exception("This is the cause"));

    final String defaultMessage =
         StaticUtils.getExceptionMessage(e, false, false);
    assertFalse(defaultMessage.contains("trace="));
    assertFalse(defaultMessage.contains("caused by"));
    assertFalse(defaultMessage.contains("cause="));

    final String messageWithCause =
         StaticUtils.getExceptionMessage(e, true, false);
    assertFalse(messageWithCause.contains("trace="));
    assertTrue(messageWithCause.contains("caused by"));
    assertFalse(messageWithCause.contains("cause="));

    final String messageWithTrace =
         StaticUtils.getExceptionMessage(e, false, true);
    assertTrue(messageWithTrace.contains("trace="));
    assertFalse(messageWithTrace.contains("caused by"));
    assertTrue(messageWithTrace.contains("cause="));
  }



  /**
   * Tests the behavior of the {@code toArray} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToArray()
          throws Exception
  {
    final List<String> nullStringList = null;
    final String[] nullStringArray =
         StaticUtils.toArray(nullStringList, String.class);
    assertNull(nullStringArray);

    final Set<Object> emptyObjectSet = Collections.emptySet();
    final Object[] emptyObjectArray =
         StaticUtils.toArray(emptyObjectSet, Object.class);
    assertNotNull(emptyObjectArray);
    assertEquals(emptyObjectArray.length, 0);

    final List<Integer> nonEmptyIntegerList = Arrays.asList(1, 2, 3, 4, 5);
    final Integer[] nonEmptyIntegerArray =
         StaticUtils.toArray(nonEmptyIntegerList, Integer.class);
    assertNotNull(nonEmptyIntegerArray);
    assertEquals(nonEmptyIntegerArray.length, 5);
    assertEquals(nonEmptyIntegerArray, new Integer[] { 1, 2, 3, 4, 5 });
  }



  /**
   * Tests the behavior of the {@code isWithinUnitTest} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testisWithinUnitTest()
         throws Exception
  {
    assertTrue(StaticUtils.isWithinUnitTest());
  }



  /**
   * Tests the behavior of the {@code throwErrorOrRuntimeException} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowErrorOrRuntimeException()
         throws Exception
  {
    try
    {
      StaticUtils.throwErrorOrRuntimeException(null);
      fail("Expected an exception from a null throwable");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    try
    {
      StaticUtils.throwErrorOrRuntimeException(new UnknownError("Testing"));
      fail("Expected an UnknownError from an UnknownError throwable");
    }
    catch (final UnknownError e)
    {
      // This was expected.
    }

    try
    {
      StaticUtils.throwErrorOrRuntimeException(
           new NullPointerException("Testing"));
      fail("Expected a NullPointerException from a NullPointerException " +
           "throwable");
    }
    catch (final NullPointerException e)
    {
      // This was expected.
    }

    try
    {
      StaticUtils.throwErrorOrRuntimeException(new IOException("Testing"));
      fail("Expected a RuntimeException from an IOException throwable");
    }
    catch (final RuntimeException e)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the {@code rethrowIfErrorOrRuntimeException} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRethrowIfErrorOrRuntimeException()
         throws Exception
  {
    StaticUtils.rethrowIfErrorOrRuntimeException(null);

    try
    {
      StaticUtils.rethrowIfErrorOrRuntimeException(new UnknownError("Testing"));
      fail("Expected an UnknownError from an UnknownError throwable");
    }
    catch (final UnknownError e)
    {
      // This was expected.
    }

    try
    {
      StaticUtils.rethrowIfErrorOrRuntimeException(
           new NullPointerException("Testing"));
      fail("Expected a NullPointerException from a NullPointerException " +
           "throwable");
    }
    catch (final NullPointerException e)
    {
      // This was expected.
    }

    StaticUtils.rethrowIfErrorOrRuntimeException(new IOException("Testing"));
  }



  /**
   * Tests the behavior of the {@code rethrowIfError} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRethrowIfError()
         throws Exception
  {
    StaticUtils.rethrowIfError(null);

    try
    {
      StaticUtils.rethrowIfError(new UnknownError("Testing"));
      fail("Expected an UnknownError from an UnknownError throwable");
    }
    catch (final UnknownError e)
    {
      // This was expected.
    }

    StaticUtils.rethrowIfError(new NullPointerException("Testing"));

    StaticUtils.rethrowIfError(new IOException("Testing"));
  }



  /**
   * Provides test coverage for the {@code computeMapCapacity} method.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test()
  public void testComputeMapCapacity()
         throws Exception
  {
    assertEquals(StaticUtils.computeMapCapacity(0), 0);

    for (int i=1; i <= 1000; i++)
    {
      assertEquals(StaticUtils.computeMapCapacity(i),
           (((i * 4 ) / 3) + 1));
    }

    final int biggestIntegerArithmeticValue = Integer.MAX_VALUE / 4;
    assertEquals(StaticUtils.computeMapCapacity(biggestIntegerArithmeticValue),
         (((biggestIntegerArithmeticValue * 4) / 3) + 1));

    final int smallestFloatingPointArithmeticValue =
         biggestIntegerArithmeticValue + 1;
    assertEquals(
         StaticUtils.computeMapCapacity(smallestFloatingPointArithmeticValue),
         (((int) (smallestFloatingPointArithmeticValue / 0.75)) + 1));

    final int tooBigForAllPracticalPurposesValue = Integer.MAX_VALUE;
    assertEquals(
         StaticUtils.computeMapCapacity(tooBigForAllPracticalPurposesValue),
         tooBigForAllPracticalPurposesValue);
  }



  /**
   * Provides test coverage for the {@code setOf} method.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test()
  public void testSetOf()
         throws Exception
  {
    assertEquals(StaticUtils.setOf(), Collections.emptySet());

    assertEquals(StaticUtils.setOf("foo"), Collections.singleton("foo"));

    assertEquals(StaticUtils.setOf("foo", "bar"),
         Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
              "foo", "bar"))));
  }



  /**
   * Provides test coverage for the {@code hashSetOf} method.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test()
  public void testHashSetOf()
         throws Exception
  {
    assertEquals(StaticUtils.hashSetOf(), new HashSet<>(0));

    assertEquals(StaticUtils.hashSetOf("foo"),
         new HashSet<>(Collections.singleton("foo")));

    assertEquals(StaticUtils.hashSetOf("foo", "bar"),
         new HashSet<>(Arrays.asList("foo", "bar")));
  }



  /**
   * Provides test coverage for the {@code linkedHashSetOf} method.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test()
  public void testLinkedHashSetOf()
         throws Exception
  {
    assertEquals(StaticUtils.linkedHashSetOf(), new LinkedHashSet<>(0));

    assertEquals(StaticUtils.linkedHashSetOf("foo"),
         new LinkedHashSet<>(Collections.singleton("foo")));

    assertEquals(StaticUtils.linkedHashSetOf("foo", "bar"),
         new LinkedHashSet<>(Arrays.asList("foo", "bar")));
  }



  /**
   * Provides test coverage for the {@code treeSetOf} method.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test()
  public void testTreeSetOf()
         throws Exception
  {
    assertEquals(StaticUtils.treeSetOf(), new TreeSet<>());

    assertEquals(StaticUtils.treeSetOf("foo"),
         new TreeSet<>(Collections.singleton("foo")));

    assertEquals(StaticUtils.treeSetOf("foo", "bar"),
         new TreeSet<>(Arrays.asList("foo", "bar")));
  }



  /**
   * Tests the {@code mapOf} methods that take varying numbers of key-value
   * pairs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMapOfVariousSizes()
         throws Exception
  {
    final Map<String,Integer> m1 = StaticUtils.mapOf("k1", 1);
    assertNotNull(m1);
    assertEquals(m1.size(), 1);
    assertEquals(m1.get("k1"), Integer.valueOf(1));

    final Map<String,Integer> m2 = StaticUtils.mapOf("k1", 1, "k2", 2);
    assertNotNull(m2);
    assertEquals(m2.size(), 2);
    assertEquals(m2.get("k1"), Integer.valueOf(1));
    assertEquals(m2.get("k2"), Integer.valueOf(2));

    final Map<String,Integer> m3 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3);
    assertNotNull(m3);
    assertEquals(m3.size(), 3);
    assertEquals(m3.get("k1"), Integer.valueOf(1));
    assertEquals(m3.get("k2"), Integer.valueOf(2));
    assertEquals(m3.get("k3"), Integer.valueOf(3));

    final Map<String,Integer> m4 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4);
    assertNotNull(m4);
    assertEquals(m4.size(), 4);
    assertEquals(m4.get("k1"), Integer.valueOf(1));
    assertEquals(m4.get("k2"), Integer.valueOf(2));
    assertEquals(m4.get("k3"), Integer.valueOf(3));
    assertEquals(m4.get("k4"), Integer.valueOf(4));

    final Map<String,Integer> m5 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4, "k5", 5);
    assertNotNull(m5);
    assertEquals(m5.size(), 5);
    assertEquals(m5.get("k1"), Integer.valueOf(1));
    assertEquals(m5.get("k2"), Integer.valueOf(2));
    assertEquals(m5.get("k3"), Integer.valueOf(3));
    assertEquals(m5.get("k4"), Integer.valueOf(4));
    assertEquals(m5.get("k5"), Integer.valueOf(5));

    final Map<String,Integer> m6 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4, "k5", 5, "k6", 6);
    assertNotNull(m6);
    assertEquals(m6.size(), 6);
    assertEquals(m6.get("k1"), Integer.valueOf(1));
    assertEquals(m6.get("k2"), Integer.valueOf(2));
    assertEquals(m6.get("k3"), Integer.valueOf(3));
    assertEquals(m6.get("k4"), Integer.valueOf(4));
    assertEquals(m6.get("k5"), Integer.valueOf(5));
    assertEquals(m6.get("k6"), Integer.valueOf(6));

    final Map<String,Integer> m7 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4, "k5", 5, "k6", 6, "k7", 7);
    assertNotNull(m7);
    assertEquals(m7.size(), 7);
    assertEquals(m7.get("k1"), Integer.valueOf(1));
    assertEquals(m7.get("k2"), Integer.valueOf(2));
    assertEquals(m7.get("k3"), Integer.valueOf(3));
    assertEquals(m7.get("k4"), Integer.valueOf(4));
    assertEquals(m7.get("k5"), Integer.valueOf(5));
    assertEquals(m7.get("k6"), Integer.valueOf(6));
    assertEquals(m7.get("k7"), Integer.valueOf(7));

    final Map<String,Integer> m8 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4, "k5", 5, "k6", 6, "k7", 7, "k8", 8);
    assertNotNull(m8);
    assertEquals(m8.size(), 8);
    assertEquals(m8.get("k1"), Integer.valueOf(1));
    assertEquals(m8.get("k2"), Integer.valueOf(2));
    assertEquals(m8.get("k3"), Integer.valueOf(3));
    assertEquals(m8.get("k4"), Integer.valueOf(4));
    assertEquals(m8.get("k5"), Integer.valueOf(5));
    assertEquals(m8.get("k6"), Integer.valueOf(6));
    assertEquals(m8.get("k7"), Integer.valueOf(7));
    assertEquals(m8.get("k8"), Integer.valueOf(8));

    final Map<String,Integer> m9 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4, "k5", 5, "k6", 6, "k7", 7, "k8", 8, "k9", 9);
    assertNotNull(m9);
    assertEquals(m9.size(), 9);
    assertEquals(m9.get("k1"), Integer.valueOf(1));
    assertEquals(m9.get("k2"), Integer.valueOf(2));
    assertEquals(m9.get("k3"), Integer.valueOf(3));
    assertEquals(m9.get("k4"), Integer.valueOf(4));
    assertEquals(m9.get("k5"), Integer.valueOf(5));
    assertEquals(m9.get("k6"), Integer.valueOf(6));
    assertEquals(m9.get("k7"), Integer.valueOf(7));
    assertEquals(m9.get("k8"), Integer.valueOf(8));
    assertEquals(m9.get("k9"), Integer.valueOf(9));

    final Map<String,Integer> m10 = StaticUtils.mapOf("k1", 1, "k2", 2, "k3", 3,
         "k4", 4, "k5", 5, "k6", 6, "k7", 7, "k8", 8, "k9", 9, "k10", 10);
    assertNotNull(m10);
    assertEquals(m10.size(), 10);
    assertEquals(m10.get("k1"), Integer.valueOf(1));
    assertEquals(m10.get("k2"), Integer.valueOf(2));
    assertEquals(m10.get("k3"), Integer.valueOf(3));
    assertEquals(m10.get("k4"), Integer.valueOf(4));
    assertEquals(m10.get("k5"), Integer.valueOf(5));
    assertEquals(m10.get("k6"), Integer.valueOf(6));
    assertEquals(m10.get("k7"), Integer.valueOf(7));
    assertEquals(m10.get("k8"), Integer.valueOf(8));
    assertEquals(m10.get("k9"), Integer.valueOf(9));
    assertEquals(m10.get("k10"), Integer.valueOf(10));
  }



  /**
   * Tests the {@code mapOf} method that takes keys and values of the same type
   * provided as varargs with keys in even-numbered indexes and values in
   * odd-numbered indexes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMapOfArray()
         throws Exception
  {
    final Map<String,String> m1 = StaticUtils.mapOf();
    assertNotNull(m1);
    assertTrue(m1.isEmpty());

    final Map<String,String> m2 = StaticUtils.mapOf((String[]) null);
    assertNotNull(m2);
    assertTrue(m2.isEmpty());

    try
    {
      StaticUtils.mapOf("foo");
    }
    catch (final LDAPSDKUsageException e)
    {
      // This was expected.
    }

    final Map<String,String> m3 = StaticUtils.mapOf("key1", "value1",
         "key2", "value2", "key3", "value3", "key4", "value4", "key5", "value5",
         "key6", "value6", "key7", "value7", "key8", "value8", "key9", "value9",
         "key10", "value10", "key11", "value11", "key12", "value12");
    assertNotNull(m3);
    assertEquals(m3.size(), 12);
    assertEquals(m3.get("key1"), "value1");
    assertEquals(m3.get("key2"), "value2");
    assertEquals(m3.get("key3"), "value3");
    assertEquals(m3.get("key4"), "value4");
    assertEquals(m3.get("key5"), "value5");
    assertEquals(m3.get("key6"), "value6");
    assertEquals(m3.get("key7"), "value7");
    assertEquals(m3.get("key8"), "value8");
    assertEquals(m3.get("key9"), "value9");
    assertEquals(m3.get("key10"), "value10");
    assertEquals(m3.get("key11"), "value11");
    assertEquals(m3.get("key12"), "value12");
  }



  /**
   * Tests the {@code mapOfObjectPairs} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMapOfObjectPairs()
         throws Exception
  {
    final Map<String,Integer> m1 = StaticUtils.mapOfObjectPairs();
    assertNotNull(m1);
    assertTrue(m1.isEmpty());

    final ObjectPair<String,Integer>[] nullItems = null;
    final Map<String,Integer> m2 = StaticUtils.mapOfObjectPairs(nullItems);
    assertNotNull(m2);
    assertTrue(m2.isEmpty());

    final Map<String,Integer> m3 = StaticUtils.mapOfObjectPairs(
         new ObjectPair<>("k1", 1));
    assertNotNull(m3);
    assertEquals(m3.size(), 1);
    assertEquals(m3.get("k1"), Integer.valueOf(1));

    final Map<String,Integer> m4 = StaticUtils.mapOfObjectPairs(
         new ObjectPair<>("k1", 1),
         new ObjectPair<>("k2", 2),
         new ObjectPair<>("k3", 3),
         new ObjectPair<>("k4", 4),
         new ObjectPair<>("k5", 5));
    assertNotNull(m4);
    assertEquals(m4.size(), 5);
    assertEquals(m4.get("k1"), Integer.valueOf(1));
    assertEquals(m4.get("k2"), Integer.valueOf(2));
    assertEquals(m4.get("k3"), Integer.valueOf(3));
    assertEquals(m4.get("k4"), Integer.valueOf(4));
    assertEquals(m4.get("k5"), Integer.valueOf(5));
  }



  /**
   * Provides test coverage for the {@code getSystemProperties} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSystemProperties()
         throws Exception
  {
    assertNotNull(StaticUtils.getSystemProperties());
    assertEquals(StaticUtils.getSystemProperties(), System.getProperties());

    assertNotNull(StaticUtils.getSystemProperties("foo", "bar"));
    assertEquals(StaticUtils.getSystemProperties("foo", "bar"),
         System.getProperties());

    System.setProperty(
         StaticUtils.class.getName() + ".forceGetSystemPropertiesToThrow",
         "true");
    assertNotNull(StaticUtils.getSystemProperties());
    assertEquals(StaticUtils.getSystemProperties(), new Properties());

    final String javaHome = System.getProperty("java.home");
    assertNotNull(javaHome);

    final Properties gotProperties =
         StaticUtils.getSystemProperties("java.home");
    assertNotNull(gotProperties);

    final Properties expectedProperties = new Properties();
    expectedProperties.setProperty("java.home", javaHome);
    assertEquals(gotProperties, expectedProperties);

    System.clearProperty(
         StaticUtils.class.getName() + ".forceGetSystemPropertiesToThrow");

    assertNotNull(StaticUtils.getSystemProperties());
    assertEquals(StaticUtils.getSystemProperties(), System.getProperties());

    assertNotNull(StaticUtils.getSystemProperties("foo", "bar"));
    assertEquals(StaticUtils.getSystemProperties("foo", "bar"),
         System.getProperties());
  }



  /**
   * Tests the behavior of methods for interacting with environment variables.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEnvironmentVariables()
         throws Exception
  {
    final Map<String,String> definedVariables =
         StaticUtils.getEnvironmentVariables();
    assertNotNull(definedVariables);

    for (final Map.Entry<String,String> e : definedVariables.entrySet())
    {
      final String name = e.getKey();
      final String expectedValue = e.getValue();
      final String actualValue = StaticUtils.getEnvironmentVariable(name);
      assertEquals(actualValue, expectedValue);

      assertEquals(StaticUtils.getEnvironmentVariable(name, "default value"),
           expectedValue);
    }

    while (true)
    {
      final String randomKey = UUID.randomUUID().toString();
      if (! definedVariables.containsKey(randomKey))
      {
        assertNull(StaticUtils.getEnvironmentVariable(randomKey));
        assertEquals(
             StaticUtils.getEnvironmentVariable(randomKey, "default value"),
             "default value");
        break;
      }
    }
  }



  /**
   * Tests the behavior when trying to encode and decode the current time
   * in the ISO 8601 format described in RFC 3339.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCurrentTimeAsRFC3339Timestamps()
         throws Exception
  {
    final long currentTime = System.currentTimeMillis();
    final String timestamp = StaticUtils.encodeRFC3339Time(currentTime);
    final Date decodedDate = StaticUtils.decodeRFC3339Time(timestamp);
    assertEquals(decodedDate.getTime(), currentTime);
  }



  /**
   * Tests the behavior when trying to encode and decode the current time (as a
   * Date) in the ISO 8601 format described in RFC 3339.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCurrentDateAsRFC3339Timestamps()
         throws Exception
  {
    final Date currentDate = new Date();
    final String timestamp = StaticUtils.encodeRFC3339Time(currentDate);
    final Date decodedDate = StaticUtils.decodeRFC3339Time(timestamp);
    assertEquals(decodedDate, currentDate);
  }



  /**
   * Tests the behavior when trying to decode the example timestamps provided in
   * RFC 3339.
   *
   * @param  timestamp     The timestamp to decode.
   * @param  expectedDate  The date expected from decoding the timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="rfc3339Examples")
  public void testDecodeRFC3339Examples(final String timestamp,
                                        final Date expectedDate)
         throws Exception
  {
    final Date decodedDate = StaticUtils.decodeRFC3339Time(timestamp);
    assertEquals(decodedDate, expectedDate);
  }



  /**
   * Retrieves test data based on the examples provided in RFC 3339 section 5.8.
   *
   * @return  Test data based on the examples provided in RFC 3339 section 5.8.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="rfc3339Examples")
  public Object[][] getRFC3339Examples()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "1985-04-12T23:20:50.52Z",
        getDate(1985, 3, 12, 23, 20, 50, 520, 0)
      },

      new Object[]
      {
        "1996-12-19T16:39:57-08:00",
        getDate(1996, 11, 19, 16, 39, 57, 0, -8)
      },

      new Object[]
      {
        "1990-12-31T23:59:60Z",
        getDate(1990, 11, 31, 23, 59, 60, 0, 0)
      },

      new Object[]
      {
        "1990-12-31T15:59:60-08:00",
        getDate(1990, 11, 31, 15, 59, 60, 0, -8)
      },

      new Object[]
      {
        "1937-01-01T12:00:27.87+00:20",
        getDate(1937, 0, 1, 12, 0, 27, 870, 0, 20)
      }
    };
  }



  /**
   * Tests the behavior when trying to decode malformed RFC 3339 timestamps.
   *
   * @param  timestamp      The timestamp to decode.
   * @param  invalidReason  The reason that the provided timestamp is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="malformedRFC3339Timestamps",
       expectedExceptions = { ParseException.class })
  public void testDecodeMalformedRFC3339Timestamps(final String timestamp,
                                                   final String invalidReason)
         throws Exception
  {
    StaticUtils.decodeRFC3339Time(timestamp);
  }



  /**
   * Retrieves data used to test decoding with malformed RFC 3339 timestamps.
   *
   * @return  Data used to test decoding with malformed RFC 3339 timestamps.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="malformedRFC3339Timestamps")
  public Object[][] getMalformedRFC3339Timestamps()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "",
        "An empty string"
      },

      new Object[]
      {
        "2020-01-01T00:00:00",
        "Missing time zone after seconds"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.000",
        "Missing time zone after sub-seconds"
      },

      new Object[]
      {
        "2o20-01-01T00:00:00.000Z",
        "Non-numeric character in the year"
      },

      new Object[]
      {
        "2020_01-01T00:00:00.000Z",
        "Incorrect separator between the year and month"
      },

      new Object[]
      {
        "2020-o1-01T00:00:00.000Z",
        "Non-numeric character in the month"
      },

      new Object[]
      {
        "2020-00-01T00:00:00.000Z",
        "Invalid month -- zero"
      },

      new Object[]
      {
        "2020-13-01T00:00:00.000Z",
        "Invalid month -- too large"
      },

      new Object[]
      {
        "2020-01_01T00:00:00.000Z",
        "Incorrect separator between the month and the day"
      },

      new Object[]
      {
        "2020-01-o1T00:00:00.000Z",
        "Non-numeric character in the day"
      },

      new Object[]
      {
        "2020-01-00T00:00:00.000Z",
        "Invalid day -- zero"
      },

      new Object[]
      {
        "2020-01-32T00:00:00.000Z",
        "Invalid day -- too large for January"
      },

      new Object[]
      {
        "2020-02-30T00:00:00.000Z",
        "Invalid day -- too large for February"
      },

      new Object[]
      {
        "2020-03-32T00:00:00.000Z",
        "Invalid day -- too large for March"
      },

      new Object[]
      {
        "2020-04-31T00:00:00.000Z",
        "Invalid day -- too large for April"
      },

      new Object[]
      {
        "2020-05-32T00:00:00.000Z",
        "Invalid day -- too large for May"
      },

      new Object[]
      {
        "2020-06-31T00:00:00.000Z",
        "Invalid day -- too large for June"
      },

      new Object[]
      {
        "2020-07-32T00:00:00.000Z",
        "Invalid day -- too large for July"
      },

      new Object[]
      {
        "2020-08-32T00:00:00.000Z",
        "Invalid day -- too large for August"
      },

      new Object[]
      {
        "2020-09-31T00:00:00.000Z",
        "Invalid day -- too large for September"
      },

      new Object[]
      {
        "2020-10-32T00:00:00.000Z",
        "Invalid day -- too large for October"
      },

      new Object[]
      {
        "2020-11-31T00:00:00.000Z",
        "Invalid day -- too large for November"
      },

      new Object[]
      {
        "2020-12-32T00:00:00.000Z",
        "Invalid day -- too large for December"
      },

      new Object[]
      {
        "2020-01-01t00:00:00.000Z",
        "Invalid separator between day and hour"
      },

      new Object[]
      {
        "2020-01-01T0o:00:00.000Z",
        "Non-numeric character in hour"
      },

      new Object[]
      {
        "2020-01-01T24:00:00.000Z",
        "Invalid hour"
      },

      new Object[]
      {
        "2020-01-01T00;00:00.000Z",
        "Invalid separator between hour and minute"
      },

      new Object[]
      {
        "2020-01-01T00:0o:00.000Z",
        "Non-numeric character in minute"
      },

      new Object[]
      {
        "2020-01-01T00:60:00.000Z",
        "Invalid minute"
      },

      new Object[]
      {
        "2020-01-01T00:00;00.000Z",
        "Invalid separator between minute and second"
      },

      new Object[]
      {
        "2020-01-01T00:00:o0.000Z",
        "Non-numeric character in second"
      },

      new Object[]
      {
        "2020-01-01T00:00:61.000Z",
        "Invalid second"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.Z",
        "No sub-second digits"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.0000Z",
        "Too many sub-second digits"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.oooZ",
        "Non-numeric character in sub-second"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.0+00",
        "Time zone offset too short"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.010_00:00",
        "Invalid time zone offset first character with sub-seconds"
      },

      new Object[]
      {
        "2020-01-01T00:00:00_00:00",
        "Invalid time zone offset first character without sub-seconds"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.000+0o:00",
        "Non-numeric character in time zone hour offset"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.000+24:00",
        "Invalid time zone hour offset"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.000+00;00",
        "Invalid separator between time zone offset hour and minute"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.000+00:0o",
        "Non-numeric character in time zone minute offset"
      },

      new Object[]
      {
        "2020-01-01T00:00:00.000+00:60",
        "Invalid time zone minute offset"
      },
    };
  }



  /**
   * Provides coverage for the methods used to read and write the contents of a
   * file using bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAndWriteFileBytes()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    StaticUtils.writeFile(f.getAbsolutePath(), StaticUtils.NO_BYTES);
    assertEquals(StaticUtils.readFileBytes(f.getAbsolutePath()),
         StaticUtils.NO_BYTES);

    final byte[] randomBytes = new byte[1024];
    new Random().nextBytes(randomBytes);

    StaticUtils.writeFile(f.getAbsolutePath(), randomBytes);
    assertEquals(StaticUtils.readFileBytes(f.getAbsolutePath()), randomBytes);
  }



  /**
   * Provides coverage for the methods used to read and write the contents of a
   * file as a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAndWriteString()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    StaticUtils.writeFile(f.getAbsolutePath(), "");
    assertEquals(StaticUtils.readFileAsString(f.getAbsolutePath(), true),
         StaticUtils.EOL);
    assertEquals(StaticUtils.readFileAsString(f.getAbsolutePath(), false), "");

    StaticUtils.writeFile(f.getAbsolutePath(), "This is a test");
    assertEquals(StaticUtils.readFileAsString(f.getAbsolutePath(), true),
         "This is a test" + StaticUtils.EOL);
    assertEquals(StaticUtils.readFileAsString(f.getAbsolutePath(), false),
         "This is a test");
  }



  /**
   * Provides coverage for the methods used to read and write the contents of a
   * file as a set of lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAndWriteLines()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    StaticUtils.writeFile(f.getAbsolutePath(), (String[]) null);
    assertEquals(StaticUtils.readFileLines(f.getAbsolutePath()),
         Collections.emptyList());

    StaticUtils.writeFile(f.getAbsolutePath(), (List<String>) null);
    assertEquals(StaticUtils.readFileLines(f.getAbsolutePath()),
         Collections.emptyList());

    StaticUtils.writeFile(f.getAbsolutePath(), "Line 1");
    assertEquals(StaticUtils.readFileLines(f.getAbsolutePath()),
         Collections.singletonList("Line 1"));

    StaticUtils.writeFile(f.getAbsolutePath(), "Line 1", "Line 2", "Line 3");
    assertEquals(StaticUtils.readFileLines(f.getAbsolutePath()),
         Arrays.asList("Line 1", "Line 2", "Line 3"));
  }



  /**
   * Tests the behavior of the {@code getAllLocalAddresses} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAllLocalAddresses()
         throws Exception
  {
    // Test when loopback addresses are implicitly included.
    final Set<InetAddress> addressesWithLoopbackImplicitlyIncluded =
         StaticUtils.getAllLocalAddresses(null);
    assertNotNull(addressesWithLoopbackImplicitlyIncluded);
    assertFalse(addressesWithLoopbackImplicitlyIncluded.isEmpty());

    boolean loopbackAddressFound = false;
    for (final InetAddress address : addressesWithLoopbackImplicitlyIncluded)
    {
      if (address.isLoopbackAddress())
      {
        loopbackAddressFound = true;
        break;
      }
    }

    assertTrue(loopbackAddressFound);


    // Test when loopback addresses are explicitly included.
    final Set<InetAddress> addressesWithLoopbackExplicitlyIncluded =
         StaticUtils.getAllLocalAddresses(null, true);
    assertNotNull(addressesWithLoopbackExplicitlyIncluded);
    assertFalse(addressesWithLoopbackExplicitlyIncluded.isEmpty());

    assertEquals(addressesWithLoopbackExplicitlyIncluded,
         addressesWithLoopbackImplicitlyIncluded);


    // Test when loopback addresses are explicitly excluded.
    final Set<InetAddress> addressesWithLoopbackExplicitlyExcluded =
         StaticUtils.getAllLocalAddresses(null, false);
    assertNotNull(addressesWithLoopbackExplicitlyExcluded);
    assertFalse(addressesWithLoopbackExplicitlyExcluded.isEmpty());
    assertTrue(addressesWithLoopbackExplicitlyExcluded.size() <
         addressesWithLoopbackImplicitlyIncluded.size());

    for (final InetAddress address : addressesWithLoopbackExplicitlyExcluded)
    {
      assertFalse(address.isLoopbackAddress());
      assertTrue(addressesWithLoopbackImplicitlyIncluded.contains(address));
    }

    for (final InetAddress address : addressesWithLoopbackImplicitlyIncluded)
    {
      if (! address.isLoopbackAddress())
      {
        assertTrue(addressesWithLoopbackExplicitlyExcluded.contains(address));
      }
    }
  }



  /**
   * Tests the behavior for the {@code isIANAReservedIPAddress} method with the
   * provided information.
   *
   * @param  address                 The address to test.  It must not be
   *                                 {@code null}.
   * @param  isPrivateUseAddress     Indicates whether the provided address is
   *                                 an address from a range reserved for
   *                                 private-use networks.
   * @param  isOtherReservedAddress  Indicates whether the provided address is
   *                                 a reserved address from a non-private-use
   *                                 range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="isIANAReservedIPAddressTestData")
  public void testIsIANAReservedIPAddress(final InetAddress address,
                                          final boolean isPrivateUseAddress,
                                          final boolean isOtherReservedAddress)
         throws Exception
  {
    if (StaticUtils.isIANAReservedIPAddress(address, true))
    {
      if (StaticUtils.isIANAReservedIPAddress(address, false))
      {
        assertFalse(isPrivateUseAddress);
        assertTrue(isOtherReservedAddress);
      }
      else
      {
        assertTrue(isPrivateUseAddress);
        assertFalse(isOtherReservedAddress);
      }
    }
    else
    {
      assertFalse(isPrivateUseAddress);
      assertFalse(isOtherReservedAddress);
    }
  }



  /**
   * Retrieves a set of test data for use in testing the
   * {@code isIANAReservedIPAddress} method.
   *
   * @return  A set of data for use in testing the
   *          {@code isIANAReservedIPAddress} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="isIANAReservedIPAddressTestData")
  public Object[][] getIsIANAReservedIPAddressTestData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        InetAddress.getByName("0.1.2.3"),
        false,  // Not a private-use address
        true    // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("1.2.3.4"),
        false,  // Not a private-use address
        false   // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("10.11.12.13"),
        true,  // It is a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("100.1.2.3"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("100.64.65.66"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("100.127.128.129"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("127.0.0.1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("127.128.129.130"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("169.253.2.3"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("169.254.1.2"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("169.255.2.3"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("172.15.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("172.16.1.2"),
        true,  // It is a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("172.31.1.2"),
        true,  // It is a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("172.32.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.0.0.1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.0.1.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.0.2.1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.0.3.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.88.98.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.88.99.1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.88.100.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.167.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.168.1.2"),
        true,  // It is a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("192.169.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.17.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.18.1.2"),
        false, // Not a private-use address
        true  //  It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.19.1.2"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.20.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.51.99.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.51.100.1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("198.51.101.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("203.0.112.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("203.0.113.1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("203.0.114.1"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("223.255.1.2"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("224.1.2.3"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("255.1.2.3"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("::1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("::1"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("1F01:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("2001:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("3F01:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        false, // Not a private-use address
        false  // Not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("4001:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("FB01:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        false, // Not a private-use address
        true   // It is a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("FC01:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        true,  // It is a private-use address
        false  // It is not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("FD01:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        true,  // It is a private-use address
        false  // It is not a reserved address
      },

      new Object[]
      {
        InetAddress.getByName("FE01:0203:0405:0607:0809:0A0B:0C0D:0E0F"),
        false, // Not a private-use address
        true   // It is a reserved address
      }
    };
  }
}
