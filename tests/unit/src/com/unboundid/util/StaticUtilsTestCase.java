/*
 * Copyright 2007-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2017 Ping Identity Corporation
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
import java.io.InputStreamReader;
import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;
import java.util.Set;
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
    String s = "JOS\u00c9 JALAPE\u00d1O";
    String l = "jos\u00e9 jalape\u00f1o";

    assertEquals(StaticUtils.toLowerCase(s), l);
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
    GregorianCalendar gc =
         new GregorianCalendar(year, month, day, hour, min, sec);
    gc.set(GregorianCalendar.MILLISECOND, msec);

    String tzID;
    if (offset >= 10)
    {
      tzID = "GMT+" + offset + "00";
    }
    else if (offset >= 0)
    {
      tzID = "GMT+0" + offset + "00";
    }
    else if (offset >= -9)
    {
      tzID = "GMT-0" + Math.abs(offset) + "00";
    }
    else
    {
      tzID = "GMT" + offset + "00";
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
   * Provides a set of test cases for the isASCIIString method.
   *
   * @param  b        The array to be examined.
   * @param  isASCII  Indicates whether the contents of the provided array
   *                  represent a valid ASCII string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIsASCII")
  public void testIsASCIIString(final byte[] b, final boolean isASCII)
         throws Exception
  {
    assertEquals(StaticUtils.isASCIIString(b), isASCII);
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
      }
    };
  }



  /**
   * Provides a set of test cases for the isPrintableString method.
   *
   * @param  b            The array to be examined.
   * @param  isPrintable  Indicates whether the contents of the provided array
   *                      represent a valid LDAP printable string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIsPrintable")
  public void testIsPrintableString(final byte[] b, final boolean isPrintable)
         throws Exception
  {
    assertEquals(StaticUtils.isPrintableString(b), isPrintable);
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
}
