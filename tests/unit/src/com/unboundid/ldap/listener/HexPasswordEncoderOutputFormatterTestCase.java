/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the hexadecimal password encoder.
 */
public final class HexPasswordEncoderOutputFormatterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an empty password, which should never happen but
   * we'll handle anyway, using the lowercase formatter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyPasswordLowercase()
         throws Exception
  {
    final HexPasswordEncoderOutputFormatter formatter =
         HexPasswordEncoderOutputFormatter.getLowercaseInstance();
    assertNotNull(formatter);
    assertTrue(formatter.useLowercaseLetters());

    final byte[] formattedBytes = formatter.format(StaticUtils.NO_BYTES);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes.length, 0);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes.length, 0);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior with an empty password, which should never happen but
   * we'll handle anyway, using the uppercase formatter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyPasswordUppercase()
         throws Exception
  {
    final HexPasswordEncoderOutputFormatter formatter =
         HexPasswordEncoderOutputFormatter.getUppercaseInstance();
    assertNotNull(formatter);
    assertFalse(formatter.useLowercaseLetters());

    final byte[] formattedBytes = formatter.format(StaticUtils.NO_BYTES);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes.length, 0);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes.length, 0);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior with a source array containing all possible byte values.
   * The output will be formatted in lowercase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatAllPossibleBytesLowercase()
         throws Exception
  {
    final byte[] sourceBytes = new byte[256];
    for (int i=0; i < sourceBytes.length; i++)
    {
      sourceBytes[i] = (byte) i;
    }

    final char[] hexDigits = "0123456789abcdef".toCharArray();
    final byte[] targetBytes = new byte[512];

    int targetPos = 0;
    for (final char firstDigit : hexDigits)
    {
      for (final char secondDigit : hexDigits)
      {
        targetBytes[targetPos++] = (byte) firstDigit;
        targetBytes[targetPos++] = (byte) secondDigit;
      }
    }

    final HexPasswordEncoderOutputFormatter formatter =
         HexPasswordEncoderOutputFormatter.getLowercaseInstance();
    assertNotNull(formatter);
    assertTrue(formatter.useLowercaseLetters());

    final byte[] formattedBytes = formatter.format(sourceBytes);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes, targetBytes);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes, sourceBytes);


    // Make sure that we can also get the correct value when un-formatting
    // the same bytes in all uppercase.
    final String lowerTargetString = StaticUtils.toUTF8String(targetBytes);
    final String upperTargetString = lowerTargetString.toUpperCase();
    final byte[] upperTargetBytes = StaticUtils.getBytes(upperTargetString);

    final byte[] unFormattedUpperBytes = formatter.unFormat(upperTargetBytes);
    assertNotNull(unFormattedUpperBytes);
    assertEquals(unFormattedUpperBytes, sourceBytes);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior with a source array containing all possible byte values.
   * The output will be formatted in uppercase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFormatAllPossibleBytesUppercase()
         throws Exception
  {
    final byte[] sourceBytes = new byte[256];
    for (int i=0; i < sourceBytes.length; i++)
    {
      sourceBytes[i] = (byte) i;
    }

    final char[] hexDigits = "0123456789ABCDEF".toCharArray();
    final byte[] targetBytes = new byte[512];

    int targetPos = 0;
    for (final char firstDigit : hexDigits)
    {
      for (final char secondDigit : hexDigits)
      {
        targetBytes[targetPos++] = (byte) firstDigit;
        targetBytes[targetPos++] = (byte) secondDigit;
      }
    }

    final HexPasswordEncoderOutputFormatter formatter =
         HexPasswordEncoderOutputFormatter.getUppercaseInstance();
    assertNotNull(formatter);
    assertFalse(formatter.useLowercaseLetters());

    final byte[] formattedBytes = formatter.format(sourceBytes);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes, targetBytes);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes, sourceBytes);


    // Make sure that we can also get the correct value when un-formatting
    // the same bytes in all lowercase.
    final String upperTargetString = StaticUtils.toUTF8String(targetBytes);
    final String lowerTargetString = upperTargetString.toLowerCase();
    final byte[] lowerTargetBytes = StaticUtils.getBytes(lowerTargetString);

    final byte[] unFormattedLowerBytes = formatter.unFormat(lowerTargetBytes);
    assertNotNull(unFormattedLowerBytes);
    assertEquals(unFormattedLowerBytes, sourceBytes);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior when trying to un-format a value that isn't valid hex,
   * using the lowercase formatter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testUnFormatMalformedValueLowercaes()
         throws Exception
  {
    final HexPasswordEncoderOutputFormatter formatter =
         HexPasswordEncoderOutputFormatter.getLowercaseInstance();
    assertNotNull(formatter);
    assertTrue(formatter.useLowercaseLetters());

    // This array is malformed both because it has an invalid length that is
    // an add number of bytes, and because it's got a character (the null
    // character) that isn't used in hex encoding.
    final byte[] malformedBytes = new byte[1];
    formatter.unFormat(malformedBytes);
  }



  /**
   * Tests the behavior when trying to un-format a value that isn't valid hex,
   * using the uppercase formatter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testUnFormatMalformedValueUppercase()
         throws Exception
  {
    final HexPasswordEncoderOutputFormatter formatter =
         HexPasswordEncoderOutputFormatter.getUppercaseInstance();
    assertNotNull(formatter);
    assertFalse(formatter.useLowercaseLetters());

    // This array is malformed both because it has an invalid length that is
    // an add number of bytes, and because it's got a character (the null
    // character) that isn't used in hex encoding.
    final byte[] malformedBytes = new byte[1];
    formatter.unFormat(malformedBytes);
  }
}
