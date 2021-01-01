/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test data for various one-time password
 * implementations.
 */
public final class OneTimePasswordTestCase
       extends LDAPSDKTestCase
{
  /**
   * @param  sharedKey     The shared key to use in the calculation.
   * @param  count         The count to use in the calculation.
   * @param  expectedHOTP  The expected TOTP code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testHOTPData")
  public void testHOTPValid(final byte[] sharedKey, final long count,
                            final String expectedHOTP)
         throws Exception
  {
    // Test with the minimal set of parameters.
    assertEquals(OneTimePassword.hotp(sharedKey, count).length(), 6);

    // Test with all the parameters.
    assertEquals(
         OneTimePassword.hotp(sharedKey, count, expectedHOTP.length()),
         expectedHOTP);

    // Test with various lengths.
    assertEquals(OneTimePassword.hotp(sharedKey, count, 6).length(), 6);
    assertEquals(OneTimePassword.hotp(sharedKey, count, 7).length(), 7);
    assertEquals(OneTimePassword.hotp(sharedKey, count, 8).length(), 8);
  }



  /**
   * Tests the behavior when trying to use HOTP with an invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testHOTPInvalidLength()
         throws Exception
  {
    OneTimePassword.hotp(StaticUtils.getBytes("12345678901234567890"), 0, 10);
  }



  /**
   * Tests the behavior when trying to use HOTP with an invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testHOTPNullKey()
         throws Exception
  {
    OneTimePassword.hotp(null, 0, 6);
  }



  /**
   * Provides test coverage for TOTP processing with the given information.
   *
   * @param  sharedKey         The shared key to use in the calculation.
   * @param  authTime          The authentication time to use for testing.
   * @param  intervalDuration  The duration of the time interval, in seconds.
   * @param  expectedTOTP      The expected TOTP code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTOTPData")
  public void testTOTPValid(final byte[] sharedKey, final long authTime,
                            final int intervalDuration,
                            final String expectedTOTP)
         throws Exception
  {
    // Test with the minimal set of parameters.
    assertEquals(OneTimePassword.totp(sharedKey).length(), 6);

    // Test with all the parameters.
    assertEquals(
         OneTimePassword.totp(sharedKey, authTime, intervalDuration,
              expectedTOTP.length()),
         expectedTOTP);

    // Test with various lengths.
    assertEquals(OneTimePassword.totp(sharedKey, authTime, intervalDuration,
         6).length(), 6);
    assertEquals(OneTimePassword.totp(sharedKey, authTime, intervalDuration,
         7).length(), 7);
    assertEquals(OneTimePassword.totp(sharedKey, authTime, intervalDuration,
         8).length(), 8);
  }



  /**
   * Tests the behavior when trying to use TOTP with an invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testTOTPInvalidLength()
         throws Exception
  {
    OneTimePassword.totp(StaticUtils.getBytes("12345678901234567890"),
         System.currentTimeMillis(), 30, 10);
  }



  /**
   * Tests the behavior when trying to use TOTP with an invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testTOTPNullKey()
         throws Exception
  {
    OneTimePassword.totp(null, System.currentTimeMillis(), 30, 6);
  }



  /**
   * Retrieves a set of data for testing HOTP functionality.  These come from
   * the test values given in Appendix D of RFC 4226.
   *
   * @return  A set of data for testing TOTP functionality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "testHOTPData")
  public Object[][] getTestHOTPData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        0L,
        "755224"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        1L,
        "287082"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        2L,
        "359152"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        3L,
        "969429"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        4L,
        "338314"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        5L,
        "254676"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        6L,
        "287922"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        7L,
        "162583"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        8L,
        "399871"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        9L,
        "520489"
      }
    };
  }



  /**
   * Retrieves a set of data for testing TOTP functionality.  These come from
   * the test vectors given in Appendix B of RFC 6238.
   *
   * @return  A set of data for testing TOTP functionality.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "testTOTPData")
  public Object[][] getTestTOTPData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        59000L,
        30,
        "94287082"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        1111111109000L,
        30,
        "07081804"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        1111111111000L,
        30,
        "14050471"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        1234567890000L,
        30,
        "89005924"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        2000000000000L,
        30,
        "69279037"
      },

      new Object[]
      {
        StaticUtils.getBytes("12345678901234567890"),
        20000000000000L,
        30,
        "65353130"
      },
    };
  }
}
