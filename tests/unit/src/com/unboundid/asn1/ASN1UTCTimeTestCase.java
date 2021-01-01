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
package com.unboundid.asn1;



import java.util.Date;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for ASN.1 UTC time elements.
 */
public final class ASN1UTCTimeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a UTC time value created from the current time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateUTCTime()
         throws Exception
  {
    ASN1UTCTime e = new ASN1UTCTime();

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    final Date date = e.getDate();
    assertNotNull(date);

    final long time = e.getTime();

    final String timestamp = e.getStringRepresentation();
    assertNotNull(timestamp);

    assertNotNull(e.toString());


    e = new ASN1UTCTime(date);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());


    e = new ASN1UTCTime(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, date);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());


    e = new ASN1UTCTime(time);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());


    e = new ASN1UTCTime(ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, time);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());


    e = new ASN1UTCTime(timestamp);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());


    e = ASN1UTCTime.decodeAsUTCTime(e);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());


    e = ASN1UTCTime.decodeAsUTCTime(e.encode());

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_UTC_TIME_TYPE);

    assertNotNull(e.getValue());

    assertNotNull(e.getDate());
    assertEquals(e.getDate(), date);

    assertEquals(e.getTime(), time);

    assertNotNull(e.getStringRepresentation());
    assertEquals(e.getStringRepresentation(), timestamp);

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when trying to decode an invalid string as a UTC time
   * timestamp.
   *
   * @param  timestamp      The expected-invalid timestamp.
   * @param  invalidReason  A string that explains why the timestamp is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidStrings",
        expectedExceptions = { ASN1Exception.class })
  public void testDecodeInvalidStrings(final String timestamp,
                                       final String invalidReason)
         throws Exception
  {
    ASN1UTCTime.decodeTimestamp(timestamp);
    fail("Expected an exception when trying to decode value '" + timestamp +
         "'.  Invalid reason is " + invalidReason);
  }



  /**
   * Retrieves a set of invalid strings to use when testing decoding.
   *
   * @return  A set of invalid strings to use when testing decoding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "invalidStrings")
  public Object[][] getInvalidStrings()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "17Z",
        "The value is too short"
      },

      new Object[]
      {
        "20170102030406Z",
        "The value is too long"
      },

      new Object[]
      {
        "1701020304069",
        "The value does not end with Z"
      },

      new Object[]
      {
        "x70102030406Z",
        "Non-digit character at the beginning of the timestamp"
      },

      new Object[]
      {
        "17010x030406Z",
        "Non-digit character in the middle of the timestamp"
      },

      new Object[]
      {
        "170102030406ZZ",
        "Ends with ZZ"
      },

      new Object[]
      {
        "179102030406Z",
        "Invalid month"
      },

      new Object[]
      {
        "170192030406Z",
        "Invalid day"
      },

      new Object[]
      {
        "170102930406Z",
        "Invalid hour"
      },

      new Object[]
      {
        "170102039406Z",
        "Invalid minute"
      },

      new Object[]
      {
        "170102030496Z",
        "Invalid second"
      },

      new Object[]
      {
        "1701020304Z",
        "Missing second"
      },

      new Object[]
      {
        "170102030406.123Z",
        "Includes sub-second"
      },

      new Object[]
      {
        "170231030406Z",
        "The timestamp specifies a date of February 31"
      },
    };
  }



  /**
   * Tests the behavior when trying to decode an empty byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeEmptyArray()
         throws Exception
  {
    ASN1UTCTime.decodeAsUTCTime(StaticUtils.NO_BYTES);
  }



  /**
   * Tests the behavior when trying to decode a byte array that suggests a
   * different number of bytes in the value than there are available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesWithLengthMismatch()
         throws Exception
  {
    final byte[] malformedElementBytes =
    {
      ASN1Constants.UNIVERSAL_UTC_TIME_TYPE,
      0x01
    };

    ASN1UTCTime.decodeAsUTCTime(malformedElementBytes);
  }



  /**
   * Tests the behavior when trying to decode a byte array whose value is all
   * zeroes.  There will be enough zeroes to require more than one byte to
   * represent the type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testArrayWithLargeValuesOfAllZeroes()
         throws Exception
  {
    final byte[] value = new byte[1024];
    final ASN1Element e = new ASN1Element(
         ASN1Constants.UNIVERSAL_UTC_TIME_TYPE, value);
    ASN1UTCTime.decodeAsUTCTime(e.encode());
  }



  /**
   * Tests the behavior when trying to decode a byte array that represents a
   * valid ASN.1 element but with a value that is an invalid string.
   *
   * @param  timestamp      The expected-invalid timestamp.
   * @param  invalidReason  A string that explains why the timestamp is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidStrings",
        expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesWithInvalidValue(final String timestamp,
                                              final String invalidReason)
         throws Exception
  {
    final ASN1Element e = new ASN1Element(
         ASN1Constants.UNIVERSAL_UTC_TIME_TYPE,
         StaticUtils.getBytes(timestamp));
    ASN1UTCTime.decodeAsUTCTime(e.encode());
  }



  /**
   * Tests the behavior when trying to decode a generic ASN.1 element created
   * with a value that is an invalid string.
   *
   * @param  timestamp      The expected-invalid timestamp.
   * @param  invalidReason  A string that explains why the timestamp is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidStrings",
        expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementWithInvalidValue(final String timestamp,
                                                final String invalidReason)
         throws Exception
  {
    final ASN1Element e = new ASN1Element(
         ASN1Constants.UNIVERSAL_UTC_TIME_TYPE,
         StaticUtils.getBytes(timestamp));
    ASN1UTCTime.decodeAsUTCTime(e);
  }
}
