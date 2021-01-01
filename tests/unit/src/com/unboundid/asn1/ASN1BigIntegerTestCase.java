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



import java.math.BigInteger;

import org.testng.annotations.Test;

import static com.unboundid.asn1.ASN1Constants.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the ASN1BigInteger class.
 */
public class ASN1BigIntegerTestCase
       extends ASN1TestCase
{
  /**
   * Tests the constructor that takes a {@code long} value with the default
   * BER type.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testCreateFromLongWithDefaultType(final long longValue)
         throws Exception
  {
    final ASN1BigInteger element = new ASN1BigInteger(longValue);
    assertEquals(element.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(element.getBigIntegerValue().longValue(), longValue);

    assertNotNull(element.toString());
    assertEquals(element.toString(), String.valueOf(longValue));

    final byte[] encodedElement = element.encode();
    assertNotNull(encodedElement);
    assertTrue(encodedElement.length > 0);

    final ASN1BigInteger decodedFromBytes =
         ASN1BigInteger.decodeAsBigInteger(encodedElement);
    assertNotNull(decodedFromBytes);
    assertEquals(decodedFromBytes.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromBytes.getBigIntegerValue().longValue(), longValue);

    assertNotNull(decodedFromBytes.toString());
    assertEquals(decodedFromBytes.toString(), String.valueOf(longValue));

    final ASN1BigInteger decodedFromElement =
         ASN1BigInteger.decodeAsBigInteger(element);
    assertNotNull(decodedFromElement);
    assertEquals(decodedFromElement.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromElement.getBigIntegerValue().longValue(),
         longValue);

    assertNotNull(decodedFromElement.toString());
    assertEquals(decodedFromElement.toString(), String.valueOf(longValue));
  }



  /**
   * Tests the constructor that takes a {@code long} value with a non-default
   * BER type.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testCreateFromLongWithNonDefaultType(final long longValue)
         throws Exception
  {
    final ASN1BigInteger element = new ASN1BigInteger((byte) 0x80, longValue);
    assertEquals(element.getType(), (byte) 0x80);
    assertEquals(element.getBigIntegerValue().longValue(), longValue);

    assertNotNull(element.toString());
    assertEquals(element.toString(), String.valueOf(longValue));

    final byte[] encodedElement = element.encode();
    assertNotNull(encodedElement);
    assertTrue(encodedElement.length > 0);

    final ASN1BigInteger decodedFromBytes =
         ASN1BigInteger.decodeAsBigInteger(encodedElement);
    assertNotNull(decodedFromBytes);
    assertEquals(decodedFromBytes.getType(), (byte) 0x80);
    assertEquals(decodedFromBytes.getBigIntegerValue().longValue(), longValue);

    assertNotNull(decodedFromBytes.toString());
    assertEquals(decodedFromBytes.toString(), String.valueOf(longValue));

    final ASN1BigInteger decodedFromElement =
         ASN1BigInteger.decodeAsBigInteger(element);
    assertNotNull(decodedFromElement);
    assertEquals(decodedFromElement.getType(), (byte) 0x80);
    assertEquals(decodedFromElement.getBigIntegerValue().longValue(),
         longValue);

    assertNotNull(decodedFromElement.toString());
    assertEquals(decodedFromElement.toString(), String.valueOf(longValue));
  }



  /**
   * Tests the constructor that takes a {@code BigInteger} value with the
   * default BER type.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testCreateFromBigIntegerWithDefaultType(final long longValue)
         throws Exception
  {
    final ASN1BigInteger element =
         new ASN1BigInteger(BigInteger.valueOf(longValue));
    assertEquals(element.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(element.getBigIntegerValue().longValue(), longValue);

    assertNotNull(element.toString());
    assertEquals(element.toString(), String.valueOf(longValue));

    final byte[] encodedElement = element.encode();
    assertNotNull(encodedElement);
    assertTrue(encodedElement.length > 0);

    final ASN1BigInteger decodedFromBytes =
         ASN1BigInteger.decodeAsBigInteger(encodedElement);
    assertNotNull(decodedFromBytes);
    assertEquals(decodedFromBytes.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromBytes.getBigIntegerValue().longValue(), longValue);

    assertNotNull(decodedFromBytes.toString());
    assertEquals(decodedFromBytes.toString(), String.valueOf(longValue));

    final ASN1BigInteger decodedFromElement =
         ASN1BigInteger.decodeAsBigInteger(element);
    assertNotNull(decodedFromElement);
    assertEquals(decodedFromElement.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromElement.getBigIntegerValue().longValue(),
         longValue);

    assertNotNull(decodedFromElement.toString());
    assertEquals(decodedFromElement.toString(), String.valueOf(longValue));
  }



  /**
   * Tests the constructor that takes a {@code BigInteger} value with a
   * non-default BER type.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testCreateFromBigIntegerWithNonDefaultType(final long longValue)
         throws Exception
  {
    final ASN1BigInteger element = new ASN1BigInteger((byte) 0x80,
         BigInteger.valueOf(longValue));
    assertEquals(element.getType(), (byte) 0x80);
    assertEquals(element.getBigIntegerValue().longValue(), longValue);

    assertNotNull(element.toString());
    assertEquals(element.toString(), String.valueOf(longValue));

    final byte[] encodedElement = element.encode();
    assertNotNull(encodedElement);
    assertTrue(encodedElement.length > 0);

    final ASN1BigInteger decodedFromBytes =
         ASN1BigInteger.decodeAsBigInteger(encodedElement);
    assertNotNull(decodedFromBytes);
    assertEquals(decodedFromBytes.getType(), (byte) 0x80);
    assertEquals(decodedFromBytes.getBigIntegerValue().longValue(), longValue);

    assertNotNull(decodedFromBytes.toString());
    assertEquals(decodedFromBytes.toString(), String.valueOf(longValue));

    final ASN1BigInteger decodedFromElement =
         ASN1BigInteger.decodeAsBigInteger(element);
    assertNotNull(decodedFromElement);
    assertEquals(decodedFromElement.getType(), (byte) 0x80);
    assertEquals(decodedFromElement.getBigIntegerValue().longValue(),
         longValue);

    assertNotNull(decodedFromElement.toString());
    assertEquals(decodedFromElement.toString(), String.valueOf(longValue));
  }



  /**
   * Tests the ability to represent a positive googol value (a one followed by
   * one hundred zeroes).
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPositiveGoogol()
         throws Exception
  {
    final StringBuilder googolBuffer = new StringBuilder(101);
    googolBuffer.append('1');
    for (int i=0; i < 100; i++)
    {
      googolBuffer.append('0');
    }

    final String googolString = googolBuffer.toString();

    final BigInteger bigIntegerValue = new BigInteger(googolString);

    final ASN1BigInteger element = new ASN1BigInteger(bigIntegerValue);
    assertEquals(element.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(element.getBigIntegerValue().toString(), googolString);

    final byte[] encodedElement = element.encode();
    assertNotNull(encodedElement);
    assertTrue(encodedElement.length > 0);

    final ASN1BigInteger decodedFromBytes =
         ASN1BigInteger.decodeAsBigInteger(encodedElement);
    assertNotNull(decodedFromBytes);
    assertEquals(decodedFromBytes.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromBytes.getBigIntegerValue().toString(),
         googolString);

    final ASN1BigInteger decodedFromElement =
         ASN1BigInteger.decodeAsBigInteger(element);
    assertNotNull(decodedFromElement);
    assertEquals(decodedFromElement.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromElement.getBigIntegerValue().toString(),
         googolString);
  }



  /**
   * Tests the ability to represent a negative googol value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNegativeGoogol()
         throws Exception
  {
    final StringBuilder negativeGoogolBuffer = new StringBuilder(102);
    negativeGoogolBuffer.append("-1");
    for (int i=0; i < 100; i++)
    {
      negativeGoogolBuffer.append('0');
    }

    final String negativeGoogolString = negativeGoogolBuffer.toString();

    final BigInteger bigIntegerValue = new BigInteger(negativeGoogolString);

    final ASN1BigInteger element = new ASN1BigInteger(bigIntegerValue);
    assertEquals(element.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(element.getBigIntegerValue().toString(), negativeGoogolString);

    final byte[] encodedElement = element.encode();
    assertNotNull(encodedElement);
    assertTrue(encodedElement.length > 0);

    final ASN1BigInteger decodedFromBytes =
         ASN1BigInteger.decodeAsBigInteger(encodedElement);
    assertNotNull(decodedFromBytes);
    assertEquals(decodedFromBytes.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromBytes.getBigIntegerValue().toString(),
         negativeGoogolString);

    final ASN1BigInteger decodedFromElement =
         ASN1BigInteger.decodeAsBigInteger(element);
    assertNotNull(decodedFromElement);
    assertEquals(decodedFromElement.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(decodedFromElement.getBigIntegerValue().toString(),
         negativeGoogolString);
  }



  /**
   * Tests the behavior when trying to decode an empty array as a big integer
   * element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementBytesEmptyArray()
         throws Exception
  {
    ASN1BigInteger.decodeAsBigInteger(NO_BYTES);
  }



  /**
   * Tests the behavior when trying to decode an array as a big integer when the
   * array suggests a value length of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeByteArrayEmptyValue()
         throws Exception
  {
    final byte[] elementBytes = { 0x02, 0x00 };
    ASN1BigInteger.decodeAsBigInteger(elementBytes);
  }



  /**
   * Tests the behavior when trying to decode an array as a big integer when the
   * array suggests a value length that does not match the number of remaining
   * bytes in the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeByteArrayLengthMismatch()
         throws Exception
  {
    final byte[] elementBytes = { 0x02, (byte) 0x82, 0x01, 0x00 };
    ASN1BigInteger.decodeAsBigInteger(elementBytes);
  }



  /**
   * Tests the behavior when trying to decode an element as a big integer when
   * that element has an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testElementWithEmptyValue()
         throws Exception
  {
    ASN1BigInteger.decodeAsBigInteger(new ASN1Element(UNIVERSAL_INTEGER_TYPE,
         NO_BYTES));
  }
}
