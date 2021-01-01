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
package com.unboundid.asn1;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.util.ByteStringBuffer;

import static com.unboundid.asn1.ASN1Constants.*;



/**
 * This class provides test coverage for the ASN1Integer class.
 */
public class ASN1IntegerTestCase
       extends ASN1TestCase
{
  /**
   * Tests the first constructor, which takes an int argument.
   *
   * @param  intValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIntegers")
  public void testConstructor1(int intValue)
         throws Exception
  {
    ASN1Integer integerElement = new ASN1Integer(intValue);
    assertEquals(integerElement.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(integerElement.intValue(), intValue);

    byte[] encodedElement = integerElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    integerElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, integerElement);

    ASN1Integer decodedInteger =
         ASN1Integer.decodeAsInteger(genericElement.encode());
    assertEquals(decodedInteger, integerElement);
    assertEquals(decodedInteger, genericElement);
    assertEquals(decodedInteger.intValue(), intValue);

    decodedInteger = ASN1Integer.decodeAsInteger(genericElement);
    assertEquals(decodedInteger, integerElement);
    assertEquals(decodedInteger, genericElement);
    assertEquals(decodedInteger.intValue(), intValue);

    assertNotNull(integerElement.toString());
  }



  /**
   * Tests the second constructor, which takes a byte type and an int value.
   *
   * @param  intValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIntegers")
  public void testConstructor2(int intValue)
         throws Exception
  {
    ASN1Integer integerElement = new ASN1Integer((byte) 0x00, intValue);
    assertEquals(integerElement.getType(), (byte) 0x00);
    assertEquals(integerElement.intValue(), intValue);

    byte[] encodedElement = integerElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    integerElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, integerElement);

    ASN1Integer decodedInteger =
         ASN1Integer.decodeAsInteger(genericElement.encode());
    assertEquals(decodedInteger, integerElement);
    assertEquals(decodedInteger, genericElement);
    assertEquals(decodedInteger.intValue(), intValue);

    decodedInteger = ASN1Integer.decodeAsInteger(genericElement);
    assertEquals(decodedInteger, integerElement);
    assertEquals(decodedInteger, genericElement);
    assertEquals(decodedInteger.intValue(), intValue);

    assertNotNull(integerElement.toString());
  }



  /**
   * Tests the {@code enocdeTo} method to ensure that it provides the expected
   * value.
   *
   * @param  intValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testIntegers")
  public void testEncodeTo(int intValue)
         throws Exception
  {
    ASN1Integer integerElement = new ASN1Integer(intValue);
    ByteStringBuffer buffer = new ByteStringBuffer();
    integerElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), integerElement.encode()));
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array whose value is
   * too short to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesAsIntegerTooShort()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Integer.decodeAsInteger(genericElement.encode());
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array whose value is
   * too long to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesAsIntegerTooLong()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Integer.decodeAsInteger(genericElement.encode());
  }



  /**
   * Tests the {@code decodeAsInteger} method with an element whose value is too
   * short to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsIntegerTooShort()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Integer.decodeAsInteger(genericElement);
  }



  /**
   * Tests the {@code decodeAsInteger} method with an element whose value is too
   * long to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsIntegerTooLong()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Integer.decodeAsInteger(genericElement);
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsIntegerTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Integer.decodeAsInteger(elementBytes);
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsIntegerTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Integer.decodeAsInteger(elementBytes);
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsIntegerLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Integer.decodeAsInteger(elementBytes);
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsIntegerMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Integer.decodeAsInteger(elementBytes);
  }



  /**
   * Tests the {@code decodeAsInteger} method with a byte array with an
   * invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsIntegerInvalidLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x05, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Integer.decodeAsInteger(elementBytes);
  }
}
