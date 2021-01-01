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
 * This class provides test coverage for the ASN1Enumerated class.
 */
public class ASN1EnumeratedTestCase
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
    ASN1Enumerated enumeratedElement = new ASN1Enumerated(intValue);
    assertEquals(enumeratedElement.getType(), UNIVERSAL_ENUMERATED_TYPE);
    assertEquals(enumeratedElement.intValue(), intValue);

    byte[] encodedElement = enumeratedElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    enumeratedElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, enumeratedElement);

    ASN1Enumerated decodedEnumerated =
         ASN1Enumerated.decodeAsEnumerated(genericElement.encode());
    assertEquals(decodedEnumerated, enumeratedElement);
    assertEquals(decodedEnumerated, genericElement);
    assertEquals(decodedEnumerated.intValue(), intValue);

    decodedEnumerated = ASN1Enumerated.decodeAsEnumerated(genericElement);
    assertEquals(decodedEnumerated, enumeratedElement);
    assertEquals(decodedEnumerated, genericElement);
    assertEquals(decodedEnumerated.intValue(), intValue);

    assertNotNull(enumeratedElement.toString());
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
    ASN1Enumerated enumeratedElement =
         new ASN1Enumerated((byte) 0x00, intValue);
    assertEquals(enumeratedElement.getType(), (byte) 0x00);
    assertEquals(enumeratedElement.intValue(), intValue);

    byte[] encodedElement = enumeratedElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    enumeratedElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, enumeratedElement);

    ASN1Enumerated decodedEnumerated =
         ASN1Enumerated.decodeAsEnumerated(genericElement.encode());
    assertEquals(decodedEnumerated, enumeratedElement);
    assertEquals(decodedEnumerated, genericElement);
    assertEquals(decodedEnumerated.intValue(), intValue);

    decodedEnumerated = ASN1Enumerated.decodeAsEnumerated(genericElement);
    assertEquals(decodedEnumerated, enumeratedElement);
    assertEquals(decodedEnumerated, genericElement);
    assertEquals(decodedEnumerated.intValue(), intValue);

    assertNotNull(enumeratedElement.toString());
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
    ASN1Enumerated enumeratedElement = new ASN1Enumerated(intValue);
    ByteStringBuffer buffer = new ByteStringBuffer();
    enumeratedElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), enumeratedElement.encode()));
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with a byte array whose value
   * is too short to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesAsEnumeratedTooShort()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Enumerated.decodeAsEnumerated(genericElement.encode());
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with an element whose value is
   * too long to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesAsEnumeratedTooLong()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Enumerated.decodeAsEnumerated(genericElement.encode());
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with an element whose value is
   * too short to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsEnumeratedTooShort()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Enumerated.decodeAsEnumerated(genericElement);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with an element whose value is
   * too long to be a valid integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsEnumeratedTooLong()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Enumerated.decodeAsEnumerated(genericElement);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsEnumeratedTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Enumerated.decodeAsEnumerated(elementBytes);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsEnumeratedTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Enumerated.decodeAsEnumerated(elementBytes);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsEnumeratedLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Enumerated.decodeAsEnumerated(elementBytes);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsEnumeratedMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Enumerated.decodeAsEnumerated(elementBytes);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method with a byte array with an
   * invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsEnumeratedInvalidLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x05, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Enumerated.decodeAsEnumerated(elementBytes);
  }
}
