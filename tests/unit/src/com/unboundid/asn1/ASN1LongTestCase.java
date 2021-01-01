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
package com.unboundid.asn1;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.util.ByteStringBuffer;

import static com.unboundid.asn1.ASN1Constants.*;



/**
 * This class provides test coverage for the ASN1Long class.
 */
public class ASN1LongTestCase
       extends ASN1TestCase
{
  /**
   * Tests the first constructor, which takes a long argument.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testConstructor1(long longValue)
         throws Exception
  {
    ASN1Long longElement = new ASN1Long(longValue);
    assertEquals(longElement.getType(), UNIVERSAL_INTEGER_TYPE);
    assertEquals(longElement.longValue(), longValue);

    assertNotNull(longElement.toString());

    byte[] encodedElement = longElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    longElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, longElement);

    ASN1Long decodedLong = ASN1Long.decodeAsLong(genericElement.encode());
    assertEquals(decodedLong, longElement);
    assertEquals(decodedLong, genericElement);
    assertEquals(decodedLong.longValue(), longValue);

    decodedLong = ASN1Long.decodeAsLong(genericElement);
    assertEquals(decodedLong, longElement);
    assertEquals(decodedLong, genericElement);
    assertEquals(decodedLong.longValue(), longValue);

    assertNotNull(longElement.toString());
  }



  /**
   * Tests the second constructor, which takes a byte type and a long value.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testConstructor2(long longValue)
         throws Exception
  {
    ASN1Long longElement = new ASN1Long((byte) 0x00, longValue);
    assertEquals(longElement.getType(), (byte) 0x00);
    assertEquals(longElement.longValue(), longValue);

    assertNotNull(longElement.toString());

    byte[] encodedElement = longElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    longElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, longElement);

    ASN1Long decodedLong = ASN1Long.decodeAsLong(genericElement.encode());
    assertEquals(decodedLong, longElement);
    assertEquals(decodedLong, genericElement);
    assertEquals(decodedLong.longValue(), longValue);

    decodedLong = ASN1Long.decodeAsLong(genericElement);
    assertEquals(decodedLong, longElement);
    assertEquals(decodedLong, genericElement);
    assertEquals(decodedLong.longValue(), longValue);

    assertNotNull(longElement.toString());
  }



  /**
   * Tests the {@code enocdeTo} method to ensure that it provides the expected
   * value.
   *
   * @param  longValue  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testLongs")
  public void testEncodeTo(long longValue)
         throws Exception
  {
    ASN1Long longElement = new ASN1Long(longValue);
    ByteStringBuffer buffer = new ByteStringBuffer();
    longElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), longElement.encode()));
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array whose value is too
   * short to be a valid long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesAsLongTooShort()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Long.decodeAsLong(genericElement.encode());
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array whose value is too
   * long to be a valid long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesAsLongTooLong()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Long.decodeAsLong(genericElement.encode());
  }



  /**
   * Tests the {@code decodeAsLong} method with an element whose value is too
   * short to be a valid long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsLongTooShort()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Long.decodeAsLong(genericElement);
  }



  /**
   * Tests the {@code decodeAsLong} method with an element whose value is too
   * long to be a valid long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsLongTooLong()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x02, new byte[0]);
    ASN1Long.decodeAsLong(genericElement);
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsLongTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Long.decodeAsLong(elementBytes);
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsLongTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Long.decodeAsLong(elementBytes);
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsLongLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Long.decodeAsLong(elementBytes);
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsLongMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Long.decodeAsLong(elementBytes);
  }



  /**
   * Tests the {@code decodeAsLong} method with a byte array with an
   * invalid length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsLongInvalidLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x09, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00 };
    ASN1Long.decodeAsLong(elementBytes);
  }
}
