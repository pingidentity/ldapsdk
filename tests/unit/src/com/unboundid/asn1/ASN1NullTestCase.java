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
 * This class provides test coverage for the ASN1Null class.
 */
public class ASN1NullTestCase
       extends ASN1TestCase
{
  /**
   * Tests the first constructor, which does not take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ASN1Null nullElement = new ASN1Null();
    assertEquals(nullElement.getType(), UNIVERSAL_NULL_TYPE);
    assertEquals(nullElement.getValue().length, 0);

    byte[] encodedElement = nullElement.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { 0x05, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    nullElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, nullElement);

    ASN1Null decodedNull = ASN1Null.decodeAsNull(genericElement.encode());
    assertEquals(decodedNull, nullElement);
    assertEquals(decodedNull, genericElement);

    decodedNull = ASN1Null.decodeAsNull(genericElement);
    assertEquals(decodedNull, nullElement);
    assertEquals(decodedNull, genericElement);

    assertNotNull(nullElement.toString());
  }



  /**
   * Tests the second constructor, which takes the type as an argument.
   *
   * @param  type  The BER type to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypes")
  public void testConstructor2(byte type)
         throws Exception
  {
    ASN1Null nullElement = new ASN1Null(type);
    assertEquals(nullElement.getType(), type);
    assertEquals(nullElement.getValue().length, 0);

    byte[] encodedElement = nullElement.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { type, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    nullElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, nullElement);

    ASN1Null decodedNull = ASN1Null.decodeAsNull(genericElement.encode());
    assertEquals(decodedNull, nullElement);
    assertEquals(decodedNull, genericElement);

    decodedNull = ASN1Null.decodeAsNull(genericElement);
    assertEquals(decodedNull, nullElement);
    assertEquals(decodedNull, genericElement);

    assertNotNull(nullElement.toString());
  }



  /**
   * Tests the {@code decodeAsNull} method with byte arrays.
   *
   * @param  type   The BER type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testDecodeGenericElementBytes(byte type, byte[] value)
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element(type, value);

    if ((value == null) || (value.length == 0))
    {
      // The element can be decoded as a null element.
      ASN1Null nullElement = ASN1Null.decodeAsNull(genericElement.encode());
      assertEquals(nullElement, genericElement);
    }
    else
    {
      try
      {
        ASN1Null.decodeAsNull(genericElement);
        fail("Expected decodeAsNull to fail with an element with a nonzero " +
             "value length");
      } catch (ASN1Exception ae) {}
    }
  }



  /**
   * Tests the {@code decodeAsNull} method.
   *
   * @param  type   The BER type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testDecodeGenericElements(byte type, byte[] value)
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element(type, value);

    if ((value == null) || (value.length == 0))
    {
      // The element can be decoded as a null element.
      ASN1Null nullElement = ASN1Null.decodeAsNull(genericElement);
      assertEquals(nullElement, genericElement);
    }
    else
    {
      try
      {
        ASN1Null.decodeAsNull(genericElement);
        fail("Expected decodeAsNull to fail with an element with a nonzero " +
             "value length");
      } catch (ASN1Exception ae) {}
    }
  }



  /**
   * Tests the {@code decodeAsNull} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsNullTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Null.decodeAsNull(elementBytes);
  }



  /**
   * Tests the {@code decodeAsNull} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsNullTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Null.decodeAsNull(elementBytes);
  }



  /**
   * Tests the {@code decodeAsNull} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsNullLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Null.decodeAsNull(elementBytes);
  }



  /**
   * Tests the {@code decodeAsNull} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsNullMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Null.decodeAsNull(elementBytes);
  }



  /**
   * Tests the {@code decodeAsNull} method with a byte array with an element
   * that has a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsNullHasValue()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00 };
    ASN1Null.decodeAsNull(elementBytes);
  }
}
