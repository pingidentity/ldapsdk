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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.ByteStringBuffer;

import static com.unboundid.asn1.ASN1Constants.*;



/**
 * This class provides test coverage for the ASN1Boolean class.
 */
public class ASN1BooleanTestCase
       extends ASN1TestCase
{
  /**
   * Tests the first constructor, which takes only a boolean value, using a
   * value of "true".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1True()
         throws Exception
  {
    ASN1Boolean booleanElement = new ASN1Boolean(true);
    assertTrue(booleanElement.booleanValue());
    assertTrue(Arrays.equals(booleanElement.getValue(), BOOLEAN_VALUE_TRUE));
    assertEquals(booleanElement.getType(), UNIVERSAL_BOOLEAN_TYPE);
    assertEquals(booleanElement, ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT);

    byte[] encodedElement = booleanElement.encode();
    assertEquals(encodedElement.length, 3);
    assertTrue(Arrays.equals(encodedElement,
                             new byte[] { 0x01, 0x01, (byte) 0xFF }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    booleanElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, booleanElement);

    ASN1Boolean booleanElement2 =
         ASN1Boolean.decodeAsBoolean(genericElement.encode());
    assertTrue(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    booleanElement2 = ASN1Boolean.decodeAsBoolean(genericElement);
    assertTrue(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    assertNotNull(booleanElement.toString());
  }



  /**
   * Tests the first constructor, which takes only a boolean value, using a
   * value of "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1False()
         throws Exception
  {
    ASN1Boolean booleanElement = new ASN1Boolean(false);
    assertFalse(booleanElement.booleanValue());
    assertTrue(Arrays.equals(booleanElement.getValue(), BOOLEAN_VALUE_FALSE));
    assertEquals(booleanElement.getType(), UNIVERSAL_BOOLEAN_TYPE);
    assertEquals(booleanElement, ASN1Boolean.UNIVERSAL_BOOLEAN_FALSE_ELEMENT);

    byte[] encodedElement = booleanElement.encode();
    assertEquals(encodedElement.length, 3);
    assertTrue(Arrays.equals(encodedElement, new byte[] { 0x01, 0x01, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    booleanElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, booleanElement);

    ASN1Boolean booleanElement2 =
         ASN1Boolean.decodeAsBoolean(genericElement.encode());
    assertFalse(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    booleanElement2 = ASN1Boolean.decodeAsBoolean(genericElement);
    assertFalse(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    assertNotNull(booleanElement.toString());
  }



  /**
   * Tests the second constructor, which takes both a type and a value, using a
   * value of "true".
   *
   * @param  type  The BER type to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypes")
  public void testConstructor2True(byte type)
         throws Exception
  {
    ASN1Boolean booleanElement = new ASN1Boolean(type, true);
    assertTrue(booleanElement.booleanValue());
    assertEquals(booleanElement.getType(), type);
    assertTrue(Arrays.equals(booleanElement.getValue(), BOOLEAN_VALUE_TRUE));

    if (type == UNIVERSAL_BOOLEAN_TYPE)
    {
      assertTrue(booleanElement.equals(
                      ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT));
    }
    else
    {
      assertFalse(booleanElement.equals(
                       ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT));
    }
    assertTrue(booleanElement.equalsIgnoreType(
                    ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT));

    byte[] encodedElement = booleanElement.encode();
    assertEquals(encodedElement.length, 3);
    assertTrue(Arrays.equals(encodedElement,
                             new byte[] { type, 0x01, (byte) 0xFF }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    booleanElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, booleanElement);

    ASN1Boolean booleanElement2 =
         ASN1Boolean.decodeAsBoolean(genericElement.encode());
    assertTrue(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    booleanElement2 = ASN1Boolean.decodeAsBoolean(genericElement);
    assertTrue(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    assertNotNull(booleanElement.toString());
  }



  /**
   * Tests the second constructor, which takes both a type and a value, using a
   * value of "false".
   *
   * @param  type  The BER type to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypes")
  public void testConstructor2False(byte type)
         throws Exception
  {
    ASN1Boolean booleanElement = new ASN1Boolean(type, false);
    assertFalse(booleanElement.booleanValue());
    assertEquals(booleanElement.getType(), type);
    assertTrue(Arrays.equals(booleanElement.getValue(), BOOLEAN_VALUE_FALSE));

    if (type == UNIVERSAL_BOOLEAN_TYPE)
    {
      assertTrue(booleanElement.equals(
                      ASN1Boolean.UNIVERSAL_BOOLEAN_FALSE_ELEMENT));
    }
    else
    {
      assertFalse(booleanElement.equals(
                       ASN1Boolean.UNIVERSAL_BOOLEAN_FALSE_ELEMENT));
    }
    assertTrue(booleanElement.equalsIgnoreType(
                    ASN1Boolean.UNIVERSAL_BOOLEAN_FALSE_ELEMENT));

    byte[] encodedElement = booleanElement.encode();
    assertEquals(encodedElement.length, 3);
    assertTrue(Arrays.equals(encodedElement, new byte[] { type, 0x01, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    booleanElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, booleanElement);

    ASN1Boolean booleanElement2 =
         ASN1Boolean.decodeAsBoolean(genericElement.encode());
    assertFalse(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    booleanElement2 = ASN1Boolean.decodeAsBoolean(genericElement);
    assertFalse(booleanElement2.booleanValue());
    assertEquals(booleanElement2, genericElement);
    assertEquals(booleanElement2, booleanElement);

    assertNotNull(booleanElement.toString());
  }



  /**
   * Tests the {@code decodeAsBoolean} method using a byte array that can be
   * decoded as a valid Boolean element with a boolean value of "true".
   *
   * @param  value  The value to use for the element to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider  = "validTrueValues")
  public void testDecodeBytesAsBooleanTrue(byte[] value)
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x01, value);
    ASN1Boolean booleanElement =
         ASN1Boolean.decodeAsBoolean(genericElement.encode());
    assertTrue(booleanElement.booleanValue());
  }



  /**
   * Tests the {@code decodeAsBoolean} method using a byte array that can
   * be decoded as a valid Boolean element with a boolean value of "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeBytesAsBooleanFalse()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x01,
                                                 new byte[] { 0x00 });
    ASN1Boolean booleanElement =
         ASN1Boolean.decodeAsBoolean(genericElement.encode());
    assertFalse(booleanElement.booleanValue());
  }



  /**
   * Tests the {@code decodeAsBoolean} method using a wide range of values, most
   * of which cannot be decoded as valid Boolean elements.
   *
   * @param  type   The BER type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testDecodeBytesAsBooleanInvalid(byte type, byte[] value)
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element(type, value);

    if ((value != null) && (value.length == 1))
    {
      // It should be possible to decode the element as a Boolean element.
      ASN1Boolean booleanElement =
           ASN1Boolean.decodeAsBoolean(genericElement.encode());
    }
    else
    {
      try
      {
        // It should not be possible to decode the element as a Boolean element.
        ASN1Boolean.decodeAsBoolean(genericElement);
        fail("Expected an exception when decoding a generic element with a " +
             "length that isn't 1.");
      } catch (ASN1Exception ae) {}
    }
  }



  /**
   * Tests the {@code decodeAsBoolean} method using an ASN.1 element that can
   * be decoded as a valid Boolean element with a boolean value of "true".
   *
   * @param  value  The value to use for the element to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider  = "validTrueValues")
  public void testDecodeElementAsBooleanTrue(byte[] value)
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x01, value);
    ASN1Boolean booleanElement = ASN1Boolean.decodeAsBoolean(genericElement);
    assertTrue(booleanElement.booleanValue());
  }



  /**
   * Tests the {@code decodeAsBoolean} method using an ASN.1 element that can
   * be decoded as a valid Boolean element with a boolean value of "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeElementAsBooleanFalse()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x01,
                                                 new byte[] { 0x00 });
    ASN1Boolean booleanElement = ASN1Boolean.decodeAsBoolean(genericElement);
    assertFalse(booleanElement.booleanValue());
  }



  /**
   * Tests the {@code decodeAsBoolean} method using a wide range of values, most
   * of which cannot be decoded as valid Boolean elements.
   *
   * @param  type   The BER type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testDecodeElementAsBooleanInvalid(byte type, byte[] value)
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element(type, value);

    if ((value != null) && (value.length == 1))
    {
      // It should be possible to decode the element as a Boolean element.
      ASN1Boolean booleanElement = ASN1Boolean.decodeAsBoolean(genericElement);
    }
    else
    {
      try
      {
        // It should not be possible to decode the element as a Boolean element.
        ASN1Boolean.decodeAsBoolean(genericElement);
        fail("Expected an exception when decoding a generic element with a " +
             "length that isn't 1.");
      } catch (ASN1Exception ae) {}
    }
  }



  /**
   * Retrieves the entire set of values that can be interpreted as a Boolean
   * value of "true".
   *
   * @return  The entire set of values that can be interpreted as a Boolean
   *          value of "true".
   */
  @DataProvider(name = "validTrueValues")
  public Object[][] getValidTrueValues()
  {
    Object[][] trueValues = new Object[255][1];

    for (int i=1; i < 256; i++)
    {
      trueValues[i-1][0] = new byte[] { (byte) (i & 0xFF) };
    }

    return trueValues;
  }



  /**
   * Tests the {@code decodeAsBoolean} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsBooleanTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Boolean.decodeAsBoolean(elementBytes);
  }



  /**
   * Tests the {@code decodeAsBoolean} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsBooleanTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Boolean.decodeAsBoolean(elementBytes);
  }



  /**
   * Tests the {@code decodeAsBoolean} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsBooleanLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Boolean.decodeAsBoolean(elementBytes);
  }



  /**
   * Tests the {@code decodeAsBoolean} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsBooleanMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Boolean.decodeAsBoolean(elementBytes);
  }



  /**
   * Tests the {@code decodeAsBoolean} method with a byte array with an invalid
   * length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsBooleanInvalidLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x02, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Boolean.decodeAsBoolean(elementBytes);
  }
}
