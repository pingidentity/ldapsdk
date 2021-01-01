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
 * This class provides test coverage for the ASN1OctetString class.
 */
public class ASN1OctetStringTestCase
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
    ASN1OctetString octetString = new ASN1OctetString();

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), UNIVERSAL_OCTET_STRING_TYPE);
    assertEquals(octetString.getValue().length, 0);
    assertEquals(octetString.stringValue(), "");

    byte[] encodedElement = octetString.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { 0x04, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the second constructor, which takes the BER type as an argument.
   *
   * @param  type  The BER type to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypes")
  public void testConstructor2(byte type)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString(type);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), type);
    assertEquals(octetString.getValue().length, 0);
    assertEquals(octetString.stringValue(), "");

    byte[] encodedElement = octetString.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { type, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the third constructor, which takes a byte array as the value.
   *
   * @param  type   The type to use for the element.  This will be ignored for
   *                this test case.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor3(byte type, byte[] value)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString(value);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), UNIVERSAL_OCTET_STRING_TYPE);
    if (value == null)
    {
      assertEquals(octetString.getValue().length, 0);
      assertEquals(octetString.stringValue(), "");
    }
    else
    {
      assertEquals(octetString.getValue().length, value.length);
      assertTrue(Arrays.equals(octetString.getValue(), value));
      octetString.stringValue();
    }

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the fourth constructor, which takes a portion of a byte array as the
   * value, using the full array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor4FullArray(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    ASN1OctetString octetString = new ASN1OctetString(value, 0, value.length);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), UNIVERSAL_OCTET_STRING_TYPE);

    assertEquals(octetString.getValue().length, value.length);
    assertTrue(Arrays.equals(octetString.getValue(), value));
    octetString.stringValue();

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the fourth constructor, which takes a portion of a byte array as the
   * value, with extra data at the beginning of the array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor4PaddingAtBeginning(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    byte[] paddedValue = new byte[value.length + 5];
    System.arraycopy(value, 0, paddedValue, 5, value.length);

    ASN1OctetString octetString = new ASN1OctetString(paddedValue, 5,
                                                      value.length);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), UNIVERSAL_OCTET_STRING_TYPE);

    assertEquals(octetString.getValue().length, value.length);
    assertTrue(Arrays.equals(octetString.getValue(), value));
    octetString.stringValue();

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the fourth constructor, which takes a portion of a byte array as the
   * value, with extra data at the end of the array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor4PaddingAtEnd(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    byte[] paddedValue = new byte[value.length + 5];
    System.arraycopy(value, 0, paddedValue, 0, value.length);

    ASN1OctetString octetString = new ASN1OctetString(paddedValue, 0,
                                                      value.length);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), UNIVERSAL_OCTET_STRING_TYPE);
    if (value == null)
    {
      assertEquals(octetString.getValue().length, 0);
      assertEquals(octetString.stringValue(), "");
    }
    else
    {
      assertEquals(octetString.getValue().length, value.length);
      assertTrue(Arrays.equals(octetString.getValue(), value));
      octetString.stringValue();
    }

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the fifth constructor, which takes a byte as the type and a byte
   * array as the value.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor5(byte type, byte[] value)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString(type, value);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), type);
    if (value == null)
    {
      assertEquals(octetString.getValue().length, 0);
      assertEquals(octetString.stringValue(), "");
    }
    else
    {
      assertEquals(octetString.getValue().length, value.length);
      assertTrue(Arrays.equals(octetString.getValue(), value));
      octetString.stringValue();
    }

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the sixth constructor, which takes a byte as the type and a portion
   * of a byte array as the value, using the full array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor6FullArray(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    ASN1OctetString octetString =
         new ASN1OctetString(type, value, 0, value.length);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), type);

    assertEquals(octetString.getValue().length, value.length);
    assertTrue(Arrays.equals(octetString.getValue(), value));
    octetString.stringValue();

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the sixth constructor, which takes a byte as the type and portion of
   * a byte array as the value, with extra data at the beginning of the array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor6PaddingAtBeginning(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    byte[] paddedValue = new byte[value.length + 5];
    System.arraycopy(value, 0, paddedValue, 5, value.length);

    ASN1OctetString octetString =
         new ASN1OctetString(type, paddedValue, 5, value.length);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), type);

    assertEquals(octetString.getValue().length, value.length);
    assertTrue(Arrays.equals(octetString.getValue(), value));
    octetString.stringValue();

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the sixth constructor, which takes a byte as the type and a portion
   * of a byte array as the value, with extra data at the end of the array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor6PaddingAtEnd(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    byte[] paddedValue = new byte[value.length + 5];
    System.arraycopy(value, 0, paddedValue, 0, value.length);

    ASN1OctetString octetString =
         new ASN1OctetString(type, paddedValue, 0, value.length);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), type);
    if (value == null)
    {
      assertEquals(octetString.getValue().length, 0);
      assertEquals(octetString.stringValue(), "");
    }
    else
    {
      assertEquals(octetString.getValue().length, value.length);
      assertTrue(Arrays.equals(octetString.getValue(), value));
      octetString.stringValue();
    }

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);
  }



  /**
   * Tests the seventh constructor, which takes a string as the value.
   *
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testStrings")
  public void testConstructor7(String value)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString(value);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), UNIVERSAL_OCTET_STRING_TYPE);
    if (value == null)
    {
      assertEquals(octetString.getValue().length, 0);
      assertEquals(octetString.stringValue(), "");
    }
    else
    {
      assertEquals(octetString.getValue().length,
                   value.getBytes("UTF-8").length);
      assertEquals(octetString.stringValue(), value);
    }

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    if (value != null)
    {
      assertEquals(decodedOctetString.stringValue(), value);
    }
  }



  /**
   * Tests the eighth constructor, which takes a byte as the type and a string
   * as the value.
   *
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testStrings")
  public void testConstructor8(String value)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString((byte) 0x00, value);

    assertNotNull(octetString.toString());

    assertEquals(octetString.getType(), (byte) 0x00);
    if (value == null)
    {
      assertEquals(octetString.getValue().length, 0);
      assertEquals(octetString.stringValue(), "");
    }
    else
    {
      assertEquals(octetString.getValue().length,
                   value.getBytes("UTF-8").length);
      assertEquals(octetString.stringValue(), value);
    }

    byte[] encodedElement = octetString.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, octetString);

    ASN1OctetString decodedOctetString =
         ASN1OctetString.decodeAsOctetString(genericElement.encode());
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    decodedOctetString = ASN1OctetString.decodeAsOctetString(genericElement);
    assertEquals(decodedOctetString, octetString);
    assertEquals(decodedOctetString, genericElement);

    if (value != null)
    {
      assertEquals(decodedOctetString.stringValue(), value);
    }
  }



  /**
   * Tests the {@code encodeTo} method with byte array values.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testEncodeToBytes(byte type, byte[] value)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString(type, value);

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);

    assertTrue(Arrays.equals(buffer.toByteArray(), octetString.encode()));
  }



  /**
   * Tests the {@code encodeTo} method with byte array values with padding at
   * the beginning of the array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testEncodeToBytesPaddingAtBeginning(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    byte[] paddedValue = new byte[value.length + 5];
    System.arraycopy(value, 0, paddedValue, 5, value.length);

    ASN1OctetString octetString =
         new ASN1OctetString(type, paddedValue, 5, value.length);

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);

    assertTrue(Arrays.equals(buffer.toByteArray(), octetString.encode()));
  }



  /**
   * Tests the {@code encodeTo} method with byte array values with padding at
   * the end of the array.
   *
   * @param  type   The type to use for the element.
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testEncodeToBytesPaddingAtEnd(byte type, byte[] value)
         throws Exception
  {
    if (value == null)
    {
      return;
    }

    byte[] paddedValue = new byte[value.length + 5];
    System.arraycopy(value, 0, paddedValue, 0, value.length);

    ASN1OctetString octetString =
         new ASN1OctetString(type, paddedValue, 0, value.length);

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);

    assertTrue(Arrays.equals(buffer.toByteArray(), octetString.encode()));
  }



  /**
   * Tests the {@code encodeTo} method with string values.
   *
   * @param  value  The value to use for the element.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test(dataProvider = "testStrings")
  public void testEncodeToString(String value)
         throws Exception
  {
    ASN1OctetString octetString = new ASN1OctetString(value);

    ByteStringBuffer buffer = new ByteStringBuffer();
    octetString.encodeTo(buffer);

    assertTrue(Arrays.equals(buffer.toByteArray(), octetString.encode()));
  }



  /**
   * Retrieves a set of string values that can be used for testing purposes.
   *
   * @return  A set of string values that can be used for testing purposes.
   */
  @DataProvider(name = "testStrings")
  public Object[][] getTestStrings()
  {
    return new Object[][]
    {
      new Object[] { (String) null },
      new Object[] { "" },
      new Object[] { "\u0000" },
      new Object[] { "a" },
      new Object[] { "ab" },
      new Object[] { "abc" },
      new Object[] { "abcd" },
      new Object[] { "abcde" },
      new Object[] { "This is an n with a tilde over it:  \u00f1" },
      new Object[] { "This is a string with 126 characters..................." +
                     "......................................................." +
                     "................" },
      new Object[] { "This is a string with 127 characters..................." +
                     "......................................................." +
                     "................." },
      new Object[] { "This is a string with 128 characters..................." +
                     "......................................................." +
                     ".................." },
      new Object[] { "This is a string with 129 characters..................." +
                     "......................................................." +
                     "..................." },
      new Object[] { "This is a string with 126 characters and it includes no" +
                     "n-ASCII characters.\u00f1.\u00f1.\u00f1................" +
                     "..............................." },
      new Object[] { "This is a string with 127 characters and it includes no" +
                     "n-ASCII characters.\u00f1.\u00f1.\u00f1................" +
                     "................................" },
      new Object[] { "This is a string with 128 characters and it includes no" +
                     "n-ASCII characters.\u00f1.\u00f1.\u00f1................" +
                     "................................." },
      new Object[] { "This is a string with 129 characters and it includes no" +
                     "n-ASCII characters.\u00f1.\u00f1.\u00f1................" +
                     ".................................." },
      new Object[] { new String(new char[4094]) },
      new Object[] { new String(new char[4095]) },
      new Object[] { new String(new char[4096]) },
      new Object[] { new String(new char[4097]) },
    };
  }



  /**
   * Tests the {@code decodeAsOctetString} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsOctetStringTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1OctetString.decodeAsOctetString(elementBytes);
  }



  /**
   * Tests the {@code decodeAsOctetString} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsOctetStringTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1OctetString.decodeAsOctetString(elementBytes);
  }



  /**
   * Tests the {@code decodeAsOctetString} method with a byte array with a
   * length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsOctetStringLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1OctetString.decodeAsOctetString(elementBytes);
  }



  /**
   * Tests the {@code decodeAsOctetString} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsOctetStringMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1OctetString.decodeAsOctetString(elementBytes);
  }
}
