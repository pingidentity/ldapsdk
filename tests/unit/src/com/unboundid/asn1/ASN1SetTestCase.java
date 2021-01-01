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
import java.util.Collection;

import org.testng.annotations.Test;

import com.unboundid.util.ByteStringBuffer;

import static com.unboundid.asn1.ASN1Constants.*;



/**
 * This class provides test coverage for the ASN1Set class.
 */
public class ASN1SetTestCase
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
    ASN1Set setElement = new ASN1Set();
    assertEquals(setElement.getType(), UNIVERSAL_SET_TYPE);
    assertEquals(setElement.getValue().length, 0);
    assertEquals(setElement.elements().length, 0);

    byte[] encodedElement = setElement.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { 0x31, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    setElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, setElement);

    ASN1Set decodedSet = ASN1Set.decodeAsSet(genericElement.encode());
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);
    assertEquals(decodedSet.elements().length, 0);

    decodedSet = ASN1Set.decodeAsSet(genericElement);
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);
    assertEquals(decodedSet.elements().length, 0);

    assertNotNull(setElement.toString());
  }



  /**
   * Tests the second constructor, which takes a byte type.
   *
   * @param  type  The BER type to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypes")
  public void testConstructor1(byte type)
         throws Exception
  {
    ASN1Set setElement = new ASN1Set(type);
    assertEquals(setElement.getType(), type);
    assertEquals(setElement.getValue().length, 0);
    assertEquals(setElement.elements().length, 0);

    byte[] encodedElement = setElement.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { type, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    setElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, setElement);

    ASN1Set decodedSet = ASN1Set.decodeAsSet(genericElement.encode());
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);
    assertEquals(decodedSet.elements().length, 0);

    decodedSet = ASN1Set.decodeAsSet(genericElement);
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);
    assertEquals(decodedSet.elements().length, 0);

    assertNotNull(setElement.toString());
  }



  /**
   * Tests the third constructor, which takes an element array.
   *
   * @param  elements  The array of elements to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testElementArrays")
  public void testConstructor3(ASN1Element[] elements)
         throws Exception
  {
    ASN1Set setElement = new ASN1Set(elements);
    assertEquals(setElement.getType(), UNIVERSAL_SET_TYPE);

    byte[] encodedElement = setElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    setElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, setElement);

    ASN1Set decodedSet = ASN1Set.decodeAsSet(genericElement.encode());
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    decodedSet = ASN1Set.decodeAsSet(genericElement);
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    assertEquals(setElement.elements().length,
                 decodedSet.elements().length);
    for (int i=0; i < setElement.elements().length; i++)
    {
      assertEquals(setElement.elements()[i],
                   decodedSet.elements()[i]);
    }

    assertNotNull(setElement.toString());
  }



  /**
   * Tests the fourth constructor, which takes a collection of ASN.1 elements.
   *
   * @param  elements  The collection of elements to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testElementCollections")
  public void testConstructor4(Collection<? extends ASN1Element> elements)
         throws Exception
  {
    ASN1Set setElement = new ASN1Set(elements);
    assertEquals(setElement.getType(), UNIVERSAL_SET_TYPE);

    byte[] encodedElement = setElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    setElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, setElement);

    ASN1Set decodedSet = ASN1Set.decodeAsSet(genericElement.encode());
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    decodedSet = ASN1Set.decodeAsSet(genericElement);
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    assertEquals(setElement.elements().length,
                 decodedSet.elements().length);
    for (int i=0; i < setElement.elements().length; i++)
    {
      assertEquals(setElement.elements()[i],
                   decodedSet.elements()[i]);
    }

    assertNotNull(setElement.toString());
  }



  /**
   * Tests the fifth constructor, which takes a byte type and an element array.
   *
   * @param  elements  The array of elements to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testElementArrays")
  public void testConstructor5(ASN1Element[] elements)
         throws Exception
  {
    ASN1Set setElement = new ASN1Set((byte) 0x00, elements);
    assertEquals(setElement.getType(), (byte) 0x00);

    byte[] encodedElement = setElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    setElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, setElement);

    ASN1Set decodedSet = ASN1Set.decodeAsSet(genericElement.encode());
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    decodedSet = ASN1Set.decodeAsSet(genericElement);
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    assertEquals(setElement.elements().length,
                 decodedSet.elements().length);
    for (int i=0; i < setElement.elements().length; i++)
    {
      assertEquals(setElement.elements()[i],
                   decodedSet.elements()[i]);
    }

    assertNotNull(setElement.toString());
  }



  /**
   * Tests the sixth constructor, which takes a byte type and a collection of
   * ASN.1 elements.
   *
   * @param  elements  The collection of elements to use for the test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testElementCollections")
  public void testConstructor6(Collection<? extends ASN1Element> elements)
         throws Exception
  {
    ASN1Set setElement = new ASN1Set((byte) 0x00, elements);
    assertEquals(setElement.getType(), (byte) 0x00);

    byte[] encodedElement = setElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    setElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, setElement);

    ASN1Set decodedSet = ASN1Set.decodeAsSet(genericElement.encode());
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    decodedSet = ASN1Set.decodeAsSet(genericElement);
    assertEquals(decodedSet, setElement);
    assertEquals(decodedSet, genericElement);

    assertEquals(setElement.elements().length,
                 decodedSet.elements().length);
    for (int i=0; i < setElement.elements().length; i++)
    {
      assertEquals(setElement.elements()[i],
                   decodedSet.elements()[i]);
    }

    assertNotNull(setElement.toString());
  }



  /**
   * Tests the behavior of the {@code decodeAsSet} method when the element
   * cannot be decoded as a set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesInvalidSet()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x00, new byte[1]);
    ASN1Set.decodeAsSet(genericElement.encode());
  }



  /**
   * Tests the behavior of the {@code decodeAsSet} method when the element
   * cannot be decoded as a set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementInvalidSet()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x00, new byte[1]);
    ASN1Set.decodeAsSet(genericElement);
  }



  /**
   * Tests the {@code decodeAsSet} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSetTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Set.decodeAsSet(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSet} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSetTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Set.decodeAsSet(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSet} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSetLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Set.decodeAsSet(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSet} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSetMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Set.decodeAsSet(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSet} method with a byte array with an
   * embedded element with a value that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementAsSetEmbeddedElementTooLong()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x04, (byte) 0x01 };
    ASN1Element e = new ASN1Element((byte) 0x30, elementBytes);
    ASN1Set.decodeAsSet(e);
  }



  /**
   * Tests the {@code decodeAsSet} method with a byte array with an
   * embedded element with a value that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSetEmbeddedElementTooLong()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x30, (byte) 0x02, (byte) 0x04,
                            (byte) 0x01 };
    ASN1Set.decodeAsSet(elementBytes);
  }
}
