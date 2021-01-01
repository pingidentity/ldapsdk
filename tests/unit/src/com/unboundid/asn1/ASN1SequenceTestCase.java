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
 * This class provides test coverage for the ASN1Sequence class.
 */
public class ASN1SequenceTestCase
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
    ASN1Sequence sequenceElement = new ASN1Sequence();
    assertEquals(sequenceElement.getType(), UNIVERSAL_SEQUENCE_TYPE);
    assertEquals(sequenceElement.getValue().length, 0);
    assertEquals(sequenceElement.elements().length, 0);

    byte[] encodedElement = sequenceElement.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { 0x30, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    sequenceElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, sequenceElement);

    ASN1Sequence decodedSequence =
         ASN1Sequence.decodeAsSequence(genericElement.encode());
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);
    assertEquals(decodedSequence.elements().length, 0);

    decodedSequence = ASN1Sequence.decodeAsSequence(genericElement);
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);
    assertEquals(decodedSequence.elements().length, 0);

    assertNotNull(sequenceElement.toString());
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
    ASN1Sequence sequenceElement = new ASN1Sequence(type);
    assertEquals(sequenceElement.getType(), type);
    assertEquals(sequenceElement.getValue().length, 0);
    assertEquals(sequenceElement.elements().length, 0);

    byte[] encodedElement = sequenceElement.encode();
    assertTrue(Arrays.equals(encodedElement, new byte[] { type, 0x00 }));

    ByteStringBuffer buffer = new ByteStringBuffer();
    sequenceElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, sequenceElement);

    ASN1Sequence decodedSequence =
         ASN1Sequence.decodeAsSequence(genericElement.encode());
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);
    assertEquals(decodedSequence.elements().length, 0);

    decodedSequence = ASN1Sequence.decodeAsSequence(genericElement);
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);
    assertEquals(decodedSequence.elements().length, 0);

    assertNotNull(sequenceElement.toString());
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
    ASN1Sequence sequenceElement = new ASN1Sequence(elements);
    assertEquals(sequenceElement.getType(), UNIVERSAL_SEQUENCE_TYPE);

    byte[] encodedElement = sequenceElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    sequenceElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, sequenceElement);

    ASN1Sequence decodedSequence =
         ASN1Sequence.decodeAsSequence(genericElement.encode());
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    decodedSequence = ASN1Sequence.decodeAsSequence(genericElement);
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    assertEquals(sequenceElement.elements().length,
                 decodedSequence.elements().length);
    for (int i=0; i < sequenceElement.elements().length; i++)
    {
      assertEquals(sequenceElement.elements()[i],
                   decodedSequence.elements()[i]);
    }

    assertNotNull(sequenceElement.toString());
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
    ASN1Sequence sequenceElement = new ASN1Sequence(elements);
    assertEquals(sequenceElement.getType(), UNIVERSAL_SEQUENCE_TYPE);

    byte[] encodedElement = sequenceElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    sequenceElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, sequenceElement);

    ASN1Sequence decodedSequence =
         ASN1Sequence.decodeAsSequence(genericElement.encode());
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    decodedSequence = ASN1Sequence.decodeAsSequence(genericElement);
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    assertEquals(sequenceElement.elements().length,
                 decodedSequence.elements().length);
    for (int i=0; i < sequenceElement.elements().length; i++)
    {
      assertEquals(sequenceElement.elements()[i],
                   decodedSequence.elements()[i]);
    }

    assertNotNull(sequenceElement.toString());
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
    ASN1Sequence sequenceElement = new ASN1Sequence((byte) 0x00, elements);
    assertEquals(sequenceElement.getType(), (byte) 0x00);

    byte[] encodedElement = sequenceElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    sequenceElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, sequenceElement);

    ASN1Sequence decodedSequence =
         ASN1Sequence.decodeAsSequence(genericElement.encode());
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    decodedSequence = ASN1Sequence.decodeAsSequence(genericElement);
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    assertEquals(sequenceElement.elements().length,
                 decodedSequence.elements().length);
    for (int i=0; i < sequenceElement.elements().length; i++)
    {
      assertEquals(sequenceElement.elements()[i],
                   decodedSequence.elements()[i]);
    }

    assertNotNull(sequenceElement.toString());
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
    ASN1Sequence sequenceElement = new ASN1Sequence((byte) 0x00, elements);
    assertEquals(sequenceElement.getType(), (byte) 0x00);

    byte[] encodedElement = sequenceElement.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    sequenceElement.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element genericElement = ASN1Element.decode(encodedElement);
    assertEquals(genericElement, sequenceElement);

    ASN1Sequence decodedSequence =
         ASN1Sequence.decodeAsSequence(genericElement.encode());
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    decodedSequence = ASN1Sequence.decodeAsSequence(genericElement);
    assertEquals(decodedSequence, sequenceElement);
    assertEquals(decodedSequence, genericElement);

    assertEquals(sequenceElement.elements().length,
                 decodedSequence.elements().length);
    for (int i=0; i < sequenceElement.elements().length; i++)
    {
      assertEquals(sequenceElement.elements()[i],
                   decodedSequence.elements()[i]);
    }

    assertNotNull(sequenceElement.toString());
  }



  /**
   * Tests the behavior of the {@code decodeAsSequence} method when the element
   * cannot be decoded as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeBytesInvalidSequence()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x00, new byte[1]);
    ASN1Sequence.decodeAsSequence(genericElement.encode());
  }



  /**
   * Tests the behavior of the {@code decodeAsSequence} method when the element
   * cannot be decoded as a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementInvalidSequence()
         throws Exception
  {
    ASN1Element genericElement = new ASN1Element((byte) 0x00, new byte[1]);
    ASN1Sequence.decodeAsSequence(genericElement);
  }



  /**
   * Tests the {@code decodeAsSequence} method with a byte array that is too
   * short to contain a valid ASN.1 element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSequenceTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01 };
    ASN1Sequence.decodeAsSequence(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSequence} method with a byte array that is too
   * with an array cut off in the middle of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSequenceTooShortWithMultiByteLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81 };
    ASN1Sequence.decodeAsSequence(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSequence} method with a byte array with a length
   * that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSequenceLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Sequence.decodeAsSequence(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSequence} method with a byte array with a
   * multi-byte length that does not match the size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSequenceMultiByteLengthMismatch()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x01, (byte) 0x81, (byte) 0x01, (byte) 0x00,
                            (byte) 0x00 };
    ASN1Sequence.decodeAsSequence(elementBytes);
  }



  /**
   * Tests the {@code decodeAsSequence} method with a byte array with an
   * embedded element with a value that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeAsSequenceEmbeddedElementTooLong()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x30, (byte) 0x02, (byte) 0x04,
                            (byte) 0x01 };
    ASN1Sequence.decodeAsSequence(elementBytes);
  }
}
