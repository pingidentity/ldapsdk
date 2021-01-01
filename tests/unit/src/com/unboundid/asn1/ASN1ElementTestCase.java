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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.GregorianCalendar;

import org.testng.annotations.Test;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the ASN1Element class.
 */
public class ASN1ElementTestCase
       extends ASN1TestCase
{
  /**
   * Tests the first constructor, which takes a BER type but no value.
   *
   * @param  type  The type to use for the test element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypes")
  public void testConstructor1(byte type)
         throws Exception
  {
    ASN1Element element = new ASN1Element(type);
    assertEquals(element.getType(), type);
    assertTrue(element.equals(element));
    assertTrue(element.equalsIgnoreType(element));

    byte[] encodedElement = element.encode();
    assertEquals(encodedElement.length, 2);

    ByteStringBuffer buffer = new ByteStringBuffer();
    element.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element decodedElement = ASN1Element.decode(encodedElement);
    assertEquals(decodedElement, element);
    assertEquals(decodedElement.getType(), type);

    assertTrue(element.equals(decodedElement));
    assertTrue(element.equalsIgnoreType(decodedElement));

    assertEquals(element.hashCode(), decodedElement.hashCode());


    ASN1Element elementWithDifferentType;
    if (type == 0x00)
    {
      elementWithDifferentType = new ASN1Element((byte) 0x01);
    }
    else
    {
      elementWithDifferentType = new ASN1Element((byte) 0x00);
    }
    assertFalse(element.equals(elementWithDifferentType));
    assertFalse(elementWithDifferentType.equals(element));
    assertTrue(element.equalsIgnoreType(elementWithDifferentType));
    assertTrue(elementWithDifferentType.equalsIgnoreType(element));


    ASN1Element elementWithNullValue = new ASN1Element(type, null);
    assertEquals(elementWithNullValue.getType(), type);
    assertTrue(elementWithNullValue.equals(element));
    assertTrue(elementWithNullValue.equalsIgnoreType(element));


    ASN1Element elementWithEmptyValue = new ASN1Element(type, new byte[0]);
    assertEquals(elementWithEmptyValue.getType(), type);
    assertTrue(elementWithEmptyValue.equals(element));
    assertTrue(elementWithEmptyValue.equalsIgnoreType(element));


    ASN1Element elementWithNonEmptyValue = new ASN1Element(type, new byte[1]);
    assertFalse(elementWithNonEmptyValue.equals(element));
    assertFalse(elementWithNonEmptyValue.equalsIgnoreType(element));

    assertNotNull(element.toString());
  }



  /**
   * Tests the second constructor, which takes both a type and value.
   *
   * @param  type   The type to use for the test element.
   * @param  value  The value to use for the test element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testConstructor2(byte type, byte[] value)
         throws Exception
  {
    ASN1Element element = new ASN1Element(type, value);
    assertEquals(element.getType(), type);
    if (value == null)
    {
      assertTrue(Arrays.equals(element.getValue(), new byte[0]));
    }
    else
    {
      assertTrue(Arrays.equals(element.getValue(), value));
    }

    byte[] encodedElement = element.encode();

    ByteStringBuffer buffer = new ByteStringBuffer();
    element.encodeTo(buffer);
    assertTrue(Arrays.equals(buffer.toByteArray(), encodedElement));

    ASN1Element decodedElement = ASN1Element.decode(encodedElement);
    assertEquals(decodedElement, element);
    assertEquals(decodedElement.getType(), type);
    if (value == null)
    {
      assertTrue(Arrays.equals(decodedElement.getValue(), new byte[0]));
    }
    else
    {
      assertTrue(Arrays.equals(decodedElement.getValue(), value));
    }

    assertTrue(element.equals(decodedElement));
    assertTrue(element.equalsIgnoreType(decodedElement));

    assertEquals(element.hashCode(), decodedElement.hashCode());

    assertNotNull(element.toString());
  }



  /**
   * Tests the {@code encodeLength} method with a number of different length
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeLength()
         throws Exception
  {
    for (int i=0; i <= 127; i++)
    {
      byte[] lengthBytes = ASN1Element.encodeLength(i);
      assertEquals(lengthBytes.length, 1);
      assertEquals(lengthBytes[0], (byte) i);
    }

    for (int i=128; i <= 255; i++)
    {
      byte[] lengthBytes = ASN1Element.encodeLength(i);
      assertEquals(lengthBytes.length, 2);
      assertTrue(Arrays.equals(lengthBytes,
                               new byte[] { (byte) 0x81, (byte) i }));
    }

    byte[] lengthBytes = ASN1Element.encodeLength(256);
    assertEquals(lengthBytes.length, 3);
    assertTrue(Arrays.equals(lengthBytes,
         new byte[] { (byte) 0x82, (byte) 0x01, (byte) 0x00 }));

    lengthBytes = ASN1Element.encodeLength(65535);
    assertEquals(lengthBytes.length, 3);
    assertTrue(Arrays.equals(lengthBytes,
         new byte[] { (byte) 0x82, (byte) 0xFF, (byte) 0xFF }));

    lengthBytes = ASN1Element.encodeLength(65536);
    assertEquals(lengthBytes.length, 4);
    assertTrue(Arrays.equals(lengthBytes,
         new byte[] { (byte) 0x83, (byte) 0x01, (byte) 0x00, (byte) 0x00 }));

    lengthBytes = ASN1Element.encodeLength(16777215);
    assertEquals(lengthBytes.length, 4);
    assertTrue(Arrays.equals(lengthBytes,
         new byte[] { (byte) 0x83, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }));

    lengthBytes = ASN1Element.encodeLength(16777216);
    assertEquals(lengthBytes.length, 5);
    assertTrue(Arrays.equals(lengthBytes,
         new byte[] { (byte) 0x84, (byte) 0x01, (byte) 0x00, (byte) 0x00,
                      (byte) 0x00 }));
  }



  /**
   * Tests the {@code encodeLengthTo} method with a number of different length
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncodeLengthTo()
         throws Exception
  {
    for (int i=0; i <= 256; i++)
    {
      ByteStringBuffer buffer = new ByteStringBuffer();
      ASN1Element.encodeLengthTo(i, buffer);
      byte[] lengthBytes = buffer.toByteArray();

      assertTrue(Arrays.equals(lengthBytes, ASN1Element.encodeLength(i)));
    }

    int[] values = { 65535, 65536, 16777215, 16777216 };
    for (int i : values)
    {
      ByteStringBuffer buffer = new ByteStringBuffer();
      ASN1Element.encodeLengthTo(i, buffer);
      byte[] lengthBytes = buffer.toByteArray();

      assertTrue(Arrays.equals(lengthBytes, ASN1Element.encodeLength(i)));
    }
  }



  /**
   * Tests to ensure that an exception is thrown when an attempt is made to
   * decode an element that doesn't have enough bytes to complete the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeTooShort()
         throws Exception
  {
    byte[] encodedElement =
    {
      0x04,
      0x01
    };

    ASN1Element.decode(encodedElement);
  }



  /**
   * Tests to ensure that an exception is thrown when an attempt is made to
   * decode an element that has more bytes available than indicated by the
   * length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeTooLong()
         throws Exception
  {
    byte[] encodedElement =
    {
      0x04,
      0x01,
      0x00,
      0x00
    };

    ASN1Element.decode(encodedElement);
  }



  /**
   * Tests the {@code writeTo} and {@code readFrom} methods.
   *
   * @param  type   The type to use for the test element.
   * @param  value  The value to use for the test element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testTypesAndValues")
  public void testWriteAndRead(byte type, byte[] value)
         throws Exception
  {
    ASN1Element element = new ASN1Element(type, value);

    File targetFile = File.createTempFile("testTypesAndValues", ".ber");
    targetFile.deleteOnExit();

    FileOutputStream outputStream = new FileOutputStream(targetFile);
    element.writeTo(outputStream);
    outputStream.close();

    FileInputStream inputStream = new FileInputStream(targetFile);
    ASN1Element decodedElement = ASN1Element.readFrom(inputStream);
    assertNotNull(decodedElement);
    assertEquals(element, decodedElement);

    assertNull(ASN1Element.readFrom(inputStream));
    inputStream.close();
  }



  /**
   * Tests the {@code readFrom} method in which the end of the stream is
   * reached after the type and before reading any of the length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadFromEndAfterType()
         throws Exception
  {
    byte[] b = new byte[] { 0x04 };
    ASN1Element.readFrom(new ByteArrayInputStream(b));
  }



  /**
   * Tests the {@code readFrom} method in which too many bytes are used to
   * represent the length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadFromLengthTooLong()
         throws Exception
  {
    byte[] b = new byte[] { 0x04, (byte) 0x85, 0x00, 0x00, 0x00, 0x00, 0x00 };
    ASN1Element.readFrom(new ByteArrayInputStream(b));
  }



  /**
   * Tests the {@code readFrom} method in which there are not enough bytes to
   * read the entire length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadFromEndInLength()
         throws Exception
  {
    byte[] b = new byte[] { 0x04, (byte) 0x81 };
    ASN1Element.readFrom(new ByteArrayInputStream(b));
  }



  /**
   * Tests the {@code readFrom} method in which there are more than the maximum
   * allowed number of bytes in the length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadFromValueTooLong()
         throws Exception
  {
    byte[] b = new byte[] { 0x04, (byte) 0x04, 0x00, 0x00, 0x00, 0x00 };
    ASN1Element.readFrom(new ByteArrayInputStream(b), 3);
  }



  /**
   * Tests the {@code readFrom} method in which there are not enough bytes to
   * contain the entire value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadFromEndInValue()
         throws Exception
  {
    byte[] b = new byte[] { 0x04, (byte) 0x04, 0x00, 0x00, 0x00 };
    ASN1Element.readFrom(new ByteArrayInputStream(b));
  }



  /**
   * Tests the {@code equals} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertFalse(e.equals(null));
  }



  /**
   * Tests the {@code equals} method with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equals(e));
  }



  /**
   * Tests the {@code equals} method with an equivalent object of exactly the
   * same type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentSameType()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equals(new ASN1Element((byte) 0x04)));
  }



  /**
   * Tests the {@code equals} method with an equivalent object of a different
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalentDifferentType()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equals(new ASN1OctetString()));
  }



  /**
   * Tests the {@code equals} method with an object that is not an ASN.1
   * element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsInvalidObjectType()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertFalse(e.equals("foo"));
  }



  /**
   * Tests the {@code equals} method with an ASN.1 element with the same type
   * but a different value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSameTypeDifferentValue()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertFalse(e.equals(new ASN1Element((byte) 0x04, new byte[1])));
  }



  /**
   * Tests the {@code equals} method with an ASN.1 element with different types
   * but the same value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentTypeSameValue()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertFalse(e.equals(new ASN1Element((byte) 0x03)));
  }



  /**
   * Tests the {@code equalsIgnoreType} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreTypeNull()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertFalse(e.equalsIgnoreType(null));
  }



  /**
   * Tests the {@code equalsIgnoreType} method with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreTypeIdentity()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equalsIgnoreType(e));
  }



  /**
   * Tests the {@code equalsIgnoreType} method with an equivalent object of
   * exactly the same type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreTypeEquivalentSameType()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equalsIgnoreType(new ASN1Element((byte) 0x04)));
  }



  /**
   * Tests the {@code equalsIgnoreType} method with an equivalent object of a
   * different type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreTypeEquivalentDifferentType()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equalsIgnoreType(new ASN1OctetString()));
  }



  /**
   * Tests the {@code equalsIgnoreType} method with an ASN.1 element with the
   * same type but a different value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreTypeSameTypeDifferentValue()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertFalse(e.equalsIgnoreType(new ASN1Element((byte) 0x04, new byte[1])));
  }



  /**
   * Tests the {@code equalsIgnoreType} method with an ASN.1 element with
   * different types but the same value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIgnoreTypeDifferentTypeSameValue()
         throws Exception
  {
    ASN1Element e = new ASN1Element((byte) 0x04);
    assertTrue(e.equalsIgnoreType(new ASN1Element((byte) 0x03)));
  }



  /**
   * Tests the {@code decodeAsBoolean} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsBoolean()
         throws Exception
  {
    ASN1Boolean b = new ASN1Boolean(true);
    ASN1Element e = ASN1Element.decode(b.encode());
    assertEquals(b.decodeAsBoolean().booleanValue(), true);
  }



  /**
   * Tests the {@code decodeAsEnumerated} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsEnumerated()
         throws Exception
  {
    ASN1Enumerated enumerated = new ASN1Enumerated(1234);
    ASN1Element element = ASN1Element.decode(enumerated.encode());
    assertEquals(element.decodeAsEnumerated().intValue(), 1234);
  }



  /**
   * Tests the {@code decodeAsGeneralizedTime} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsGeneralizedTime()
         throws Exception
  {
    final long time = System.currentTimeMillis();

    final ASN1GeneralizedTime generalizedTime = new ASN1GeneralizedTime(time);
    final ASN1Element element = ASN1Element.decode(generalizedTime.encode());
    assertEquals(element.decodeAsGeneralizedTime().getTime(), time);
  }



  /**
   * Tests the {@code decodeAsInteger} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsInteger()
         throws Exception
  {
    ASN1Integer i = new ASN1Integer(5678);
    ASN1Element e = ASN1Element.decode(i.encode());
    assertEquals(e.decodeAsInteger().intValue(), 5678);
  }



  /**
   * Tests the {@code decodeAsLong} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsLong()
         throws Exception
  {
    ASN1Long l = new ASN1Long(8765L);
    ASN1Element e = ASN1Element.decode(l.encode());
    assertEquals(e.decodeAsLong().longValue(), 8765L);
  }



  /**
   * Tests the {@code decodeAsBigInteger} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsBigInteger()
         throws Exception
  {
    final ASN1BigInteger i = new ASN1BigInteger(8765L);
    final ASN1Element e = ASN1Element.decode(i.encode());
    assertEquals(e.decodeAsBigInteger().getBigIntegerValue().longValue(),
         8765L);
  }



  /**
   * Tests the {@code decodeAsNull} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsNull()
         throws Exception
  {
    ASN1Null n = new ASN1Null();
    ASN1Element e = ASN1Element.decode(n.encode());
    e.decodeAsNull();
  }



  /**
   * Tests the {@code decodeAsOctetString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsOctetString()
         throws Exception
  {
    ASN1OctetString s = new ASN1OctetString("foo");
    ASN1Element e = ASN1Element.decode(s.encode());
    assertEquals(e.decodeAsOctetString().stringValue(), "foo");
  }



  /**
   * Tests the {@code decodeAsSequence} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsSequence()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString("bar")
    };

    ASN1Sequence s = new ASN1Sequence(elements);
    ASN1Element e = ASN1Element.decode(s.encode());
    assertEquals(e.decodeAsSequence().elements().length, 2);
  }



  /**
   * Tests the {@code decodeAsSet} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsSet()
         throws Exception
  {
    ASN1Element[] elements =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString("bar")
    };

    ASN1Set s = new ASN1Set(elements);
    ASN1Element e = ASN1Element.decode(s.encode());
    assertEquals(e.decodeAsSet().elements().length, 2);
  }



  /**
   * Tests the {@code decodeAsUTCTime} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeAsUTCTime()
         throws Exception
  {
    final GregorianCalendar calendar =
         new GregorianCalendar(StaticUtils.getUTCTimeZone());
    calendar.set(GregorianCalendar.MILLISECOND, 0);

    final long time = calendar.getTimeInMillis();

    final ASN1UTCTime utcTime = new ASN1UTCTime(time);
    final ASN1Element element = ASN1Element.decode(utcTime.encode());
    assertEquals(element.decodeAsUTCTime().getTime(), time);
  }



  /**
   * Tests the {@code getTypeClass} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetTypeClass()
         throws Exception
  {
    final ASN1OctetString universalElement =
         new ASN1OctetString((byte) 0x04, "univesral");
    assertEquals(universalElement.getTypeClass(),
         ASN1Constants.TYPE_MASK_UNIVERSAL_CLASS);

    final ASN1OctetString applicationElement =
         new ASN1OctetString((byte) 0x44, "application");
    assertEquals(applicationElement.getTypeClass(),
         ASN1Constants.TYPE_MASK_APPLICATION_CLASS);

    final ASN1OctetString contextSpecificElement =
         new ASN1OctetString((byte) 0x84, "context-specific");
    assertEquals(contextSpecificElement.getTypeClass(),
         ASN1Constants.TYPE_MASK_CONTEXT_SPECIFIC_CLASS);

    final ASN1OctetString privateElement =
         new ASN1OctetString((byte) 0xC4, "private");
    assertEquals(privateElement.getTypeClass(),
         ASN1Constants.TYPE_MASK_PRIVATE_CLASS);
  }



  /**
   * Tests the {@code isConstructed} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIsConstructed()
         throws Exception
  {
    assertFalse(new ASN1Boolean(false).isConstructed());
    assertFalse(new ASN1Enumerated(0).isConstructed());
    assertFalse(new ASN1GeneralizedTime().isConstructed());
    assertFalse(new ASN1Integer(0).isConstructed());
    assertFalse(new ASN1Long(0L).isConstructed());
    assertFalse(new ASN1BigInteger(0L).isConstructed());
    assertFalse(new ASN1Null().isConstructed());
    assertFalse(new ASN1OctetString("foo").isConstructed());
    assertFalse(new ASN1UTCTime().isConstructed());

    assertTrue(new ASN1Sequence().isConstructed());
    assertTrue(new ASN1Sequence(new ASN1OctetString("foo")).isConstructed());
    assertTrue(new ASN1Sequence(new ASN1OctetString("foo"),
         new ASN1OctetString("bar")).isConstructed());

    assertTrue(new ASN1Set().isConstructed());
    assertTrue(new ASN1Set(new ASN1OctetString("foo")).isConstructed());
    assertTrue(new ASN1Set(new ASN1OctetString("foo"),
         new ASN1OctetString("bar")).isConstructed());
  }
}
