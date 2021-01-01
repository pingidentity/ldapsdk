/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code ASN1Buffer} class.
 */
public class ASN1BufferTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests with generic elements.
   *
   * @param  element  The element to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="genericElements")
  public void testGenericElement(final ASN1Element element)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);

    byte[] elementBytes = element.encode();

    b.addElement(element);
    assertEquals(b.length(), elementBytes.length);
    byte[] bufferBytes = b.toByteArray();
    assertEquals(bufferBytes.length, elementBytes.length);
    assertTrue(Arrays.equals(bufferBytes, elementBytes));

    assertEquals(b.length(), elementBytes.length);
    b.clear();
    assertEquals(b.length(), 0);

    b = new ASN1Buffer(1);

    b.addElement(element);

    ByteArrayOutputStream s = new ByteArrayOutputStream();
    b.writeTo(s);
    bufferBytes = s.toByteArray();
    assertEquals(bufferBytes.length, elementBytes.length);
    assertTrue(Arrays.equals(bufferBytes, elementBytes));

    ByteBuffer byteBuffer = b.asByteBuffer();
    assertEquals(byteBuffer.position(), 0);
    assertEquals(byteBuffer.limit(), elementBytes.length);

    assertEquals(b.length(), elementBytes.length);
    b.clear();
    assertEquals(b.length(), 0);
  }



  /**
   * Provides a set of generic ASN.1 elements for testing.
   *
   * @return  A set of generic ASN.1 elements for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="genericElements")
  public Object[][] getGenericElements()
         throws Exception
  {
    return new Object[][]
    {
      new Object[] { new ASN1Element((byte) 0x00) },
      new Object[] { new ASN1Element((byte) 0x04) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[0]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[1]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[127]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[128]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[129]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[255]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[256]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[257]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[65535]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[65536]) },
      new Object[] { new ASN1Element((byte) 0x04, new byte[65537]) },
      new Object[] { new ASN1Boolean(true) },
      new Object[] { new ASN1Boolean(false) },
      new Object[] { new ASN1Enumerated(0) },
      new Object[] { new ASN1Enumerated(1) },
      new Object[] { new ASN1Enumerated(123456789) },
      new Object[] { new ASN1Integer(-123456789) },
      new Object[] { new ASN1Integer(-1) },
      new Object[] { new ASN1Integer(0) },
      new Object[] { new ASN1Integer(1) },
      new Object[] { new ASN1Integer(123456789) },
      new Object[] { new ASN1Long(-1234567890123456789L) },
      new Object[] { new ASN1Long(-123456789L) },
      new Object[] { new ASN1Long(-1L) },
      new Object[] { new ASN1Long(0L) },
      new Object[] { new ASN1Long(1L) },
      new Object[] { new ASN1Long(123456789L) },
      new Object[] { new ASN1Long(1234567890123456789L) },
      new Object[] { new ASN1BigInteger(-1234567890123456789L) },
      new Object[] { new ASN1BigInteger(-123456789L) },
      new Object[] { new ASN1BigInteger(-1L) },
      new Object[] { new ASN1BigInteger(0L) },
      new Object[] { new ASN1BigInteger(1L) },
      new Object[] { new ASN1BigInteger(123456789L) },
      new Object[] { new ASN1BigInteger(1234567890123456789L) },
      new Object[] { new ASN1Null() },
      new Object[] { new ASN1OctetString() },
      new Object[] { new ASN1OctetString(new byte[0]) },
      new Object[] { new ASN1OctetString(new byte[1]) },
      new Object[] { new ASN1OctetString(new byte[65536]) },
      new Object[] { new ASN1Sequence() },
      new Object[] { new ASN1Sequence(new ASN1OctetString()) },
      new Object[] { new ASN1Sequence(new ASN1OctetString(new byte[65535])) },
      new Object[] { new ASN1Set() },
      new Object[] { new ASN1Set(new ASN1OctetString()) },
      new Object[] { new ASN1Set(new ASN1OctetString(new byte[65535])) },
    };
  }



  /**
   * Performs a set of tests with Boolean elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBooleanElements()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);


    ASN1Boolean booleanElement = ASN1Boolean.UNIVERSAL_BOOLEAN_TRUE_ELEMENT;
    byte[] elementBytes = booleanElement.encode();

    b.addBoolean(true);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    booleanElement = ASN1Boolean.UNIVERSAL_BOOLEAN_FALSE_ELEMENT;
    elementBytes = booleanElement.encode();

    b.clear();
    b.addBoolean(false);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    booleanElement = new ASN1Boolean((byte) 0x80, true);
    elementBytes = booleanElement.encode();

    b.clear();
    b.addBoolean((byte) 0x80, true);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    booleanElement = new ASN1Boolean((byte) 0x80, false);
    elementBytes = booleanElement.encode();

    b.clear();
    b.addBoolean((byte) 0x80, false);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with enumerated elements.
   *
   * @param  intValue  The integer value to use for the enumerated element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="integerValues")
  public void testEnumeratedElement(final int intValue)
         throws Exception
  {
    if (intValue < 0)
    {
      return;
    }

    ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);

    ASN1Enumerated enumeratedElement = new ASN1Enumerated(intValue);
    byte[] elementBytes = enumeratedElement.encode();

    b.addEnumerated(intValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    enumeratedElement = new ASN1Enumerated((byte) 0x80, intValue);
    elementBytes = enumeratedElement.encode();

    b.clear();
    b.addEnumerated((byte) 0x80, intValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with generalized time elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneralizedTimeElement()
         throws Exception
  {
    final ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);

    final Date d = new Date();
    final ASN1GeneralizedTime generalizedTimeElement =
         new ASN1GeneralizedTime(d);
    final byte[] elementBytes = generalizedTimeElement.encode();

    b.addGeneralizedTime(d);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));

    b.clear();
    b.addGeneralizedTime(d.getTime());
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with integer elements.
   *
   * @param  intValue  The integer value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="integerValues")
  public void testIntegerElement(final int intValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);

    ASN1Integer integerElement = new ASN1Integer(intValue);
    byte[] elementBytes = integerElement.encode();

    b.addInteger(intValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    integerElement = new ASN1Integer((byte) 0x80, intValue);
    elementBytes = integerElement.encode();

    b.clear();
    b.addInteger((byte) 0x80, intValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Provides a set of integer values for testing.
   *
   * @return  A set of integer values for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="integerValues")
  public Object[][] getIntegerValues()
         throws Exception
  {
    ArrayList<Integer> intList = new ArrayList<Integer>();
    intList.add(0);
    intList.add(1);
    intList.add(-1);
    intList.add(Integer.MAX_VALUE);
    intList.add(Integer.MAX_VALUE - 1);
    intList.add(Integer.MAX_VALUE - 2);
    intList.add(Integer.MIN_VALUE);
    intList.add(Integer.MIN_VALUE + 1);
    intList.add(Integer.MIN_VALUE + 2);

    for (int i=0; i < 31; i++)
    {
      double d = Math.pow(2, i);

      int intValue = (int) d;
      intList.add(intValue);
      intList.add(intValue+1);
      intList.add(intValue+2);
      intList.add(intValue-1);
      intList.add(intValue-2);

      intValue *= -1;
      intList.add(intValue);
      intList.add(intValue+1);
      intList.add(intValue+2);
      intList.add(intValue-1);
      intList.add(intValue-2);
    }

    Object[][] intArray = new Object[intList.size()][1];
    for (int i=0; i < intArray.length; i++)
    {
      intArray[i][0] = intList.get(i);
    }

    return intArray;
  }



  /**
   * Performs a set of tests with long elements.
   *
   * @param  longValue  The long value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="longValues")
  public void testLongElement(final long longValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);

    ASN1Long longElement = new ASN1Long(longValue);
    byte[] elementBytes = longElement.encode();

    b.addInteger(longValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    longElement = new ASN1Long((byte) 0x80, longValue);
    elementBytes = longElement.encode();

    b.clear();
    b.addInteger((byte) 0x80, longValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Provides a set of long values for testing.
   *
   * @return  A set of long values for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="longValues")
  public Object[][] getLongValues()
         throws Exception
  {
    ArrayList<Long> longList = new ArrayList<Long>();
    longList.add(0L);
    longList.add(1L);
    longList.add(-1L);
    longList.add(Long.MAX_VALUE);
    longList.add(Long.MAX_VALUE - 1);
    longList.add(Long.MAX_VALUE - 2);
    longList.add(Long.MIN_VALUE);
    longList.add(Long.MIN_VALUE + 1);
    longList.add(Long.MIN_VALUE + 2);
    longList.add((long) Integer.MAX_VALUE);
    longList.add((long) Integer.MAX_VALUE - 1);
    longList.add((long) Integer.MAX_VALUE - 2);
    longList.add((long) Integer.MIN_VALUE);
    longList.add((long) Integer.MIN_VALUE + 1);
    longList.add((long) Integer.MIN_VALUE + 2);

    for (int i=0; i < 63; i++)
    {
      double d = Math.pow(2, i);

      long longValue = (long) d;
      longList.add(longValue);
      longList.add(longValue+1);
      longList.add(longValue+2);
      longList.add(longValue-1);
      longList.add(longValue-2);

      longValue *= -1;
      longList.add(longValue);
      longList.add(longValue+1);
      longList.add(longValue+2);
      longList.add(longValue-1);
      longList.add(longValue-2);
    }

    Object[][] longArray = new Object[longList.size()][1];
    for (int i=0; i < longArray.length; i++)
    {
      longArray[i][0] = longList.get(i);
    }

    return longArray;
  }



  /**
   * Performs a set of tests with big integer elements.
   *
   * @param  longValue  The long value to use for the element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="longValues")
  public void testBigIntegerElement(final long longValue)
         throws Exception
  {
    final ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);

    ASN1BigInteger bigIntegerElement = new ASN1BigInteger(longValue);
    byte[] elementBytes = bigIntegerElement.encode();

    b.addInteger(BigInteger.valueOf(longValue));
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    bigIntegerElement = new ASN1BigInteger((byte) 0x80, longValue);
    elementBytes = bigIntegerElement.encode();

    b.clear();
    b.addInteger((byte) 0x80, BigInteger.valueOf(longValue));
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with null elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullElements()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);


    ASN1Null nullElement = ASN1Null.UNIVERSAL_NULL_ELEMENT;
    byte[] elementBytes = nullElement.encode();

    b.addNull();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    nullElement = new ASN1Null((byte) 0x80);
    elementBytes = nullElement.encode();

    b.clear();
    b.addNull((byte) 0x80);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with an empty octet string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOctetStringEmpty()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1OctetString octetStringElement = new ASN1OctetString();
    byte[] elementBytes = octetStringElement.encode();

    b.addOctetString();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    octetStringElement = new ASN1OctetString((byte) 0x80);
    elementBytes = octetStringElement.encode();

    b.clear();
    b.addOctetString((byte) 0x80);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with an octet string with a null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOctetStringNullValue()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1OctetString octetStringElement = new ASN1OctetString();
    byte[] elementBytes = octetStringElement.encode();

    b.addOctetString((byte[]) null);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    b.clear();
    b.addOctetString((StringBuilder) null);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    b.clear();
    b.addOctetString((String) null);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    octetStringElement = new ASN1OctetString((byte) 0x80);
    elementBytes = octetStringElement.encode();

    b.clear();
    b.addOctetString((byte) 0x80, (byte[]) null);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    b.clear();
    b.addOctetString((byte) 0x80, (StringBuilder) null);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    b.clear();
    b.addOctetString((byte) 0x80, (String) null);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with octet string elements using binary values.
   *
   * @param  element  The element to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="genericElements")
  public void testOctetStringBinary(final ASN1Element element)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1OctetString octetStringElement =
         new ASN1OctetString(element.getValue());
    byte[] elementBytes = octetStringElement.encode();

    b.addOctetString(element.getValue());
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    octetStringElement =
         new ASN1OctetString(element.getType(), element.getValue());
    elementBytes = octetStringElement.encode();

    b.clear();
    b.addOctetString(element.getType(), element.getValue());
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with octet string elements using string values.
   *
   * @param  stringValue  The string value to use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="stringValues")
  public void testOctetStringCharSequence(final String stringValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1OctetString octetStringElement = new ASN1OctetString(stringValue);
    byte[] elementBytes = octetStringElement.encode();

    b.addOctetString(new StringBuilder(stringValue));
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    octetStringElement = new ASN1OctetString((byte) 0x80, stringValue);
    elementBytes = octetStringElement.encode();

    b.clear();
    b.addOctetString((byte) 0x80, new StringBuilder(stringValue));
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Performs a set of tests with octet string elements using string values.
   *
   * @param  stringValue  The string value to use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="stringValues")
  public void testOctetStringString(final String stringValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1OctetString octetStringElement = new ASN1OctetString(stringValue);
    byte[] elementBytes = octetStringElement.encode();

    b.addOctetString(stringValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    octetStringElement = new ASN1OctetString((byte) 0x80, stringValue);
    elementBytes = octetStringElement.encode();

    b.clear();
    b.addOctetString((byte) 0x80, stringValue);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }



  /**
   * Provides a set of string values for testing.
   *
   * @return  The string values to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="stringValues")
  public Object[][] getStringValues()
         throws Exception
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { "a" },
      new Object[] { "aa" },
      new Object[] { "aaa" },
      new Object[] { "aaaa" },
      new Object[] { "aaaaa" },
      new Object[] { "aaaaaa" },
      new Object[] { "aaaaaaa" },
      new Object[] { "aaaaaaaa" },
      new Object[] { "aaaaaaaaa" },
      new Object[] { "aaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "\u00e9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaa\u00e9aaaaaaaaaaaaaaaaaaaaaaaa" },
      new Object[] { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u00e9" },
    };
  }



  /**
   * Performs a set of tests with sequence elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSequenceElements()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1Sequence sequenceElement = new ASN1Sequence();
    byte[] elementBytes = sequenceElement.encode();

    ASN1BufferSequence bufferSequence = b.beginSequence();
    bufferSequence.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    sequenceElement = new ASN1Sequence((byte) 0xA0);
    elementBytes = sequenceElement.encode();

    b.clear();
    bufferSequence = b.beginSequence((byte) 0xA0);
    bufferSequence.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));



    Object[][] genericElementsArray = getGenericElements();
    ASN1Element[] genericElements =
         new ASN1Element[genericElementsArray.length];
    for (int i=0; i < genericElements.length; i++)
    {
      genericElements[i] = (ASN1Element) genericElementsArray[i][0];
    }


    sequenceElement = new ASN1Sequence(genericElements);
    elementBytes = sequenceElement.encode();

    b.clear();
    bufferSequence = b.beginSequence();
    for (ASN1Element e : genericElements)
    {
      b.addElement(e);
    }
    bufferSequence.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    sequenceElement = new ASN1Sequence((byte) 0xA0, genericElements);
    elementBytes = sequenceElement.encode();

    b.clear();
    bufferSequence = b.beginSequence((byte) 0xA0);
    for (ASN1Element e : genericElements)
    {
      b.addElement(e);
    }
    bufferSequence.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    for (ASN1Element e : genericElements)
    {
      sequenceElement = new ASN1Sequence(e);
      elementBytes = sequenceElement.encode();

      b.clear();
      bufferSequence = b.beginSequence();
      b.addElement(e);
      bufferSequence.end();
      assertEquals(b.length(), elementBytes.length);
      assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


      sequenceElement = new ASN1Sequence((byte) 0xA0, e);
      elementBytes = sequenceElement.encode();

      b.clear();
      bufferSequence = b.beginSequence((byte) 0xA0);
      b.addElement(e);
      bufferSequence.end();
      assertEquals(b.length(), elementBytes.length);
      assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
    }
  }



  /**
   * Performs a set of tests with set elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetElements()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();

    assertEquals(b.length(), 0);
    b.clear();
    assertEquals(b.length(), 0);


    ASN1Set setElement = new ASN1Set();
    byte[] elementBytes = setElement.encode();

    ASN1BufferSet bufferSet = b.beginSet();
    bufferSet.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    setElement = new ASN1Set((byte) 0xA0);
    elementBytes = setElement.encode();

    b.clear();
    bufferSet = b.beginSet((byte) 0xA0);
    bufferSet.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));



    Object[][] genericElementsArray = getGenericElements();
    ASN1Element[] genericElements =
         new ASN1Element[genericElementsArray.length];
    for (int i=0; i < genericElements.length; i++)
    {
      genericElements[i] = (ASN1Element) genericElementsArray[i][0];
    }


    setElement = new ASN1Set(genericElements);
    elementBytes = setElement.encode();

    b.clear();
    bufferSet = b.beginSet();
    for (ASN1Element e : genericElements)
    {
      b.addElement(e);
    }
    bufferSet.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    setElement = new ASN1Set((byte) 0xA0, genericElements);
    elementBytes = setElement.encode();

    b.clear();
    bufferSet = b.beginSet((byte) 0xA0);
    for (ASN1Element e : genericElements)
    {
      b.addElement(e);
    }
    bufferSet.end();
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


    for (ASN1Element e : genericElements)
    {
      setElement = new ASN1Set(e);
      elementBytes = setElement.encode();

      b.clear();
      bufferSet = b.beginSet();
      b.addElement(e);
      bufferSet.end();
      assertEquals(b.length(), elementBytes.length);
      assertTrue(Arrays.equals(b.toByteArray(), elementBytes));


      setElement = new ASN1Set((byte) 0xA0, e);
      elementBytes = setElement.encode();

      b.clear();
      bufferSet = b.beginSet((byte) 0xA0);
      b.addElement(e);
      bufferSet.end();
      assertEquals(b.length(), elementBytes.length);
      assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
    }
  }



  /**
   * Performs a set of tests with UTC time elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUTCTimeElement()
         throws Exception
  {
    final ASN1Buffer b = new ASN1Buffer();
    assertEquals(b.length(), 0);

    final Date d = new Date();
    final ASN1UTCTime utcTimeElement = new ASN1UTCTime(d);
    final byte[] elementBytes = utcTimeElement.encode();

    b.addUTCTime(d);
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));

    b.clear();
    b.addUTCTime(d.getTime());
    assertEquals(b.length(), elementBytes.length);
    assertTrue(Arrays.equals(b.toByteArray(), elementBytes));
  }
}
