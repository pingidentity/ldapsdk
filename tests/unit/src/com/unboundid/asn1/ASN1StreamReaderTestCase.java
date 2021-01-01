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



import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code ASN1StreamReader}
 * class.
 */
public class ASN1StreamReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to read from an empty input stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyInputStream()
         throws Exception
  {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream, -1);

    assertEquals(reader.peek(), -1);
    assertNull(reader.readElement());
    reader.close();

    assertEquals(reader.getTotalBytesRead(), 0);
  }



  /**
   * Tests the behavior when trying to read from an input stream that contains
   * only a type but no length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInputStreamContainsOnlyType()
         throws Exception
  {
    ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[1]);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(reader.readElement());
  }



  /**
   * Tests the behavior when trying to read from an input stream that contains
   * only part of a multi-byte length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInputStreamContainsOnlyPartialLength()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x00, (byte) 0x81 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(reader.readElement());
  }



  /**
   * Tests the behavior when trying to read from an input stream that contains
   * a multi-byte length that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInputStreamContainsMultiByteLengthTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x00, (byte) 0x80 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(reader.readElement());
  }



  /**
   * Tests the behavior when trying to read from an input stream that contains
   * a multi-byte length that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInputStreamContainsMultiByteLengthTooLong()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x00, (byte) 0x85 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(reader.readElement());
  }



  /**
   * Tests the behavior when trying to read from an input stream with an element
   * length that is greater than the maximum allowed element size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testInputStreamContainsElementExceedingMaxSize()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x00, (byte) 0x7F };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream, 100);

    assertNull(reader.readElement());
  }



  /**
   * Tests the behavior when trying to read from an input stream that doesn't
   * have enough bytes for the full value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testNotEnoughValueBytes()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x00, (byte) 0x02, (byte) 0x01 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertNull(reader.readElement());
  }



  /**
   * Tests the {@code readElement} method.
   *
   * @param  element  The ASN.1 element to use for the tests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="genericElements")
  public void testReadElement(final ASN1Element element)
         throws Exception
  {
    byte[] elementBytes = element.encode();

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.peek(), (element.getType() & 0xFF));

    ASN1Element e = reader.readElement();
    assertNotNull(e);
    assertEquals(e, element);
    assertEquals(e.encode().length, elementBytes.length);
    assertTrue(Arrays.equals(e.encode(), elementBytes));

    assertEquals(reader.peek(), -1);
    assertNull(reader.readElement());
    reader.close();

    assertEquals(reader.getTotalBytesRead(), (long) elementBytes.length);
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
      new Object[] { new ASN1GeneralizedTime() },
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
      new Object[] { new ASN1UTCTime() }
    };
  }



  /**
   * Tests the ability to read valid Boolean elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void readValidBooleanElements()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    b.addBoolean(true);
    b.addBoolean((byte) 0x80, true);
    b.addBoolean(false);
    b.addBoolean((byte) 0x80, false);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertTrue(reader.readBoolean());
    assertTrue(reader.readBoolean());
    assertFalse(reader.readBoolean());
    assertFalse(reader.readBoolean());
    assertNull(reader.readBoolean());
  }



  /**
   * Tests the behavior when trying to read a Boolean element in which the end
   * of the stream is reached before the end of the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadBooleanElementMissingValue()
         throws Exception
  {
    byte[] dataBytes = { (byte) 0x01, (byte) 0x01 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(dataBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBoolean();
  }



  /**
   * Tests the behavior when trying to read a Boolean element with an invalid
   * length that isn't long enough.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadBooleanElementInvalidLengthTooShort()
         throws Exception
  {
    byte[] dataBytes = { (byte) 0x01, (byte) 0x00 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(dataBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBoolean();
  }



  /**
   * Tests the behavior when trying to read a Boolean element with an invalid
   * length that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadBooleanElementInvalidLengthTooLong()
         throws Exception
  {
    byte[] dataBytes = { (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x00 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(dataBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBoolean();
  }



  /**
   * Tests the behavior when trying to read a Boolean element with an invalid
   * length that is too long and not enough bytes in the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadBooleanElementInvalidLengthTooLongNotEnoughValueBytes()
         throws Exception
  {
    byte[] dataBytes = { (byte) 0x01, (byte) 0x02, (byte) 0x00, };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(dataBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBoolean();
  }



  /**
   * Tests the ability to read valid enumerated elements.
   *
   * @param  intValue  The value to use for the enumerated element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="integerValues")
  public void readValidEnumeratedElements(final int intValue)
         throws Exception
  {
    if (intValue < 0)
    {
      return;
    }

    ASN1Buffer b = new ASN1Buffer();
    b.addEnumerated(intValue);
    b.addEnumerated((byte) 0x80, intValue);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readEnumerated(), Integer.valueOf(intValue));
    assertEquals(reader.readEnumerated(), Integer.valueOf(intValue));
    assertNull(reader.readEnumerated());
  }



  /**
   * Tests the ability to read generalized time elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void readValidGeneralizedTimeElement()
         throws Exception
  {
    final Date d = new Date();
    final long t = d.getTime();

    final ASN1Buffer b = new ASN1Buffer();
    b.addGeneralizedTime(d);
    b.addGeneralizedTime((byte) 0x80, d);
    b.addGeneralizedTime(t);
    b.addGeneralizedTime((byte) 0x80, t);

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readGeneralizedTime(), d);
    assertEquals(reader.readGeneralizedTime(), d);
    assertEquals(reader.readGeneralizedTime(), d);
    assertEquals(reader.readGeneralizedTime(), d);
    assertNull(reader.readGeneralizedTime());
  }



  /**
   * Tests the behavior when trying to read a generalized time value when the
   * input stream doesn't have enough data for the complete element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void readGeneralizedTimeElementNotEnoughBytesForValue()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x18, (byte) 0x02, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readGeneralizedTime();
  }



  /**
   * Tests the behavior when trying to read a generalized time value when the
   * element read is too short to be a valid generalized time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void readGeneralizedTimeElementValueTooShort()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x18, (byte) 0x01, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readGeneralizedTime();
  }



  /**
   * Tests the ability to read valid integer elements.
   *
   * @param  intValue  The value to use for the integer element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="integerValues")
  public void readValidIntegerElements(final int intValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    b.addInteger(intValue);
    b.addInteger((byte) 0x80, intValue);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readInteger(), Integer.valueOf(intValue));
    assertEquals(reader.readInteger(), Integer.valueOf(intValue));
    assertNull(reader.readInteger());
  }



  /**
   * Tests the behavior when trying to read an integer element that does not
   * have enough bytes for the full length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadIntegerNotEnoughBytesForValue()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x02, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readInteger();
  }



  /**
   * Tests the behavior when trying to read an integer element with a length
   * that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadIntegerLengthTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readInteger();
  }



  /**
   * Tests the behavior when trying to read an integer element with a length
   * that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadIntegerLengthTooLong()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x05, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readInteger();
  }



  /**
   * Tests the behavior when trying to read an integer element with a length
   * that is too long and not enough bytes for the full length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadIntegerLengthTooLongNotEnoughBytesForValue()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x05, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readInteger();
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
   * Tests the ability to read valid long elements.
   *
   * @param  longValue  The value to use for the long element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="longValues")
  public void readValidLongElements(final long longValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    b.addInteger(longValue);
    b.addInteger((byte) 0x80, longValue);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readLong(), Long.valueOf(longValue));
    assertEquals(reader.readLong(), Long.valueOf(longValue));
    assertNull(reader.readLong());
  }



  /**
   * Tests the behavior when trying to read a long element that does not
   * have enough bytes for the full length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadLongNotEnoughBytesForValue()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x02, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readLong();
  }



  /**
   * Tests the behavior when trying to read a long element with a length
   * that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadLongLengthTooShort()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readLong();
  }



  /**
   * Tests the behavior when trying to read a long element with a length
   * that is too long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadLongLengthTooLong()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x09, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readInteger();
  }



  /**
   * Tests the behavior when trying to read a long element with a length
   * that is too long and not enough bytes for the full length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadLongLengthTooLongNotEnoughBytesForValue()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x02, (byte) 0x09, (byte) 0x00 };

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readInteger();
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
   * Tests the ability to read valid big integer elements.
   *
   * @param  longValue  The value to use for the long element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="longValues")
  public void readValidBigIntegerElements(final long longValue)
         throws Exception
  {
    final BigInteger bigIntegerValue = BigInteger.valueOf(longValue);

    final ASN1Buffer b = new ASN1Buffer();
    b.addInteger(bigIntegerValue);
    b.addInteger((byte) 0x80, bigIntegerValue);

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readBigInteger(), bigIntegerValue);
    assertEquals(reader.readBigInteger(), bigIntegerValue);
    assertNull(reader.readBigInteger());
  }



  /**
   * Tests the behavior when trying to read a big integer element that does not
   * have enough bytes for the full length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadBigIntegerNotEnoughBytesForValue()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x02, (byte) 0x02, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBigInteger();
  }



  /**
   * Tests the behavior when trying to read a big integer element with a length
   * that is too short.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadBigIntegerLengthTooShort()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x02, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBigInteger();
  }



  /**
   * Tests the behavior when trying to read a big integer element with a length
   * that is too long and not enough bytes for the full length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadBigIntegerLengthTooLongNotEnoughBytesForValue()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x02, (byte) 0x09, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBigInteger();
  }



  /**
   * Tests the ability to read valid null elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void readValidNullElements()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    b.addNull();
    b.addNull((byte) 0x80);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readNull();
    reader.readNull();
    reader.readNull();
  }



  /**
   * Tests the behavior when trying to read a null element with a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadNullWithValue()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x05, (byte) 0x01, (byte) 0x00 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readNull();
  }



  /**
   * Tests the behavior when trying to read a null element with a value and not
   * enough bytes for the full value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadNullWithValueNotEnoughBytes()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x05, (byte) 0x01 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readNull();
  }



  /**
   * Tests the ability to read valid octet string elements as byte arrays.
   *
   * @param  element  The element to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="genericElements")
  public void readValidOctetStringBytes(final ASN1Element element)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    b.addOctetString(element.getValue());
    b.addOctetString(element.getType(), element.getValue());

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertTrue(Arrays.equals(reader.readBytes(), element.getValue()));
    assertTrue(Arrays.equals(reader.readBytes(), element.getValue()));
    assertNull(reader.readBytes());
  }



  /**
   * Tests the behavior when trying to read an octet string in which there are
   * not enough bytes for the indicated value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadOctetStringBytesNotEnoughValueBytes()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x04, 0x01 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readBytes();
  }



  /**
   * Tests the ability to read valid octet string elements as strings.
   *
   * @param  stringValue  The string value to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="stringValues")
  public void readValidOctetStringStrings(final String stringValue)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    b.addOctetString(stringValue);
    b.addOctetString((byte) 0x80, stringValue);

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readString(), stringValue);
    assertEquals(reader.readString(), stringValue);
    assertNull(reader.readString());
  }



  /**
   * Tests the behavior when trying to read an octet string in which there are
   * not enough bytes for the indicated value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testReadOctetStringStringNotEnoughValueBytes()
         throws Exception
  {
    byte[] elementBytes = { (byte) 0x04, 0x01 };

    ByteArrayInputStream inputStream = new ByteArrayInputStream(elementBytes);
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readString();
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
   * Tests the behavior when trying to read an empty sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySequence()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence();
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSequence seq = reader.beginSequence();

    assertFalse(seq.hasMoreElements());
    assertEquals(seq.getType(), ASN1Constants.UNIVERSAL_SEQUENCE_TYPE);
    assertTrue(seq.getLength() == 0);

    assertNull(reader.readElement());
    assertNull(reader.beginSequence());
  }



  /**
   * Tests the behavior when trying to a sequence containing a single element.
   *
   * @param  element  The element to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="genericElements")
  public void testSingleElementSequence(final ASN1Element element)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence();
    b.addElement(element);
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSequence seq = reader.beginSequence();
    assertEquals(seq.getType(), ASN1Constants.UNIVERSAL_SEQUENCE_TYPE);
    assertTrue(seq.getLength() > 0);
    assertTrue(seq.hasMoreElements());

    ASN1Element e = reader.readElement();
    assertEquals(e, element);

    assertFalse(seq.hasMoreElements());
    assertNull(reader.readElement());
    assertNull(reader.beginSequence());
  }



  /**
   * Tests the behavior when trying to a sequence containing multiple elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiElementSequence()
         throws Exception
  {
    int elementCount = 0;

    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence();
    for (Object[] o : getGenericElements())
    {
      b.addElement((ASN1Element) o[0]);
      elementCount++;
    }
    s.end();


    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSequence seq = reader.beginSequence();

    while (seq.hasMoreElements())
    {
      assertNotNull(reader.readElement());
      elementCount--;
    }

    assertEquals(elementCount, 0);
    assertNull(reader.readElement());
    assertNull(reader.beginSequence());
  }



  /**
   * Tests the behavior when trying to read beyond the end of a sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadBeyondSequenceEnd()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSequence s = b.beginSequence();
    for (Object[] o : getGenericElements())
    {
      b.addElement((ASN1Element) o[0]);
    }
    s.end();
    b.addNull();


    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSequence seq = reader.beginSequence();

    while (seq.hasMoreElements())
    {
      assertNotNull(reader.readElement());
    }

    assertNotNull(reader.readElement());
    seq.hasMoreElements();
  }



  /**
   * Tests the behavior when trying to read an empty set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySet()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSet s = b.beginSet();
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSet set = reader.beginSet();

    assertFalse(set.hasMoreElements());
    assertEquals(set.getType(), ASN1Constants.UNIVERSAL_SET_TYPE);
    assertTrue(set.getLength() == 0);

    assertNull(reader.readElement());
    assertNull(reader.beginSet());
  }



  /**
   * Tests the behavior when trying to a set containing a single element.
   *
   * @param  element  The element to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="genericElements")
  public void testSingleElementSet(final ASN1Element element)
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSet s = b.beginSet();
    b.addElement(element);
    s.end();

    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSet set = reader.beginSet();
    assertEquals(set.getType(), ASN1Constants.UNIVERSAL_SET_TYPE);
    assertTrue(set.getLength() > 0);
    assertTrue(set.hasMoreElements());

    ASN1Element e = reader.readElement();
    assertEquals(e, element);

    assertFalse(set.hasMoreElements());
    assertNull(reader.readElement());
    assertNull(reader.beginSet());
  }



  /**
   * Tests the behavior when trying to a set containing multiple elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiElementSet()
         throws Exception
  {
    int elementCount = 0;

    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSet s = b.beginSet();
    for (Object[] o : getGenericElements())
    {
      b.addElement((ASN1Element) o[0]);
      elementCount++;
    }
    s.end();


    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSet set = reader.beginSet();

    while (set.hasMoreElements())
    {
      assertNotNull(reader.readElement());
      elementCount--;
    }

    assertEquals(elementCount, 0);
    assertNull(reader.readElement());
    assertNull(reader.beginSet());
  }



  /**
   * Tests the behavior when trying to read beyond the end of a set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testReadBeyondSetEnd()
         throws Exception
  {
    ASN1Buffer b = new ASN1Buffer();
    ASN1BufferSet s = b.beginSet();
    for (Object[] o : getGenericElements())
    {
      b.addElement((ASN1Element) o[0]);
    }
    s.end();
    b.addNull();


    ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    ASN1StreamReaderSet set = reader.beginSet();

    while (set.hasMoreElements())
    {
      assertNotNull(reader.readElement());
    }

    assertNotNull(reader.readElement());
    set.hasMoreElements();
  }



  /**
   * Provides test coverage for elements read from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValuesReadFromFile()
         throws Exception
  {
    File f = createTempFile();
    FileOutputStream os = new FileOutputStream(f);

    new ASN1Element((byte) 0x00).writeTo(os);
    new ASN1Boolean(true).writeTo(os);
    new ASN1Boolean(false).writeTo(os);
    new ASN1Enumerated(0).writeTo(os);
    new ASN1Integer(0).writeTo(os);
    new ASN1Long(0L).writeTo(os);
    new ASN1BigInteger(0L).writeTo(os);
    new ASN1Null().writeTo(os);
    new ASN1OctetString().writeTo(os);
    new ASN1Sequence().writeTo(os);
    new ASN1Set().writeTo(os);

    os.flush();
    os.close();

    ASN1StreamReader reader = new ASN1StreamReader(new FileInputStream(f));
    while (true)
    {
      ASN1Element e = reader.readElement();
      if (e == null)
      {
        break;
      }
    }

    reader.close();
    f.delete();
  }



  /**
   * Provides test coverage for the get and set socket timeout exception
   * methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings({"deprecation"})
  public void testIgnoreSocketTimeoutException()
         throws Exception
  {
    ASN1StreamReader reader =
         new ASN1StreamReader(new ByteArrayInputStream(new byte[0]));

    assertFalse(reader.ignoreSocketTimeoutException());
    assertFalse(reader.ignoreInitialSocketTimeoutException());
    assertFalse(reader.ignoreSubsequentSocketTimeoutException());

    reader.setIgnoreSocketTimeout(true);
    assertTrue(reader.ignoreSocketTimeoutException());
    assertTrue(reader.ignoreInitialSocketTimeoutException());
    assertTrue(reader.ignoreSubsequentSocketTimeoutException());

    reader.setIgnoreSocketTimeout(false);
    assertFalse(reader.ignoreSocketTimeoutException());
    assertFalse(reader.ignoreInitialSocketTimeoutException());
    assertFalse(reader.ignoreSubsequentSocketTimeoutException());

    reader.setIgnoreSocketTimeout(true, false);
    assertTrue(reader.ignoreSocketTimeoutException());
    assertTrue(reader.ignoreInitialSocketTimeoutException());
    assertFalse(reader.ignoreSubsequentSocketTimeoutException());

    reader.setIgnoreSocketTimeout(false, true);
    assertFalse(reader.ignoreSocketTimeoutException());
    assertFalse(reader.ignoreInitialSocketTimeoutException());
    assertTrue(reader.ignoreSubsequentSocketTimeoutException());

    reader.setIgnoreSocketTimeout(false, false);
    assertFalse(reader.ignoreSocketTimeoutException());
    assertFalse(reader.ignoreInitialSocketTimeoutException());
    assertFalse(reader.ignoreSubsequentSocketTimeoutException());
  }



  /**
   * Tests the ability to read UTC time elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void readValidUTCTimeElement()
         throws Exception
  {
    final GregorianCalendar calendar =
         new GregorianCalendar(StaticUtils.getUTCTimeZone());
    calendar.set(GregorianCalendar.MILLISECOND, 0);

    final long t = calendar.getTimeInMillis();
    final Date d = new Date(t);

    final ASN1Buffer b = new ASN1Buffer();
    b.addUTCTime(t);
    b.addUTCTime((byte) 0x80, t);
    b.addUTCTime(d);
    b.addUTCTime((byte) 0x80, d);

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(b.toByteArray());
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    assertEquals(reader.readUTCTime(), d);
    assertEquals(reader.readUTCTime(), d);
    assertEquals(reader.readUTCTime(), d);
    assertEquals(reader.readUTCTime(), d);
    assertNull(reader.readUTCTime());
  }



  /**
   * Tests the behavior when trying to read a UTC time value when the input
   * stream doesn't have enough data for the complete element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void readUTCTimeElementNotEnoughBytesForValue()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x19, (byte) 0x02, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readUTCTime();
  }



  /**
   * Tests the behavior when trying to read a UTC time value when the element
   * read is too short to be a valid UTC time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void readUTCTimeElementValueTooShort()
         throws Exception
  {
    final byte[] elementBytes = { (byte) 0x19, (byte) 0x01, (byte) 0x00 };

    final ByteArrayInputStream inputStream =
         new ByteArrayInputStream(elementBytes);
    final ASN1StreamReader reader = new ASN1StreamReader(inputStream);

    reader.readUTCTime();
  }
}
