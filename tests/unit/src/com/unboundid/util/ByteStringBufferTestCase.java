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
package com.unboundid.util;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Random;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the {@code ByteStringBuffer}
 * class.
 */
public class ByteStringBufferTestCase
       extends UtilTestCase
{
  /**
   * Provides test coverage for the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    assertTrue(buffer.capacity() > 0);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.getBackingArray().length, buffer.capacity());
    assertEquals(buffer.toByteArray().length, 0);
    assertEquals(buffer.toByteString().getValue().length, 0);
    assertEquals(buffer.toString().length(), 0);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the second constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer(10);

    assertEquals(buffer.capacity(), 10);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.getBackingArray().length, 10);
    assertEquals(buffer.toByteArray().length, 0);
    assertEquals(buffer.toByteString().getValue().length, 0);
    assertEquals(buffer.toString().length(), 0);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * boolean value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendBoolean()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    byte[] bufferBytes  = buffer.toByteArray();
    byte[] backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(bufferBytes.length, 0);

    buffer.append(true);
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 4);
    assertEquals(bufferBytes.length, 4);
    assertEquals(bufferBytes[0], (byte) 't');
    assertEquals(bufferBytes[1], (byte) 'r');
    assertEquals(bufferBytes[2], (byte) 'u');
    assertEquals(bufferBytes[3], (byte) 'e');
    assertEquals(backingArray[0], (byte) 't');
    assertEquals(backingArray[1], (byte) 'r');
    assertEquals(backingArray[2], (byte) 'u');
    assertEquals(backingArray[3], (byte) 'e');

    buffer.clear();
    buffer.append(false);
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 5);
    assertEquals(bufferBytes.length, 5);
    assertEquals(bufferBytes[0], (byte) 'f');
    assertEquals(bufferBytes[1], (byte) 'a');
    assertEquals(bufferBytes[2], (byte) 'l');
    assertEquals(bufferBytes[3], (byte) 's');
    assertEquals(bufferBytes[4], (byte) 'e');
    assertEquals(backingArray[0], (byte) 'f');
    assertEquals(backingArray[1], (byte) 'a');
    assertEquals(backingArray[2], (byte) 'l');
    assertEquals(backingArray[3], (byte) 's');
    assertEquals(backingArray[4], (byte) 'e');

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * single byte.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByte()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    byte[] bufferBytes  = buffer.toByteArray();
    byte[] backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(bufferBytes.length, 0);

    buffer.append((byte) 0x01);
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 1);
    assertEquals(bufferBytes.length, 1);
    assertEquals(bufferBytes[0], (byte) 0x01);
    assertEquals(backingArray[0], (byte) 0x01);
    assertEquals(backingArray[1], (byte) 0x00);

    buffer.append((byte) 0x02);
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 2);
    assertEquals(bufferBytes.length, 2);
    assertEquals(bufferBytes[0], (byte) 0x01);
    assertEquals(bufferBytes[1], (byte) 0x02);
    assertEquals(backingArray[0], (byte) 0x01);
    assertEquals(backingArray[1], (byte) 0x02);

    for (int i=0; i < 100; i++)
    {
      buffer.append((byte) i);
    }
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 102);
    assertEquals(bufferBytes.length, 102);
    assertEquals(bufferBytes[0], (byte) 0x01);
    assertEquals(bufferBytes[1], (byte) 0x02);
    assertEquals(bufferBytes[101], (byte) 0x63);
    assertEquals(backingArray[0], (byte) 0x01);
    assertEquals(backingArray[1], (byte) 0x02);
    assertEquals(backingArray[101], (byte) 0x63);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte array with a {@code null} array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendByteArrayNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    byte[] b = null;
    buffer.append(b);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteArrayEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[0]);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte array with a single-byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteArraySingleByte()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[] { 'd' });
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "food");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte array with a multi-byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteArrayMultipleBytes()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[] { 'b', 'a', 'r' });
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with a {@code null} array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendByteArrayPortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    byte[] b = null;
    buffer.append(b, 0, 0);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendByteArrayPortionNegativeOffset()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[0], -1, 0);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendByteArrayPortionNegativeLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[0], 0, -1);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with an offset of zero and a length greater than
   * the total number of bytes in the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendByteArrayPortionOffsetZeroLengthTooBig()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[0], 0, 1);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with a positive of zero and a length that is too
   * large but smaller than the total size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendByteArrayPortionOffsetNonzeroLengthTooBig()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[10], 7, 5);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of byte array with an empty array and a length of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteArrayPortionEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[0], 0, 0);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with a length of a single byte.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteArrayPortionSingleByteLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[] { 'b', 'a', 'r' }, 1, 1);
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "fooa");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a byte array with a length of multiple bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteArrayPortionMultiByteLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new byte[] { 'a', 'b', 'a', 'r', 'c' }, 1, 3);
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string with a null byte string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendByteStringNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append((ByteString) null);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string with an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteStringEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(ByteStringFactory.create());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string with a value containing a single byte.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteStringSingleByte()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(ByteStringFactory.create("d"));
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "food");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string with a value containing multiple bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendByteStringMultipleBytes()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(ByteStringFactory.create("bar"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string buffer with a null buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendBufferNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append((ByteStringBuffer) null);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string buffer with an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendBufferEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new ByteStringBuffer());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string buffer with a buffer containing a single byte.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendBufferSingleByte()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new ByteStringBuffer().append('d'));
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "food");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string buffer with a buffer containing multiple bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendBufferMultipleBytes()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new ByteStringBuffer().append("bar"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * byte string buffer with the same buffer to which the data is being
   * appended.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendBufferSelf()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.append(buffer);
    assertEquals(buffer.length(), 0);

    buffer.append('a');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "a");

    buffer.append(buffer);
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "aa");

    buffer.append(buffer).append(buffer);
    assertEquals(buffer.length(), 8);
    assertEquals(buffer.toString(), "aaaaaaaa");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * single character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacter()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    byte[] bufferBytes  = buffer.toByteArray();
    byte[] backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(bufferBytes.length, 0);

    buffer.append('h');
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 1);
    assertEquals(bufferBytes.length, 1);
    assertEquals(bufferBytes[0], (byte) 'h');
    assertEquals(backingArray[0], (byte) 'h');
    assertEquals(backingArray[1], (byte) 0x00);

    buffer.append('i');
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 2);
    assertEquals(bufferBytes.length, 2);
    assertEquals(bufferBytes[0], (byte) 'h');
    assertEquals(bufferBytes[1], (byte) 'i');
    assertEquals(backingArray[0], (byte) 'h');
    assertEquals(backingArray[1], (byte) 'i');

    for (int i=0; i < 100; i++)
    {
      buffer.append((char) i);
    }
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 102);
    assertEquals(bufferBytes.length, 102);
    assertEquals(bufferBytes[0], (byte) 'h');
    assertEquals(bufferBytes[1], (byte) 'i');
    assertEquals(bufferBytes[101], (byte) 0x63);
    assertEquals(backingArray[0], (byte) 'h');
    assertEquals(backingArray[1], (byte) 'i');
    assertEquals(backingArray[101], (byte) 0x63);

    buffer.append('\u00f1'); // Lowercase "n" with a tilde; bytes are 0xc3b1
    bufferBytes  = buffer.toByteArray();
    backingArray = buffer.getBackingArray();
    assertEquals(buffer.capacity(), backingArray.length);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 104);
    assertEquals(bufferBytes.length, 104);
    assertEquals(bufferBytes[0], (byte) 'h');
    assertEquals(bufferBytes[1], (byte) 'i');
    assertEquals(bufferBytes[101], (byte) 0x63);
    assertEquals(bufferBytes[102], (byte) 0xc3);
    assertEquals(bufferBytes[103], (byte) 0xb1);
    assertEquals(backingArray[0], (byte) 'h');
    assertEquals(backingArray[1], (byte) 'i');
    assertEquals(backingArray[101], (byte) 0x63);
    assertEquals(backingArray[102], (byte) 0xc3);
    assertEquals(backingArray[103], (byte) 0xb1);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character array with a {@code null} array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendCharacterArrayNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c = null;
    buffer.append(c);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[0]);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character array with a single-byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArraySingleByte()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[] { 'd' });
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "food");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character array with a multi-byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayMultipleBytes()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[] { 'b', 'a', 'r' });
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character array containing non-ASCII characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.append(new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' });
    assertEquals(buffer.toString(), "Jalape\u00f1o");
    assertEquals(buffer.length(), 9);

    byte[] bufferBytes = buffer.toByteArray();
    assertEquals(bufferBytes[0], (byte) 'J');
    assertEquals(bufferBytes[1], (byte) 'a');
    assertEquals(bufferBytes[2], (byte) 'l');
    assertEquals(bufferBytes[3], (byte) 'a');
    assertEquals(bufferBytes[4], (byte) 'p');
    assertEquals(bufferBytes[5], (byte) 'e');
    assertEquals(bufferBytes[6], (byte) 0xc3);
    assertEquals(bufferBytes[7], (byte) 0xb1);
    assertEquals(bufferBytes[8], (byte) 'o');

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with a {@code null} array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendCharacterArrayPortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] b = null;
    buffer.append(b, 0, 0);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendCharacterArrayPortionNegativeOffset()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[0], -1, 0);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendCharacterArrayPortionNegativeLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[0], 0, -1);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with an offset of zero and a length greater
   * than the total number of bytes in the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendCharacterArrayPortionOffsetZeroLengthTooBig()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[0], 0, 1);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with a positive of zero and a length that is
   * too large but smaller than the total size of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testAppendCharacterArrayPortionOffsetNonzeroLengthTooBig()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[10], 7, 5);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of character array with an empty array and a length of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayPortionEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[0], 0, 0);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with a length of a single byte.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayPortionSingleByteLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[] { 'b', 'a', 'r' }, 1, 1);
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "fooa");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array with a length of multiple bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayPortionMultiByteLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new char[] { 'a', 'b', 'a', 'r', 'c' }, 1, 3);
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * portion of a character array containing non-ASCII characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharacterArrayPortionNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.append(new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' },
                  4, 3);
    assertEquals(buffer.toString(), "pe\u00f1");
    assertEquals(buffer.length(), 4);

    byte[] bufferBytes = buffer.toByteArray();
    assertEquals(bufferBytes[0], (byte) 'p');
    assertEquals(bufferBytes[1], (byte) 'e');
    assertEquals(bufferBytes[2], (byte) 0xc3);
    assertEquals(bufferBytes[3], (byte) 0xb1);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character sequence with a {@code null} string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendCharSequenceNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append((CharSequence) null);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character sequence with a {@code null} string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testAppendCharSequencePortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append((CharSequence) null, 0, 10);
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character sequence with an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharSequenceEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.append("");
    assertEquals(buffer.length(), 0);

    buffer.append(new StringBuilder());
    assertEquals(buffer.length(), 0);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character sequence with a non-empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharSequenceNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new StringBuilder("bar"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character sequence with a non-empty string containing non-ASCII characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharSequenceNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.append("Jalape\u00f1o");
    assertEquals(buffer.length(), 9);
    assertEquals(buffer.toString(), "Jalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * character sequence with a non-empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendCharSequencePortionNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.append("foobar", 0, 0);
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.append("foobar", 0, 3);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append("foobar", 3, 3);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.append(new StringBuilder("foobar"), 3, 6);
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes an
   * integer value.
   *
   * @param  i  The integer value to be tested.
   */
  @Test(dataProvider="testIntegerValues")
  public void testAppendInteger(final int i)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(i);
    assertEquals(buffer.toString(), String.valueOf(i));
  }



  /**
   * Provides test coverage for the {@code append} method variant that takes a
   * long value.
   *
   * @param  l  The long value to be tested.
   */
  @Test(dataProvider="testLongValues")
  public void testAppendLong(final long l)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(l);
    assertEquals(buffer.toString(), String.valueOf(l));
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * boolean value.
   */
  @Test()
  public void testInsertBoolean()
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");

    buffer.insert(1, true);
    buffer.insert(2, false);

    assertEquals(buffer.toString(), "ftfalserueoo");
  }




  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single byte with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.insert(-1, (byte) 0x00);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single byte with position that is greater than the end of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertBytePositionTooLarge()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.insert(1, (byte) 0x00);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single byte into an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteIntoEmptyBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.insert(0, (byte) 'f');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "f");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single byte into the beginning of a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteIntoBeginningOfBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append('r');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "r");

    buffer.insert(0, (byte) 'a');
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "ar");

    buffer.insert(0, (byte) 'b');
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single byte into the end of a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteIntoEndOfBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append('b');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "b");

    buffer.insert(1, (byte) 'a');
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "ba");

    buffer.insert(2, (byte) 'r');
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single byte into the middle of a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteIntoMiddleOfBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("br");
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "br");

    buffer.insert(1, (byte) 'a');
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(1, (byte) 'o');
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "boar");

    buffer.insert(4, (byte) 'd');
    assertEquals(buffer.length(), 5);
    assertEquals(buffer.toString(), "board");

    buffer.insert(4, (byte) 'd');
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "boardd");

    buffer.insert(5, (byte) 'e');
    assertEquals(buffer.length(), 7);
    assertEquals(buffer.toString(), "boarded");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertByteArrayNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    byte[] b = null;
    buffer.insert(0, b);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, new byte[0]);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, new byte[0]);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new byte[0]);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array into an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.insert(0, new byte[] { 'f', 'o', 'o' });
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("bar");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(0, new byte[] { 'f', 'o', 'o' });
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(3, new byte[] { 'b', 'a', 'r' });
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte array into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    buffer.insert(1, new byte[] { 'o', 'o', 'b' });
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertByteArrayPortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    byte[] b = null;
    buffer.insert(0, b, 0, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPortionNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, new byte[0], 0, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPortionPositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, new byte[0], 0, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPortionNegativeOffset()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new byte[0], -1, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPortionNegativeLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new byte[0], 0, -1);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with length that is longer than the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPortionLengthLargerThanArray()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new byte[0], 0, 1);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with length that is smaller than the array but
   * still too long given the offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteArrayPortionOffsetPlusLengthLargerThanArray()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new byte[10], 7, 5);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayPortionEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new byte[0], 0, 0);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array with an non-empty array but a zero length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayPortionNonEmptyZeroLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new byte[10], 5, 0);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array into an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayPortionIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.insert(0, new byte[] { 'f', 'o', 'o', 'b', 'a', 'r' }, 0, 3);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayPortionIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(0, new byte[] { 'f', 'o', 'o', 'b', 'a', 'r' }, 3, 3);
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "barfoo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a byte array at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayPortionAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(3, new byte[] { 'b', 'a', 'r' }, 0, 3);
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of byte array into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteArrayPortionIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    buffer.insert(1, new byte[] { 'o', 'o', 'b' }, 0, 3);
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string with a null byte string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertByteStringNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    ByteString b = null;
    buffer.insert(0, b);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteStringNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, ByteStringFactory.create());
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertByteStringPositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, ByteStringFactory.create());
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string with an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteStringEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, ByteStringFactory.create());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string into an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteStringIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.insert(0, ByteStringFactory.create("foo"));
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteStringIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("bar");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(0, ByteStringFactory.create("foo"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteStringAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(3, ByteStringFactory.create("bar"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertByteStringIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    buffer.insert(1, ByteStringFactory.create("oob"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertBufferNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    ByteStringBuffer b = null;
    buffer.insert(0, b);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertBufferNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, new ByteStringBuffer());
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertBufferPositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, new ByteStringBuffer());
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertBufferEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new ByteStringBuffer());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer into an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertBufferIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.insert(0, new ByteStringBuffer().append("foo"));
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertBufferIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("bar");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(0, new ByteStringBuffer().append("foo"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertBufferAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(3, new ByteStringBuffer().append("bar"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * byte string buffer into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertBufferIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    buffer.insert(1, new ByteStringBuffer().append("oob"));
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "foobar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single character with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.insert(-1, 'a');
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single character with position that is greater than the end of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterPositionTooLarge()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.insert(1, 'a');
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single character into an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterIntoEmptyBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.insert(0, 'f');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "f");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single non-ASCII character into an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertNonASCIICharacterIntoEmptyBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);

    buffer.insert(0, '\u00f1');
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "\u00f1");

    byte[] bufferArray = buffer.toByteArray();
    assertEquals(bufferArray.length, 2);
    assertEquals(bufferArray[0], (byte) 0xc3);
    assertEquals(bufferArray[1], (byte) 0xb1);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single character into the beginning of a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterIntoBeginningOfBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append('r');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "r");

    buffer.insert(0, 'a');
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "ar");

    buffer.insert(0, 'b');
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(0, '\u00f1');
    assertEquals(buffer.length(), 5);
    assertEquals(buffer.toString(), "\u00f1bar");

    byte[] bufferArray = buffer.toByteArray();
    assertEquals(bufferArray.length, 5);
    assertEquals(bufferArray[0], (byte) 0xc3);
    assertEquals(bufferArray[1], (byte) 0xb1);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single character into the end of a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterIntoEndOfBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append('b');
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "b");

    buffer.insert(1, 'a');
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "ba");

    buffer.insert(2, 'r');
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(3, '\u00f1');
    assertEquals(buffer.length(), 5);
    assertEquals(buffer.toString(), "bar\u00f1");

    byte[] bufferArray = buffer.toByteArray();
    assertEquals(bufferArray.length, 5);
    assertEquals(bufferArray[3], (byte) 0xc3);
    assertEquals(bufferArray[4], (byte) 0xb1);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * single character into the middle of a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterIntoMiddleOfBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("br");
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "br");

    buffer.insert(1, 'a');
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.insert(1, 'o');
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "boar");

    buffer.insert(4, 'd');
    assertEquals(buffer.length(), 5);
    assertEquals(buffer.toString(), "board");

    buffer.insert(4, 'd');
    assertEquals(buffer.length(), 6);
    assertEquals(buffer.toString(), "boardd");

    buffer.insert(5, 'e');
    assertEquals(buffer.length(), 7);
    assertEquals(buffer.toString(), "boarded");

    buffer.insert(3, '\u00f1');
    assertEquals(buffer.length(), 9);
    assertEquals(buffer.toString(), "boa\u00f1rded");

    byte[] bufferArray = buffer.toByteArray();
    assertEquals(bufferArray.length, 9);
    assertEquals(bufferArray[3], (byte) 0xc3);
    assertEquals(bufferArray[4], (byte) 0xb1);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertCharacterArrayNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    char[] b = null;
    buffer.insert(0, b);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, new char[0]);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, new char[0]);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new char[0]);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array into an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(0, c);
    assertEquals(buffer.length(), 9);
    assertEquals(buffer.toString(), "Jalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(0, c);
    assertEquals(buffer.length(), 12);
    assertEquals(buffer.toString(), "Jalape\u00f1ofoo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(3, c);
    assertEquals(buffer.length(), 12);
    assertEquals(buffer.toString(), "fooJalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character array into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(1, c);
    assertEquals(buffer.length(), 12);
    assertEquals(buffer.toString(), "fJalape\u00f1oar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertCharacterArrayPortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    char[] b = null;
    buffer.insert(0, b, 0, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPortionNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, new char[0], 0, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPortionPositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, new char[0], 0, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPortionNegativeOffset()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new char[0], -1, 0);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPortionNegativeLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new char[0], 0, -1);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with length that is longer than the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPortionLengthLargerThanArray()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new char[0], 0, 1);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with length that is smaller than the array but
   * still too long given the offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterArrayPortionOffsetPlusLengthLargerThanArray()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(0, new char[10], 7, 5);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayPortionEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new char[0], 0, 0);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array with an non-empty array but a zero length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayPortionNonEmptyZeroLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new char[10], 5, 0);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array into an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayPortionIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(0, c, 5, 3);
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "e\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayPortionIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(0, c, 5, 3);
    assertEquals(buffer.length(), 7);
    assertEquals(buffer.toString(), "e\u00f1ofoo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of a character array at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayPortionAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(3, c, 5, 3);
    assertEquals(buffer.length(), 7);
    assertEquals(buffer.toString(), "fooe\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * portion of character array into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterArrayPortionIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.insert(1, c, 5, 3);
    assertEquals(buffer.length(), 7);
    assertEquals(buffer.toString(), "fe\u00f1oar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence with a null string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testInsertCharacterSequenceNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    String s = null;
    buffer.insert(0, s);
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterSequenceNegativePosition()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(-1, new StringBuilder());
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence with a position beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testInsertCharacterSequencePositionAfterEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    buffer.insert(1, new StringBuilder());
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence with an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterSequenceEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, "");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, new StringBuilder());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence into an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterSequenceIntoEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.insert(0, "Jalape\u00f1o");
    assertEquals(buffer.length(), 9);
    assertEquals(buffer.toString(), "Jalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence into the first position of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterSequenceIntoBeginning()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(0, new StringBuilder("Jalape\u00f1o"));
    assertEquals(buffer.length(), 12);
    assertEquals(buffer.toString(), "Jalape\u00f1ofoo");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence at the end of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterSequenceAtEnd()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(3, "Jalape\u00f1o");
    assertEquals(buffer.length(), 12);
    assertEquals(buffer.toString(), "fooJalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * character sequence into the middle of a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInsertCharacterSequenceIntoMiddle()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("far");
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "far");

    buffer.insert(1, "Jalape\u00f1o");
    assertEquals(buffer.length(), 12);
    assertEquals(buffer.toString(), "fJalape\u00f1oar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes an
   * integer value.
   *
   * @param  i  The integer value to be tested.
   */
  @Test(dataProvider="testIntegerValues")
  public void testInsertInteger(final int i)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, i);
    assertEquals(buffer.toString(), "f" + i + "oo");
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * long value.
   *
   * @param  l  The long value to be tested.
   */
  @Test(dataProvider="testLongValues")
  public void testInsertLong(final long l)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.insert(1, l);
    assertEquals(buffer.toString(), "f" + l + "oo");
  }



  /**
   * Provides test coverage for the {@code insert} method variant that takes a
   * boolean value.
   */
  @Test()
  public void testSetBoolean()
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(true);
    assertEquals(buffer.toString(), "true");

    buffer.set(false);
    assertEquals(buffer.toString(), "false");
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * single byte with an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set((byte) 'a');
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "a");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * single byte with a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set((byte) 'a');
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "a");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetByteArrayNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    byte[] b = null;
    buffer.set(b);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteArrayEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new byte[0]);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte array with a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteArrayNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new byte[] { 'b', 'a', 'r' });
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetByteArrayPortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    byte[] b = null;
    buffer.set(b, 0, 0);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetByteArrayPortionNegativeOffset()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new byte[0], -1, 0);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetByteArrayPortionNegativeLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new byte[0], 0, -1);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a length that is greater than the size of the
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetByteArrayPortionLengthTooLarge()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new byte[5], 0, 10);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a length that is less than the size of the
   * array but the offset plus length is beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetByteArrayPortionOffsetPlusLengthTooLarge()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new byte[10], 7, 5);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteArrayPortionEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new byte[0], 0, 0);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a non-empty array but a zero length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteArrayPortionZeroLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new byte[5], 3, 0);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a byte array with a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteArrayPortionNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new byte[] { 'b', 'a', 'r' }, 0, 3);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte string with a null object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetByteStringNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    ByteString b = null;
    buffer.set(b);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte string with an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteStringEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(ByteStringFactory.create());
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte string with a non-empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetByteStringNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(ByteStringFactory.create("bar"));
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte string buffer with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetBufferNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    ByteStringBuffer b = null;
    buffer.set(b);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte string buffer with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetBufferEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new ByteStringBuffer());
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * byte string buffer with a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetBufferNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new ByteStringBuffer().append("bar"));
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * single character with an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set('a');
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "a");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * single character with an empty buffer using a non-ASCII character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterEmptyNonASCII()
       throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set('\u00f1');
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "\u00f1");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * single character with a non-empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set('a');
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 1);
    assertEquals(buffer.toString(), "a");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * single character with a non-empty buffer using a non-ASCII character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterNonEmptyNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set('\u00f1');
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "\u00f1");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetCharacterArrayNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    char[] b = null;
    buffer.set(b);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new char[0]);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character array with a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new char[] { 'b', 'a', 'r' });
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character array with a non-empty array containing a non-ASCII character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayNonEmptyNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.set(c);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 9);
    assertEquals(buffer.toString(), "Jalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetCharacterArrayPortionNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    char[] b = null;
    buffer.set(b, 0, 0);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a negative offset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetCharacterArrayPortionNegativeOffset()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new char[0], -1, 0);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetCharacterArrayPortionNegativeLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new char[0], 0, -1);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a length that is greater than the size of
   * the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetCharacterArrayPortionLengthTooLarge()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new char[5], 0, 10);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a length that is less than the size of
   * the array but the offset plus length is beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testSetCharacterArrayPortionOffsetPlusLengthTooLarge()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.set(new char[10], 7, 5);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayPortionEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new char[0], 0, 0);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a non-empty array but a zero length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayPortionZeroLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new char[5], 3, 0);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayPortionNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(new char[] { 'b', 'a', 'r' }, 0, 3);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * portion of a character array with a non-empty array containing a non-ASCII
   * character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterArrayPortionNonEmptyNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    char[] c =  new char[] { 'J', 'a', 'l', 'a', 'p', 'e', '\u00f1', 'o' };
    buffer.set(c, 5, 3);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 4);
    assertEquals(buffer.toString(), "e\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character sequence with a null array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testSetCharacterSequenceNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    String s = null;
    buffer.set(s);
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character sequence with an empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterSequenceEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set("");
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character sequence with a non-empty array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterSequenceNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set("bar");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "bar");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a
   * character sequence with a non-empty array containing a non-ASCII character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetCharacterSequenceNonEmptyNonASCII()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set("Jalape\u00f1o");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 9);
    assertEquals(buffer.toString(), "Jalape\u00f1o");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes an
   * integer value.
   *
   * @param  i  The integer value to be tested.
   */
  @Test(dataProvider="testIntegerValues")
  public void testSetInteger(final int i)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(i);
    assertEquals(buffer.toString(), String.valueOf(i));
  }



  /**
   * Provides test coverage for the {@code set} method variant that takes a long
   * value.
   *
   * @param  l  The long value to be tested.
   */
  @Test(dataProvider="testLongValues")
  public void testSetLong(final long l)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.set(l);
    assertEquals(buffer.toString(), String.valueOf(l));
  }



  /**
   * Provides test coverage for the {@code clear} method with an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClearEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.clear();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code clear} method with a non-empty
   * buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClearNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.clear();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code trimToSize} method with an empty
   * buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrimToSizeEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");

    buffer.ensureCapacity(50);
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");
    assertTrue(buffer.capacity() >= 50);
    assertTrue(buffer.getBackingArray().length >= 50);

    buffer.trimToSize();
    assertTrue(buffer.isEmpty());
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");
    assertEquals(buffer.capacity(), 0);
    assertEquals(buffer.getBackingArray().length, 0);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code trimToSize} method with a non-empty
   * buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrimToSizeNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.ensureCapacity(50);
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");
    assertTrue(buffer.capacity() >= 50);
    assertTrue(buffer.getBackingArray().length >= 50);

    buffer.trimToSize();
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");
    assertEquals(buffer.capacity(), 3);
    assertEquals(buffer.getBackingArray().length, 3);

    buffer.trimToSize();
    assertFalse(buffer.isEmpty());
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");
    assertEquals(buffer.capacity(), 3);
    assertEquals(buffer.getBackingArray().length, 3);

    buffer.hashCode();
  }



  /**
   * Provides test coverage for the {@code write} method with an empty buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.write(outputStream);

    assertEquals(outputStream.size(), 0);
    assertEquals(outputStream.toByteArray().length, 0);
  }



  /**
   * Provides test coverage for the {@code write} method with a non-empty
   * buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWriteNonEmpty()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    buffer.write(outputStream);

    assertEquals(outputStream.size(), 3);
    assertEquals(outputStream.toByteArray().length, 3);
  }



  /**
   * Provides test coverage for the {@code code} method with a null object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    assertFalse(buffer.equals(null));
  }



  /**
   * Provides test coverage for the {@code code} method with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    assertTrue(buffer.equals(buffer));
  }



  /**
   * Provides test coverage for the {@code code} method with a duplicate of the
   * object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDuplicate()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    ByteStringBuffer b2 = buffer.duplicate();
    assertFalse(b2 == buffer);
    assertTrue(buffer.equals(b2));
  }



  /**
   * Provides test coverage for the {@code code} method with an object that is
   * not a byte string buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotBuffer()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    assertFalse(buffer.equals("not a buffer"));
  }



  /**
   * Provides test coverage for the {@code code} method with a buffer containing
   * different content with a different length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDifferentLengthDifferentContent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    ByteStringBuffer b2 = new ByteStringBuffer().append("food");
    assertFalse(buffer.equals(b2));
  }



  /**
   * Provides test coverage for the {@code code} method with a buffer containing
   * different content but an equivalent length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsSameLengthDifferentContent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer().append("foo");

    ByteStringBuffer b2 = new ByteStringBuffer().append("bar");
    assertFalse(buffer.equals(b2));
  }



  /**
   * Tests the {@code setLength} method with a negative value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void setLengthNegative()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.toString(), "foo");

    buffer.setLength(-1);
  }



  /**
   * Tests the {@code setLength} method with a length of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setLengthZero()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.toString(), "foo");

    buffer.setLength(0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the {@code setLength} method with a nonzero length that is less than
   * the current length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setLengthLessThanCurrent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("food");
    assertEquals(buffer.toString(), "food");

    buffer.setLength(3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Tests the {@code setLength} method with a nonzero length that is equal to
   * the current length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setLengthEqualsCurrent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertEquals(buffer.toString(), "foo");

    buffer.setLength(3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Tests the {@code setLength} method with a nonzero length that is greater
   * than the current length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setLengthGreaterThanCurrent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("food");
    assertEquals(buffer.toString(), "food");

    buffer.setLength(3);
    assertEquals(buffer.toString(), "foo");

    buffer.setLength(4);
    assertEquals(buffer.toString(), "foo\u0000");
  }



  /**
   * Tests the {@code setCapacity} method with a negative value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void setCapacityNegative()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.setCapacity(-1);
  }



  /**
   * Tests the {@code setCapacity} method with a capacity of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setCapacityZero()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("foo");
    assertTrue(buffer.capacity() >= 3);

    buffer.setCapacity(0);
    assertEquals(buffer.capacity(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the {@code setCapacity} method with a nonzero capacity that is less
   * than the current length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setCapacityLessThanLength()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("food");
    assertTrue(buffer.capacity() >= 4);
    assertEquals(buffer.length(), 4);


    buffer.setCapacity(3);
    assertEquals(buffer.capacity(), 3);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Tests the {@code setCapacity} method with a nonzero capacity that is equal
   * to the current capacity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setCapacityEqualsCurrent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("food");
    assertEquals(buffer.toString(), "food");

    buffer.setCapacity(3);
    assertEquals(buffer.capacity(), 3);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.setCapacity(3);
    assertEquals(buffer.capacity(), 3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Tests the {@code setCapacity} method with a nonzero capacity that is
   * greater than the current capacity.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void setCapacityGreaterThanCurrent()
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("food");
    assertEquals(buffer.toString(), "food");

    buffer.setCapacity(3);
    assertEquals(buffer.capacity(), 3);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");

    buffer.setCapacity(4);
    assertEquals(buffer.capacity(), 4);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Retrieves a set of integer values that may be used for testing.
   *
   * @return  A set of integer values that may be used for testing.
   */
  @DataProvider(name="testIntegerValues")
  public Object[][] getTestIntegerValues()
  {
    return new Object[][]
    {
      new Object[] { 0 },
      new Object[] { 1 },
      new Object[] { 2 },
      new Object[] { 3 },
      new Object[] { 4 },
      new Object[] { 5 },
      new Object[] { 6 },
      new Object[] { 7 },
      new Object[] { 8 },
      new Object[] { 9 },
      new Object[] { 10 },
      new Object[] { 12 },
      new Object[] { 100 },
      new Object[] { 123 },
      new Object[] { 1000 },
      new Object[] { 1234 },
      new Object[] { 10000 },
      new Object[] { 12345 },
      new Object[] { 100000 },
      new Object[] { 123456 },
      new Object[] { 1000000 },
      new Object[] { 1234567 },
      new Object[] { 10000000 },
      new Object[] { 12345678 },
      new Object[] { 100000000 },
      new Object[] { 123456789 },
      new Object[] { 1000000000 },
      new Object[] { 1234567890 },
      new Object[] { 1000000000 },
      new Object[] { 1234567890 },
      new Object[] { -1 },
      new Object[] { -2 },
      new Object[] { -3 },
      new Object[] { -4 },
      new Object[] { -5 },
      new Object[] { -6 },
      new Object[] { -7 },
      new Object[] { -8 },
      new Object[] { -9 },
      new Object[] { -10 },
      new Object[] { -12 },
      new Object[] { -100 },
      new Object[] { -123 },
      new Object[] { -1000 },
      new Object[] { -1234 },
      new Object[] { -10000 },
      new Object[] { -12345 },
      new Object[] { -100000 },
      new Object[] { -123456 },
      new Object[] { -1000000 },
      new Object[] { -1234567 },
      new Object[] { -10000000 },
      new Object[] { -12345678 },
      new Object[] { -100000000 },
      new Object[] { -123456789 },
      new Object[] { -1000000000 },
      new Object[] { -1234567890 },
      new Object[] { -1000000000 },
      new Object[] { -1234567890 },
      new Object[] { Integer.MAX_VALUE },
      new Object[] { -Integer.MAX_VALUE },
      new Object[] { Integer.MAX_VALUE - 1 },
      new Object[] { Integer.MIN_VALUE },
      new Object[] { Integer.MIN_VALUE + 1 },
    };
  }



  /**
   * Retrieves a set of long values that may be used for testing.
   *
   * @return  A set of long values that may be used for testing.
   */
  @DataProvider(name="testLongValues")
  public Object[][] getTestLongValues()
  {
    return new Object[][]
    {
      new Object[] { 0L },
      new Object[] { 1L },
      new Object[] { 2L },
      new Object[] { 3L },
      new Object[] { 4L },
      new Object[] { 5L },
      new Object[] { 6L },
      new Object[] { 7L },
      new Object[] { 8L },
      new Object[] { 9L },
      new Object[] { 10L },
      new Object[] { 12L },
      new Object[] { 100L },
      new Object[] { 123L },
      new Object[] { 1000L },
      new Object[] { 1234L },
      new Object[] { 10000L },
      new Object[] { 12345L },
      new Object[] { 100000L },
      new Object[] { 123456L },
      new Object[] { 1000000L },
      new Object[] { 1234567L },
      new Object[] { 10000000L },
      new Object[] { 12345678L },
      new Object[] { 100000000L },
      new Object[] { 123456789L },
      new Object[] { 1000000000L },
      new Object[] { 1234567890L },
      new Object[] { 1000000000L },
      new Object[] { 1234567890L },
      new Object[] { 10000000000L },
      new Object[] { 12345678900L },
      new Object[] { 100000000000L },
      new Object[] { 123456789001L },
      new Object[] { 1000000000000L },
      new Object[] { 1234567890012L },
      new Object[] { 10000000000000L },
      new Object[] { 12345678900123L },
      new Object[] { 100000000000000L },
      new Object[] { 123456789001234L },
      new Object[] { 1000000000000000L },
      new Object[] { 1234567890012345L },
      new Object[] { 10000000000000000L },
      new Object[] { 12345678900123456L },
      new Object[] { 100000000000000000L },
      new Object[] { 123456789001234567L },
      new Object[] { 1000000000000000000L },
      new Object[] { 1234567890012345678L },
      new Object[] { 1000000000000000000L },
      new Object[] { 1234567890012345678L },
      new Object[] { -1L },
      new Object[] { -2L },
      new Object[] { -3L },
      new Object[] { -4L },
      new Object[] { -5L },
      new Object[] { -6L },
      new Object[] { -7L },
      new Object[] { -8L },
      new Object[] { -9L },
      new Object[] { -10L },
      new Object[] { -12L },
      new Object[] { -100L },
      new Object[] { -123L },
      new Object[] { -1000L },
      new Object[] { -1234L },
      new Object[] { -10000L },
      new Object[] { -12345L },
      new Object[] { -100000L },
      new Object[] { -123456L },
      new Object[] { -1000000L },
      new Object[] { -1234567L },
      new Object[] { -10000000L },
      new Object[] { -12345678L },
      new Object[] { -100000000L },
      new Object[] { -123456789L },
      new Object[] { -1000000000L },
      new Object[] { -1234567890L },
      new Object[] { -1000000000L },
      new Object[] { -1234567890L },
      new Object[] { -12345678900L },
      new Object[] { -100000000000L },
      new Object[] { -123456789001L },
      new Object[] { -1000000000000L },
      new Object[] { -1234567890012L },
      new Object[] { -10000000000000L },
      new Object[] { -12345678900123L },
      new Object[] { -100000000000000L },
      new Object[] { -123456789001234L },
      new Object[] { -1000000000000000L },
      new Object[] { -1234567890012345L },
      new Object[] { -10000000000000000L },
      new Object[] { -12345678900123456L },
      new Object[] { -100000000000000000L },
      new Object[] { -123456789001234567L },
      new Object[] { -1000000000000000000L },
      new Object[] { -1234567890012345678L },
      new Object[] { -1000000000000000000L },
      new Object[] { -1234567890012345678L },
      new Object[] { Integer.MAX_VALUE },
      new Object[] { -Integer.MAX_VALUE },
      new Object[] { Integer.MAX_VALUE - 1 },
      new Object[] { Integer.MIN_VALUE },
      new Object[] { Integer.MIN_VALUE + 1 },
      new Object[] { Long.MAX_VALUE },
      new Object[] { -Long.MAX_VALUE },
      new Object[] { Long.MAX_VALUE - 1 },
      new Object[] { Long.MIN_VALUE },
      new Object[] { Long.MIN_VALUE + 1 },
    };
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * zero bytes from the beginning of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteZeroFromBeginning()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(0);
    assertEquals(buffer.length(), 5);
    assertEquals(buffer.toString(), "12345");
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * the entire length from the beginning of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteAllFromBeginning()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(5);
    assertEquals(buffer.length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * the entire length from the beginning of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeletePortionFromBeginning()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(3);
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "45");
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * a negative length from the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testDeleteNegativeFromBeginning()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(-1);
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * more bytes from the beginning of the buffer than it actually contains.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testDeleteTooMuchFromBeginning()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(6);
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * zero bytes from the middle of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteZeroBytesFromMiddle()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(3, 0);
    assertEquals(buffer.toString(), "12345");
    assertEquals(buffer.length(), 5);
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * data from the middle to the end of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteBytesFromMiddleToEnd()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(2, 3);
    assertEquals(buffer.length(), 2);
    assertEquals(buffer.toString(), "12");
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * data from the middle, but not until the end of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteSubsetFromMiddle()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(2, 2);
    assertEquals(buffer.length(), 3);
    assertEquals(buffer.toString(), "125");
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * data from the middle, but not until the end of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testDeleteNegativeOffset()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(-1, 0);
  }



  /**
   * Tests the behavior of the {@code delete} method with an attempt to delete
   * data from the middle, but not until the end of the buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IndexOutOfBoundsException.class })
  public void testDeleteOffsetPlusLengthTooLarge()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append("12345");
    assertEquals(buffer.length(), 5);

    buffer.delete(1, 5);
  }



  /**
   * Tests the behavior of the byteAt method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteAt()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();

    try
    {
      buffer.byteAt(-1);
      fail("Expected an exception with a negative offset");
    }
    catch (final IndexOutOfBoundsException e)
    {
      // This was expected.
    }

    try
    {
      buffer.byteAt(0);
      fail("Expected an exception with the offset equal to the length");
    }
    catch (final IndexOutOfBoundsException e)
    {
      // This was expected.
    }

    try
    {
      buffer.byteAt(1234);
      fail("Expected an exception with the offset greater than the length");
    }
    catch (final IndexOutOfBoundsException e)
    {
      // This was expected.
    }

    final Random random = new Random();
    final byte[] array = new byte[1234];
    random.nextBytes(array);

    buffer.append(array);
    for (int i=0; i < array.length; i ++)
    {
      assertEquals(buffer.byteAt(i), array[i]);
    }
  }



  /**
   * Tests the behavior of the bytesAt method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBytesAt()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();

    try
    {
      buffer.bytesAt(-1, 0);
      fail("Expected an exception with a negative offset");
    }
    catch (final IndexOutOfBoundsException e)
    {
      // This was expected.
    }

    try
    {
      buffer.bytesAt(0, -1);
      fail("Expected an exception with a negative length");
    }
    catch (final IndexOutOfBoundsException e)
    {
      // This was expected.
    }

    try
    {
      buffer.bytesAt(0, 1);
      fail("Expected an exception with the offset plus length greater than " +
           "the buffer length");
    }
    catch (final IndexOutOfBoundsException e)
    {
      // This was expected.
    }


    assertNotNull(buffer.bytesAt(0, 0));
    assertEquals(buffer.bytesAt(0, 0), StaticUtils.NO_BYTES);

    final Random random = new Random();
    final byte[] array1 = new byte[123];
    final byte[] array2 = new byte[456];
    final byte[] array3 = new byte[789];

    random.nextBytes(array1);
    random.nextBytes(array2);
    random.nextBytes(array3);

    buffer.append(array1);
    buffer.append(array2);
    buffer.append(array3);

    assertEquals(buffer.bytesAt(0, 123), array1);
    assertEquals(buffer.bytesAt(123, 456), array2);
    assertEquals(buffer.bytesAt(579, 789), array3);
    assertEquals(buffer.bytesAt(0, buffer.length()), buffer.toByteArray());
  }



  /**
   * Tests the behavior of the startsWith and endsWith methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartsWithAndEndsWith()
         throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();

    final Random random = new Random();
    final byte[] array1 = new byte[123];
    final byte[] array2 = new byte[456];
    final byte[] array3 = new byte[789];

    random.nextBytes(array1);
    random.nextBytes(array2);
    random.nextBytes(array3);

    assertFalse(buffer.startsWith(array1));
    assertFalse(buffer.startsWith(array2));
    assertFalse(buffer.startsWith(array3));

    assertFalse(buffer.endsWith(array1));
    assertFalse(buffer.endsWith(array2));
    assertFalse(buffer.endsWith(array3));

    buffer.append(array1);

    assertTrue(buffer.startsWith(array1));
    assertFalse(buffer.startsWith(array2));
    assertFalse(buffer.startsWith(array3));

    assertTrue(buffer.endsWith(array1));
    assertFalse(buffer.endsWith(array2));
    assertFalse(buffer.endsWith(array3));

    assertTrue(buffer.startsWith(buffer.toByteArray()));
    assertTrue(buffer.endsWith(buffer.toByteArray()));

    buffer.append(array2);

    assertTrue(buffer.startsWith(array1));
    assertFalse(buffer.startsWith(array2));
    assertFalse(buffer.startsWith(array3));

    assertFalse(buffer.endsWith(array1));
    assertTrue(buffer.endsWith(array2));
    assertFalse(buffer.endsWith(array3));

    assertTrue(buffer.startsWith(buffer.toByteArray()));
    assertTrue(buffer.endsWith(buffer.toByteArray()));

    buffer.append(array3);

    assertTrue(buffer.startsWith(array1));
    assertFalse(buffer.startsWith(array2));
    assertFalse(buffer.startsWith(array3));

    assertFalse(buffer.endsWith(array1));
    assertFalse(buffer.endsWith(array2));
    assertTrue(buffer.endsWith(array3));

    assertTrue(buffer.startsWith(buffer.toByteArray()));
    assertTrue(buffer.endsWith(buffer.toByteArray()));
  }



  /**
   * Tests the behavior when trying to read the contents of a file into the
   * buffer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFrom()
         throws Exception
  {
    final File emptyFile = createTempFile();
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.readFrom(emptyFile);
    assertEquals(buffer.toByteArray(), StaticUtils.NO_BYTES);

    final File testFile = createTempFile(
         "Line 1",
         "Line 2",
         "Line 3");

    buffer.readFrom(testFile);
    assertEquals(buffer.toString(),
         "Line 1" + StaticUtils.EOL + "Line 2" + StaticUtils.EOL +
              "Line 3" + StaticUtils.EOL);
  }



  /**
   * Tests the behavior when trying to read from an input stream into the buffer
   * when a read error occurs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFromInputStreamWithIOException()
         throws Exception
  {
    final TestInputStream testInputStream = new TestInputStream(
         new ByteArrayInputStream(StaticUtils.byteArray(1, 2, 3, 4)),
         new IOException("Read error"), 1, false);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    try
    {
      buffer.readFrom(testInputStream);
      fail("Expected an exception when trying to read from the input stream");
    }
    catch (final IOException e)
    {
      // This was expected.
    }
  }
}
