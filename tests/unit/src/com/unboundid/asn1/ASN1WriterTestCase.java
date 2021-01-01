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



import java.io.ByteArrayOutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.testng.annotations.Test;



/**
 * This class provides test coverage for the ASN1Writer class.
 */
public class ASN1WriterTestCase
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
  public void testElementConstructor1(byte type)
         throws Exception
  {
    ASN1Element element = new ASN1Element(type);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    ASN1Writer.writeElement(element, outputStream);
    byte[] elementBytes = outputStream.toByteArray();

    assertTrue(Arrays.equals(elementBytes, element.encode()));

    outputStream.reset();
    ASN1Writer.writeElement(element, outputStream);
    byte[] newBytes = outputStream.toByteArray();

    assertTrue(Arrays.equals(newBytes, elementBytes));

    ByteBuffer buffer = ByteBuffer.allocate(elementBytes.length);
    ASN1Writer.writeElement(element, buffer);
    assertEquals(buffer.position(), 0);
    assertEquals(buffer.limit(), elementBytes.length);

    buffer = ByteBuffer.allocate(elementBytes.length * 2);
    ASN1Writer.writeElement(element, buffer);
    assertEquals(buffer.position(), 0);
    assertEquals(buffer.limit(), elementBytes.length);

    buffer = ByteBuffer.allocate(elementBytes.length - 1);
    try
    {
      ASN1Writer.writeElement(element, buffer);
      fail("Expected a buffer overflow exception");
    }
    catch (BufferOverflowException boe)
    {
      // This is expected
    }
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
  public void testElementConstructor2(byte type, byte[] value)
         throws Exception
  {
    ASN1Element element = new ASN1Element(type, value);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    ASN1Writer.writeElement(element, outputStream);
    byte[] elementBytes = outputStream.toByteArray();

    assertTrue(Arrays.equals(elementBytes, element.encode()));

    outputStream.reset();
    ASN1Writer.writeElement(element, outputStream);
    byte[] newBytes = outputStream.toByteArray();

    assertTrue(Arrays.equals(newBytes, elementBytes));

    ByteBuffer buffer = ByteBuffer.allocate(elementBytes.length);
    ASN1Writer.writeElement(element, buffer);
    assertEquals(buffer.position(), 0);
    assertEquals(buffer.limit(), elementBytes.length);

    buffer = ByteBuffer.allocate(elementBytes.length * 2);
    ASN1Writer.writeElement(element, buffer);
    assertEquals(buffer.position(), 0);
    assertEquals(buffer.limit(), elementBytes.length);

    buffer = ByteBuffer.allocate(elementBytes.length - 1);
    try
    {
      ASN1Writer.writeElement(element, buffer);
      fail("Expected a buffer overflow exception");
    }
    catch (BufferOverflowException boe)
    {
      // This is expected
    }
  }



  /**
   * Tests the ASN.1 writer with a large element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLargeElement()
         throws Exception
  {
    ASN1Element element = new ASN1Element((byte) 0x04, new byte[1048576]);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    ASN1Writer.writeElement(element, outputStream);
    byte[] elementBytes = outputStream.toByteArray();

    assertTrue(Arrays.equals(elementBytes, element.encode()));

    outputStream.reset();
    ASN1Writer.writeElement(element, outputStream);
    byte[] newBytes = outputStream.toByteArray();

    assertTrue(Arrays.equals(newBytes, elementBytes));

    ByteBuffer buffer = ByteBuffer.allocate(elementBytes.length);
    ASN1Writer.writeElement(element, buffer);
    assertEquals(buffer.position(), 0);
    assertEquals(buffer.limit(), elementBytes.length);

    buffer = ByteBuffer.allocate(elementBytes.length * 2);
    ASN1Writer.writeElement(element, buffer);
    assertEquals(buffer.position(), 0);
    assertEquals(buffer.limit(), elementBytes.length);

    buffer = ByteBuffer.allocate(elementBytes.length - 1);
    try
    {
      ASN1Writer.writeElement(element, buffer);
      fail("Expected a buffer overflow exception");
    }
    catch (BufferOverflowException boe)
    {
      // This is expected
    }
  }
}
