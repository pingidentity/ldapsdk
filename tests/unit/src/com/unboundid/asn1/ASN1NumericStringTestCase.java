/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the ASN1NumericString class.
 */
public class ASN1NumericStringTestCase
       extends ASN1TestCase
{
  /**
   * Tests the behavior when trying to create an empty numeric string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyString()
         throws Exception
  {
    ASN1NumericString s = new ASN1NumericString("");

    s = ASN1NumericString.decodeAsNumericString(s.encode());

    s = ASN1NumericString.decodeAsNumericString(s);

    s = s.decodeAsNumericString();

    assertEquals(s.getType(), 0x12);

    assertNotNull(s.getValue());
    assertEquals(s.getValue(), StaticUtils.NO_BYTES);

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), "");

    assertNotNull(s.toString());
    assertEquals(s.toString(), "");
  }



  /**
   * Tests the behavior when trying to create an empty numeric string from a
   * null string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyStringFromNull()
         throws Exception
  {
    ASN1NumericString s = new ASN1NumericString(null);

    s = ASN1NumericString.decodeAsNumericString(s.encode());

    s = ASN1NumericString.decodeAsNumericString(s);

    s = s.decodeAsNumericString();

    assertEquals(s.getType(), 0x12);

    assertNotNull(s.getValue());
    assertEquals(s.getValue(), StaticUtils.NO_BYTES);

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), "");

    assertNotNull(s.toString());
    assertEquals(s.toString(), "");
  }



  /**
   * Tests the behavior when trying to create a non-empty numeric string with
   * a valid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyString()
         throws Exception
  {
    final String stringValue = "1 2 3 4 5 6 7 8 9 0";
    ASN1NumericString s = new ASN1NumericString(stringValue);

    s = ASN1NumericString.decodeAsNumericString(s.encode());

    s = ASN1NumericString.decodeAsNumericString(s);

    s = s.decodeAsNumericString();

    assertEquals(s.getType(), 0x12);

    assertNotNull(s.getValue());
    assertEquals(s.getValue(), StaticUtils.getBytes(stringValue));

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), stringValue);

    assertNotNull(s.toString());
    assertEquals(s.toString(), stringValue);
  }



  /**
   * Tests the behavior when trying to create a non-empty numeric string with
   * a valid value that is longer than 127 bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongNonEmptyString()
         throws Exception
  {
    final String stringValue = "1234567890123456789012345678901234567890" +
         "123456789012345678901234567890123456789012345678901234567890" +
         "123456789012345678901234567890";
    ASN1NumericString s = new ASN1NumericString(stringValue);

    s = ASN1NumericString.decodeAsNumericString(s.encode());

    s = ASN1NumericString.decodeAsNumericString(s);

    s = s.decodeAsNumericString();

    assertEquals(s.getType(), 0x12);

    assertNotNull(s.getValue());
    assertEquals(s.getValue(), StaticUtils.getBytes(stringValue));

    assertNotNull(s.stringValue());
    assertEquals(s.stringValue(), stringValue);

    assertNotNull(s.toString());
    assertEquals(s.toString(), stringValue);
  }



  /**
   * Tests the behavior when trying to create a numeric string from a string
   * that contains characters that are digits or the space.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testCreateNumericStringFromInvalidString()
         throws Exception
  {
    new ASN1NumericString("-12345");
  }



  /**
   * Tests the behavior when trying to decode an empty array as a numeric
   * string element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeEmptyArray()
         throws Exception
  {
    ASN1NumericString.decodeAsNumericString(StaticUtils.NO_BYTES);
  }



  /**
   * Tests the behavior when trying to decode an array with a length mismatch.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeLengthMismatch()
         throws Exception
  {
    ASN1NumericString.decodeAsNumericString(
         StaticUtils.byteArray(0x06, 0x02, 0x00));
  }



  /**
   * Tests the behavior when trying to decode an array with a value that is not
   * a valid numeric string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeArrayWithInvalidValue()
         throws Exception
  {
    ASN1NumericString.decodeAsNumericString(
         StaticUtils.getBytes("-12345"));
  }



  /**
   * Tests the behavior when trying to decode an element with a value that is
   * not a valid numeric string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeElementWithInvalidValue()
         throws Exception
  {
    ASN1NumericString.decodeAsNumericString(new ASN1Element((byte) 0x12,
         StaticUtils.getBytes("-12345")));
  }
}
