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



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;



/**
 * This class provides a set of test cases for the ByteString and
 * ByteStringFactory classes.
 */
public class ByteStringTestCase
       extends UtilTestCase
{
  /**
   * Performs a set of tests with an empty byte string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmpty()
         throws Exception
  {
    ByteString bs = ByteStringFactory.create();

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with a {@code null} byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullArray()
         throws Exception
  {
    byte[] b = null;
    ByteString bs = ByteStringFactory.create(b);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with an empty byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyArray()
         throws Exception
  {
    byte[] b = new byte[0];
    ByteString bs = ByteStringFactory.create(b);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with a non-empty byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyArray()
         throws Exception
  {
    byte[] b = new byte[] { 'f', 'o', 'o' };
    ByteString bs = ByteStringFactory.create(b);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 3);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "foo");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString("foo"));

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Performs a set of tests with a zero-length portion of a zero-length byte
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyPortionEmptyArray()
         throws Exception
  {
    byte[] b = new byte[0];
    ByteString bs = ByteStringFactory.create(b, 0, 0);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with a zero-length portion of a nonzero-length byte
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyPortionNonEmptyArray()
         throws Exception
  {
    byte[] b = new byte[5];
    ByteString bs = ByteStringFactory.create(b, 3, 0);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with a non-empty byte array in which the entire
   * array holds the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyArrayPortionEntireArray()
         throws Exception
  {
    byte[] b = new byte[] { 'f', 'o', 'o' };
    ByteString bs = ByteStringFactory.create(b, 0, 3);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 3);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "foo");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString("foo"));

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 3);
    assertEquals(buffer.toString(), "foo");
  }



  /**
   * Performs a set of tests with a non-empty byte array in which the value is
   * only included in a portion of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyArrayPortionPartialArray()
         throws Exception
  {
    byte[] b = new byte[] { 'f', 'o', 'o', 'b', 'a', 'r' };
    ByteString bs = ByteStringFactory.create(b, 1, 3);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 3);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "oob");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString("oob"));

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 3);
    assertEquals(buffer.toString(), "oob");
  }



  /**
   * Performs a set of tests with a {@code null} string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullString()
         throws Exception
  {
    String s = null;
    ByteString bs = ByteStringFactory.create(s);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyString()
         throws Exception
  {
    String s = "";
    ByteString bs = ByteStringFactory.create(s);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 0);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString());

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 0);
    assertEquals(buffer.toString(), "");
  }



  /**
   * Performs a set of tests with a non-empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyString()
         throws Exception
  {
    String s = "foo";
    ByteString bs = ByteStringFactory.create(s);

    assertNotNull(bs);

    assertNotNull(bs.getValue());
    assertEquals(bs.getValue().length, 3);

    assertNotNull(bs.stringValue());
    assertEquals(bs.stringValue(), "foo");

    assertNotNull(bs.toASN1OctetString());
    assertEquals(bs.toASN1OctetString(), new ASN1OctetString("foo"));

    ByteStringBuffer buffer = new ByteStringBuffer();
    bs.appendValueTo(buffer);
    assertEquals(buffer.toString().length(), 3);
    assertEquals(buffer.toString(), "foo");
  }
}
