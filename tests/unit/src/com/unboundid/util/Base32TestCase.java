/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.text.ParseException;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the Base32 class.
 */
public class Base32TestCase
       extends UtilTestCase
{
  /**
   * Tests the behavior of the encode and decode methods.
   *
   * @param  decoded  The raw, decoded data to use for testing.
   * @param  encoded  The expected base32-encoded representation of the given
   *                  raw data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBase32Data")
  public void testEncodeAndDecode(final byte[] decoded, final String encoded)
         throws Exception
  {
    final String calcEncoded = Base32.encode(decoded);
    assertEquals(calcEncoded, encoded);

    final StringBuilder sb = new StringBuilder();
    Base32.encode(decoded, sb);
    assertEquals(sb.toString(), encoded);

    sb.setLength(0);
    Base32.encode(decoded, 0, decoded.length, sb);
    assertEquals(sb.toString(), encoded);

    final ByteStringBuffer bsb = new ByteStringBuffer();
    Base32.encode(decoded, bsb);
    assertEquals(bsb.toString(), encoded);

    bsb.setLength(0);
    Base32.encode(decoded, 0, decoded.length, bsb);
    assertEquals(bsb.toString(), encoded);

    final byte[] calcDecoded = Base32.decode(encoded);
    assertEquals(calcDecoded, decoded,
         "Expected " + StaticUtils.toHex(decoded) + " but got " +
              StaticUtils.toHex(calcDecoded));

    assertEquals(Base32.decode(encoded.toUpperCase()), decoded);
    assertEquals(Base32.decode(encoded.toLowerCase()), decoded);

    final String doubleEncoded = Base32.encode(encoded);
    final String singleDecoded = Base32.decodeToString(doubleEncoded);
    assertEquals(singleDecoded, encoded);

    sb.setLength(0);
    Base32.encode(encoded, sb);
    assertEquals(sb.toString(), doubleEncoded);

    bsb.setLength(0);
    Base32.encode(encoded, bsb);
    assertEquals(bsb.toString(), doubleEncoded);
  }



  /**
   * Tests the behavior of the decode method with a string with an invalid
   * length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeInvalidLength()
         throws Exception
  {
    Base32.decode("NOTAMULTIPLEOFEIGHT");
  }



  /**
   * Tests the behavior of the decode method with an equal sign in an unexpected
   * location.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeUnexpectedEqual()
         throws Exception
  {
    Base32.decode("UNEXPECTED=EQUAL=SIGN=PLACEMENTS");
  }



  /**
   * Tests the behavior of the decode method with invalid characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeInvalidCharacters()
         throws Exception
  {
    Base32.decode("0AND1ARENOTUSED=");
  }



  /**
   * Retrieves a set of data that may be used for testing base32 encoding and
   * decoding.
   *
   * @return  A set of data that may be used for testing base32 encoding and
   *          decoding.
   */
  @DataProvider(name = "testBase32Data")
  public Object[][] getTestBase32Data()
  {
    return new Object[][]
    {
      new Object[]
      {
        new byte[0],
        ""
      },

      new Object[]
      {
        StaticUtils.getBytes("f"),
        "MY======"
      },

      new Object[]
      {
        StaticUtils.getBytes("fo"),
        "MZXQ===="
      },

      new Object[]
      {
        StaticUtils.getBytes("foo"),
        "MZXW6==="
      },

      new Object[]
      {
        StaticUtils.getBytes("foob"),
        "MZXW6YQ="
      },

      new Object[]
      {
        StaticUtils.getBytes("fooba"),
        "MZXW6YTB"
      },

      new Object[]
      {
        StaticUtils.getBytes("foobar"),
        "MZXW6YTBOI======"
      },

      new Object[]
      {
        new byte[]
        {
          (byte) 0x00,
          (byte) 0x44,
          (byte) 0x32,
          (byte) 0x14,
          (byte) 0xC7,
          (byte) 0x42,
          (byte) 0x54,
          (byte) 0xB6,
          (byte) 0x35,
          (byte) 0xCF,
          (byte) 0x84,
          (byte) 0x65,
          (byte) 0x3A,
          (byte) 0x56,
          (byte) 0xD7,
          (byte) 0xC6,
          (byte) 0x75,
          (byte) 0xBE,
          (byte) 0x77,
          (byte) 0xDF,
        },
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
      },
    };
  }
}
