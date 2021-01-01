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
package com.unboundid.util;



import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the Base64 class.
 */
public class Base64TestCase
       extends UtilTestCase
{
  /**
   * Tests the {@code encode} and {@code decode} methods to ensure that an
   * encoded representation of a provided value can be decoded back to that same
   * value.
   *
   * @param  decoded  The raw data to be encoded.
   * @param  encoded  The encoded form of the provided data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBase64Data")
  public void testEncodeAndDecode(byte[] decoded, String encoded)
         throws Exception
  {
    String calculatedEncoded = Base64.encode(decoded);
    assertEquals(calculatedEncoded, encoded,
         "Encode expected " + encoded + " but got " + calculatedEncoded);

    byte[] calculatedDecoded = Base64.decode(encoded);
    assertTrue(Arrays.equals(calculatedDecoded, decoded),
               "Decode expected " + toHex(decoded) + " but got " +
                    toHex(calculatedDecoded));

    String urlEncoded = convertToURLEncoded(encoded, true);
    String calculatedURLEncoded = Base64.urlEncode(decoded, true);
    assertEquals(calculatedURLEncoded, urlEncoded,
         "URL encode expected " + urlEncoded + " but got " +
              calculatedURLEncoded);

    byte[] calculatedURLDecoded = Base64.urlDecode(urlEncoded);
    assertTrue(Arrays.equals(calculatedURLDecoded, decoded),
         "URL decode expected " + toHex(decoded) + " but got " +
              toHex(calculatedURLDecoded));

    urlEncoded = convertToURLEncoded(encoded, false);
    calculatedURLEncoded = Base64.urlEncode(decoded, false);
    assertEquals(calculatedURLEncoded, urlEncoded,
         "Unpadded URL encode expected " + urlEncoded + " but got " +
              calculatedURLEncoded);

    calculatedURLDecoded = Base64.urlDecode(urlEncoded);
    assertTrue(Arrays.equals(calculatedURLDecoded, decoded),
         "URL decode expected " + toHex(decoded) + " but got " +
              toHex(calculatedURLDecoded));
  }



  /**
   * Tests the {@code encode} and {@code decode} methods using raw data
   * represented as a string rather than a byte array.
   *
   * @param  decoded  The raw data to be encoded.
   * @param  encoded  The encoded form of the provided data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBase64Data")
  public void testEncodeAndDecodeByteStrings(byte[] decoded, String encoded)
         throws Exception
  {
    ByteStringBuffer buffer = new ByteStringBuffer();
    Base64.encode(decoded, buffer);
    assertEquals(buffer.toString(), encoded);

    String urlEncoded = convertToURLEncoded(encoded, true);
    buffer.setLength(0);
    Base64.urlEncode(decoded, 0, decoded.length, buffer, true);
    assertEquals(buffer.toString(), urlEncoded,
         "URL encode expected " + urlEncoded + " but got " +
              buffer.toString());

    byte[] calculatedDecoded = Base64.decode(encoded);
    assertTrue(Arrays.equals(calculatedDecoded, decoded),
               "Decode expected " + toHex(decoded) + " but got " +
               toHex(calculatedDecoded));

    byte[] calculatedURLDecoded = Base64.urlDecode(urlEncoded);
    assertTrue(Arrays.equals(calculatedURLDecoded, decoded),
         "URL Decode expected " + toHex(decoded) + " but got " +
         toHex(calculatedURLDecoded));

    for (int i=1; i < 10; i++)
    {
      buffer.setLength(0);
      final byte[] leftPadded = new byte[decoded.length+i];
      System.arraycopy(decoded, 0, leftPadded, i, decoded.length);
      Base64.encode(leftPadded, i, decoded.length, buffer);
      assertEquals(buffer.toString(), encoded);

      buffer.setLength(0);
      Base64.urlEncode(leftPadded, i, decoded.length, buffer, true);
      assertEquals(buffer.toString(), urlEncoded);

      buffer.setLength(0);
      final byte[] rightPadded = new byte[decoded.length+i];
      System.arraycopy(decoded, 0, rightPadded, 0, decoded.length);
      Base64.encode(rightPadded, 0, decoded.length, buffer);
      assertEquals(buffer.toString(), encoded);

      buffer.setLength(0);
      Base64.urlEncode(rightPadded, 0, decoded.length, buffer, true);
      assertEquals(buffer.toString(), urlEncoded);

      buffer.setLength(0);
      final byte[] bothPadded = new byte[decoded.length+i+i];
      System.arraycopy(decoded, 0, bothPadded, i, decoded.length);
      Base64.encode(bothPadded, i, decoded.length, buffer);
      assertEquals(buffer.toString(), encoded);

      buffer.setLength(0);
      Base64.urlEncode(bothPadded, i, decoded.length, buffer, true);
      assertEquals(buffer.toString(), urlEncoded);
    }
  }



  /**
   * Tests the {@code encode} and {@code decode} methods using raw data
   * represented as a string rather than a byte array.
   *
   * @param  decoded  The raw data to be encoded.
   * @param  encoded  The encoded form of the provided data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBase64Data")
  public void testEncodeAndDecodeStrings(byte[] decoded, String encoded)
         throws Exception
  {
    String doubleEncoded = Base64.encode(encoded);
    String singleDecoded = Base64.decodeToString(doubleEncoded);
    assertEquals(singleDecoded, encoded);

    String singleURLEncoded = Base64.urlEncode(decoded, true);
    String doubleURLEncoded = Base64.urlEncode(singleURLEncoded, true);
    String singleURLDecoded = Base64.urlDecodeToString(doubleURLEncoded);
    assertEquals(singleURLDecoded, singleURLEncoded);

    StringBuilder buffer = new StringBuilder();
    Base64.encode(encoded, buffer);
    assertEquals(buffer.toString(), doubleEncoded);

    final ByteStringBuffer bsb = new ByteStringBuffer();
    Base64.encode(encoded, bsb);
    assertEquals(bsb.toString(), doubleEncoded);

    buffer.setLength(0);
    Base64.urlEncode(singleURLEncoded, buffer, true);
    assertEquals(buffer.toString(), doubleURLEncoded);

    bsb.setLength(0);
    Base64.urlEncode(singleURLEncoded, bsb, true);
    assertEquals(bsb.toString(), doubleURLEncoded);

    for (int i=1; i < 10; i++)
    {
      buffer.setLength(0);
      final byte[] leftPadded = new byte[decoded.length+i];
      System.arraycopy(decoded, 0, leftPadded, i, decoded.length);
      Base64.encode(leftPadded, i, decoded.length, buffer);
      assertEquals(buffer.toString(), encoded);

      buffer.setLength(0);
      Base64.urlEncode(leftPadded, i, decoded.length, buffer, true);
      assertEquals(buffer.toString(), singleURLEncoded);

      buffer.setLength(0);
      final byte[] rightPadded = new byte[decoded.length+i];
      System.arraycopy(decoded, 0, rightPadded, 0, decoded.length);
      Base64.encode(rightPadded, 0, decoded.length, buffer);
      assertEquals(buffer.toString(), encoded);

      buffer.setLength(0);
      Base64.urlEncode(rightPadded, 0, decoded.length, buffer, true);
      assertEquals(buffer.toString(), singleURLEncoded);

      buffer.setLength(0);
      final byte[] bothPadded = new byte[decoded.length+i+i];
      System.arraycopy(decoded, 0, bothPadded, i, decoded.length);
      Base64.encode(bothPadded, i, decoded.length, buffer);
      assertEquals(buffer.toString(), encoded);

      buffer.setLength(0);
      Base64.urlEncode(bothPadded, i, decoded.length, buffer, true);
      assertEquals(buffer.toString(), singleURLEncoded);
    }
  }



  /**
   * Tests the {@code encode} method with a {@code null} argument.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeNull()
  {
    Base64.encode((byte[]) null);
  }



  /**
   * Tests the {@code decode} method with a {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDecodeNull()
         throws Exception
  {
    Base64.decode(null);
  }



  /**
   * Tests the {@code decode} method with a string that is not a multiple of
   * four characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeNotMultipleOfFour()
         throws Exception
  {
    Base64.decode("notamultipleof4characters");
  }



  /**
   * Tests the {@code decode} method with a string that is not a multiple of
   * four characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testURLDecodeNotMultipleOfFour()
         throws Exception
  {
    Base64.urlDecode("notamultipleof4characters");
  }



  /**
   * Tests the {@code decode} method with a string that contains an invalid
   * character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeInvalidCharacter()
         throws Exception
  {
    Base64.decode("spaces are not valid");
  }



  /**
   * Tests the {@code decode} method with a string that contains an invalid
   * character.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testURLDecodeInvalidCharacter()
         throws Exception
  {
    Base64.urlDecode("spaces are not valid");
  }



  /**
   * Tests the {@code decode} method with a misplaced equal sign in the middle
   * of the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeInvalidMiddleEqualPosition()
         throws Exception
  {
    Base64.decode("invlaid=position");
  }



  /**
   * Tests the {@code decode} method with a misplaced equal sign at the end of
   * the value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ParseException.class })
  public void testDecodeInvalidEndEqualPosition()
         throws Exception
  {
    Base64.decode("a===");
  }



  /**
   * Retrieves a sest of data that can be used to test the {@code encode} and
   * {@code decode} methods.
   *
   * @return  A set of data that can be used to test the {@code encode} and
   *          {@code decode} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "testBase64Data")
  public Object[][] getTestToHexData()
         throws Exception
  {
    ArrayList<byte[]> decodedList = new ArrayList<byte[]>();
    ArrayList<String> encodedList = new ArrayList<String>();

    decodedList.add(new byte[0]);
    encodedList.add("");

    decodedList.add(new byte[1]);
    encodedList.add("AA==");

    decodedList.add(new byte[2]);
    encodedList.add("AAA=");

    decodedList.add(new byte[3]);
    encodedList.add("AAAA");

    decodedList.add(new byte[4]);
    encodedList.add("AAAAAA==");

    decodedList.add(new byte[5]);
    encodedList.add("AAAAAAA=");

    decodedList.add(new byte[6]);
    encodedList.add("AAAAAAAA");

    decodedList.add(new byte[7]);
    encodedList.add("AAAAAAAAAA==");

    decodedList.add(new byte[8]);
    encodedList.add("AAAAAAAAAAA=");

    decodedList.add(new byte[9]);
    encodedList.add("AAAAAAAAAAAA");

    decodedList.add(new byte[10]);
    encodedList.add("AAAAAAAAAAAAAA==");

    decodedList.add(new byte[11]);
    encodedList.add("AAAAAAAAAAAAAAA=");

    decodedList.add(new byte[12]);
    encodedList.add("AAAAAAAAAAAAAAAA");

    decodedList.add("hello".getBytes("UTF-8"));
    encodedList.add("aGVsbG8=");

    decodedList.add("hello".getBytes("UTF-8"));
    encodedList.add("aGVsbG8=");

    decodedList.add("Hello".getBytes("UTF-8"));
    encodedList.add("SGVsbG8=");

    decodedList.add("Hello, World!".getBytes("UTF-8"));
    encodedList.add("SGVsbG8sIFdvcmxkIQ==");

    decodedList.add("foo".getBytes("UTF-8"));
    encodedList.add("Zm9v");

    decodedList.add("bar".getBytes("UTF-8"));
    encodedList.add("YmFy");

    byte[] b = new byte[254];
    for (int i=1; i < 255; i++)
    {
      b[i-1] = (byte) (i & 0xFF);
    }
    decodedList.add(b);
    encodedList.add("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkq" +
                    "KywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNU" +
                    "VVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+" +
                    "f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6Slpqeo" +
                    "qaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS" +
                    "09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8" +
                    "/f4=");

    b = new byte[255];
    for (int i=2; i < 257; i++)
    {
      b[i-2] = (byte) (i & 0xFF);
    }
    decodedList.add(b);
    encodedList.add("AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSor" +
                    "LC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RV" +
                    "VldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/" +
                    "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ip" +
                    "qqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT" +
                    "1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9" +
                    "/v8A");

    b = new byte[256];
    for (int i=0; i < 256; i++)
    {
      b[i] = (byte) (i & 0xFF);
    }
    decodedList.add(b);
    encodedList.add("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygp" +
                    "KissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJT" +
                    "VFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9" +
                    "fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaan" +
                    "qKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR" +
                    "0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7" +
                    "/P3+/w==");


    Object[][] returnArray = new Object[decodedList.size()][2];
    for (int i=0; i < returnArray.length; i++)
    {
      returnArray[i][0] = decodedList.get(i);
      returnArray[i][1] = encodedList.get(i);
    }

    return returnArray;
  }



  /**
   * Converts the provided string, which must contain a base64-encoded value,
   * to the base64url-encoded equivalent.
   *
   * @param  b64  The base64-encoded string to convert to base64url.
   * @param  pad  Indicates whether to include padding.
   *
   * @return  A base64url-encoded equivalent of the provided base64-encoded
   *          string.
   */
  private static String convertToURLEncoded(final String b64,
                                            final boolean pad)
  {
    String s = b64;
    final int equalPos = s.indexOf('=');
    if ((! pad) && (equalPos > 0))
    {
      s = b64.substring(0, equalPos);
    }

    return s.replace('+', '-').replace('/', '_').replace("=", "%3d");
  }
}
