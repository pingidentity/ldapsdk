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



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.util.OID;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides test coverage for the ASN1ObjectIdentifier class.
 */
public class ASN1ObjectIdentifierTestCase
       extends ASN1TestCase
{
  /**
   * Tests a valid object identifier.
   *
   * @param  oidString     The string representation of the OID to use when
   *                       testing.
   * @param  encodedValue  The expected encoded value for the OID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "validOIDs")
  public void testValidObjectIdentifier(final String oidString,
                                        final byte[] encodedValue)
         throws Exception
  {
    ASN1ObjectIdentifier element = new ASN1ObjectIdentifier(oidString);

    assertEquals(element.getType(), 0x06);

    assertNotNull(element.getOID());
    assertEquals(element.getOID().toString(), oidString);

    assertNotNull(element.getValue());
    assertEquals(element.getValue(), encodedValue);

    assertNotNull(element.toString());


    element = new ASN1ObjectIdentifier(new OID(oidString));

    assertEquals(element.getType(), 0x06);

    assertNotNull(element.getOID());
    assertEquals(element.getOID().toString(), oidString);

    assertNotNull(element.getValue());
    assertEquals(element.getValue(), encodedValue);

    assertNotNull(element.toString());


    element = ASN1ObjectIdentifier.decodeAsObjectIdentifier(
         new ASN1Element(ASN1Constants.UNIVERSAL_OBJECT_IDENTIFIER_TYPE,
              encodedValue));

    assertEquals(element.getType(), 0x06);

    assertNotNull(element.getOID());
    assertEquals(element.getOID().toString(), oidString);

    assertNotNull(element.getValue());
    assertEquals(element.getValue(), encodedValue);

    assertNotNull(element.toString());


    element = ASN1ObjectIdentifier.decodeAsObjectIdentifier(
         new ASN1Element(ASN1Constants.UNIVERSAL_OBJECT_IDENTIFIER_TYPE,
              encodedValue).encode());

    assertEquals(element.getType(), 0x06);

    assertNotNull(element.getOID());
    assertEquals(element.getOID().toString(), oidString);

    assertNotNull(element.getValue());
    assertEquals(element.getValue(), encodedValue);

    assertNotNull(element.toString());


    element = element.decodeAsObjectIdentifier();

    assertEquals(element.getType(), 0x06);

    assertNotNull(element.getOID());
    assertEquals(element.getOID().toString(), oidString);

    assertNotNull(element.getValue());
    assertEquals(element.getValue(), encodedValue);

    assertNotNull(element.toString());
  }



  /**
   * Retrieves data that can be used for testing valid OIDs.
   *
   * @return  Data that can be used for testing valid OIDs.
   */
  @DataProvider(name = "validOIDs")
  public Object[][] getValidOIDs()
  {
    return new Object[][]
    {
      new Object[]
      {
        "1.2",
        byteArray(0x2A)
      },

      new Object[]
      {
        "1.2.3",
        byteArray(0x2A, 0x03)
      },

      new Object[]
      {
        "1.2.3.4",
        byteArray(0x2A, 0x03, 0x04)
      },

      new Object[]
      {
        "1.2.3.4.5.6.7.8.9",
        byteArray(0x2A, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09)
      },

      new Object[]
      {
        "0.0",
        byteArray(0x00)
      },

      new Object[]
      {
        "0.39",
        byteArray(0x27)
      },

      new Object[]
      {
        "1.0",
        byteArray(0x28)
      },

      new Object[]
      {
        "1.39",
        byteArray(0x4F)
      },

      new Object[]
      {
        "2.0",
        byteArray(0x50)
      },

      new Object[]
      {
        "2.39",
        byteArray(0x77)
      },

      new Object[]
      {
        "1.2.3456789",
        byteArray(0x2A, 0x81, 0xD2, 0xFE, 0x15)
      },

      new Object[]
      {
        "2.123456789",
        byteArray(0xBA, 0xEF, 0x9A, 0x65)
      },

      new Object[]
      {
        "2.128.32768.8388608.268435456",
        byteArray(0x81, 0x50, 0x82, 0x80, 0x00, 0x84, 0x80, 0x80, 0x00, 0x81,
             0x80, 0x80, 0x80, 0x00)
      },

      new Object[]
      {
        "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25." +
             "26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42.43.44.45." +
             "46.47.48.49.50.51.52.53.54.55.56.57.58.59.60.61.62.63.64.65." +
             "66.67.68.69.70.71.72.73.74.75.76.77.78.79.80.81.82.83.84.85." +
             "86.87.88.89.90.91.92.93.94.95.96.97.98.99.100.101.102.103." +
             "104.105.106.107.108.109.110.111.112.113.114.115.116.117.118." +
             "119.120.121.122.123.124.125.126.127.128.129.130",
        byteArray(0x2A, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
             0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
             0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
             0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
             0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
             0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
             0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
             0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
             0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
             0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
             0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
             0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81, 0x00, 0x81, 0x01, 0x81,
             0x02)
      }
    };
  }



  /**
   * Tests an invalid object identifier.
   *
   * @param  oidString      The string representation of an invalid OID.
   * @param  invalidReason  The reason the provided string is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "invalidOIDs",
        expectedExceptions =  { ASN1Exception.class })
  public void testValidObjectIdentifier(final String oidString,
                                        final String invalidReason)
         throws Exception
  {
    new ASN1ObjectIdentifier(oidString);
  }



  /**
   * Retrieves data that can be used for testing valid OIDs.
   *
   * @return  Data that can be used for testing valid OIDs.
   */
  @DataProvider(name = "invalidOIDs")
  public Object[][] getInvalidOIDs()
  {
    return new Object[][]
    {
      new Object[]
      {
        "not numeric",
        "Not a numeric OID"
      },

      new Object[]
      {
        "1",
        "Not enough components in the OID"
      },

      new Object[]
      {
        "0.40",
        "First component of zero and second component above 39"
      },

      new Object[]
      {
        "1.40",
        "First component of one and second component above 39"
      },

      new Object[]
      {
        "3.0",
        "First component greater than two"
      }
    };
  }



  /**
   * Tests the behavior when trying to decode an empty array as an object
   * identifier element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeEmptyArray()
         throws Exception
  {
    ASN1ObjectIdentifier.decodeAsObjectIdentifier(NO_BYTES);
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
    ASN1ObjectIdentifier.decodeAsObjectIdentifier(byteArray(0x06, 0x02, 0x00));
  }



  /**
   * Tests the behavior when trying to decode an array with an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeEmptyValue()
         throws Exception
  {
    ASN1ObjectIdentifier.decodeAsObjectIdentifier(byteArray(0x06, 0x00));
  }



  /**
   * Tests the behavior when trying to decode an element with an incomplete
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { ASN1Exception.class })
  public void testDecodeIncompleteValue()
         throws Exception
  {
    ASN1ObjectIdentifier.decodeAsObjectIdentifier(
         new ASN1Element((byte) 0x06, byteArray(0x06, 0x01, 0xFF)));
  }
}
