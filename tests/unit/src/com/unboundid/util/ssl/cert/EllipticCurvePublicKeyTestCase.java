/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
package com.unboundid.util.ssl.cert;



import java.math.BigInteger;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1BitString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the EllipticCurvePublicKey
 * class.
 */
public final class EllipticCurvePublicKeyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a public key with both x and y coordinates, and where the y
   * coordinate is even.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBothXAndYCoordinatesWithEvenYCoordinate()
         throws Exception
  {
    EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), BigInteger.valueOf(9876543210L));

    publicKey = new EllipticCurvePublicKey(publicKey.encode());

    assertNotNull(publicKey.getXCoordinate());
    assertEquals(publicKey.getXCoordinate(), BigInteger.valueOf(1234567890L));

    assertNotNull(publicKey.getYCoordinate());
    assertEquals(publicKey.getYCoordinate(), BigInteger.valueOf(9876543210L));

    assertFalse(publicKey.usesCompressedForm());

    assertTrue(publicKey.yCoordinateIsEven());

    assertNotNull(publicKey.toString());
  }



  /**
   * Tests a public key with both x and y coordinates, and where the y
   * coordinate is odd.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBothXAndYCoordinatesWithOddYCoordinate()
         throws Exception
  {
    EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(9876543210L), BigInteger.valueOf(123456789L));

    publicKey = new EllipticCurvePublicKey(publicKey.encode());

    assertNotNull(publicKey.getXCoordinate());
    assertEquals(publicKey.getXCoordinate(), BigInteger.valueOf(9876543210L));

    assertNotNull(publicKey.getYCoordinate());
    assertEquals(publicKey.getYCoordinate(), BigInteger.valueOf(123456789L));

    assertFalse(publicKey.usesCompressedForm());

    assertFalse(publicKey.yCoordinateIsEven());

    assertNotNull(publicKey.toString());
  }



  /**
   * Tests a public key with just the x coordinate, and an indication that the y
   * coordinate is even.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyXCoordinateWithYCoordinateIsEvenIndicator()
         throws Exception
  {
    EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), true);

    publicKey = new EllipticCurvePublicKey(publicKey.encode());

    assertNotNull(publicKey.getXCoordinate());
    assertEquals(publicKey.getXCoordinate(), BigInteger.valueOf(1234567890L));

    assertNull(publicKey.getYCoordinate());

    assertTrue(publicKey.usesCompressedForm());

    assertTrue(publicKey.yCoordinateIsEven());

    assertNotNull(publicKey.toString());
  }



  /**
   * Tests a public key with just the x coordinate, and an indication that the y
   * coordinate is odd.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyXCoordinateWithYCoordinateIsOddIndicator()
         throws Exception
  {
    EllipticCurvePublicKey publicKey = new EllipticCurvePublicKey(
         BigInteger.valueOf(1234567890L), false);

    publicKey = new EllipticCurvePublicKey(publicKey.encode());

    assertNotNull(publicKey.getXCoordinate());
    assertEquals(publicKey.getXCoordinate(), BigInteger.valueOf(1234567890L));

    assertNull(publicKey.getYCoordinate());

    assertTrue(publicKey.usesCompressedForm());

    assertFalse(publicKey.yCoordinateIsEven());

    assertNotNull(publicKey.toString());
  }



  /**
   * Tests the behavior when trying to encode a public key with an x coordinate
   * that is larger than 32 bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeXCoordinateTooBig()
         throws Exception
  {
    final byte[] xCoordinateBytes = new byte[50];
    xCoordinateBytes[0] = 0x01;

    new EllipticCurvePublicKey(new BigInteger(xCoordinateBytes), true).encode();
  }



  /**
   * Tests the behavior when trying to encode a public key with a y coordinate
   * that is larger than 32 bytes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testEncodeYCoordinateTooBig()
         throws Exception
  {
    final byte[] yCoordinateBytes = new byte[50];
    yCoordinateBytes[0] = 0x01;

    new EllipticCurvePublicKey(BigInteger.valueOf(123456789L),
         new BigInteger(yCoordinateBytes)).encode();
  }



  /**
   * Tests the behavior when trying to decode a public key that is 65 bytes long
   * but doesn't start with 0x04.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeUncompressedKeyWithWrongFirstByte()
         throws Exception
  {
    final byte[] keyBytes = new byte[65];
    keyBytes[0] = (byte) 0xFF;

    final ASN1BitString bitString = new ASN1BitString(
         ASN1BitString.getBitsForBytes(keyBytes));
    new EllipticCurvePublicKey(bitString);
  }



  /**
   * Tests the behavior when trying to decode a public key that is 33 bytes long
   * but doesn't start with 0x02 or 0x03.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeCompressedKeyWithWrongFirstByte()
         throws Exception
  {
    final byte[] keyBytes = new byte[33];
    keyBytes[0] = (byte) 0xFF;

    final ASN1BitString bitString = new ASN1BitString(
         ASN1BitString.getBitsForBytes(keyBytes));
    new EllipticCurvePublicKey(bitString);
  }



  /**
   * Tests the behavior when trying to decode a public key that is neither 65
   * nor 33 bytes long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeKeyWithUnexpectedSize()
         throws Exception
  {
    final ASN1BitString bitString = new ASN1BitString(
         ASN1BitString.getBitsForBytes(new byte[100]));
    new EllipticCurvePublicKey(bitString);
  }



  /**
   * Tests the behavior when trying to decode a public key that is neither 65
   * nor 33 bytes long.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { CertException.class })
  public void testDecodeBitStringWithNonMultipleOfEightBits()
         throws Exception
  {
    new EllipticCurvePublicKey(new ASN1BitString(true));
  }
}
