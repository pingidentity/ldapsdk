/*
 * Copyright 2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the ASN1BitString class.
 */
public class ASN1BitStringTestCase
       extends ASN1TestCase
{
  /**
   * Tests the behavior when trying to create an empty bit string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyBitString()
         throws Exception
  {
    ASN1BitString e = new ASN1BitString();

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

    assertNotNull(e.getBits());
    assertEquals(e.getBits().length, 0);

    assertNotNull(e.getBytes());
    assertEquals(e.getBytes(), StaticUtils.NO_BYTES);

    assertNotNull(e.toString());
    assertEquals(e.toString(), "");


    e = new ASN1BitString("");

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

    assertNotNull(e.getBits());
    assertEquals(e.getBits().length, 0);

    assertNotNull(e.getBytes());
    assertEquals(e.getBytes(), StaticUtils.NO_BYTES);

    assertNotNull(e.toString());
    assertEquals(e.toString(), "");


    e = ASN1BitString.decodeAsBitString(e.encode());

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

    assertNotNull(e.getBits());
    assertEquals(e.getBits().length, 0);

    assertNotNull(e.getBytes());
    assertEquals(e.getBytes(), StaticUtils.NO_BYTES);

    assertNotNull(e.toString());
    assertEquals(e.toString(), "");


    e = ASN1BitString.decodeAsBitString(e);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

    assertNotNull(e.getBits());
    assertEquals(e.getBits().length, 0);

    assertNotNull(e.getBytes());
    assertEquals(e.getBytes(), StaticUtils.NO_BYTES);

    assertNotNull(e.toString());
    assertEquals(e.toString(), "");


    e = ASN1BitString.decodeAsBitString(e);

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

    assertNotNull(e.getBits());
    assertEquals(e.getBits().length, 0);

    assertNotNull(e.getBytes());
    assertEquals(e.getBytes(), StaticUtils.NO_BYTES);

    assertNotNull(e.toString());
    assertEquals(e.toString(), "");


    e = e.decodeAsBitString();

    assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

    assertNotNull(e.getBits());
    assertEquals(e.getBits().length, 0);

    assertNotNull(e.getBytes());
    assertEquals(e.getBytes(), StaticUtils.NO_BYTES);

    assertNotNull(e.toString());
    assertEquals(e.toString(), "");
  }



  /**
   * Tests the behavior when trying to create a non-empty bit string in which
   * all even bits are 1 and all odd bits are 0.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyBitStringWith1Then0()
         throws Exception
  {
    for (int i=0; i < 2000; i++)
    {
      final boolean[] bits = new boolean[i];
      final StringBuilder buffer = new StringBuilder();
      for (int j=0; j < bits.length; j++)
      {
        if ((j % 2) == 0)
        {
          bits[j] = true;
          buffer.append('1');
        }
        else
        {
          bits[j] = false;
          buffer.append('0');
        }
      }

      final String bitString = buffer.toString();

      ASN1BitString e = new ASN1BitString(bits);

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertEquals(e.getBits(), bits);

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = new ASN1BitString(e.toString());

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = ASN1BitString.decodeAsBitString(e.encode());

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = ASN1BitString.decodeAsBitString(e);

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = ASN1BitString.decodeAsBitString(e);

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = e.decodeAsBitString();

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);
    }
  }



  /**
   * Tests the behavior when trying to create a non-empty bit string in which
   * all even bits are 0 and all odd bits are 1.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyBitStringWith0Then1()
         throws Exception
  {
    for (int i=0; i < 2000; i++)
    {
      final boolean[] bits = new boolean[i];
      final StringBuilder buffer = new StringBuilder();
      for (int j=0; j < bits.length; j++)
      {
        if ((j % 2) != 0)
        {
          bits[j] = true;
          buffer.append('1');
        }
        else
        {
          bits[j] = false;
          buffer.append('0');
        }
      }

      final String bitString = buffer.toString();

      ASN1BitString e = new ASN1BitString(bits);

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertEquals(e.getBits(), bits);

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = new ASN1BitString(e.toString());

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = ASN1BitString.decodeAsBitString(e.encode());

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = ASN1BitString.decodeAsBitString(e);

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = ASN1BitString.decodeAsBitString(e);

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);


      e = e.decodeAsBitString();

      assertEquals(e.getType(), ASN1Constants.UNIVERSAL_BIT_STRING_TYPE);

      assertNotNull(e.getBits());
      assertEquals(e.getBits().length, i);
      assertTrue(Arrays.equals(e.getBits(), bits));

      if ((i % 8) == 0)
      {
        assertNotNull(e.getBytes());
        assertEquals(e.getBytes().length, (i / 8));
      }
      else
      {
        try
        {
          e.getBytes();
          fail("Expected an exception when trying to get the bytes for bit " +
               "string " + bitString);
        }
        catch (final ASN1Exception ae)
        {
          // This was expected.
        }
      }

      assertNotNull(e.toString());
      assertEquals(e.toString(), bitString);
    }
  }



  /**
   * Tests the behavior when trying to create a bit string from a malformed
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testCreateFromMalformedString()
         throws Exception
  {
    new ASN1BitString("malformed");
  }



  /**
   * Tests the behavior when trying to decode an empty byte array as a bit
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeEmptyArray()
         throws Exception
  {
    ASN1BitString.decodeAsBitString(StaticUtils.NO_BYTES);
  }



  /**
   * Tests the behavior when trying to decode an element with an empty value
   * as a bit string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementWithEmptyValue()
         throws Exception
  {
    ASN1BitString.decodeAsBitString(new byte[] { 0x03, 0x00 });
  }



  /**
   * Tests the behavior when trying to decode an element with an empty value
   * as a bit string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementWithLengthMismatch()
         throws Exception
  {
    ASN1BitString.decodeAsBitString(new byte[] { 0x03, 0x01 });
  }



  /**
   * Tests the behavior when trying to decode an element with a single-byte
   * value as a bit string when that single byte is not zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementWithSingleByteNonzeroValue()
         throws Exception
  {
    ASN1BitString.decodeAsBitString(new ASN1Element(
         ASN1Constants.UNIVERSAL_BIT_STRING_TYPE, new byte[] { 0x01 }));
  }



  /**
   * Tests the behavior when trying to decode an element with a value that
   * indicates an invalid number of padding bits.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ASN1Exception.class })
  public void testDecodeElementWithInvalidPaddingBitCount()
         throws Exception
  {
    ASN1BitString.decodeAsBitString(new ASN1Element(
         ASN1Constants.UNIVERSAL_BIT_STRING_TYPE, new byte[] { 0x09, 0x00 }));
  }
}
