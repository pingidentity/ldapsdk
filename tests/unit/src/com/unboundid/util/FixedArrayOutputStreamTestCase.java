/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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



import java.io.IOException;
import java.util.Arrays;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the
 * {@code FixedArrayOutputStream} class.
 */
public final class FixedArrayOutputStreamTestCase
       extends UtilTestCase
{
  /**
   * Tests output stream functionality when using the entire array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullArray()
         throws Exception
  {
    final byte[] b = new byte[10];
    Arrays.fill(b, (byte) 0x77);

    final FixedArrayOutputStream s = new FixedArrayOutputStream(b);

    assertNotNull(s);

    assertNotNull(s.getBackingArray());
    assertSame(s.getBackingArray(), b);

    assertEquals(s.getInitialPosition(), 0);
    assertEquals(s.getLength(), 10);
    assertEquals(s.getBytesWritten(), 0);

    s.write((byte) 0x01);
    assertEquals(s.getBytesWritten(), 1);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x77, 0x77, 0x77, 0x77, 0x77,
         0x77, 0x77, 0x77, 0x77 }));

    final byte[] ones = new byte[5];
    Arrays.fill(ones, (byte) 0x01);
    s.write(ones);
    assertEquals(s.getBytesWritten(), 6);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
         0x77, 0x77, 0x77, 0x77 }));

    final byte[] increasing = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    s.write(increasing, 1, 3);
    assertEquals(s.getBytesWritten(), 9);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
         0x02, 0x03, 0x04, 0x77 }));

    s.write((byte) 0x06);
    assertEquals(s.getBytesWritten(), 10);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
         0x02, 0x03, 0x04, 0x06 }));

    try
    {
      s.write((byte) 0x07);
      fail("Expected an exception when trying to write a single byte to a " +
           "full array.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
      assertEquals(s.getBytesWritten(), 10);
      assertSame(s.getBackingArray(), b);
      assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01,
           0x01, 0x02, 0x03, 0x04, 0x06 }));
    }

    s.write(new byte[0]);
    assertEquals(s.getBytesWritten(), 10);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
         0x02, 0x03, 0x04, 0x06 }));

    try
    {
      s.write(ones);
      fail("Expected an exception when trying to write a complete array to a " +
           "full array.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
      assertEquals(s.getBytesWritten(), 10);
      assertSame(s.getBackingArray(), b);
      assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01,
           0x01, 0x02, 0x03, 0x04, 0x06 }));
    }

    try
    {
      s.write(ones, 1, 3);
      fail("Expected an exception when trying to write a partial array to a " +
           "full array.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
      assertEquals(s.getBytesWritten(), 10);
      assertSame(s.getBackingArray(), b);
      assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01,
           0x01, 0x02, 0x03, 0x04, 0x06 }));
    }

    s.write(ones, 0, 0);
    assertEquals(s.getBytesWritten(), 10);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
         0x02, 0x03, 0x04, 0x06 }));

    s.flush();
    s.close();
  }



  /**
   * Tests output stream functionality when using a portion of the provided
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPartialArray()
         throws Exception
  {
    final byte[] b = new byte[10];
    Arrays.fill(b, (byte) 0x77);

    final FixedArrayOutputStream s = new FixedArrayOutputStream(b, 2, 7);

    assertNotNull(s);

    assertNotNull(s.getBackingArray());
    assertSame(s.getBackingArray(), b);

    assertEquals(s.getInitialPosition(), 2);
    assertEquals(s.getLength(), 7);
    assertEquals(s.getBytesWritten(), 0);

    s.write((byte) 0x01);
    assertEquals(s.getBytesWritten(), 1);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x77, 0x77, 0x77,
         0x77, 0x77, 0x77, 0x77 }));

    final byte[] ones = new byte[4];
    Arrays.fill(ones, (byte) 0x01);
    s.write(ones);
    assertEquals(s.getBytesWritten(), 5);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01, 0x01,
         0x01, 0x77, 0x77, 0x77 }));

    final byte[] increasing = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    s.write(increasing, 2, 2);
    assertEquals(s.getBytesWritten(), 7);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01, 0x01,
         0x01, 0x03, 0x04, 0x77 }));

    try
    {
      s.write((byte) 0x07);
      fail("Expected an exception when trying to write a single byte to a " +
           "full array.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
      assertEquals(s.getBytesWritten(), 7);
      assertSame(s.getBackingArray(), b);
      assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01,
           0x01, 0x01, 0x03, 0x04, 0x77 }));
    }

    s.write(new byte[0]);
    assertEquals(s.getBytesWritten(), 7);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01, 0x01,
         0x01, 0x03, 0x04, 0x77 }));

    try
    {
      s.write(ones);
      fail("Expected an exception when trying to write a complete array to a " +
           "full array.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
      assertEquals(s.getBytesWritten(), 7);
      assertSame(s.getBackingArray(), b);
      assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01,
           0x01, 0x01, 0x03, 0x04, 0x77 }));
    }

    try
    {
      s.write(ones, 1, 3);
      fail("Expected an exception when trying to write a partial array to a " +
           "full array.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
      assertEquals(s.getBytesWritten(), 7);
      assertSame(s.getBackingArray(), b);
      assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01,
           0x01, 0x01, 0x03, 0x04, 0x77 }));
    }

    s.write(ones, 0, 0);
    assertEquals(s.getBytesWritten(), 7);
    assertSame(s.getBackingArray(), b);
    assertTrue(Arrays.equals(b, new byte[] { 0x77, 0x77, 0x01, 0x01, 0x01, 0x01,
         0x01, 0x03, 0x04, 0x77 }));

    s.flush();
    s.close();
  }



  /**
   * Tests the behavior when attempting to create an output stream with a null
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testCreateNullArray()
         throws Exception
  {
    new FixedArrayOutputStream(null);
  }



  /**
   * Tests the behavior when attempting to create an output stream with a null
   * array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testCreateNullArrayPartial()
         throws Exception
  {
    new FixedArrayOutputStream(null, 0, 10);
  }



  /**
   * Tests the behavior when attempting to create an output stream in which the
   * start position is beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateStartBeyondEnd()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10], 11, 0);
  }



  /**
   * Tests the behavior when attempting to create an output stream in which the
   * start position plus the length is beyond the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateStartPlusLengthBeyondEnd()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10], 2, 12);
  }



  /**
   * Tests the behavior when attempting to create an output stream in which the
   * start position is negative.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateStartNegative()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10], -1, 5);
  }



  /**
   * Tests the behavior when attempting to create an output stream in which the
   * length is negative.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateLengthNegative()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10], 1, -5);
  }



  /**
   * Tests the behavior when trying to write when a null array is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testWriteNullArray()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10]).write(null);
  }



  /**
   * Tests the behavior when trying to write when a null array is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { NullPointerException.class })
  public void testWriteNullArrayPartial()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10]).write(null, 0, 0);
  }



  /**
   * Tests the behavior when trying to write with a negative position.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWriteNegativePosition()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10]).write(new byte[5], -1, 0);
  }



  /**
   * Tests the behavior when trying to write with a negative length.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWriteNegativeLength()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10]).write(new byte[5], 2, -1);
  }



  /**
   * Tests the behavior when trying to write with position plus length beyond
   * the end of the array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWriteBeyondEnd()
         throws Exception
  {
    new FixedArrayOutputStream(new byte[10]).write(new byte[5], 2, 4);
  }
}
