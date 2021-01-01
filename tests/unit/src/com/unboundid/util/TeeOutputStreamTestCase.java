/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the {@code TeeOutputStream}
 * class.
 */
public final class TeeOutputStreamTestCase
       extends UtilTestCase
{
  /**
   * Tests the behavior when initialized with a null array.  This primarily
   * ensures that no exceptions are thrown during processing, since all output
   * will be discarded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullArray()
         throws Exception
  {
    final OutputStream[] targetStreams = null;
    final TeeOutputStream teeOutputStream = new TeeOutputStream(targetStreams);

    // Try writing a single byte.
    teeOutputStream.write(0x00);

    // Try writing a byte array.
    teeOutputStream.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    // Try writing a portion of a byte array.
    teeOutputStream.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);

    // Try flushing the stream.
    teeOutputStream.flush();

    // Try closing the stream.
    teeOutputStream.close();
  }



  /**
   * Tests the behavior when initialized with an empty array.  This primarily
   * ensures that no exceptions are thrown during processing, since all output
   * will be discarded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyArray()
         throws Exception
  {
    final TeeOutputStream teeOutputStream = new TeeOutputStream();

    // Try writing a single byte.
    teeOutputStream.write(0x00);

    // Try writing a byte array.
    teeOutputStream.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    // Try writing a portion of a byte array.
    teeOutputStream.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);

    // Try flushing the stream.
    teeOutputStream.flush();

    // Try closing the stream.
    teeOutputStream.close();
  }



  /**
   * Tests the behavior when initialized with an array containing multiple
   * elements.  All data will be written to multiple streams through the tee
   * output stream, as well as to a separate stream maintained manually, and all
   * resulting streams will be compared to ensure they have identical content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyArray()
         throws Exception
  {
    final File separateFile = createTempFile();
    final File teedFile     = createTempFile();

    final FileOutputStream separateFOS = new FileOutputStream(separateFile);
    final FileOutputStream teedFOS = new FileOutputStream(teedFile);
    final ByteArrayOutputStream teedBAOS = new ByteArrayOutputStream();

    final TeeOutputStream teeOutputStream =
         new TeeOutputStream(teedFOS, teedBAOS);

    // Try writing a single byte.
    separateFOS.write(0x00);
    teeOutputStream.write(0x00);

    // Try writing a byte array.
    separateFOS.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });
    teeOutputStream.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    // Try writing a portion of a byte array.
    separateFOS.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);
    teeOutputStream.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);

    // Try flushing the stream.
    separateFOS.flush();
    teeOutputStream.flush();

    // Try closing the stream.
    separateFOS.close();
    teeOutputStream.close();

    final byte[] separateMD5 = getMD5Digest(separateFile);
    final byte[] teedFileMD5 = getMD5Digest(teedFile);
    final byte[] teedBAOSMD5 = getMD5Digest(teedBAOS.toByteArray());

    assertEquals(separateMD5, teedFileMD5);
    assertEquals(separateMD5, teedBAOSMD5);
    assertEquals(teedFileMD5, teedBAOSMD5);
  }



  /**
   * Tests the behavior when initialized with a null collection.  This primarily
   * ensures that no exceptions are thrown during processing, since all output
   * will be discarded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullCollection()
         throws Exception
  {
    final ArrayList<OutputStream> targetStreams = null;
    final TeeOutputStream teeOutputStream = new TeeOutputStream(targetStreams);

    // Try writing a single byte.
    teeOutputStream.write(0x00);

    // Try writing a byte array.
    teeOutputStream.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    // Try writing a portion of a byte array.
    teeOutputStream.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);

    // Try flushing the stream.
    teeOutputStream.flush();

    // Try closing the stream.
    teeOutputStream.close();
  }



  /**
   * Tests the behavior when initialized with an empty collection.  This
   * primarily ensures that no exceptions are thrown during processing, since
   * all output will be discarded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyCollection()
         throws Exception
  {
    final ArrayList<OutputStream> targetStreams =
         new ArrayList<OutputStream>(0);
    final TeeOutputStream teeOutputStream = new TeeOutputStream(targetStreams);

    // Try writing a single byte.
    teeOutputStream.write(0x00);

    // Try writing a byte array.
    teeOutputStream.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    // Try writing a portion of a byte array.
    teeOutputStream.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);

    // Try flushing the stream.
    teeOutputStream.flush();

    // Try closing the stream.
    teeOutputStream.close();
  }



  /**
   * Tests the behavior when initialized with a collection containing multiple
   * elements.  All data will be written to multiple streams through the tee
   * output stream, as well as to a separate stream maintained manually, and all
   * resulting streams will be compared to ensure they have identical content.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyCollection()
         throws Exception
  {
    final File separateFile = createTempFile();
    final File teedFile     = createTempFile();

    final FileOutputStream separateFOS = new FileOutputStream(separateFile);
    final FileOutputStream teedFOS = new FileOutputStream(teedFile);
    final ByteArrayOutputStream teedBAOS = new ByteArrayOutputStream();

    final ArrayList<OutputStream> targetStreams =
         new ArrayList<OutputStream>(2);
    targetStreams.add(teedFOS);
    targetStreams.add(teedBAOS);
    final TeeOutputStream teeOutputStream = new TeeOutputStream(targetStreams);

    // Try writing a single byte.
    separateFOS.write(0x00);
    teeOutputStream.write(0x00);

    // Try writing a byte array.
    separateFOS.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });
    teeOutputStream.write(new byte[] { 0x01, 0x02, 0x03, 0x04 });

    // Try writing a portion of a byte array.
    separateFOS.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);
    teeOutputStream.write(new byte[] { 0x05, 0x06, 0x07, 0x08 }, 1, 2);

    // Try flushing the stream.
    separateFOS.flush();
    teeOutputStream.flush();

    // Try closing the stream.
    separateFOS.close();
    teeOutputStream.close();

    final byte[] separateMD5 = getMD5Digest(separateFile);
    final byte[] teedFileMD5 = getMD5Digest(teedFile);
    final byte[] teedBAOSMD5 = getMD5Digest(teedBAOS.toByteArray());

    assertEquals(separateMD5, teedFileMD5);
    assertEquals(separateMD5, teedBAOSMD5);
    assertEquals(teedFileMD5, teedBAOSMD5);
  }



  /**
   * Tests to ensure correct behavior if an exception is thrown by one of the
   * subordinate streams when it is closed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExceptionOnClose()
         throws Exception
  {
    final TestOutputStream s1 = new TestOutputStream(
         NullOutputStream.getInstance(),
         new IOException("s1"), Integer.MAX_VALUE, true);
    final TestOutputStream s2 = new TestOutputStream(
         NullOutputStream.getInstance(),
         new IOException("s2"), Integer.MAX_VALUE, true);
    final TestOutputStream s3 = new TestOutputStream(
         NullOutputStream.getInstance(),
         new IOException("s3"), Integer.MAX_VALUE, false);

    assertFalse(s1.isClosed());
    assertFalse(s2.isClosed());
    assertFalse(s2.isClosed());

    final TeeOutputStream tOS = new TeeOutputStream(s1, s2, s3);

    assertFalse(s1.isClosed());
    assertFalse(s2.isClosed());
    assertFalse(s2.isClosed());

    try
    {
      tOS.close();
      fail("Expected an IO exception when trying to close the streams.");
    }
    catch (final IOException ioe)
    {
      // Ensure that the first exception is the one that gets thrown.
      assertEquals(ioe.getMessage(), "s1");
    }

    assertTrue(s1.isClosed());
    assertTrue(s2.isClosed());
    assertTrue(s3.isClosed());
  }
}
