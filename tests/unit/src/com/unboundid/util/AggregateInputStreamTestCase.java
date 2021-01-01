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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the aggregate input stream class.
 */
public final class AggregateInputStreamTestCase
       extends UtilTestCase
{
  /**
   * Provides test coverage for the method used to read a single byte from the
   * aggregate input stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSingleBytes()
         throws Exception
  {
    final byte[] completeArray =
         StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz");
    final InputStream[] partialStreams =
    {
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")),
      new ByteArrayInputStream(StaticUtils.getBytes("nopq")),
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("r")),
      new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")),
      new ByteArrayInputStream(StaticUtils.getBytes(""))
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    for (int i=0; i < completeArray.length; i++)
    {
      assertTrue(inputStream.available() >= 0);
      final int byteRead = inputStream.read();
      assertTrue(byteRead > 0);
      assertEquals((byte) byteRead, completeArray[i]);
      assertTrue(inputStream.available() >= 0);
    }

    assertEquals(inputStream.read(), -1);
    assertEquals(inputStream.available(), 0);
    inputStream.close();
  }



  /**
   * Provides test coverage for the method used to read multiple bytes into a
   * byte array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadByteArrays()
         throws Exception
  {
    final byte[] completeArray =
         StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz");
    final InputStream[] partialStreams =
    {
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")),
      new ByteArrayInputStream(StaticUtils.getBytes("nopq")),
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("r")),
      new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")),
      new ByteArrayInputStream(StaticUtils.getBytes(""))
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    final byte[] b = new byte[100];
    for (int i=0; i < completeArray.length; i++)
    {
      assertTrue(inputStream.available() >= 0);
      final int bytesRead = inputStream.read(b);
      if (bytesRead < 0)
      {
        break;
      }
      else
      {
        buffer.append(b, 0, bytesRead);
      }
    }

    assertEquals(inputStream.read(), -1);
    inputStream.close();

    assertEquals(buffer.toByteArray(), completeArray);
  }



  /**
   * Tests the behavior when trying to create an aggregate input stream from
   * a collection of files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromFiles()
         throws Exception
  {
    final byte[] completeArray =
         StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz");

    final File f1 = createTempFile();
    final File f2 = createTempFile();
    final File f3 = createTempFile();
    final File f4 = createTempFile();
    final File f5 = createTempFile();
    final File f6 = createTempFile();
    final File f7 = createTempFile();

    final FileOutputStream os1 = new FileOutputStream(f1, false);
    os1.close();

    final FileOutputStream os2 = new FileOutputStream(f2, false);
    os2.write(StaticUtils.getBytes("abcdefghijklm"));
    os2.close();

    final FileOutputStream os3 = new FileOutputStream(f3, false);
    os3.write(StaticUtils.getBytes("nopq"));
    os3.close();

    final FileOutputStream os4 = new FileOutputStream(f4, false);
    os4.close();

    final FileOutputStream os5 = new FileOutputStream(f5, false);
    os5.write(StaticUtils.getBytes("r"));
    os5.close();

    final FileOutputStream os6 = new FileOutputStream(f6, false);
    os6.write(StaticUtils.getBytes("stuvwxyz"));
    os6.close();

    final FileOutputStream os7 = new FileOutputStream(f7, false);
    os7.close();

    final AggregateInputStream inputStream =
         new AggregateInputStream(f1, f2, f3, f4, f5, f6, f7);

    final ByteStringBuffer buffer = new ByteStringBuffer();
    final byte[] b = new byte[100];
    for (int i=0; i < completeArray.length; i++)
    {
      assertTrue(inputStream.available() >= 0);
      final int bytesRead = inputStream.read(b);
      if (bytesRead < 0)
      {
        break;
      }
      else
      {
        buffer.append(b, 0, bytesRead);
      }
    }

    assertEquals(inputStream.read(), -1);
    inputStream.close();

    assertEquals(buffer.toByteArray(), completeArray);
  }



  /**
   * Tests the behavior when trying to create an aggregate input stream from
   * a collection of files, including a nonexistent file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromIncludingNonexistent()
         throws Exception
  {
    final byte[] completeArray =
         StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz");

    final File f1 = createTempFile();
    final File f2 = createTempFile();
    final File f3 = createTempFile();
    final File f4 = createTempFile();
    final File f5 = createTempFile();
    final File f6 = createTempFile();
    final File f7 = createTempFile();

    assertTrue(f3.delete());

    try
    {
      new AggregateInputStream(f1, f2, f3, f4, f5, f6, f7);
      fail("Expected an exception when trying to create an aggregate input " +
           "stream with a nonexistent file");
    }
    catch (final IOException ioe)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the methods used to skip data.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSkip()
         throws Exception
  {
    final byte[] completeArray =
         StaticUtils.getBytes("abcdefghijklmnopqrstuvwxyz");
    final InputStream[] partialStreams =
    {
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")),
      new ByteArrayInputStream(StaticUtils.getBytes("nopq")),
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("r")),
      new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")),
      new ByteArrayInputStream(StaticUtils.getBytes(""))
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    while (true)
    {
      assertTrue(inputStream.skip(100L) >= 0L);
      final int byteRead = inputStream.read();
      assertTrue(inputStream.skip(100L) >= 0L);

      if (byteRead < 0)
      {
        break;
      }
    }

    assertEquals(inputStream.read(), -1);
    inputStream.close();
  }



  /**
   * Tests the behavior for the methods around mark and reset.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMarkSupport()
         throws Exception
  {
    final InputStream[] partialStreams =
    {
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")),
      new ByteArrayInputStream(StaticUtils.getBytes("nopq")),
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("r")),
      new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")),
      new ByteArrayInputStream(StaticUtils.getBytes(""))
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    final int b = inputStream.read();
    assertTrue(b >= 0);

    assertFalse(inputStream.markSupported());

    inputStream.mark(100);

    try
    {
      inputStream.reset();
      fail("Expected an exception when trying to reset the stream.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
    }

    inputStream.close();
  }



  /**
   * Tests the behavior when attempting to close the input stream when there is
   * still data to be read, and without expecting any exceptions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCloseBeforeEndWithoutExceptions()
         throws Exception
  {
    final InputStream[] partialStreams =
    {
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")),
      new ByteArrayInputStream(StaticUtils.getBytes("nopq")),
      new ByteArrayInputStream(StaticUtils.getBytes("")),
      new ByteArrayInputStream(StaticUtils.getBytes("r")),
      new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")),
      new ByteArrayInputStream(StaticUtils.getBytes(""))
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    final int b = inputStream.read();
    assertTrue(b >= 0);

    inputStream.close();
  }



  /**
   * Tests the behavior when attempting to close the input stream when there is
   * still data to be read, and in which case all subordinate streams throw
   * exceptions on close.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCloseBeforeEndAllThrowException()
         throws Exception
  {
    final IOException e = new IOException("foo");
    final InputStream[] partialStreams =
    {
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("nopq")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("r")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("")), e,
           Integer.MAX_VALUE, true)
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    final int b = inputStream.read();
    assertTrue(b >= 0);

    try
    {
      inputStream.close();
      fail("Expected an exception when trying to close the aggregate stream.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when attempting to close the input stream when there is
   * still data to be read, and in which case later streams in the set throw
   * exceptions on close.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCloseBeforeEndNonFirstThrowException()
         throws Exception
  {
    final IOException e = new IOException("foo");
    final InputStream[] partialStreams =
    {
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("")), e,
           Integer.MAX_VALUE, false),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("abcdefghijklm")), e,
           Integer.MAX_VALUE, false),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("nopq")), e,
           Integer.MAX_VALUE, false),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("r")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("stuvwxyz")), e,
           Integer.MAX_VALUE, true),
      new TestInputStream(
           new ByteArrayInputStream(StaticUtils.getBytes("")), e,
           Integer.MAX_VALUE, true)
    };

    final AggregateInputStream inputStream =
         new AggregateInputStream(partialStreams);

    final int b = inputStream.read();
    assertTrue(b >= 0);

    try
    {
      inputStream.close();
      fail("Expected an exception when trying to close the aggregate stream.");
    }
    catch (final IOException ioe)
    {
      // This was expected.
    }
  }
}
