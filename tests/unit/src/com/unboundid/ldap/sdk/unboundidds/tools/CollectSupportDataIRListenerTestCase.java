/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataArchiveFragmentIntermediateResponse;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataOutputIntermediateResponse;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataOutputStream;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.TestOutputStream;



/**
 * This class provides a set of test cases for the collect support data IR
 * listener class.
 */
public final class CollectSupportDataIRListenerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for output message responses.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputMessages()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final CollectSupportDataIRListener listener =
         new CollectSupportDataIRListener(tool, outputFile);

    listener.handleOutputIntermediateResponse(
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_OUTPUT,
              "standard output message"));

    assertEquals(out.size(),
         "standard output message".length() + StaticUtils.EOL_BYTES.length);
    assertEquals(err.size(), 0);

    assertFalse(outputFile.exists());

    assertNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    out.reset();
    assertEquals(out.size(), 0);

    listener.handleOutputIntermediateResponse(
         new CollectSupportDataOutputIntermediateResponse(
              CollectSupportDataOutputStream.STANDARD_ERROR,
              "standard error message"));

    assertEquals(out.size(), 0);
    assertEquals(err.size(),
         "standard error message".length() + StaticUtils.EOL_BYTES.length);

    assertFalse(outputFile.exists());

    assertNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    err.reset();
    assertEquals(err.size(), 0);

    listener.close();

    assertEquals(out.size(), 0);
    assertEquals(err.size(), 0);

    assertFalse(outputFile.exists());

    assertNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());
  }



  /**
   * Tests the behavior for archive fragments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArchiveFragments()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final CollectSupportDataIRListener listener =
         new CollectSupportDataIRListener(tool, outputFile);

    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, true, StaticUtils.getBytes("Hello")));

    assertTrue(out.size() > 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 5L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    out.reset();
    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, false, StaticUtils.getBytes("There")));

    assertTrue(out.size() > 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 10L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    out.reset();

    listener.close();

    assertEquals(out.size(), 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 10L);

    assertEquals(readFileBytes(outputFile),
         StaticUtils.getBytes("HelloThere"));

    assertNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());
  }



  /**
   * Tests the behavior for some other type of intermediate response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOtherResponse()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final CollectSupportDataIRListener listener =
         new CollectSupportDataIRListener(tool, outputFile);

    listener.handleOtherIntermediateResponse(new IntermediateResponse(
         "1.2.3.4", new ASN1OctetString("foo")));

    assertEquals(out.size(), 0);
    assertTrue(err.size() > 0);

    assertFalse(outputFile.exists());

    assertNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    err.reset();
    assertEquals(out.size(), 0);

    listener.close();

    assertEquals(out.size(), 0);
    assertEquals(err.size(), 0);

    assertFalse(outputFile.exists());

    assertNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());
  }



  /**
   * Tests the behavior for the case in which an attempt to write an archive
   * fragment throws an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnWrite()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final CollectSupportDataIRListener listener =
         new CollectSupportDataIRListener(tool, outputFile);

    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, true, StaticUtils.getBytes("Hello")));

    assertTrue(out.size() > 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 5L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    out.reset();

    final OutputStream streamToWrap = listener.getOutputStreamReference().get();
    listener.getOutputStreamReference().set(
         new TestOutputStream(streamToWrap, new IOException("write error"),
              0, false));

    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, false, StaticUtils.getBytes("There")));

    assertEquals(out.size(), 0);
    assertTrue(err.size() > 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 5L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNotNull(listener.getFirstIOExceptionReference().get());

    out.reset();
    err.reset();

    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, false, StaticUtils.getBytes("There")));

    assertEquals(out.size(), 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 5L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNotNull(listener.getFirstIOExceptionReference().get());

    out.reset();
    err.reset();

    try
    {
      listener.close();
      fail("Expected an exception when trying to close the output stream");
    }
    catch (final IOException e)
    {
      // This was expected.
    }

    assertEquals(out.size(), 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 5L);

    assertEquals(readFileBytes(outputFile),
         StaticUtils.getBytes("Hello"));

    assertNull(listener.getOutputStreamReference().get());

    assertNotNull(listener.getFirstIOExceptionReference().get());
  }



  /**
   * Tests the behavior for the case in which an attempt to close the output
   * stream should throw an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThrowOnClose()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final CollectSupportDataIRListener listener =
         new CollectSupportDataIRListener(tool, outputFile);

    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, true, StaticUtils.getBytes("Hello")));

    assertTrue(out.size() > 0);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 5L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    out.reset();

    final OutputStream streamToWrap = listener.getOutputStreamReference().get();
    listener.getOutputStreamReference().set(
         new TestOutputStream(streamToWrap, new IOException("close error"),
              Integer.MAX_VALUE, true));

    listener.handleArchiveFragmentIntermediateResponse(
         new CollectSupportDataArchiveFragmentIntermediateResponse("csd.zip",
              10L, false, StaticUtils.getBytes("There")));

    assertTrue(out.size() > 0L);
    assertEquals(err.size(), 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 10L);

    assertNotNull(listener.getOutputStreamReference().get());

    assertNull(listener.getFirstIOExceptionReference().get());

    out.reset();

    try
    {
      listener.close();
      fail("Expected an exception when trying to close the output stream");
    }
    catch (final IOException e)
    {
      // This was expected.
    }

    assertEquals(out.size(), 0);
    assertTrue(err.size() > 0);

    assertTrue(outputFile.exists());
    assertEquals(outputFile.length(), 10L);

    assertEquals(readFileBytes(outputFile),
         StaticUtils.getBytes("HelloThere"));

    assertNull(listener.getOutputStreamReference().get());

    assertNotNull(listener.getFirstIOExceptionReference().get());
  }
}
