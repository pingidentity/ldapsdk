/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.examples;



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the base64 tool.
 */
public final class Base64ToolTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to get usage information when not providing
   * a subcommand.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageWithoutSubcommand()
         throws Exception
  {
    final ResultCode resultCode = Base64Tool.main(System.in, null, null,
         "--help");
    assertEquals(resultCode, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to get usage information when providing a
   * valid subcommand name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageWithValidSubcommand()
         throws Exception
  {
    final ResultCode resultCode = Base64Tool.main(System.in, null, null,
         "encode", "--help");
    assertEquals(resultCode, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to get usage information when providing a
   * valid subcommand name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsageWithInvalidSubcommand()
         throws Exception
  {
    final ResultCode resultCode = Base64Tool.main(System.in, null, null,
         "invalid", "--help");
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to get a list of all subcommands.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelpSubcommands()
         throws Exception
  {
    final ResultCode resultCode = Base64Tool.main(System.in, null, null,
         "--help-subcommands");
    assertEquals(resultCode, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the tool when the input data is provided as an
   * argument and the output is written to standard out.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testInputArgumentOutputStream()
         throws Exception
  {
    final InputStream encodeIn = null;
    final ByteArrayOutputStream encodeOut = new ByteArrayOutputStream();
    final OutputStream encodeErr = System.err;

    final ResultCode encodeResultCode =
         Base64Tool.main(encodeIn, encodeOut, encodeErr,
              "encode",
              "--data", "Test");
    assertEquals(encodeResultCode, ResultCode.SUCCESS);

    final ByteStringBuffer expectedEncodedBytes = new ByteStringBuffer();
    expectedEncodedBytes.append(Base64.encode("Test"));
    expectedEncodedBytes.append(StaticUtils.EOL_BYTES);
    assertEquals(encodeOut.toByteArray(), expectedEncodedBytes.toByteArray());


    final InputStream decodeIn = null;
    final ByteArrayOutputStream decodeOut = new ByteArrayOutputStream();
    final OutputStream decodeErr = System.err;

    final ResultCode decodeResultCode =
         Base64Tool.main(decodeIn, decodeOut, decodeErr,
              "decode",
              "--data", Base64.encode("Test"));
    assertEquals(decodeResultCode, ResultCode.SUCCESS);

    assertEquals(decodeOut.toByteArray(),
         StaticUtils.getBytes("Test"));
  }



  /**
   * Tests the behavior of the tool when the input data is provided via standard
   * input and the output is written to standard out.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testInputStreamOutputStream()
         throws Exception
  {
    final ByteArrayInputStream encodeIn =
         new ByteArrayInputStream("Stream".getBytes("UTF-8"));
    final ByteArrayOutputStream encodeOut = new ByteArrayOutputStream();
    final OutputStream encodeErr = System.err;

    final ResultCode encodeResultCode =
         Base64Tool.main(encodeIn, encodeOut, encodeErr,
              "encode");
    assertEquals(encodeResultCode, ResultCode.SUCCESS);

    final ByteStringBuffer expectedEncodedBytes = new ByteStringBuffer();
    expectedEncodedBytes.append(Base64.encode("Stream"));
    expectedEncodedBytes.append(StaticUtils.EOL_BYTES);
    assertEquals(encodeOut.toByteArray(), expectedEncodedBytes.toByteArray());


    final InputStream decodeIn =
         new ByteArrayInputStream(encodeOut.toByteArray());
    final ByteArrayOutputStream decodeOut = new ByteArrayOutputStream();
    final OutputStream decodeErr = System.err;

    final ResultCode decodeResultCode =
         Base64Tool.main(decodeIn, decodeOut, decodeErr,
              "decode");
    assertEquals(decodeResultCode, ResultCode.SUCCESS);

    assertEquals(decodeOut.toByteArray(),
         StaticUtils.getBytes("Stream"));
  }



  /**
   * Tests the behavior of the tool when the input and output are both
   * file-based and we use the URL encoding and read arguments from a properties
   * file.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testInputFileOutputFileURLEncodingWithPropertiesFile()
         throws Exception
  {
    // Generate a properties file just to get coverage for that ability.  We
    // won't use the generated properties file.
    final File generatedPropertiesFile = createTempFile();

    final InputStream generateIn = null;
    final OutputStream generateOut = null;
    final OutputStream generateErr = null;

    final ResultCode genResultCode =  Base64Tool.main(generateIn, generateOut,
         generateErr,
         "--generatePropertiesFile", generatedPropertiesFile.getAbsolutePath());
    assertEquals(genResultCode, ResultCode.SUCCESS);


    final File encodeInputFile = createTempFile("Clear");
    final File encodeOutputFile = createTempFile();
    final File decodeOutputFile = createTempFile();

    final File propertiesFile = createTempFile(
         "url=true",
         "base64.ignoreTrailingLineBreak=true",
         "base64.addTrailingLineBreak=true",
         "base64.encode.inputFile=" + encodeInputFile.getAbsolutePath(),
         "base64.encode.outputFile=" + encodeOutputFile.getAbsolutePath(),
         "base64.decode.inputFile=" + encodeOutputFile.getAbsolutePath(),
         "base64.decode.outputFile=" + decodeOutputFile.getAbsolutePath());

    final InputStream encodeIn = null;
    final OutputStream encodeOut = null;
    final OutputStream encodeErr = null;

    final ResultCode encodeResultCode =
         Base64Tool.main(encodeIn, encodeOut, encodeErr,
              "encode",
              "--propertiesFilePath", propertiesFile.getAbsolutePath());
    assertEquals(encodeResultCode, ResultCode.SUCCESS);


    final InputStream decodeIn = null;
    final OutputStream decodeOut = null;
    final OutputStream decodeErr = null;

    final ResultCode decodeResultCode =
         Base64Tool.main(decodeIn, decodeOut, decodeErr,
              "decode",
              "--propertiesFilePath", propertiesFile.getAbsolutePath());
    assertEquals(decodeResultCode, ResultCode.SUCCESS);

    final BufferedReader r =
         new BufferedReader(new FileReader(decodeOutputFile));
    assertEquals(r.readLine(), "Clear");
    assertNull(r.readLine());
    r.close();
  }



  /**
   * Tests the behavior when decoding data split across multiple lines in a
   * file that also contains blank lines, comments, and lines starting with
   * dashes.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeFromFileWithLotsToIgnore()
         throws Exception
  {
    final String fullData = Base64.encode("Hello, World!");
    final String firstPart = fullData.substring(0, 10);
    final String lastPart = fullData.substring(10);

    final File inputFile = createTempFile(
         "",
         "# Ignore this comment",
         "--- Ignore this dashed line",
         firstPart,
         "",
         "# Another comment",
         lastPart,
         "",
         "--- A final dashed line");

    final File outputFile = createTempFile();

    final InputStream in = null;
    final OutputStream out = null;
    final OutputStream err = System.err;

    final ResultCode resultCode = Base64Tool.main(in, out, err,
         "decode",
         "--inputFile", inputFile.getAbsolutePath(),
         "--outputFile", outputFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final BufferedReader r = new BufferedReader(new FileReader(outputFile));
    assertEquals(r.readLine(), "Hello, World!");
    assertNull(r.readLine());
    r.close();
  }



  /**
   * Tests the behavior when trying to decode invalid data.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeInvalidData()
         throws Exception
  {
    final InputStream in = null;
    final OutputStream out = null;
    final OutputStream err = null;

    final ResultCode resultCode = Base64Tool.main(in, out, err,
         "decode",
         "--data", "~~~invalid~~~");
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to decode invalid data.
   *
   * @throws  Exception   If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeInvalidURLData()
         throws Exception
  {
    final InputStream in = null;
    final OutputStream out = null;
    final OutputStream err = null;

    final ResultCode resultCode = Base64Tool.main(in, out, err,
         "decode",
         "--data", "~~~invalid~~~",
         "--url");
    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to run the tool in interactive mode.
   *
   * Tests the ldapsearch tool with a minimal set of arguments.  Default values
   * for all of the arguments will be provided when possible, and the tool will
   * quit before actually attempting a search.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInteractiveMode()
         throws Exception
  {

    final InputStream originalSystemIn = System.in;

    try
    {
      final File outputFile = createTempFile();
      final InputStream in = getInputStream(
           "1", // Choose the decode subcommand
           "1", // Choose to edit the data to decode,
           Base64.encode("interactive"), // The data to decode
           "3", // Choose the output file to create
           outputFile.getAbsolutePath(), // The path to the output file
           "d", // Display the arguments
           "", // Done displaying the arguments
           "r"); // Run the tool.
      System.setIn(in);

      final OutputStream out = null;
      final OutputStream err = null;

      final ResultCode resultCode = Base64Tool.main(in, out, err,
           "--interactive");
      assertEquals(resultCode, ResultCode.SUCCESS);

      final BufferedReader r = new BufferedReader(new FileReader(outputFile));
      assertEquals(r.readLine(), "interactive");
      assertNull(r.readLine());
      r.close();
    }
    finally
    {
      System.setIn(originalSystemIn);
    }
  }



  /**
   * Retrieves an input stream that may be used as standard input to supply the
   * specified set of lines.
   *
   * @param  lines  The lines that will be supplied to the input stream.
   *
   * @return  The input stream that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static InputStream getInputStream(final String... lines)
          throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String s : lines)
    {
      buffer.append(s);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    return new ByteArrayInputStream(buffer.toByteArray());
  }
}
