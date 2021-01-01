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
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the collect support data
 * command-line tool.
 */
public final class CollectSupportDataTestCase
       extends LDAPSDKTestCase
{
  /**
   * The result code that the in-memory directory server will return if it's
   * asked to process an extended operation that it does not support.
   */
  private static final ResultCode EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS =
       ResultCode.UNWILLING_TO_PERFORM;



  /**
   * The result code that will be returned when attempting to invoek the tool in
   * local mode when the server-side code is not available.
   */
  private static final ResultCode LOCAL_MODE_NOT_AVAILABLE =
       ResultCode.NOT_SUPPORTED;



  /**
   * Provides test coverage for a number of tool methods that don't require
   * invoking the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final CollectSupportData tool = new CollectSupportData(null, null);

    assertNotNull(tool.getToolName());
    assertFalse(tool.getToolName().isEmpty());

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertFalse(tool.getToolVersion().isEmpty());

    assertTrue(tool.supportsInteractiveMode());

    assertFalse(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertTrue(tool.supportsSSLDebugging());

    assertTrue(tool.logToolInvocationByDefault());

    assertNull(tool.getToolCompletionMessage());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Invokes the tool for the purpose of obtaining usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(CollectSupportData.main(out, err, "--help"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
    assertEquals(err.size(), 0);
  }



  /**
   * Tests the behavior when trying to invoke the extended operation using a
   * minimal set of arguments.  This will use the in-memory directory server,
   * which doesn't provide support for the extended operation the attempt will
   * fail, but it will at least get code coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationMinimalArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath());

    assertEquals(resultCode, EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation using
   * valid values for nearly all arguments.  This will use the in-memory
   * directory server, which doesn't provide support for the extended operation
   * the attempt will fail, but it will at least get code coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationAllArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File encryptionPassphraseFile = createTempFile();
    assertTrue(encryptionPassphraseFile.delete());

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--useAdministrativeSession",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--passphraseFile", encryptionPassphraseFile.getAbsolutePath(),
         "--generatePassphrase",
         "--collectExpensiveData",
         "--collectReplicationStateDump",
         "--includeBinaryFiles",
         "--archiveExtensionSource",
         "--useSequentialMode",
         "--securityLevel", "maximum",
         "--jstackCount", "0",
         "--reportCount", "0",
         "--reportIntervalSeconds", "1",
         "--logDuration", "5 minutes",
         "--comment", "This is a comment",
         "--proxyToServerAddress", "ds.example.com",
         "--proxyToServerPort", "636",
         "--noPrompt",
         "--dryRun");

    assertEquals(resultCode, EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS);

    assertFalse(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation with a
   * server that is not available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationUnavailableServer()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final String listenPort = String.valueOf(ds.getListenPort());
    ds.shutDown(true);

    try
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final ByteArrayOutputStream err = new ByteArrayOutputStream();
      final CollectSupportData tool = new CollectSupportData(out, err);

      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());

      final ResultCode resultCode = tool.runTool(
           "--useRemoteServer",
           "--hostname", "localhost",
           "--port", listenPort,
           "--outputPath", outputFile.getAbsolutePath());

      assertEquals(resultCode, ResultCode.CONNECT_ERROR);

      assertTrue(tool.defaultToPromptForBindPassword());

      assertNotNull(tool.getToolCompletionMessage());
    }
    finally
    {
      ds.startListening();
    }
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when
   * reading the encryption passphrase from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationReadValidPassphraseFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File passphraseFile =
         createTempFile("this-is-the-encryption-passphrase");

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--passphraseFile", passphraseFile.getAbsolutePath());

    assertEquals(resultCode, EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when
   * reading the encryption passphrase from an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationEmptyPassphraseFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

      final File passphraseFile = createTempFile();

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--passphraseFile", passphraseFile.getAbsolutePath());

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when
   * reading the encryption passphrase from a multi-line file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationMultiLinePassphraseFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File passphraseFile = createTempFile(
         "This is the first line.",
         "This is a second line.");

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--passphraseFile", passphraseFile.getAbsolutePath());

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when
   * using the encrypt option with noPrompt and no passphrase file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationNoPassphraseFileWithNoPrompt()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--noPrompt");

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertFalse(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when the
   * passphrase file does not exist and the generatePassphrase option was not
   * provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationMissingPassphraseFileWithoutGenerate()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File passphraseFile = createTempFile();
    assertTrue(passphraseFile.delete());

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--passphraseFile", passphraseFile.getAbsolutePath());

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when
   * prompting for the encryption passphrase.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationPromptForPassphrase()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File passphraseFile = createTempFile();
    assertTrue(passphraseFile.delete());

    PasswordReader.setTestReaderLines(
         "this-is-a-first-attempt-at-a-passphrase",
         "this-is-a-different-passphrase",
         "this-is-a-confirmed-encryption-passphrase",
         "this-is-a-confirmed-encryption-passphrase");
    try
    {
      final ResultCode resultCode = tool.runTool(
           "--useRemoteServer",
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--outputPath", outputFile.getAbsolutePath(),
           "--encrypt");

      assertEquals(resultCode, EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS);

      assertTrue(tool.defaultToPromptForBindPassword());

      assertNotNull(tool.getToolCompletionMessage());
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the behavior when trying to invoke the extended operation when
   * prompting for the encryption passphrase but an error occurs while trying
   * to obtain it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationPromptForPassphraseFailure()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File passphraseFile = createTempFile();
    assertTrue(passphraseFile.delete());

    PasswordReader.setTestReaderLines(
         "this-is-a-passphrase-but-without-confirmation");
    try
    {
      final ResultCode resultCode = tool.runTool(
           "--useRemoteServer",
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--outputPath", outputFile.getAbsolutePath(),
           "--encrypt");

      assertEquals(resultCode, ResultCode.LOCAL_ERROR);

      assertTrue(tool.defaultToPromptForBindPassword());

      assertNotNull(tool.getToolCompletionMessage());
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the behavior when trying to invoke the extended operation with a
   * valid log time range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationValidTimeRange()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final long now = System.currentTimeMillis();
    final long tenMinutesAgo = now - 600_000L;

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--logTimeRange", StaticUtils.encodeGeneralizedTime(tenMinutesAgo) +
              ',' + StaticUtils.encodeGeneralizedTime(now));

    assertEquals(resultCode, EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation with a
   * malformed log time range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationMalformedTimeRange()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final long now = System.currentTimeMillis();
    final long tenMinutesAgo = now - 600_000L;

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--logTimeRange", "malformed");

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the code used to parse the time range with a variety of options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTimeRange()
         throws Exception
  {
    // Get the current time, but with zero milliseconds.  This is needed to
    // ensure that we can more easily compare timestamps when using formats that
    // do and do not use millisecond-level precision.
    final GregorianCalendar calendar = new GregorianCalendar();
    calendar.set(Calendar.MILLISECOND, 0);

    final long nowTime = calendar.getTimeInMillis();
    final long tenMinutesAgoTime = nowTime - 600_000L;

    final Date nowDate = new Date(nowTime);
    final Date tenMinutesAgoDate = new Date(tenMinutesAgoTime);


    // Test with two generalized time values.
    ObjectPair<Date,Date> pair = CollectSupportData.parseTimeRange(
         StaticUtils.encodeGeneralizedTime(tenMinutesAgoTime) + ',' +
              StaticUtils.encodeGeneralizedTime(nowTime),
         true);
    assertEquals(pair.getFirst(), tenMinutesAgoDate);
    assertEquals(pair.getSecond(), nowDate);


    // Test with just one generalized time value.
    pair = CollectSupportData.parseTimeRange(
         StaticUtils.encodeGeneralizedTime(tenMinutesAgoTime),
         true);
    assertEquals(pair.getFirst(), tenMinutesAgoDate);
    assertNull(pair.getSecond());


    // Test with a timestamp format that is similar to the generalized time
    // format, but without a time zone indicator (indicating the local time
    // zone).
    SimpleDateFormat timestampFormatter =
         new SimpleDateFormat("yyyyMMddHHmmss");
    pair = CollectSupportData.parseTimeRange(
         timestampFormatter.format(tenMinutesAgoDate) + ',' +
              timestampFormatter.format(nowDate),
         true);
    assertEquals(pair.getFirst(), tenMinutesAgoDate);
    assertEquals(pair.getSecond(), nowDate);


    // Test with a timestamp format that uses the server-default logging format
    // with millisecond-level precision.
    timestampFormatter = new SimpleDateFormat(
         CollectSupportData.SERVER_LOG_TIMESTAMP_FORMAT_WITH_MILLIS);
    pair = CollectSupportData.parseTimeRange(
         timestampFormatter.format(tenMinutesAgoDate) + ',' +
              timestampFormatter.format(nowDate),
         true);
    assertEquals(pair.getFirst(), tenMinutesAgoDate);
    assertEquals(pair.getSecond(), nowDate);


    // Test with a timestamp format that uses the server-default logging format
    // with millisecond precision.
    timestampFormatter = new SimpleDateFormat(
         CollectSupportData.SERVER_LOG_TIMESTAMP_FORMAT_WITHOUT_MILLIS);
    pair = CollectSupportData.parseTimeRange(
         timestampFormatter.format(tenMinutesAgoDate) + ',' +
              timestampFormatter.format(nowDate),
         true);
    assertEquals(pair.getFirst(), tenMinutesAgoDate);
    assertEquals(pair.getSecond(), nowDate);


    // Test with a start time that is greater than the end time.
    try
    {
      CollectSupportData.parseTimeRange(
           StaticUtils.encodeGeneralizedTime(nowTime) + ',' +
                StaticUtils.encodeGeneralizedTime(tenMinutesAgoTime),
           true);
      fail("Expected an exception with startTime > endTime");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.PARAM_ERROR);
    }


    // Test with a malformed time range when using strict mode.
    try
    {
      CollectSupportData.parseTimeRange("malformed", true);
      fail("Expected an exception with a malformed time range");
    }
    catch (final LDAPException e)
    {
      assertEquals(e.getResultCode(), ResultCode.PARAM_ERROR);
    }


    // Test with a malformed time range when using nonstrict mode.
    assertNull(CollectSupportData.parseTimeRange("malformed", false));


    // Test when trying to invoke the tool with a malformed time range.
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--logTimeRange", "malformed");

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the extended operation with valid
   * log file head and tail sizes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvokeExtendedOperationLogFileHeadAndTailSizes()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final long now = System.currentTimeMillis();
    final long tenMinutesAgo = now - 600_000L;

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--logFileHeadCollectionSizeKB", "123",
         "--logFileTailCollectionSizeKB", "456");

    assertEquals(resultCode, EXTOP_NOT_SUPPORTED_BY_IN_MEMORY_DS);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode without
   * any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeNoArguments()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode using
   * valid values for nearly all arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeAllArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final File encryptionPassphraseFile = createTempFile();
    assertTrue(encryptionPassphraseFile.delete());

    final ResultCode resultCode = tool.runTool(
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputPath", outputFile.getAbsolutePath(),
         "--encrypt",
         "--passphraseFile", encryptionPassphraseFile.getAbsolutePath(),
         "--generatePassphrase",
         "--collectExpensiveData",
         "--collectReplicationStateDump",
         "--includeBinaryFiles",
         "--archiveExtensionSource",
         "--useSequentialMode",
         "--securityLevel", "maximum",
         "--jstackCount", "0",
         "--reportCount", "0",
         "--reportIntervalSeconds", "1",
         "--logDuration", "5 minutes",
         "--comment", "This is a comment",
         "--pid", "1234",
         "--scriptFriendly",
         "--noPrompt",
         "--dryRun");

    // We'll get a NO_OPERATION result code because we provided the --dryRun
    // argument.
    assertEquals(resultCode, ResultCode.NO_OPERATION);

    assertFalse(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with just
   * the --noLDAP argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeNoLDAP()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final ResultCode resultCode = tool.runTool("--noLDAP");

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with the
   * --decrypt argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeDecrypt()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final File fileToDecrypt = createTempFile("this-is-the-file-to-decrypt");
    final File passphraseFile = createTempFile("this-is-the-passphrase");

    final ResultCode resultCode = tool.runTool(
         "--decrypt", fileToDecrypt.getAbsolutePath(),
         "--passphraseFile", passphraseFile.getAbsolutePath());

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with a
   * valid log time range with both start and end times.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeValidTimeRangeBothStartAndEndTimes()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final long now = System.currentTimeMillis();
    final long tenMinutesAgo = now - 600_000L;

    final ResultCode resultCode = tool.runTool(
         "--logTimeRange", StaticUtils.encodeGeneralizedTime(tenMinutesAgo) +
              ',' + StaticUtils.encodeGeneralizedTime(now));

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with a
   * valid log time range with only a start time.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeValidTimeRangeOnlyStartTime()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final long now = System.currentTimeMillis();
    final long tenMinutesAgo = now - 600_000L;

    final ResultCode resultCode = tool.runTool(
         "--logTimeRange", StaticUtils.encodeGeneralizedTime(tenMinutesAgo));

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with a
   * malformed log time range when using a remote server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeMalformedTimeRangeWithRemoteServer()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final ResultCode resultCode = tool.runTool(
         "--useRemoteServer",
         "--logTimeRange", "malformed");

    assertEquals(resultCode, ResultCode.PARAM_ERROR);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with a
   * malformed log time range when not using a remote server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeMalformedTimeRangeWithoutRemoteServer()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final ResultCode resultCode = tool.runTool(
         "--logTimeRange", "malformed");

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }



  /**
   * Tests the behavior when trying to invoke the tool in local mode with
   * head and tail log file capture sizes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLocalModeLogFileHeadAndTailSizes()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();
    final CollectSupportData tool = new CollectSupportData(out, err);

    final long now = System.currentTimeMillis();
    final long tenMinutesAgo = now - 600_000L;

    final ResultCode resultCode = tool.runTool(
         "--logFileHeadCollectionSizeKB", "123",
         "--logFileTailCollectionSizeKB", "456");

    assertEquals(resultCode, LOCAL_MODE_NOT_AVAILABLE);

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getToolCompletionMessage());
  }
}
