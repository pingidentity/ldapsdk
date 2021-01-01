/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code ToolUtils} class.
 */
public final class ToolUtilsTestCase
       extends LDAPSDKTestCase
{
  /**
   * A print stream that can be used to suppress all output.
   */
  private static final PrintStream SUPPRESS_OUTPUT =
       NullOutputStream.getPrintStream();



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file is
   * valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadEncryptionPassphraseFromValidFile()
         throws Exception
  {
    final String passphrase = "ThisIsThePassphrase";
    final File passphraseFile = createTempFile(passphrase);

    assertEquals(ToolUtils.readEncryptionPassphraseFromFile(passphraseFile),
         passphrase);
  }



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file is
   * {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testReadEncryptionPassphraseFromNullFile()
         throws Exception
  {
    ToolUtils.readEncryptionPassphraseFromFile(null);
  }



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file is
   * missing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadEncryptionPassphraseFromMissingFile()
         throws Exception
  {
    final File missingFile = createTempFile();
    assertTrue(missingFile.delete());

    ToolUtils.readEncryptionPassphraseFromFile(missingFile);
  }



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file
   * exists but is not a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadEncryptionPassphraseFromFileNotFile()
         throws Exception
  {
    final File directory = createTempDir();

    ToolUtils.readEncryptionPassphraseFromFile(directory);
  }



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file is
   * empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadEncryptionPassphraseFromEmptyFile()
         throws Exception
  {
    final File emptyFile = createTempFile();

    ToolUtils.readEncryptionPassphraseFromFile(emptyFile);
  }



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file
   * contains a single empty line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadEncryptionPassphraseFromEmptyPassphraseFile()
         throws Exception
  {
    final File emptyPassphraseFile = createTempFile("");

    ToolUtils.readEncryptionPassphraseFromFile(emptyPassphraseFile);
  }



  /**
   * Tests the {@code readEncryptionPassphraseFromFile} method when the file
   * contains a single empty line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadEncryptionPassphraseFromMultiLineFile()
         throws Exception
  {
    final File multiLineFile = createTempFile("line1", "line2");

    ToolUtils.readEncryptionPassphraseFromFile(multiLineFile);
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it is provided
   * with a {@code null} output stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPromptForEncryptionPassphraseNullOutputStream()
         throws Exception
  {
    ToolUtils.promptForEncryptionPassphrase(false, true, null, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it is provided
   * with a {@code null} error stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPromptForEncryptionPassphraseNullErrorStream()
         throws Exception
  {
    ToolUtils.promptForEncryptionPassphrase(false, true, SUPPRESS_OUTPUT, null);
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it allows an
   * empty passphrase and does not require confirmation, when an empty
   * passphrase was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseAllowEmptyNoConfirm()
         throws Exception
  {
    try
    {
      PasswordReader.setTestReaderLines("");

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(true, false, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT),
           "");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it allows an
   * empty passphrase and requires confirmation, when an empty passphrase was
   * provided and successfully confirmed on the first try.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseAllowEmptyWithConfirmOnFirstTry()
         throws Exception
  {
    try
    {
      PasswordReader.setTestReaderLines("", "");

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(true, true, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT),
           "");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it allows an
   * empty passphrase and requires confirmation, when an empty passphrase was
   * provided but requires multiple attempts to be confirmed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseAllowEmptyWithConfirmRetry()
         throws Exception
  {
    try
    {
      PasswordReader.setTestReaderLines("", "wrong", "", "");

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(true, true, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT),
           "");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it allows an
   * empty passphrase and does not require confirmation, when a non-empty
   * passphrase was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseAllowEmptyNotEmptyNoConfirm()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(true, false, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it allows an
   * empty passphrase and requires confirmation, when a non-empty
   * passphrase was provided and is successfully confirmed on the first try.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseAllowEmptyNotEmptyConfirmFirst()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase, passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(true, true, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when it allows an
   * empty passphrase and requires confirmation, when a non-empty
   * passphrase was provided but requires multiple attempts to confirm it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseAllowEmptyNotEmptyConfirmRetry()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase, "wrong", passphrase,
           passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(true, true, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when does not allow
   * an empty passphrase and does not require confirmation, and a non-empty
   * passphrase was provided on the first attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseDoNotAllowEmptyNoConfirmNoRetry()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(false, false,
                SUPPRESS_OUTPUT, SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when does not allow
   * an empty passphrase and does not require confirmation, and a non-empty
   * passphrase was provided on a subsequent attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseDoNotAllowEmptyNoConfirmOnRetry()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines("", "", passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(false, false,
                SUPPRESS_OUTPUT, SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when does not allow
   * an empty passphrase and requires confirmation, and a non-empty passphrase
   * was provided and successfully confirmed on the first attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseDoNotAllowEmptyConfirmNoRetry()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase, passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(false, true,
                SUPPRESS_OUTPUT, SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code promptForEncryptionPassphrase} method when does not allow
   * an empty passphrase and requires confirmation, and a non-empty passphrase
   * was provided and successfully confirmed on a subsequent attempt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForEncryptionPassphraseDoNotAllowEmptyConfirmOnRetry()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase, "wrong", "", passphrase,
           passphrase);

      assertEquals(
           ToolUtils.promptForEncryptionPassphrase(false, true,
                SUPPRESS_OUTPUT, SUPPRESS_OUTPUT),
           passphrase);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code wrap} method with a {@code null} {@code PrintStream}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWrapNullPrintStream()
         throws Exception
  {
    ToolUtils.wrap("message", null);
  }



  /**
   * Tests the {@code wrap} method with a {@code null} message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapNullMessage()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrap(null, printStream);

    printStream.close();
    assertEquals(byteArrayOutputStream.toByteArray(), StaticUtils.EOL_BYTES);
  }



  /**
   * Tests the {@code wrap} method with an empty message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapEmptyMessage()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrap("", printStream);

    printStream.close();
    assertEquals(byteArrayOutputStream.toByteArray(), StaticUtils.EOL_BYTES);
  }



  /**
   * Tests the {@code wrap} method with a short message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapShortMessage()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrap("short", printStream);

    printStream.close();

    assertEquals(StaticUtils.toUTF8String(byteArrayOutputStream.toByteArray()),
         "short" + StaticUtils.EOL);
  }



  /**
   * Tests the {@code wrap} method with a long message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapLongMessage()
         throws Exception
  {
    final String longMessage = "This is a very long message that should get " +
         "wrapped because it is a very long message for the purpose of " +
         "testing the wrapping functionality. Not like a gift wrap, or a " +
         "musical rap, but more like word wrap. Actually, it's exactly like " +
         "word wrapping, because that's what it is. I suppose that I could " +
         "have called the method wordWrapNotGiftWrapOrMusicalRap, but that " +
         "would have been unnecessary and overly verbose. But I think that " +
         "this message is long enough now.";

    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrap(longMessage, printStream);

    printStream.close();

    final StringBuilder reconstructedMessageBuffer = new StringBuilder();

    int numLines = 0;
    final byte[] outputBytes = byteArrayOutputStream.toByteArray();
    final BufferedReader reader = new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(outputBytes)));
    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        break;
      }

      if (reconstructedMessageBuffer.length() > 0)
      {
        reconstructedMessageBuffer.append(' ');
      }
      reconstructedMessageBuffer.append(line);

      numLines++;
    }

    assertEquals(reconstructedMessageBuffer.toString(), longMessage);
    assertTrue((numLines > 1),
         "wrapped message:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(outputBytes));

    assertTrue(
         StaticUtils.toUTF8String(outputBytes).endsWith(StaticUtils.EOL));
  }



  /**
   * Tests the {@code wrapPrompt} method with a {@code null}
   * {@code PrintStream}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWrapPromptNullPrintStream()
         throws Exception
  {
    ToolUtils.wrapPrompt("message", true, null);
  }



  /**
   * Tests the {@code wrapPrompt} method with a {@code null} message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWrapPromptNullMessage()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt(null, true, printStream);
  }



  /**
   * Tests the {@code wrapPrompt} method with a an empty message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testWrapPromptEmptyMessage()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt("", true, printStream);
  }



  /**
   * Tests the {@code wrapPrompt} method with a short message that does not have
   * a trailing space and no trailing space should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapPromptShortMessageWithoutTrailingSpaceDoNotAddSpace()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt("short", false, printStream);

    printStream.close();

    assertEquals(StaticUtils.toUTF8String(byteArrayOutputStream.toByteArray()),
         "short");
  }



  /**
   * Tests the {@code wrapPrompt} method with a short message that does not have
   * a trailing space and a trailing space should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapPromptShortMessageWithoutTrailingSpaceAddSpace()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt("short", true, printStream);

    printStream.close();

    assertEquals(StaticUtils.toUTF8String(byteArrayOutputStream.toByteArray()),
         "short ");
  }



  /**
   * Tests the {@code wrapPrompt} method with a short message that has a
   * trailing space and no trailing space should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapPromptShortMessageWithTrailingSpaceDoNotAddSpace()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt("short ", false, printStream);

    printStream.close();

    assertEquals(StaticUtils.toUTF8String(byteArrayOutputStream.toByteArray()),
         "short ");
  }



  /**
   * Tests the {@code wrapPrompt} method with a short message that has a
   * trailing space and a trailing space should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapPromptShortMessageWithTrailingSpaceAddSpace()
         throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt("short ", true, printStream);

    printStream.close();

    assertEquals(StaticUtils.toUTF8String(byteArrayOutputStream.toByteArray()),
         "short ");
  }



  /**
   * Tests the {@code wrapPrompt} method with a long message when no trailing
   * space should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapPromptLongMessageDoNotAddSpace()
         throws Exception
  {
    final String longMessage = "This is a very long message that should get " +
         "wrapped because it is a very long message for the purpose of " +
         "testing the wrapping functionality. Not like a gift wrap, or a " +
         "musical rap, but more like word wrap. Actually, it's exactly like " +
         "word wrapping, because that's what it is. I suppose that I could " +
         "have called the method wordWrapNotGiftWrapOrMusicalRap, but that " +
         "would have been unnecessary and overly verbose. But I think that " +
         "this message is long enough now.";

    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt(longMessage, false, printStream);

    printStream.close();

    final StringBuilder reconstructedMessageBuffer = new StringBuilder();

    int numLines = 0;
    final byte[] outputBytes = byteArrayOutputStream.toByteArray();
    final BufferedReader reader = new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(outputBytes)));
    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        break;
      }

      if (reconstructedMessageBuffer.length() > 0)
      {
        reconstructedMessageBuffer.append(' ');
      }
      reconstructedMessageBuffer.append(line);

      numLines++;
    }

    assertEquals(reconstructedMessageBuffer.toString(), longMessage);
    assertTrue((numLines > 1),
         "wrapped message:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(outputBytes));

    assertFalse(
         StaticUtils.toUTF8String(outputBytes).endsWith(StaticUtils.EOL));
  }



  /**
   * Tests the {@code wrapPrompt} method with a long message when a trailing
   * space should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrapPromptLongMessageAddSpace()
         throws Exception
  {
    final String longMessage = "This is a very long message that should get " +
         "wrapped because it is a very long message for the purpose of " +
         "testing the wrapping functionality. Not like a gift wrap, or a " +
         "musical rap, but more like word wrap. Actually, it's exactly like " +
         "word wrapping, because that's what it is. I suppose that I could " +
         "have called the method wordWrapNotGiftWrapOrMusicalRap, but that " +
         "would have been unnecessary and overly verbose. But I think that " +
         "this message is long enough now.";

    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    final PrintStream printStream = new PrintStream(byteArrayOutputStream);

    ToolUtils.wrapPrompt(longMessage, true, printStream);

    printStream.close();

    final StringBuilder reconstructedMessageBuffer = new StringBuilder();

    int numLines = 0;
    final byte[] outputBytes = byteArrayOutputStream.toByteArray();
    final BufferedReader reader = new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(outputBytes)));
    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        break;
      }

      if (reconstructedMessageBuffer.length() > 0)
      {
        reconstructedMessageBuffer.append(' ');
      }
      reconstructedMessageBuffer.append(line);

      numLines++;
    }

    assertEquals(reconstructedMessageBuffer.toString(), longMessage + ' ');
    assertTrue((numLines > 1),
         "wrapped message:" + StaticUtils.EOL +
              StaticUtils.toUTF8String(outputBytes));

    assertFalse(
         StaticUtils.toUTF8String(outputBytes).endsWith(StaticUtils.EOL));
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a {@code null} set
   * of files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetInputStreamForLDIFFilesNullFiles()
         throws Exception
  {
    ToolUtils.getInputStreamForLDIFFiles(null, null, SUPPRESS_OUTPUT,
         SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with an empty set of
   * files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetInputStreamForLDIFFilesEmptyFiles()
         throws Exception
  {
    ToolUtils.getInputStreamForLDIFFiles(Collections.<File>emptyList(), null,
         SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a {@code null}
   * output stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetInputStreamForLDIFFilesNullOutputStream()
         throws Exception
  {
    final File testFile = createTempFile();

    ToolUtils.getInputStreamForLDIFFiles(Collections.singletonList(testFile),
         null, null, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a {@code null}
   * error stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetInputStreamForLDIFFilesNullErrorStream()
         throws Exception
  {
    final File testFile = createTempFile();

    ToolUtils.getInputStreamForLDIFFiles(Collections.singletonList(testFile),
         null, SUPPRESS_OUTPUT, null);
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is neither encrypted nor compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesOneFileNotEncryptedNotCompressed()
         throws Exception
  {
    final Entry testEntry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File testFile = createTempFile(testEntry.toLDIF());

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Collections.singletonList(testFile), null, SUPPRESS_OUTPUT,
              SUPPRESS_OUTPUT);

    final InputStream inputStream = p.getFirst();
    assertNotNull(inputStream);

    final String passphrase = p.getSecond();
    assertNull(passphrase);

    final LDIFReader ldifReader = new LDIFReader(inputStream);
    assertEquals(ldifReader.readEntry(), testEntry);
    assertNull(ldifReader.readEntry());
    ldifReader.close();
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is compressed but not encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesOneFileNotEncryptedCompressed()
         throws Exception
  {
    final Entry testEntry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File testFile = createTempFile(testEntry.toLDIF());
    assertTrue(testFile.delete());

    final LDIFWriter ldifWriter = new LDIFWriter(new GZIPOutputStream(
         new FileOutputStream(testFile)));
    ldifWriter.writeEntry(testEntry);
    ldifWriter.close();

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Collections.singletonList(testFile), null, SUPPRESS_OUTPUT,
              SUPPRESS_OUTPUT);

    final InputStream inputStream = p.getFirst();
    assertNotNull(inputStream);

    final String passphrase = p.getSecond();
    assertNull(passphrase);

    final LDIFReader ldifReader = new LDIFReader(inputStream);
    assertEquals(ldifReader.readEntry(), testEntry);
    assertNull(ldifReader.readEntry());
    ldifReader.close();
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is encrypted but not compressed.  The correct passphrase will be
   * provided as an argument rather than obtained via prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesOneFileEncryptedNotCompressed1()
         throws Exception
  {
    final Entry testEntry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File testFile = createTempFile(testEntry.toLDIF());
    assertTrue(testFile.delete());

    final String passphrase = "ThisIsThePassphrase";
    final LDIFWriter ldifWriter = new LDIFWriter(
         new PassphraseEncryptedOutputStream("ThisIsThePassphrase",
              new FileOutputStream(testFile)));
    ldifWriter.writeEntry(testEntry);
    ldifWriter.close();

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Collections.singletonList(testFile), passphrase, SUPPRESS_OUTPUT,
              SUPPRESS_OUTPUT);

    final InputStream inputStream = p.getFirst();
    assertNotNull(inputStream);

    assertNotNull(p.getSecond());
    assertEquals(p.getSecond(), passphrase);

    final LDIFReader ldifReader = new LDIFReader(inputStream);
    assertEquals(ldifReader.readEntry(), testEntry);
    assertNull(ldifReader.readEntry());
    ldifReader.close();
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is encrypted but not compressed.  The wrong passphrase will be
   * provided as an argument rather than obtained via prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testGetInputStreamForLDIFFilesOneFileEncryptedNotCompressed2()
         throws Exception
  {
    final Entry testEntry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File testFile = createTempFile(testEntry.toLDIF());
    assertTrue(testFile.delete());

    final LDIFWriter ldifWriter = new LDIFWriter(
         new PassphraseEncryptedOutputStream("ThisIsThePassphrase",
              new FileOutputStream(testFile)));
    ldifWriter.writeEntry(testEntry);
    ldifWriter.close();

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Collections.singletonList(testFile), "wrong", SUPPRESS_OUTPUT,
              SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is encrypted but not compressed.  The correct passphrase will be provided
   * interactively, and the correct passphrase will be provided on the first
   * try.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesOneFileEncryptedNotCompressed3()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines(passphrase);

      final Entry testEntry = new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      final File testFile = createTempFile(testEntry.toLDIF());
      assertTrue(testFile.delete());

      final LDIFWriter ldifWriter = new LDIFWriter(
           new PassphraseEncryptedOutputStream(passphrase,
                new FileOutputStream(testFile)));
      ldifWriter.writeEntry(testEntry);
      ldifWriter.close();

      final ObjectPair<InputStream,String> p =
           ToolUtils.getInputStreamForLDIFFiles(
                Collections.singletonList(testFile), null, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT);

      final InputStream inputStream = p.getFirst();
      assertNotNull(inputStream);

      assertNotNull(p.getSecond());
      assertEquals(p.getSecond(), passphrase);

      final LDIFReader ldifReader = new LDIFReader(inputStream);
      assertEquals(ldifReader.readEntry(), testEntry);
      assertNull(ldifReader.readEntry());
      ldifReader.close();
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is encrypted but not compressed.  The correct passphrase will be provided
   * interactively, and the correct passphrase will be provided on the second
   * try.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesOneFileEncryptedNotCompressed4()
         throws Exception
  {
    try
    {
      final String passphrase = "ThisIsThePassphrase";
      PasswordReader.setTestReaderLines("wrong", passphrase);

      final Entry testEntry = new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      final File testFile = createTempFile(testEntry.toLDIF());
      assertTrue(testFile.delete());

      final LDIFWriter ldifWriter = new LDIFWriter(
           new PassphraseEncryptedOutputStream(passphrase,
                new FileOutputStream(testFile)));
      ldifWriter.writeEntry(testEntry);
      ldifWriter.close();

      final ObjectPair<InputStream,String> p =
           ToolUtils.getInputStreamForLDIFFiles(
                Collections.singletonList(testFile), null, SUPPRESS_OUTPUT,
                SUPPRESS_OUTPUT);

      final InputStream inputStream = p.getFirst();
      assertNotNull(inputStream);

      assertNotNull(p.getSecond());
      assertEquals(p.getSecond(), passphrase);

      final LDIFReader ldifReader = new LDIFReader(inputStream);
      assertEquals(ldifReader.readEntry(), testEntry);
      assertNull(ldifReader.readEntry());
      ldifReader.close();
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with a single file that
   * is both encrypted and compressed.  The correct passphrase will be provided
   * non-interactively.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesOneFileEncryptedCompressed()
         throws Exception
  {
    final Entry testEntry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File testFile = createTempFile(testEntry.toLDIF());
    assertTrue(testFile.delete());

    final String passphrase = "ThisIsThePassphrase";
    final LDIFWriter ldifWriter = new LDIFWriter(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("ThisIsThePassphrase",
              new FileOutputStream(testFile))));
    ldifWriter.writeEntry(testEntry);
    ldifWriter.close();

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Collections.singletonList(testFile), passphrase, SUPPRESS_OUTPUT,
              SUPPRESS_OUTPUT);

    final InputStream inputStream = p.getFirst();
    assertNotNull(inputStream);

    assertNotNull(p.getSecond());
    assertEquals(p.getSecond(), passphrase);

    final LDIFReader ldifReader = new LDIFReader(inputStream);
    assertEquals(ldifReader.readEntry(), testEntry);
    assertNull(ldifReader.readEntry());
    ldifReader.close();
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with multiple files
   * that have a mix of encryption and compression characteristics.  All
   * encrypted files will use the same passphrase, and that passphrase will be
   * provided rather than obtained via prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesMultipleFiles1()
         throws Exception
  {
    final String passphrase = "ThisIsThePassphrase";

    final Entry testEntry1 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    final File testFile1 = createTempFile(testEntry1.toLDIF());

    final Entry testEntry2 = new Entry(
         "dn: ou=foo,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: foo");
    final File testFile2 = createTempFile();
    assertTrue(testFile2.delete());
    LDIFWriter ldifWriter = new LDIFWriter(new GZIPOutputStream(
         new FileOutputStream(testFile2)));
    ldifWriter.writeEntry(testEntry2);
    ldifWriter.close();

    final Entry testEntry3 = new Entry(
         "dn: ou=bar,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: bar");
    final File testFile3 = createTempFile();
    assertTrue(testFile3.delete());
    ldifWriter = new LDIFWriter(new PassphraseEncryptedOutputStream(passphrase,
         new FileOutputStream(testFile3)));
    ldifWriter.writeEntry(testEntry3);
    ldifWriter.close();

    final Entry testEntry4 = new Entry(
         "dn: ou=baz,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: baz");
    final File testFile4 = createTempFile();
    assertTrue(testFile4.delete());
    ldifWriter = new LDIFWriter(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream(passphrase,
              new FileOutputStream(testFile4))));
    ldifWriter.writeEntry(testEntry4);
    ldifWriter.close();

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Arrays.asList(testFile1, testFile2, testFile3, testFile4),
              passphrase, SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);

    final InputStream inputStream = p.getFirst();
    assertNotNull(inputStream);

    assertNotNull(p.getSecond());
    assertEquals(p.getSecond(), passphrase);

    final LDIFReader ldifReader = new LDIFReader(inputStream);
    assertEquals(ldifReader.readEntry(), testEntry1);
    assertEquals(ldifReader.readEntry(), testEntry2);
    assertEquals(ldifReader.readEntry(), testEntry3);
    assertEquals(ldifReader.readEntry(), testEntry4);
    assertNull(ldifReader.readEntry());
    ldifReader.close();
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with multiple files
   * that have a mix of encryption and compression characteristics. The
   * encrypted files will use different passphrases, and the passphrase will
   * be provided rather than obtained via prompt, so the attempt to obtain the
   * input stream will fail.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testGetInputStreamForLDIFFilesMultipleFiles2()
         throws Exception
  {
    final Entry testEntry1 = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    final File testFile1 = createTempFile(testEntry1.toLDIF());

    final Entry testEntry2 = new Entry(
         "dn: ou=foo,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: foo");
    final File testFile2 = createTempFile();
    assertTrue(testFile2.delete());
    LDIFWriter ldifWriter = new LDIFWriter(new GZIPOutputStream(
         new FileOutputStream(testFile2)));
    ldifWriter.writeEntry(testEntry2);
    ldifWriter.close();

    final Entry testEntry3 = new Entry(
         "dn: ou=bar,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: bar");
    final File testFile3 = createTempFile();
    assertTrue(testFile3.delete());
    ldifWriter = new LDIFWriter(new PassphraseEncryptedOutputStream(
         "ThisIsTheFirstPassphrase",
         new FileOutputStream(testFile3)));
    ldifWriter.writeEntry(testEntry3);
    ldifWriter.close();

    final Entry testEntry4 = new Entry(
         "dn: ou=baz,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: baz");
    final File testFile4 = createTempFile();
    assertTrue(testFile4.delete());
    ldifWriter = new LDIFWriter(new GZIPOutputStream(
         new PassphraseEncryptedOutputStream("ThisIsTheSecondPassphrase",
              new FileOutputStream(testFile4))));
    ldifWriter.writeEntry(testEntry4);
    ldifWriter.close();

    final ObjectPair<InputStream,String> p =
         ToolUtils.getInputStreamForLDIFFiles(
              Arrays.asList(testFile1, testFile2, testFile3, testFile4),
              "ThisIsTheFirstPassphrase", SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getInputStreamForLDIFFiles} method with multiple files
   * that have a mix of encryption and compression characteristics. The
   * encrypted files will use different passphrases, and the passphrases will be
   * provided via prompt so the data should be readable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInputStreamForLDIFFilesMultipleFiles3()
         throws Exception
  {
    try
    {
      final String passphrase1 = "ThisIsTheFirstPassphrase";
      final String passphrase2 = "ThisIsTheSecondPassphrase";
      PasswordReader.setTestReaderLines(passphrase1, "wrong", passphrase2);

      final Entry testEntry1 = new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      final File testFile1 = createTempFile(testEntry1.toLDIF());

      final Entry testEntry2 = new Entry(
           "dn: ou=foo,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: foo");
      final File testFile2 = createTempFile();
      assertTrue(testFile2.delete());
      LDIFWriter ldifWriter = new LDIFWriter(new GZIPOutputStream(
           new FileOutputStream(testFile2)));
      ldifWriter.writeEntry(testEntry2);
      ldifWriter.close();

      final Entry testEntry3 = new Entry(
           "dn: ou=bar,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: bar");
      final File testFile3 = createTempFile();
      assertTrue(testFile3.delete());
      ldifWriter = new LDIFWriter(new PassphraseEncryptedOutputStream(
           passphrase1, new FileOutputStream(testFile3)));
      ldifWriter.writeEntry(testEntry3);
      ldifWriter.close();

      final Entry testEntry4 = new Entry(
           "dn: ou=baz,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: baz");
      final File testFile4 = createTempFile();
      assertTrue(testFile4.delete());
      ldifWriter = new LDIFWriter(new GZIPOutputStream(
           new PassphraseEncryptedOutputStream(passphrase1,
                new FileOutputStream(testFile4))));
      ldifWriter.writeEntry(testEntry4);
      ldifWriter.close();

      final ObjectPair<InputStream,String> p =
           ToolUtils.getInputStreamForLDIFFiles(
                Arrays.asList(testFile1, testFile2, testFile3, testFile4), null,
                SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);

      final InputStream inputStream = p.getFirst();
      assertNotNull(inputStream);

      assertNotNull(p.getSecond());
      assertEquals(p.getSecond(), passphrase1);

      final LDIFReader ldifReader = new LDIFReader(inputStream);
      assertEquals(ldifReader.readEntry(), testEntry1);
      assertEquals(ldifReader.readEntry(), testEntry2);
      assertEquals(ldifReader.readEntry(), testEntry3);
      assertEquals(ldifReader.readEntry(), testEntry4);
      assertNull(ldifReader.readEntry());
      ldifReader.close();
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the {@code getPossiblyGZIPCompressedInputStream} with a
   * {@code null} input stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyGZIPCompressedInputStreamNullStream()
         throws Exception
  {
    ToolUtils.getPossiblyGZIPCompressedInputStream(null);
  }



  /**
   * Tests the {@code getPossiblyGZIPCompressedInputStream} with an input stream
   * that is not compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPossiblyGZIPCompressedInputStreamNotCompressed()
         throws Exception
  {
    final File notCompressedFile = createTempFile("this is not compressed");

    final InputStream inputStream =
         ToolUtils.getPossiblyGZIPCompressedInputStream(
              new FileInputStream(notCompressedFile));
    assertNotNull(inputStream);

    final BufferedReader reader =
         new BufferedReader(new InputStreamReader(inputStream));
    assertEquals(reader.readLine(), "this is not compressed");
    assertNull(reader.readLine());
    reader.close();
  }



  /**
   * Tests the {@code getPossiblyGZIPCompressedInputStream} with an input stream
   * that is compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetPossiblyGZIPCompressedInputStreamCompressed()
         throws Exception
  {
    final File compressedFile = createTempFile();
    assertTrue(compressedFile.delete());

    final PrintStream printStream = new PrintStream(new GZIPOutputStream(
         new FileOutputStream(compressedFile)));
    printStream.println("this is compressed");
    printStream.close();

    final InputStream inputStream =
         ToolUtils.getPossiblyGZIPCompressedInputStream(
              new FileInputStream(compressedFile));
    assertNotNull(inputStream);

    final BufferedReader reader =
         new BufferedReader(new InputStreamReader(inputStream));
    assertEquals(reader.readLine(), "this is compressed");
    assertNull(reader.readLine());
    reader.close();
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with a
   * {@code null} input stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamNullInputStream()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(null, (char[]) null,
         false, "Enter the passphrase", "Wrong passphrase", SUPPRESS_OUTPUT,
         SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with a
   * {@code null} passphrase prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamNullPrompt()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(
         new ByteArrayInputStream(StaticUtils.NO_BYTES), (char[]) null, false,
         null, "Wrong passphrase", SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with an empty
   * passphrase prompt.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamEmptyPrompt()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(
         new ByteArrayInputStream(StaticUtils.NO_BYTES), (char[]) null, false,
         "", "Wrong passphrase", SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with a
   * {@code null} passphrase error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamNullError()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(
         new ByteArrayInputStream(StaticUtils.NO_BYTES), (char[]) null, false,
         "Enter the passphrase", null, SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with an empty
   * passphrase error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamEmptyError()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(
         new ByteArrayInputStream(StaticUtils.NO_BYTES), (char[]) null, false,
         "Enter the passphrase", "", SUPPRESS_OUTPUT, SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with a
   * {@code null} output stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamNullOutputStream()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(
         new ByteArrayInputStream(StaticUtils.NO_BYTES), (char[]) null,
         false, "Enter the passphrase", "Wrong passphrase", null,
         SUPPRESS_OUTPUT);
  }



  /**
   * Tests the {@code getPossiblyPassphraseEncryptedInputStream} with a
   * {@code null} error stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPossiblyPassphraseEncryptedInputStreamNullErrorStream()
         throws Exception
  {
    ToolUtils.getPossiblyPassphraseEncryptedInputStream(
         new ByteArrayInputStream(StaticUtils.NO_BYTES), (char[]) null,
         false, "Enter the passphrase", "Wrong passphrase", SUPPRESS_OUTPUT,
         null);
  }
}
