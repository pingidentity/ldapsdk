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



import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.zip.GZIPInputStream;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.AggregateInputStream;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PassphraseEncryptedInputStream;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PassphraseEncryptedStreamHeader;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a number of utility methods primarily intended for use
 * with command-line tools.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level= ThreadSafetyLevel.NOT_THREADSAFE)
public final class ToolUtils
{
  /**
   * The column at which long lines should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * A handle to a method that can be used to get the passphrase for an
   * encryption settings definition ID if the server code is available.  We have
   * to call this via reflection because the server code may not be available.
   */
  @Nullable private static final Method
       GET_PASSPHRASE_FOR_ENCRYPTION_SETTINGS_ID_METHOD;
  static
  {
    Method m = null;

    try
    {
      final Class<?> serverStaticUtilsClass = Class.forName(
           "com.unboundid.directory.server.util.StaticUtils");
      m = serverStaticUtilsClass.getMethod(
           "getPassphraseForEncryptionSettingsID", String.class,
           PrintStream.class, PrintStream.class);
    }
    catch (final Exception e)
    {
      // This is fine.  It probably just means that the server code isn't
      // available.
      Debug.debugException(Level.FINEST, e);
    }

    GET_PASSPHRASE_FOR_ENCRYPTION_SETTINGS_ID_METHOD = m;
  }



  /**
   * Prevent this utility class from being instantiated.
   */
  private ToolUtils()
  {
    // No implementation is required.
  }



  /**
   * Reads an encryption passphrase from the specified file.  The file must
   * contain exactly one line, which must not be empty, and must be comprised
   * entirely of the encryption passphrase.
   *
   * @param  f  The file from which the passphrase should be read.  It must not
   *            be {@code null}.
   *
   * @return  The encryption passphrase read from the specified file.
   *
   * @throws  LDAPException  If a problem occurs while attempting to read the
   *                         encryption passphrase.
   */
  @NotNull()
  public static String readEncryptionPassphraseFromFile(@NotNull final File f)
         throws LDAPException
  {
    Validator.ensureTrue((f != null),
         "ToolUtils.readEncryptionPassphraseFromFile.f must not be null.");

    if (! f.exists())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_TOOL_UTILS_ENCRYPTION_PW_FILE_MISSING.get(f.getAbsolutePath()));
    }

    if (! f.isFile())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_TOOL_UTILS_ENCRYPTION_PW_FILE_NOT_FILE.get(f.getAbsolutePath()));
    }

    try (FileReader fileReader = new FileReader(f);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      final String encryptionPassphrase = bufferedReader.readLine();
      if (encryptionPassphrase == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_TOOL_UTILS_ENCRYPTION_PW_FILE_EMPTY.get(f.getAbsolutePath()));
      }
      else if (bufferedReader.readLine() != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_TOOL_UTILS_ENCRYPTION_PW_FILE_MULTIPLE_LINES.get(
                  f.getAbsolutePath()));
      }
      else if (encryptionPassphrase.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_TOOL_UTILS_ENCRYPTION_PW_FILE_EMPTY.get(f.getAbsolutePath()));
      }

      return encryptionPassphrase;
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_TOOL_UTILS_ENCRYPTION_PW_FILE_READ_ERROR.get(
                f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)));
    }
  }



  /**
   * Interactively prompts the user for an encryption passphrase.
   *
   * @param  allowEmpty  Indicates whether the encryption passphrase is allowed
   *                     to be empty.  If this is {@code false}, then the user
   *                     will be re-prompted for the passphrase if the value
   *                     they enter is empty.
   * @param  confirm     Indicates whether the user will asked to confirm the
   *                     passphrase.  If this is {@code true}, then the user
   *                     will have to enter the same passphrase twice.  If this
   *                     is {@code false}, then the user will only be prompted
   *                     once.
   * @param  out         The {@code PrintStream} that will be used for standard
   *                     output.  It must not be {@code null}.
   * @param  err         The {@code PrintStream} that will be used for standard
   *                     error.  It must not be {@code null}.
   *
   * @return  The encryption passphrase provided by the user.
   *
   * @throws  LDAPException  If a problem is encountered while trying to obtain
   *                         the passphrase from the user.
   */
  @NotNull()
  public static String promptForEncryptionPassphrase(final boolean allowEmpty,
              final boolean confirm,
              @NotNull final PrintStream out,
              @NotNull final PrintStream err)
          throws LDAPException
  {
    return promptForEncryptionPassphrase(allowEmpty, confirm,
         INFO_TOOL_UTILS_ENCRYPTION_PW_PROMPT.get(),
         INFO_TOOL_UTILS_ENCRYPTION_PW_CONFIRM.get(), out, err);
  }



  /**
   * Interactively prompts the user for an encryption passphrase.
   *
   * @param  allowEmpty     Indicates whether the encryption passphrase is
   *                        allowed to be empty.  If this is {@code false}, then
   *                        the user will be re-prompted for the passphrase if
   *                        the value they enter is empty.
   * @param  confirm        Indicates whether the user will asked to confirm the
   *                        passphrase.  If this is {@code true}, then the user
   *                        will have to enter the same passphrase twice.  If
   *                        this is {@code false}, then the user will only be
   *                        prompted once.
   * @param  initialPrompt  The initial prompt that will be presented to the
   *                        user.  It must not be {@code null} or empty.
   * @param  confirmPrompt  The prompt that will be presented to the user when
   *                        asked to confirm the passphrase.  It may be
   *                        {@code null} only if {@code confirm} is
   *                        {@code false}.
   * @param  out            The {@code PrintStream} that will be used for
   *                        standard output.  It must not be {@code null}.
   * @param  err            The {@code PrintStream} that will be used for
   *                        standard error.  It must not be {@code null}.
   *
   * @return  The encryption passphrase provided by the user.
   *
   * @throws  LDAPException  If a problem is encountered while trying to obtain
   *                         the passphrase from the user.
   */
  @NotNull()
  public static String promptForEncryptionPassphrase(final boolean allowEmpty,
                            final boolean confirm,
                            @NotNull final CharSequence initialPrompt,
                            @Nullable final CharSequence confirmPrompt,
                            @NotNull final PrintStream out,
                            @NotNull final PrintStream err)
          throws LDAPException
  {
    Validator.ensureTrue(
         ((initialPrompt != null) && (initialPrompt.length() > 0)),
         "TestUtils.promptForEncryptionPassphrase.initialPrompt must not be " +
              "null or empty.");
    Validator.ensureTrue(
         ((! confirm) ||
              ((confirmPrompt != null) && (confirmPrompt.length() > 0))),
         "TestUtils.promptForEncryptionPassphrase.confirmPrompt must not be " +
              "null or empty when confirm is true.");
    Validator.ensureTrue((out != null),
         "ToolUtils.promptForEncryptionPassphrase.out must not be null");
    Validator.ensureTrue((err != null),
         "ToolUtils.promptForEncryptionPassphrase.err must not be null");

    while (true)
    {
      char[] passphraseChars = null;
      char[] confirmChars = null;

      try
      {
        wrapPrompt(initialPrompt, true, out);

        passphraseChars = PasswordReader.readPasswordChars();
        if ((passphraseChars == null) || (passphraseChars.length == 0))
        {
          if (allowEmpty)
          {
            passphraseChars = StaticUtils.NO_CHARS;
          }
          else
          {
            wrap(ERR_TOOL_UTILS_ENCRYPTION_PW_EMPTY.get(), err);
            err.println();
            continue;
          }
        }

        if (confirm)
        {
          wrapPrompt(confirmPrompt, true, out);

          confirmChars = PasswordReader.readPasswordChars();
          if ((confirmChars == null) ||
               (! Arrays.equals(passphraseChars, confirmChars)))
          {
            wrap(ERR_TOOL_UTILS_ENCRYPTION_PW_MISMATCH.get(), err);
            err.println();
            continue;
          }
        }

        return new String(passphraseChars);
      }
      finally
      {
        if (passphraseChars != null)
        {
          Arrays.fill(passphraseChars, '\u0000');
        }

        if (confirmChars != null)
        {
          Arrays.fill(confirmChars, '\u0000');
        }
      }
    }
  }



  /**
   * Writes a wrapped version of the provided message to the given stream.
   *
   * @param  message  The message to be written.  If it is {@code null} or
   *                  empty, then an empty line will be printed.
   * @param  out      The {@code PrintStream} that should be used to write the
   *                  provided message.
   */
  public static void wrap(@NotNull final CharSequence message,
                          @NotNull final PrintStream out)
  {
    Validator.ensureTrue((out != null), "ToolUtils.wrap.out must not be null.");

    if ((message == null) || (message.length() == 0))
    {
      out.println();
      return;
    }

    for (final String line :
         StaticUtils.wrapLine(message.toString(), WRAP_COLUMN))
    {
      out.println(line);
    }
  }



  /**
   * Wraps the provided prompt such that every line except the last will be
   * followed by a newline, but the last line will not be followed by a newline.
   *
   * @param  prompt               The prompt to be wrapped.  It must not be
   *                              {@code null} or empty.
   * @param  ensureTrailingSpace  Indicates whether to ensure that there is a
   *                              trailing space after the end of the prompt.
   * @param  out                  The {@code PrintStream} to which the prompt
   *                              should be written.  It must not be
   *                              {@code null}.
   */
  public static void wrapPrompt(@NotNull final CharSequence prompt,
                                final boolean ensureTrailingSpace,
                                @NotNull final PrintStream out)
  {
    Validator.ensureTrue(((prompt != null) && (prompt.length() > 0)),
         "ToolUtils.wrapPrompt.prompt must not be null or empty.");
    Validator.ensureTrue((out != null),
         "ToolUtils.wrapPrompt.out must not be null.");

    String promptString = prompt.toString();
    if (ensureTrailingSpace && (! promptString.endsWith(" ")))
    {
      promptString += ' ';
    }

    final List<String> lines = StaticUtils.wrapLine(promptString, WRAP_COLUMN);
    final Iterator<String> iterator = lines.iterator();
    while (iterator.hasNext())
    {
      final String line = iterator.next();
      if (iterator.hasNext())
      {
        out.println(line);
      }
      else
      {
        out.print(line);
      }
    }
  }



  /**
   * Retrieves an input stream that can be used to read data from the specified
   * list of files.  It will handle the possibility that any or all of the LDIF
   * files are encrypted and/or compressed.
   *
   * @param  ldifFiles             The list of LDIF files from which the data
   *                               is to be read.  It must not be {@code null}
   *                               or empty.
   * @param  encryptionPassphrase  The passphrase that should be used to access
   *                               encrypted LDIF files.  It may be {@code null}
   *                               if the user should be interactively prompted
   *                               for the passphrase if any of the files is
   *                               encrypted.
   * @param  out                   The print stream to use for standard output.
   *                               It must not be {@code null}.
   * @param  err                   The print stream to use for standard error.
   *                               It must not be {@code null}.
   *
   * @return  An {@code ObjectPair} whose first element is an input stream that
   *          can be used to read data from the specified list of files, and
   *          whose second element is a possibly-{@code null} passphrase that
   *          is used to encrypt the input data.
   *
   * @throws  IOException  If a problem is encountered while attempting to get
   *                       the input stream for reading the data.
   */
  @NotNull()
  public static ObjectPair<InputStream,String> getInputStreamForLDIFFiles(
                     @NotNull final List<File> ldifFiles,
                     @Nullable final String encryptionPassphrase,
                     @NotNull final PrintStream out,
                     @NotNull final PrintStream err)
         throws IOException
  {
    Validator.ensureTrue(((ldifFiles != null) && (! ldifFiles.isEmpty())),
         "ToolUtils.getInputStreamForLDIFFiles.ldifFiles must not be null or " +
              "empty.");
    Validator.ensureTrue((out != null),
         "ToolUtils.getInputStreamForLDIFFiles.out must not be null");
    Validator.ensureTrue((err != null),
         "ToolUtils.getInputStreamForLDIFFiles.err must not be null");


    boolean createdSuccessfully = false;
    final ArrayList<InputStream> inputStreams =
         new ArrayList<>(ldifFiles.size() * 2);

    try
    {
      byte[] twoEOLs = null;
      String passphrase = encryptionPassphrase;
      for (final File f : ldifFiles)
      {
        if (! inputStreams.isEmpty())
        {
          if (twoEOLs == null)
          {
            final ByteStringBuffer buffer = new ByteStringBuffer(4);
            buffer.append(StaticUtils.EOL_BYTES);
            buffer.append(StaticUtils.EOL_BYTES);
            twoEOLs = buffer.toByteArray();
          }

          inputStreams.add(new ByteArrayInputStream(twoEOLs));
        }

        InputStream inputStream = new FileInputStream(f);
        try
        {
          final ObjectPair<InputStream,String> p =
               getPossiblyPassphraseEncryptedInputStream(
                    inputStream, passphrase, (encryptionPassphrase == null),
                    INFO_TOOL_UTILS_ENCRYPTED_LDIF_FILE_PW_PROMPT.get(
                         f.getPath()),
                    ERR_TOOL_UTILS_ENCRYPTED_LDIF_FILE_WRONG_PW.get(), out,
                    err);
          inputStream = p.getFirst();
          if ((p.getSecond() != null) && (passphrase == null))
          {
            passphrase = p.getSecond();
          }
        }
        catch (final GeneralSecurityException e)
        {
          Debug.debugException(e);
          inputStream.close();
          throw new IOException(
               ERR_TOOL_UTILS_ENCRYPTED_LDIF_FILE_CANNOT_DECRYPT.get(
                    f.getPath(), StaticUtils.getExceptionMessage(e)),
               e);
        }

        inputStream = getPossiblyGZIPCompressedInputStream(inputStream);
        inputStreams.add(inputStream);
      }

      createdSuccessfully = true;
      if (inputStreams.size() == 1)
      {
        return new ObjectPair<>(inputStreams.get(0), passphrase);
      }
      else
      {
        return new ObjectPair<InputStream,String>(
             new AggregateInputStream(inputStreams), passphrase);
      }
    }
    finally
    {
      if (! createdSuccessfully)
      {
        for (final InputStream inputStream : inputStreams)
        {
          try
          {
            inputStream.close();
          }
          catch (final IOException e)
          {
            Debug.debugException(e);
          }
        }
      }
    }
  }



  /**
   * Retrieves an {@code InputStream} that can be used to read data from the
   * provided input stream that may have potentially been GZIP-compressed.  If
   * the provided input stream does not appear to contain GZIP-compressed data,
   * then the returned stream will permit reading the data from the provided
   * stream without any alteration.
   * <BR><BR>
   * The determination will be made by looking to see if the first two bytes
   * read from the provided input stream are 0x1F and 0x8B, respectively (which
   * is the GZIP magic header).  To avoid false positives, this method should
   * only be used if it is known that if the input stream does not contain
   * compressed data, then it will not start with that two-byte sequence.  This
   * method should always be safe to use if the data to be read is text.  If the
   * data may be binary and that binary data may happen to start with 0x1F 0x8B,
   * then this method should not be used.
   * <BR><BR>
   * The input stream's {@code mark} and {@code reset} methods will be used to
   * permit peeking at the data at the head of the input stream.  If the
   * provided stream does not support the use of those methods, then it will be
   * wrapped in a {@code BufferedInputStream}, which does support them.
   *
   * @param  inputStream  The input stream from which the data is to be read.
   *
   * @return  A {@code GZIPInputStream} that wraps the provided input stream if
   *          the stream appears to contain GZIP-compressed data, or the
   *          provided input stream (potentially wrapped in a
   *          {@code BufferedInputStream}) if the provided stream does not
   *          appear to contain GZIP-compressed data.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       determine whether the stream contains GZIP-compressed
   *                       data.
   */
  @NotNull()
  public static InputStream getPossiblyGZIPCompressedInputStream(
                                 @NotNull final InputStream inputStream)
         throws IOException
  {
    Validator.ensureTrue((inputStream != null),
         "StaticUtils.getPossiblyGZIPCompressedInputStream.inputStream must " +
              "not be null.");


    // Mark the input stream so that we can peek at data from the beginning of
    // the stream.
    final InputStream markableInputStream;
    if (inputStream.markSupported())
    {
      markableInputStream = inputStream;
    }
    else
    {
      markableInputStream = new BufferedInputStream(inputStream);
    }

    markableInputStream.mark(2);


    // Check to see if the file starts with the GZIP magic header.  Whether it
    // does or not, reset the stream so that we can read it from the beginning.
    final boolean isCompressed;
    try
    {
      isCompressed = ((markableInputStream.read() == 0x1F) &&
           (markableInputStream.read() == 0x8B));
    }
    finally
    {
      markableInputStream.reset();
    }


    // If the stream starts with the GZIP magic header, then assume it's
    // GZIP-compressed.  Otherwise, assume it's not.
    if (isCompressed)
    {
      return new GZIPInputStream(markableInputStream);
    }
    else
    {
      return markableInputStream;
    }
  }



  /**
   * Retrieves an {@code InputStream} that can be used to read data from the
   * provided input stream that may have potentially been encrypted with a
   * {@link PassphraseEncryptedOutputStream}.  If the provided input stream does
   * not appear to contain passphrase-encrypted data, then the returned stream
   * will permit reading the data from the provided stream without any
   * alteration.
   * <BR><BR>
   * The determination will be made by looking to see if the input stream starts
   * with a valid {@link PassphraseEncryptedStreamHeader}.  Because of the
   * complex nature of that header, it is highly unlikely that the input stream
   * will just happen to start with a valid header if the stream does not
   * actually contain encrypted data.
   * <BR><BR>
   * The input stream's {@code mark} and {@code reset} methods will be used to
   * permit peeking at the data at the head of the input stream.  If the
   * provided stream does not support the use of those methods, then it will be
   * wrapped in a {@code BufferedInputStream}, which does support them.
   *
   * @param  inputStream                  The input stream from which the data
   *                                      is to be read.  It must not be
   *                                      {@code null}.
   * @param  potentialPassphrase          A potential passphrase that may have
   *                                      been used to encrypt the data.  It
   *                                      may be {@code null} if the passphrase
   *                                      should only be obtained via
   *                                      interactive prompting, or if the
   *                                      data was encrypted with a server-side
   *                                      encryption settings definition.  If
   *                                      the passphrase is not {@code null} but
   *                                      is incorrect, then the user may be
   *                                      interactively prompted for the correct
   *                                      passphrase.
   * @param  promptOnIncorrectPassphrase  Indicates whether the user should be
   *                                      interactively prompted for the correct
   *                                      passphrase if the provided passphrase
   *                                      is non-{@code null} and is also
   *                                      incorrect.
   * @param  passphrasePrompt             The prompt that will be presented to
   *                                      the user if the input stream does
   *                                      contain encrypted data and the
   *                                      passphrase needs to be interactively
   *                                      requested from the user.  It must not
   *                                      be {@code null} or empty.
   * @param  incorrectPassphraseError     The error message that will be
   *                                      presented to the user if the entered
   *                                      passphrase is not correct.  It must
   *                                      not be {@code null} or empty.
   * @param  standardOutput               The {@code PrintStream} to use to
   *                                      write to standard output while
   *                                      interactively prompting for the
   *                                      passphrase.  It must not be
   *                                      {@code null}.
   * @param  standardError                The {@code PrintStream} to use to
   *                                      write to standard error while
   *                                      interactively prompting for the
   *                                      passphrase.  It must not be
   *                                      {@code null}.
   *
   * @return  An {@code ObjectPair} that combines the resulting input stream
   *          with the associated encryption passphrase.  If the provided input
   *          stream is encrypted, then the returned input stream element will
   *          be a {@code PassphraseEncryptedInputStream} and the returned
   *          passphrase element will be non-{@code null}.  If the provided
   *          input stream is not encrypted, then the returned input stream
   *          element will be the provided input stream (potentially wrapped in
   *          a {@code BufferedInputStream}), and the returned passphrase
   *          element will be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       determine whether the stream contains
   *                       passphrase-encrypted data.
   *
   * @throws  InvalidKeyException  If the provided passphrase is incorrect and
   *                               the user should not be interactively prompted
   *                               for the correct passphrase.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    attempting to prepare to decrypt data
   *                                    read from the input stream.
   */
  @NotNull()
  public static ObjectPair<InputStream,String>
                     getPossiblyPassphraseEncryptedInputStream(
                          @NotNull final InputStream inputStream,
                          @Nullable final String potentialPassphrase,
                          final boolean promptOnIncorrectPassphrase,
                          @NotNull final CharSequence passphrasePrompt,
                          @NotNull final CharSequence incorrectPassphraseError,
                          @NotNull final PrintStream standardOutput,
                          @NotNull final PrintStream standardError)
         throws IOException, InvalidKeyException, GeneralSecurityException
  {
    final Collection<char[]> potentialPassphrases;
    if (potentialPassphrase == null)
    {
      potentialPassphrases = Collections.emptySet();
    }
    else
    {
      potentialPassphrases =
           Collections.singleton(potentialPassphrase.toCharArray());
    }

    final ObjectPair<InputStream, char[]> p =
         getPossiblyPassphraseEncryptedInputStream(inputStream,
              potentialPassphrases, promptOnIncorrectPassphrase,
              passphrasePrompt, incorrectPassphraseError, standardOutput,
              standardError);

    if (p.getSecond() == null)
    {
      return new ObjectPair<>(p.getFirst(), null);
    }
    else
    {
      return new ObjectPair<>(p.getFirst(), new String(p.getSecond()));
    }
  }



  /**
   * Retrieves an {@code InputStream} that can be used to read data from the
   * provided input stream that may have potentially been encrypted with a
   * {@link PassphraseEncryptedOutputStream}.  If the provided input stream does
   * not appear to contain passphrase-encrypted data, then the returned stream
   * will permit reading the data from the provided stream without any
   * alteration.
   * <BR><BR>
   * The determination will be made by looking to see if the input stream starts
   * with a valid {@link PassphraseEncryptedStreamHeader}.  Because of the
   * complex nature of that header, it is highly unlikely that the input stream
   * will just happen to start with a valid header if the stream does not
   * actually contain encrypted data.
   * <BR><BR>
   * The input stream's {@code mark} and {@code reset} methods will be used to
   * permit peeking at the data at the head of the input stream.  If the
   * provided stream does not support the use of those methods, then it will be
   * wrapped in a {@code BufferedInputStream}, which does support them.
   *
   * @param  inputStream                  The input stream from which the data
   *                                      is to be read.  It must not be
   *                                      {@code null}.
   * @param  potentialPassphrase          A potential passphrase that may have
   *                                      been used to encrypt the data.  It
   *                                      may be {@code null} if the passphrase
   *                                      should only be obtained via
   *                                      interactive prompting, or if the
   *                                      data was encrypted with a server-side
   *                                      encryption settings definition.  If
   *                                      the passphrase is not {@code null} but
   *                                      is incorrect, then the user may be
   *                                      interactively prompted for the correct
   *                                      passphrase.
   * @param  promptOnIncorrectPassphrase  Indicates whether the user should be
   *                                      interactively prompted for the correct
   *                                      passphrase if the provided passphrase
   *                                      is non-{@code null} and is also
   *                                      incorrect.
   * @param  passphrasePrompt             The prompt that will be presented to
   *                                      the user if the input stream does
   *                                      contain encrypted data and the
   *                                      passphrase needs to be interactively
   *                                      requested from the user.  It must not
   *                                      be {@code null} or empty.
   * @param  incorrectPassphraseError     The error message that will be
   *                                      presented to the user if the entered
   *                                      passphrase is not correct.  It must
   *                                      not be {@code null} or empty.
   * @param  standardOutput               The {@code PrintStream} to use to
   *                                      write to standard output while
   *                                      interactively prompting for the
   *                                      passphrase.  It must not be
   *                                      {@code null}.
   * @param  standardError                The {@code PrintStream} to use to
   *                                      write to standard error while
   *                                      interactively prompting for the
   *                                      passphrase.  It must not be
   *                                      {@code null}.
   *
   * @return  An {@code ObjectPair} that combines the resulting input stream
   *          with the associated encryption passphrase.  If the provided input
   *          stream is encrypted, then the returned input stream element will
   *          be a {@code PassphraseEncryptedInputStream} and the returned
   *          passphrase element will be non-{@code null}.  If the provided
   *          input stream is not encrypted, then the returned input stream
   *          element will be the provided input stream (potentially wrapped in
   *          a {@code BufferedInputStream}), and the returned passphrase
   *          element will be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       determine whether the stream contains
   *                       passphrase-encrypted data.
   *
   * @throws  InvalidKeyException  If the provided passphrase is incorrect and
   *                               the user should not be interactively prompted
   *                               for the correct passphrase.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    attempting to prepare to decrypt data
   *                                    read from the input stream.
   */
  @NotNull()
  public static ObjectPair<InputStream,char[]>
                     getPossiblyPassphraseEncryptedInputStream(
                          @NotNull final InputStream inputStream,
                          @Nullable final char[] potentialPassphrase,
                          final boolean promptOnIncorrectPassphrase,
                          @NotNull final CharSequence passphrasePrompt,
                          @NotNull final CharSequence incorrectPassphraseError,
                          @NotNull final PrintStream standardOutput,
                          @NotNull final PrintStream standardError)
         throws IOException, InvalidKeyException, GeneralSecurityException
  {
    final Collection<char[]> potentialPassphrases;
    if (potentialPassphrase == null)
    {
      potentialPassphrases = Collections.emptySet();
    }
    else
    {
      potentialPassphrases =
           Collections.singleton(potentialPassphrase);
    }

    final ObjectPair<InputStream, char[]> p =
         getPossiblyPassphraseEncryptedInputStream(inputStream,
              potentialPassphrases, promptOnIncorrectPassphrase,
              passphrasePrompt, incorrectPassphraseError, standardOutput,
              standardError);

    if (p.getSecond() == null)
    {
      return new ObjectPair<>(p.getFirst(), null);
    }
    else
    {
      return new ObjectPair<>(p.getFirst(), p.getSecond());
    }
  }



  /**
   * Retrieves an {@code InputStream} that can be used to read data from the
   * provided input stream that may have potentially been encrypted with a
   * {@link PassphraseEncryptedOutputStream}.  If the provided input stream does
   * not appear to contain passphrase-encrypted data, then the returned stream
   * will permit reading the data from the provided stream without any
   * alteration.
   * <BR><BR>
   * The determination will be made by looking to see if the input stream starts
   * with a valid {@link PassphraseEncryptedStreamHeader}.  Because of the
   * complex nature of that header, it is highly unlikely that the input stream
   * will just happen to start with a valid header if the stream does not
   * actually contain encrypted data.
   * <BR><BR>
   * The input stream's {@code mark} and {@code reset} methods will be used to
   * permit peeking at the data at the head of the input stream.  If the
   * provided stream does not support the use of those methods, then it will be
   * wrapped in a {@code BufferedInputStream}, which does support them.
   *
   * @param  inputStream                  The input stream from which the data
   *                                      is to be read.  It must not be
   *                                      {@code null}.
   * @param  potentialPassphrases         A collection of potential passphrases
   *                                      that may have been used to encrypt the
   *                                      data.  It may be {@code null} or empty
   *                                      if the passphrase should only be
   *                                      obtained via interactive prompting, or
   *                                      if the data was encrypted with a
   *                                      server-side encryption settings
   *                                      definition.  If none of the provided
   *                                      passphrases are correct, then the user
   *                                      may still be interactively prompted
   *                                      for the correct passphrase.
   * @param  promptOnIncorrectPassphrase  Indicates whether the user should be
   *                                      interactively prompted for the correct
   *                                      passphrase if the provided passphrase
   *                                      is non-{@code null} and is also
   *                                      incorrect.
   * @param  passphrasePrompt             The prompt that will be presented to
   *                                      the user if the input stream does
   *                                      contain encrypted data and the
   *                                      passphrase needs to be interactively
   *                                      requested from the user.  It must not
   *                                      be {@code null} or empty.
   * @param  incorrectPassphraseError     The error message that will be
   *                                      presented to the user if the entered
   *                                      passphrase is not correct.  It must
   *                                      not be {@code null} or empty.
   * @param  standardOutput               The {@code PrintStream} to use to
   *                                      write to standard output while
   *                                      interactively prompting for the
   *                                      passphrase.  It must not be
   *                                      {@code null}.
   * @param  standardError                The {@code PrintStream} to use to
   *                                      write to standard error while
   *                                      interactively prompting for the
   *                                      passphrase.  It must not be
   *                                      {@code null}.
   *
   * @return  An {@code ObjectPair} that combines the resulting input stream
   *          with the associated encryption passphrase.  If the provided input
   *          stream is encrypted, then the returned input stream element will
   *          be a {@code PassphraseEncryptedInputStream} and the returned
   *          passphrase element will be non-{@code null}.  If the provided
   *          input stream is not encrypted, then the returned input stream
   *          element will be the provided input stream (potentially wrapped in
   *          a {@code BufferedInputStream}), and the returned passphrase
   *          element will be {@code null}.
   *
   * @throws  IOException  If a problem is encountered while attempting to
   *                       determine whether the stream contains
   *                       passphrase-encrypted data.
   *
   * @throws  InvalidKeyException  If the provided passphrase is incorrect and
   *                               the user should not be interactively prompted
   *                               for the correct passphrase.
   *
   * @throws  GeneralSecurityException  If a problem is encountered while
   *                                    attempting to prepare to decrypt data
   *                                    read from the input stream.
   */
  @NotNull()
  public static ObjectPair<InputStream,char[]>
              getPossiblyPassphraseEncryptedInputStream(
                   @NotNull final InputStream inputStream,
                   @Nullable final Collection<char[]> potentialPassphrases,
                   final boolean promptOnIncorrectPassphrase,
                   @NotNull final CharSequence passphrasePrompt,
                   @NotNull final CharSequence incorrectPassphraseError,
                   @NotNull final PrintStream standardOutput,
                   @NotNull final PrintStream standardError)
         throws IOException, InvalidKeyException, GeneralSecurityException
  {
    Validator.ensureTrue((inputStream != null),
         "StaticUtils.getPossiblyPassphraseEncryptedInputStream.inputStream " +
              "must not be null.");
    Validator.ensureTrue(
         ((passphrasePrompt != null) && (passphrasePrompt.length() > 0)),
         "StaticUtils.getPossiblyPassphraseEncryptedInputStream." +
              "passphrasePrompt must not be null or empty.");
    Validator.ensureTrue(
         ((incorrectPassphraseError != null) &&
              (incorrectPassphraseError.length() > 0)),
         "StaticUtils.getPossiblyPassphraseEncryptedInputStream." +
              "incorrectPassphraseError must not be null or empty.");
    Validator.ensureTrue((standardOutput!= null),
         "StaticUtils.getPossiblyPassphraseEncryptedInputStream." +
              "standardOutput must not be null.");
    Validator.ensureTrue((standardError!= null),
         "StaticUtils.getPossiblyPassphraseEncryptedInputStream." +
              "standardError must not be null.");


    // Mark the input stream so that we can peek at data from the beginning of
    // the stream.
    final InputStream markableInputStream;
    if (inputStream.markSupported())
    {
      markableInputStream = inputStream;
    }
    else
    {
      markableInputStream = new BufferedInputStream(inputStream);
    }

    markableInputStream.mark(1024);


    // Try to read a passphrase-encrypted stream header from the beginning of
    // the stream.  Just decode the header, but don't attempt to make it usable
    // for encryption or decryption.
    final PassphraseEncryptedStreamHeader streamHeaderShell;
    try
    {
      streamHeaderShell = PassphraseEncryptedStreamHeader.readFrom(
           markableInputStream, null);
    }
    catch (final LDAPException e)
    {
      // This is fine.  It just means that the stream doesn't contain encrypted
      // data.  In that case, reset the stream and return it so that the
      // unencrypted data can be read.
      Debug.debugException(Level.FINEST, e);
      markableInputStream.reset();
      return new ObjectPair<>(markableInputStream, null);
    }


    // If the header includes a key identifier, and if the server code is
    // available, then see if we can get a passphrase for the corresponding
    // encryption settings definition ID.
    if ((streamHeaderShell.getKeyIdentifier() != null) &&
         (GET_PASSPHRASE_FOR_ENCRYPTION_SETTINGS_ID_METHOD != null))
    {
      try
      {
        final Object passphraseObject =
             GET_PASSPHRASE_FOR_ENCRYPTION_SETTINGS_ID_METHOD.invoke(null,
                  streamHeaderShell.getKeyIdentifier(), standardOutput,
                  standardError);
        if ((passphraseObject != null) && (passphraseObject instanceof String))
        {
          final char[] passphraseChars =
               ((String) passphraseObject).toCharArray();
          final PassphraseEncryptedStreamHeader validStreamHeader =
               PassphraseEncryptedStreamHeader.decode(
                    streamHeaderShell.getEncodedHeader(),
                    passphraseChars);
          return new ObjectPair<InputStream,char[]>(
               new PassphraseEncryptedInputStream(markableInputStream,
                    validStreamHeader),
               passphraseChars);
        }
      }
      catch (final Exception e)
      {
        // This means that either an error occurred while trying to get the
        // passphrase, or the passphrase we got was incorrect.  That's fine.
        // We'll just continue on to prompt for the passphrase.
        Debug.debugException(e);
      }
    }


    // If any potential passphrases were provided, then see if any of them is
    // correct.
    if (potentialPassphrases != null)
    {
      final Iterator<char[]> passphraseIterator =
           potentialPassphrases.iterator();
      while (passphraseIterator.hasNext())
      {
        try
        {
          final char[] passphraseChars = passphraseIterator.next();
          final PassphraseEncryptedStreamHeader validStreamHeader =
               PassphraseEncryptedStreamHeader.decode(
                    streamHeaderShell.getEncodedHeader(),
                    passphraseChars);
          return new ObjectPair<InputStream,char[]>(
               new PassphraseEncryptedInputStream(markableInputStream,
                    validStreamHeader),
               passphraseChars);
        }
        catch (final InvalidKeyException e)
        {
          // The provided passphrase is not correct.  That's fine.  We'll just
          // prompt for the correct one.
          Debug.debugException(e);
          if ((! promptOnIncorrectPassphrase) &&
               (! passphraseIterator.hasNext()))
          {
            throw e;
          }
        }
        catch (final GeneralSecurityException e)
        {
          Debug.debugException(e);
          if (! passphraseIterator.hasNext())
          {
            throw e;
          }
        }
        catch (final LDAPException e)
        {
          // This should never happen, since we were previously able to decode
          // the header.  Just treat it like a GeneralSecurityException.
          Debug.debugException(e);
          if (! passphraseIterator.hasNext())
          {
            throw new GeneralSecurityException(e.getMessage(), e);
          }
        }
      }
    }


    // If we've gotten here, then we need to interactively prompt for the
    // passphrase.
    while (true)
    {
      // Read the passphrase from the user.
      final String promptedPassphrase;
      try
      {
        promptedPassphrase =
             promptForEncryptionPassphrase(false, false, passphrasePrompt, null,
                  standardOutput, standardError);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new IOException(e.getMessage(), e);
      }


      // Check to see if the passphrase was correct.  If so, then use it.
      // Otherwise, show an error and prompt again.
      try
      {
        final char[] passphraseChars = promptedPassphrase.toCharArray();
        final PassphraseEncryptedStreamHeader validStreamHeader =
             PassphraseEncryptedStreamHeader.decode(
                  streamHeaderShell.getEncodedHeader(), passphraseChars);
        return new ObjectPair<InputStream,char[]>(
             new PassphraseEncryptedInputStream(markableInputStream,
                  validStreamHeader),
             passphraseChars);
      }
      catch (final InvalidKeyException e)
      {
        Debug.debugException(e);

        // The passphrase was incorrect.  Display a wrapped error message and
        // re-prompt.
        wrap(incorrectPassphraseError, standardError);
        standardError.println();
      }
      catch (final GeneralSecurityException e)
      {
        Debug.debugException(e);
        throw e;
      }
      catch (final LDAPException e)
      {
        // This should never happen, since we were previously able to decode the
        // header.  Just treat it like a GeneralSecurityException.
        Debug.debugException(e);
        throw new GeneralSecurityException(e.getMessage(), e);
      }
    }
  }
}
