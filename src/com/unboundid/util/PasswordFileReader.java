/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a mechanism for reading a password from a file.  Password
 * files must contain exactly one line, which must be non-empty, and the entire
 * content of that line will be used as the password.
 * <BR><BR>
 * The contents of the file may have optionally been encrypted with the
 * {@link PassphraseEncryptedOutputStream}, and may have optionally been
 * compressed with the {@code GZIPOutputStream}.  If the data is both compressed
 * and encrypted, then it must have been compressed before it was encrypted, so
 * that it is necessary to decrypt the data before it can be decompressed.
 * <BR><BR>
 * If the file is encrypted, then the encryption key may be obtained in one of
 * the following ways:
 * <UL>
 *   <LI>If this code is running in a tool that is part of a Ping Identity
 *       Directory Server installation (or a related product like the Directory
 *       Proxy Server or Data Synchronization Server, or an alternately branded
 *       version of these products, like the Alcatel-Lucent or Nokia 8661
 *       versions), and the file was encrypted with a key from that server's
 *       encryption settings database, then the tool will try to get the
 *       key from the corresponding encryption settings definition.  In many
 *       cases, this may not require any interaction from the user at all.</LI>
 *   <LI>The reader maintains a cache of passwords that have been previously
 *       used.  If the same password is used to encrypt multiple files, it may
 *       only need to be requested once from the user.  The caller can also
 *       manually add passwords to this cache if they are known in advance.</LI>
 *   <LI>The user can be interactively prompted for the password.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordFileReader
{
  // A list of passwords that will be tried as encryption keys if an encrypted
  // password file is encountered.
  @NotNull private final CopyOnWriteArrayList<char[]> encryptionPasswordCache;

  // The print stream that should be used as standard output of an encrypted
  // password file is encountered and it is necessary to prompt for the password
  // used as the encryption key.
  @NotNull private final PrintStream standardError;

  // The print stream that should be used as standard output of an encrypted
  // password file is encountered and it is necessary to prompt for the password
  // used as the encryption key.
  @NotNull private final PrintStream standardOutput;



  /**
   * Creates a new instance of this password file reader.  The JVM-default
   * standard output and error streams will be used.
   */
  public PasswordFileReader()
  {
    this(System.out, System.err);
  }



  /**
   * Creates a new instance of this password file reader.
   *
   * @param  standardOutput  The print stream that should be used as standard
   *                         output if an encrypted password file is encountered
   *                         and it is necessary to prompt for the password
   *                         used as the encryption key.  This must not be
   *                         {@code null}.
   * @param  standardError   The print stream that should be used as standard
   *                         error if an encrypted password file is encountered
   *                         and it is necessary to prompt for the password
   *                         used as the encryption key.  This must not be
   *                         {@code null}.
   */
  public PasswordFileReader(@NotNull final PrintStream standardOutput,
                            @NotNull final PrintStream standardError)
  {
    Validator.ensureNotNullWithMessage(standardOutput,
         "PasswordFileReader.standardOutput must not be null.");
    Validator.ensureNotNullWithMessage(standardError,
         "PasswordFileReader.standardError must not be null.");

    this.standardOutput = standardOutput;
    this.standardError = standardError;

    encryptionPasswordCache = new CopyOnWriteArrayList<>();
  }



  /**
   * Attempts to read a password from the specified file.
   *
   * @param  path  The path to the file from which the password should be read.
   *               It must not be {@code null}, and the file must exist.
   *
   * @return  The characters that comprise the password read from the specified
   *          file.
   *
   * @throws  IOException  If a problem is encountered while trying to read the
   *                       password from the file.
   *
   * @throws  LDAPException  If the file does not exist, if it does not contain
   *                         exactly one line, or if that line is empty.
   */
  @NotNull()
  public char[] readPassword(@NotNull final String path)
         throws IOException, LDAPException
  {
    return readPassword(new File(path));
  }



  /**
   * Attempts to read a password from the specified file.
   *
   * @param  file  The path file from which the password should be read.  It
   *               must not be {@code null}, and the file must exist.
   *
   * @return  The characters that comprise the password read from the specified
   *          file.
   *
   * @throws  IOException  If a problem is encountered while trying to read the
   *                       password from the file.
   *
   * @throws  LDAPException  If the file does not exist, if it does not contain
   *                         exactly one line, or if that line is empty.
   */
  @NotNull()
  public char[] readPassword(@NotNull final File file)
         throws IOException, LDAPException
  {
    if (! file.exists())
    {
      throw new IOException(ERR_PW_FILE_READER_FILE_MISSING.get(
           file.getAbsolutePath()));
    }

    if (! file.isFile())
    {
      throw new IOException(ERR_PW_FILE_READER_FILE_NOT_FILE.get(
           file.getAbsolutePath()));
    }

    InputStream inputStream = new FileInputStream(file);
    try
    {
      try
      {
        final ObjectPair<InputStream, char[]> encryptedFileData =
             ToolUtils.getPossiblyPassphraseEncryptedInputStream(inputStream,
                  encryptionPasswordCache, true,
                  INFO_PW_FILE_READER_ENTER_PW_PROMPT
                       .get(file.getAbsolutePath()),
                  ERR_PW_FILE_READER_WRONG_PW.get(file.getAbsolutePath()),
                  standardOutput, standardError);
        inputStream = encryptedFileData.getFirst();

        final char[] encryptionPassword = encryptedFileData.getSecond();
        if (encryptionPassword != null)
        {
          synchronized (encryptionPasswordCache)
          {
            boolean passwordIsAlreadyCached = false;
            for (final char[] cachedPassword : encryptionPasswordCache)
            {
              if (Arrays.equals(encryptionPassword, cachedPassword))
              {
                passwordIsAlreadyCached = true;
                break;
              }
            }

            if (!passwordIsAlreadyCached)
            {
              encryptionPasswordCache.add(encryptionPassword);
            }
          }
        }
      }
      catch (final GeneralSecurityException e)
      {
        Debug.debugException(e);
        throw new IOException(e);
      }

      inputStream = ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);

      try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(inputStream)))
      {
        final String passwordLine = reader.readLine();
        if (passwordLine == null)
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_PW_FILE_READER_FILE_EMPTY.get(file.getAbsolutePath()));
        }

        final String secondLine = reader.readLine();
        if (secondLine != null)
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_PW_FILE_READER_FILE_HAS_MULTIPLE_LINES.get(
               file.getAbsolutePath()));
        }

        if (passwordLine.isEmpty())
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_PW_FILE_READER_FILE_HAS_EMPTY_LINE.get(
                    file.getAbsolutePath()));
        }

        return passwordLine.toCharArray();
      }
    }
    finally
    {
      try
      {

        inputStream.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }



  /**
   * Retrieves a list of the encryption passwords currently held in the cache.
   *
   * @return  A list of the encryption passwords currently held in the cache, or
   *          an empty list if there are no cached passwords.
   */
  @NotNull()
  public List<char[]> getCachedEncryptionPasswords()
  {
    final ArrayList<char[]> cacheCopy;
    synchronized (encryptionPasswordCache)
    {
      cacheCopy = new ArrayList<>(encryptionPasswordCache.size());
      for (final char[] cachedPassword : encryptionPasswordCache)
      {
        cacheCopy.add(Arrays.copyOf(cachedPassword, cachedPassword.length));
      }
    }

    return Collections.unmodifiableList(cacheCopy);
  }



  /**
   * Adds the provided password to the cache of passwords that will be tried as
   * potential encryption keys if an encrypted password file is encountered.
   *
   * @param  encryptionPassword  A password to add to the cache of passwords
   *                             that will be tried as potential encryption keys
   *                             if an encrypted password file is encountered.
   *                             It must not be {@code null} or empty.
   */
  public void addToEncryptionPasswordCache(
                   @NotNull final String encryptionPassword)
  {
    addToEncryptionPasswordCache(encryptionPassword.toCharArray());
  }



  /**
   * Adds the provided password to the cache of passwords that will be tried as
   * potential encryption keys if an encrypted password file is encountered.
   *
   * @param  encryptionPassword  A password to add to the cache of passwords
   *                             that will be tried as potential encryption keys
   *                             if an encrypted password file is encountered.
   *                             It must not be {@code null} or empty.
   */
  public void addToEncryptionPasswordCache(
                   @NotNull final char[] encryptionPassword)
  {
    Validator.ensureNotNullWithMessage(encryptionPassword,
         "PasswordFileReader.addToEncryptionPasswordCache.encryptionPassword " +
              "must not be null or empty.");
    Validator.ensureTrue((encryptionPassword.length > 0),
         "PasswordFileReader.addToEncryptionPasswordCache.encryptionPassword " +
              "must not be null or empty.");

    synchronized (encryptionPasswordCache)
    {
      for (final char[] cachedPassword : encryptionPasswordCache)
      {
        if (Arrays.equals(cachedPassword, encryptionPassword))
        {
          return;
        }
      }

      encryptionPasswordCache.add(encryptionPassword);
    }
  }



  /**
   * Clears the cache of passwords that will be tried as potential encryption
   * keys if an encrypted password file is encountered.
   *
   * @param  zeroArrays  Indicates whether to zero out the contents of the
   *                     cached passwords before clearing them.  If this is
   *                     {@code true}, then all of the backing arrays for the
   *                     cached passwords will be overwritten with all null
   *                     characters to erase the original passwords from memory.
   */
  public void clearEncryptionPasswordCache(final boolean zeroArrays)
  {
    synchronized (encryptionPasswordCache)
    {
      if (zeroArrays)
      {
        for (final char[] cachedPassword : encryptionPasswordCache)
        {
          Arrays.fill(cachedPassword, '\u0000');
        }
      }

      encryptionPasswordCache.clear();
    }
  }
}
