/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a mechanism for reading a password from the command line
 * in a way that attempts to prevent it from being displayed.  If it is
 * available (i.e., Java SE 6 or later), the
 * {@code java.io.Console.readPassword} method will be used to accomplish this.
 * For Java SE 5 clients, a more primitive approach must be taken, which
 * requires flooding standard output with backspace characters using a
 * high-priority thread.  This has only a limited effectiveness, but it is the
 * best option available for older Java versions.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordReader
{
  /**
   * The input stream from which to read the password.  This should only be set
   * when running unit tests.
   */
  @Nullable private static volatile BufferedReader TEST_READER = null;



  /**
   * The default value to use for the environment variable.  This should only
   * be set when running unit tests.
   */
  @Nullable private static volatile String DEFAULT_ENVIRONMENT_VARIABLE_VALUE =
       null;



  /**
   * The name of an environment variable that can be used to specify the path
   * to a file that contains the password to be read.  This is also
   * predominantly intended for use when running unit tests, and may be
   * necessary for tests running in a separate process that can't use the
   * {@code TEST_READER}.
   */
  @NotNull private static final String PASSWORD_FILE_ENVIRONMENT_VARIABLE =
       "LDAP_SDK_PASSWORD_READER_PASSWORD_FILE";



  /**
   * Creates a new instance of this password reader thread.
   */
  private PasswordReader()
  {
    // No implementation is required.
  }



  /**
   * Reads a password from the console as a character array.
   *
   * @return  The characters that comprise the password that was read.
   *
   * @throws  LDAPException  If a problem is encountered while trying to read
   *                         the password.
   */
  @NotNull()
  public static char[] readPasswordChars()
         throws LDAPException
  {
    // If an input stream is available, then read the password from it.
    final BufferedReader testReader = TEST_READER;
    if (testReader != null)
    {
      try
      {
        return testReader.readLine().toCharArray();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_PW_READER_FAILURE.get(StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    // If a password input file environment variable has been set, then read
    // the password from that file.
    final String environmentVariableValue = StaticUtils.getEnvironmentVariable(
         PASSWORD_FILE_ENVIRONMENT_VARIABLE,
         DEFAULT_ENVIRONMENT_VARIABLE_VALUE);
    if (environmentVariableValue != null)
    {
      try
      {
        final File f = new File(environmentVariableValue);
        final PasswordFileReader r = new PasswordFileReader();
        return r.readPassword(f);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_PW_READER_FAILURE.get(StaticUtils.getExceptionMessage(e)),
             e);
      }
    }


    if (System.console() == null)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_PW_READER_CANNOT_READ_PW_WITH_NO_CONSOLE.get());
    }

    return System.console().readPassword();
  }



  /**
   * Reads a password from the console as a byte array.
   *
   * @return  The characters that comprise the password that was read.
   *
   * @throws  LDAPException  If a problem is encountered while trying to read
   *                         the password.
   */
  @NotNull()
  public static byte[] readPassword()
         throws LDAPException
  {
    // Get the characters that make up the password.
    final char[] pwChars = readPasswordChars();

    // Convert the password to bytes.
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(pwChars);
    Arrays.fill(pwChars, '\u0000');
    final byte[] pwBytes = buffer.toByteArray();
    buffer.clear(true);
    return pwBytes;
  }



  /**
   * This is a legacy method that now does nothing.  It was required by a
   * former version of this class when older versions of Java were still
   * supported, and is retained only for the purpose of API backward
   * compatibility.
   *
   * @deprecated  This method is no longer used.
   */
  @Deprecated()
  public void run()
  {
    // No implementation is required.
  }



  /**
   * Specifies the lines that should be used as input when reading the password.
   * This should only be set when running unit tests, and the
   * {@link #setTestReader(BufferedReader)} method should be called with a value
   * of {@code null} before the end of the test to ensure that the password
   * reader is reverted back to its normal behavior.
   *
   * @param  lines  The lines of input that should be provided to the password
   *                reader instead of actually obtaining them interactively.
   *                It must not be {@code null} but may be empty.
   */
  @InternalUseOnly()
  public static void setTestReaderLines(@NotNull final String... lines)
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String line : lines)
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    TEST_READER = new BufferedReader(new InputStreamReader(
         new ByteArrayInputStream(buffer.toByteArray())));
  }



  /**
   * Specifies the input stream from which to read the password.  This should
   * only be set when running unit tests, and this method should be called
   * again with a value of {@code null} before the end of the test to ensure
   * that the password reader is reverted back to its normal behavior.
   *
   * @param  reader  The input stream from which to read the password.  It may
   *                 be {@code null} to obtain the password from the normal
   *                 means.
   */
  @InternalUseOnly()
  public static void setTestReader(@Nullable final BufferedReader reader)
  {
    TEST_READER = reader;
  }



  /**
   * Sets the default value that should be used for the environment variable if
   * it is not set.  This is only intended for use in testing purposes.
   *
   * @param  value  The default value that should be used for the environment
   *                variable if it is not set.  It may be {@code null} if the
   *                environment variable should be treated as unset.
   */
  @InternalUseOnly()
  static void setDefaultEnvironmentVariableValue(@Nullable final String value)
  {
    DEFAULT_ENVIRONMENT_VARIABLE_VALUE = value;
  }
}
