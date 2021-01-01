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
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases that cover the password reader (at
 * least the parts that don't require access to a console).
 */
public final class PasswordReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to read the characters that comprise a password when
   * using a test reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPasswordCharsFromTestReader()
         throws Exception
  {
    try
    {
      PasswordReader.setTestReaderLines("password");

      final char[] passwordChars = PasswordReader.readPasswordChars();
      assertNotNull(passwordChars);
      assertEquals(new String(passwordChars), "password");
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the ability to read the bytes that comprise a password when using a
   * test reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPasswordBytesFromTestReader()
         throws Exception
  {
    try
    {
      PasswordReader.setTestReaderLines("password");

      final byte[] passwordBytes = PasswordReader.readPassword();
      assertNotNull(passwordBytes);
      assertEquals(passwordBytes, StaticUtils.getBytes("password"));
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }
  }



  /**
   * Tests the behavior when trying to read a password from a test reader when
   * the attempt fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadPasswordFromUnavailableTestReader()
         throws Exception
  {
    try (ByteArrayInputStream byteArrayInputStream =
              new ByteArrayInputStream(StaticUtils.getBytes("password"));
         TestInputStream testInputStream = new TestInputStream(
              byteArrayInputStream, new IOException("password read error"),
              0, false);
         InputStreamReader inputStreamReader =
              new InputStreamReader(testInputStream);
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      try
      {
        PasswordReader.setTestReader(bufferedReader);
        PasswordReader.readPassword();
        fail("Expected an exception when trying to read a password from a " +
             "buffered reader backed by an invalid input stream");
      }
      finally
      {
        PasswordReader.setTestReader(null);
      }
    }
  }



  /**
   * Tests the ability to read the characters that comprise a password when
   * reading from a file specified using an environment variable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPasswordCharsFromFileFromEnvironmentVariable()
         throws Exception
  {
    try
    {
      final File passwordFile = createTempFile("password");
      PasswordReader.setDefaultEnvironmentVariableValue(
           passwordFile.getAbsolutePath());

      final char[] passwordChars = PasswordReader.readPasswordChars();
      assertNotNull(passwordChars);
      assertEquals(new String(passwordChars), "password");
    }
    finally
    {
      PasswordReader.setDefaultEnvironmentVariableValue(null);
    }
  }



  /**
   * Tests the ability to read the bytes that comprise a password when using a
   * test reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPasswordBytesFromFileFromEnvironmentVariable()
         throws Exception
  {
    try
    {
      final File passwordFile = createTempFile("password");
      PasswordReader.setDefaultEnvironmentVariableValue(
           passwordFile.getAbsolutePath());

      final byte[] passwordBytes = PasswordReader.readPassword();
      assertNotNull(passwordBytes);
      assertEquals(passwordBytes, StaticUtils.getBytes("password"));
    }
    finally
    {
      PasswordReader.setDefaultEnvironmentVariableValue(null);
    }
  }



  /**
   * Tests the behavior when trying to read a password from a test reader when
   * the attempt fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadPasswordFromUnavailableFileFromEnvironmentVariable()
         throws Exception
  {
    try
    {
      final File passwordFile = createTempFile("password");
      assertTrue(passwordFile.delete());
      PasswordReader.setDefaultEnvironmentVariableValue(
           passwordFile.getAbsolutePath());

      PasswordReader.readPassword();
      fail("Expected an exception when trying to read a password from a " +
           "nonexistent file specified by an environment variable.");
    }
    finally
    {
      PasswordReader.setDefaultEnvironmentVariableValue(null);
    }
  }



  /**
   * Tests the behavior when trying to read a password when no console is
   * available and no alternate method is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testReadPasswordWithNoConsoleOrAlternative()
         throws Exception
  {
    assertNull(System.console());
    PasswordReader.readPassword();
    fail("Expected an exception when trying to read a password when no " +
         "console is available and there is no alternative.");
  }
}
