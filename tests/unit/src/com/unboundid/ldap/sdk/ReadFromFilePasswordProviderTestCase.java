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
package com.unboundid.ldap.sdk;



import java.io.File;
import java.io.PrintWriter;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the read from file password
 * provider.
 */
public final class ReadFromFilePasswordProviderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the basic behavior of the password provider with the path given as
   * a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromValidFileAsString()
         throws Exception
  {
    // Create a password file.  It should end with an end-of-line sequence.
    final File f = createTempFile("password");

    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(f.getAbsolutePath());

    final byte[] passwordBytes = passwordProvider.getPasswordBytes();
    assertEquals(passwordBytes, "password".getBytes("UTF-8"));
  }



  /**
   * Tests the basic behavior of the password provider with the path given as
   * a string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFromValidFileAsObject()
         throws Exception
  {
    // Create a password file.  It will not end with an end-of-line sequence.
    final File f = createTempFile();
    final PrintWriter w = new PrintWriter(f);
    w.print("password");
    w.close();

    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(f);

    final byte[] passwordBytes = passwordProvider.getPasswordBytes();
    assertEquals(passwordBytes, "password".getBytes("UTF-8"));
  }



  /**
   * Tests the behavior of the password provider with a file that does not
   * exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMissingFile()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(f);
    passwordProvider.getPasswordBytes();
  }



  /**
   * Tests the behavior of the password provider with an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEmptyFile()
         throws Exception
  {
    final File f = createTempFile();

    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(f);
    passwordProvider.getPasswordBytes();
  }



  /**
   * Tests the ability to perform a simple bind using the read from file
   * password provider.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleBindSuccessful()
         throws Exception
  {
    final File f = createTempFile("password");

    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(f);

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final SimpleBindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", passwordProvider);

    assertNull(bindRequest.getPassword());

    assertNotNull(bindRequest.getPasswordProvider());

    assertResultCodeEquals(conn, bindRequest, ResultCode.SUCCESS);

    conn.close();
  }



  /**
   * Tests the ability to perform a simple bind using the read from file
   * password provider, in which the password provider is configured to retrieve
   * the password from a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleBindFailed()
         throws Exception
  {
    final File f = createTempFile();
    f.delete();

    final ReadFromFilePasswordProvider passwordProvider =
         new ReadFromFilePasswordProvider(f);

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final SimpleBindRequest bindRequest =
         new SimpleBindRequest(new DN("cn=Directory Manager"),
              passwordProvider);

    assertNull(bindRequest.getPassword());

    assertNotNull(bindRequest.getPasswordProvider());

    assertResultCodeEquals(conn, bindRequest, ResultCode.LOCAL_ERROR);

    conn.close();
  }
}
