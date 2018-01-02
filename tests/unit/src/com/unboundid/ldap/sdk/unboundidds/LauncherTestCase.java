/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2010-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the {@code Launcher} class.
 */
public final class LauncherTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a test case for launching the tool with a null set of arguments.
   */
  @Test()
  public void testNullArgs()
  {
    final PrintStream originalSystemOut = System.out;
    final PrintStream originalSystemErr = System.err;

    try
    {
      final ByteArrayOutputStream outStream = new ByteArrayOutputStream();
      final ByteArrayOutputStream errStream = new ByteArrayOutputStream();

      System.setOut(new PrintStream(outStream));
      System.setErr(new PrintStream(errStream));

      Launcher.main((String[]) null);

      assertTrue(outStream.size() > 0);
      assertTrue(errStream.size() == 0);
    }
    finally
    {
      System.setOut(originalSystemOut);
      System.setErr(originalSystemErr);
    }
  }



  /**
   * Provides a test case for launching the tool with an empty set of arguments.
   */
  @Test()
  public void testEmptyArgs()
  {
    final ByteArrayOutputStream outStream = new ByteArrayOutputStream();
    final ByteArrayOutputStream errStream = new ByteArrayOutputStream();

    assertEquals(Launcher.main(outStream, errStream), ResultCode.SUCCESS);

    assertTrue(outStream.size() > 0);
    assertTrue(errStream.size() == 0);
  }



  /**
   * Provides a test case for launching the tool with a valid tool name and a
   * valid set of arguments for that tool.
   *
   * @param  toolName  The name of a valid tool.
   */
  @Test(dataProvider="valid-tool-names")
  public void testValidToolName(final String toolName)
  {
    final ByteArrayOutputStream outStream = new ByteArrayOutputStream();
    final ByteArrayOutputStream errStream = new ByteArrayOutputStream();

    assertEquals(Launcher.main(outStream, errStream, toolName, "--help"),
         ResultCode.SUCCESS);

    assertTrue(outStream.size() > 0);
    assertTrue(errStream.size() == 0);
  }



  /**
   * Retrieves a set of valid tool names.
   *
   * @return  A set of valid tool names.
   */
  @DataProvider(name="valid-tool-names")
  public Object[][] getValidToolNames()
  {
    return new Object[][]
    {
      new Object[] { "authrate" },
      new Object[] { "base64" },
      new Object[] { "deliver-one-time-password" },
      new Object[] { "deliver-password-reset-token" },
      new Object[] { "dump-dns" },
      new Object[] { "generate-schema-from-source" },
      new Object[] { "generate-source-from-schema" },
      new Object[] { "generate-totp-shared-secret" },
      new Object[] { "identify-references-to-missing-entries" },
      new Object[] { "identify-unique-attribute-conflicts" },
      new Object[] { "in-memory-directory-server" },
      new Object[] { "ldapcompare" },
      new Object[] { "ldapmodify" },
      new Object[] { "ldapsearch" },
      new Object[] { "ldap-debugger" },
      new Object[] { "manage-account" },
      new Object[] { "manage-certificates" },
      new Object[] { "modrate" },
      new Object[] { "move-subtree" },
      new Object[] { "register-yubikey-otp-device" },
      new Object[] { "searchrate" },
      new Object[] { "search-and-mod-rate" },
      new Object[] { "split-ldif" },
      new Object[] { "subtree-accessibility" },
      new Object[] { "summarize-access-log" },
      new Object[] { "transform-ldif" },
      new Object[] { "validate-ldif" },
      new Object[] { "version" }
    };
  }



  /**
   * Provides a test case for launching the tool with an invalid tool name.
   */
  @Test()
  public void testInvalidToolName()
  {
    final ByteArrayOutputStream outStream = new ByteArrayOutputStream();
    final ByteArrayOutputStream errStream = new ByteArrayOutputStream();

    assertFalse(Launcher.main(outStream, errStream, "invalid", "--help").equals(
         ResultCode.SUCCESS));

    assertTrue(outStream.size() == 0);
    assertTrue(errStream.size() > 0);
  }
}
