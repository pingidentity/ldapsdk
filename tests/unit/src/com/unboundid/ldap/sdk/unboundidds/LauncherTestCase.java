/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
import java.io.File;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.Set;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.StaticUtils;

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
      new Object[] { "collect-support-data" },
      new Object[] { "deliver-one-time-password" },
      new Object[] { "deliver-password-reset-token" },
      new Object[] { "dump-dns" },
      new Object[] { "generate-schema-from-source" },
      new Object[] { "generate-source-from-schema" },
      new Object[] { "generate-totp-shared-secret" },
      new Object[] { "identify-references-to-missing-entries" },
      new Object[] { "identify-unique-attribute-conflicts" },
      new Object[] { "in-memory-directory-server" },
      new Object[] { "indent-ldap-filter" },
      new Object[] { "ldapcompare" },
      new Object[] { "ldapdelete" },
      new Object[] { "ldapmodify" },
      new Object[] { "ldappasswordmodify" },
      new Object[] { "ldapsearch" },
      new Object[] { "ldap-debugger" },
      new Object[] { "ldap-result-code" },
      new Object[] { "ldifmodify" },
      new Object[] { "ldifsearch" },
      new Object[] { "ldif-diff" },
      new Object[] { "manage-account" },
      new Object[] { "manage-certificates" },
      new Object[] { "modrate" },
      new Object[] { "move-subtree" },
      new Object[] { "oid-lookup" },
      new Object[] { "parallel-update" },
      new Object[] { "register-yubikey-otp-device" },
      new Object[] { "searchrate" },
      new Object[] { "search-and-mod-rate" },
      new Object[] { "split-ldif" },
      new Object[] { "subtree-accessibility" },
      new Object[] { "summarize-access-log" },
      new Object[] { "test-ldap-sdk-performance" },
      new Object[] { "tls-cipher-suite-selector" },
      new Object[] { "transform-ldif" },
      new Object[] { "validate-ldap-schema" },
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



  /**
   * Tests to ensure that it's possible to get an instance of all of the
   * defined tools.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetToolInstance()
         throws Exception
  {
    for (final Class<?> c : Launcher.getToolClasses())
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final ByteArrayOutputStream err = new ByteArrayOutputStream();

      final CommandLineTool tool = Launcher.getToolInstance(c, out, err);
      assertNotNull(tool);
    }
  }



  /**
   * Ensures that all tools we distribute with the LDAP SDK can be invoked
   * through the launcher.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void ensureAllDistributedToolsIncluded()
         throws Exception
  {
    final Set<String> expectedToolNames = new HashSet<>();
    for (final Object[] toolNamesArray : getValidToolNames())
    {
      final String toolName = (String) toolNamesArray[0];
      if (toolName.equals("test-ldap-sdk-performance") ||
           toolName.equals("tls-cipher-suite-selector") ||
           toolName.equals("version"))
      {
        // These are internal tools that we don't intend to ship directly but
        // can still be invoked using the launcher.
        continue;
      }

      expectedToolNames.add((String) toolNamesArray[0]);
    }

    final Set<String> foundToolShellScripts = new HashSet<>();
    final Set<String> foundToolBatchFiles = new HashSet<>();
    final File baseDir = new File(System.getProperty("basedir"));
    final File toolsDir =
         StaticUtils.constructPath(baseDir, "dist-root", "tools");
    for (final File f : toolsDir.listFiles())
    {
      if (f.isDirectory())
      {
        fail("Unexpected directory '" + f.getAbsolutePath() +
             "' found in tools directory");
      }

      final String name = f.getName();
      if (name.startsWith("."))
      {
        // This is a script or batch file meant to support other tools rather
        // than one that is intended to be used directly.
        continue;
      }

      if (name.endsWith(".bat"))
      {
        foundToolBatchFiles.add(name);
      }
      else
      {
        foundToolShellScripts.add(name);
      }
    }

    for (final String scriptName : foundToolShellScripts)
    {
      assertTrue(foundToolBatchFiles.contains(scriptName + ".bat"),
           "Missing batch file corresponding to shell script " + scriptName);
    }

    for (final String batchFile : foundToolBatchFiles)
    {
      final String scriptName =
           batchFile.substring(0, (batchFile.length() - 4));
      assertTrue(foundToolShellScripts.contains(scriptName),
           "Missing shell script " + scriptName +
                "corresponding to batch file " + batchFile);
    }

    assertEquals(foundToolShellScripts.size(), foundToolBatchFiles.size(),
         "Size mismatch between shell scripts " + foundToolShellScripts +
              " and batch files " + foundToolBatchFiles);

    for (final String scriptName : foundToolShellScripts)
    {
      assertTrue(expectedToolNames.contains(scriptName),
           "Missing launcher support for script " + scriptName);
    }

    for (final String scriptName : expectedToolNames)
    {
      assertTrue(foundToolShellScripts.contains(scriptName),
           "Missing script for launcher tool " + scriptName);
    }
  }
}
