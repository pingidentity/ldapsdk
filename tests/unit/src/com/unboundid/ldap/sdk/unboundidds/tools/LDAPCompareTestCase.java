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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.
            AdministrativeSessionInMemoryExtendedOperationHandler;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides a set of test cases for the {@code LDAPCompare}
 * command-line tool.
 */
public final class LDAPCompareTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of various tool methods that can be called without
   * actually running the tool.
   */
  @Test()
  public void testToolMethods()
  {
    final LDAPCompare tool = new LDAPCompare(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "ldapcompare");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertEquals(tool.getMinTrailingArguments(), 0);

    assertEquals(tool.getMaxTrailingArguments(), -1);

    assertNotNull(tool.getTrailingArgumentsPlaceholder());
    assertFalse(tool.getTrailingArgumentsPlaceholder().isEmpty());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsAuthentication());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.supportsSASLHelp());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertTrue(tool.supportsMultipleServers());

    assertTrue(tool.supportsSSLDebugging());

    assertFalse(tool.logToolInvocationByDefault());

    assertNull(tool.getToolCompletionMessage());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
    assertEquals(tool.getExampleUsages().size(), 3);
  }



  /**
   * Tests to ensure that the tool can be successfully invoked to obtain usage
   * information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final ResultCode resultCode = LDAPCompare.main(out, err, "--help");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(out.toByteArray());
    assertTrue(out.toByteArray().length > 0);

    assertNotNull(err.toByteArray());
    assertEquals(err.toByteArray().length, 0);
  }



  /**
   * Tests the behavior for a simple compare operation in which the
   * attribute-value assertion matches the target entry and the default success
   * result code should be used as the exit code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareTrueDefaultResultCode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior for a simple compare operation in which the
   * attribute-value assertion matches the target entry and the compare result
   * code should be used as the exit code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareTrueCompareResultCode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior for a simple compare operation in which the
   * attribute-value assertion does not match the target entry and the default
   * success result code should be used as the exit code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareFalseDefaultResultCode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:organizationalUnit",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior for a simple compare operation in which the
   * attribute-value assertion does not match the target entry and the compare
   * result code should be used as the exit code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareFalseCompareResultCode()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_FALSE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:organizationalUnit",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior for a simple compare operation in which the
   * attribute-value assertion yields an error result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testErrorResult()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.NO_SUCH_OBJECT, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:organizationalUnit",
         "ou=missing,dc=example,dc=com");
  }



  /**
   * Tests the behavior when performing multiple compare operations with the DNs
   * provided as trailing arguments.  All of the assertions will match.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleComparesAllMatch()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:top",
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");
  }



  /**
   * Tests the behavior when performing multiple compare operations with the DNs
   * provided as trailing arguments.  None of the assertions will match.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleComparesNoneMatch()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:organization",
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");
  }



  /**
   * Tests the behavior when performing multiple compare operations with the DNs
   * provided as trailing arguments.  There will be a mix of matching and
   * non-matching assertions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleComparesSomeMatch()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:organizationalUnit",
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");
  }



  /**
   * Tests the behavior when performing multiple compare operations with the DNs
   * provided as trailing arguments.  One of the operations will fail because
   * the target entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleComparesWithFailure()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.NO_SUCH_OBJECT, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:organizationalUnit",
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "ou=nonexistent,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");
  }



  /**
   * Tests the behavior of the tool when an error occurs with regard to the
   * presence or absence of the --continueOnError argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testContinueOnError()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.NO_SUCH_OBJECT, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFormat", "json",
         "--outputFile", outputFile.getAbsolutePath(),
         "objectClass:organizationalUnit",
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "ou=nonexistent,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");

    Map<DN,JSONObject> jsonObjects = readJSONObjects(outputFile);
    assertEquals(jsonObjects.size(), 3);
    assertTrue(jsonObjects.containsKey(new DN("dc=example,dc=com")));
    assertTrue(jsonObjects.containsKey(new DN("ou=People,dc=example,dc=com")));
    assertTrue(jsonObjects.containsKey(
         new DN("ou=nonexistent,dc=example,dc=com")));
    assertFalse(jsonObjects.containsKey(
         new DN("uid=test.user,ou=People,dc=example,dc=com")));


    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.NO_SUCH_OBJECT, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFormat", "json",
         "--outputFile", outputFile.getAbsolutePath(),
         "--continueOnError",
         "objectClass:organizationalUnit",
         "dc=example,dc=com",
         "ou=People,dc=example,dc=com",
         "ou=nonexistent,dc=example,dc=com",
         "uid=test.user,ou=People,dc=example,dc=com");

    jsonObjects = readJSONObjects(outputFile);
    assertEquals(jsonObjects.size(), 4);
    assertTrue(jsonObjects.containsKey(new DN("dc=example,dc=com")));
    assertTrue(jsonObjects.containsKey(new DN("ou=People,dc=example,dc=com")));
    assertTrue(jsonObjects.containsKey(
         new DN("ou=nonexistent,dc=example,dc=com")));
    assertTrue(jsonObjects.containsKey(
         new DN("uid=test.user,ou=People,dc=example,dc=com")));


    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.NO_SUCH_OBJECT, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFormat", "json",
         "--outputFile", outputFile.getAbsolutePath(),
         "--continueOnError",
         "objectClass:organizationalUnit",
         "ou=nonexistent,dc=example,dc=com");

    jsonObjects = readJSONObjects(outputFile);
    assertEquals(jsonObjects.size(), 1);
    assertFalse(jsonObjects.containsKey(new DN("dc=example,dc=com")));
    assertFalse(jsonObjects.containsKey(new DN("ou=People,dc=example,dc=com")));
    assertTrue(jsonObjects.containsKey(
         new DN("ou=nonexistent,dc=example,dc=com")));
    assertFalse(jsonObjects.containsKey(
         new DN("uid=test.user,ou=People,dc=example,dc=com")));
  }



  /**
   * Tests the behavior for the case in which the assertion value is
   * base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBase64EncodedAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass::" + Base64.encode("top"),
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when not reading any data from a file, but also not
   * providing any trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNeitherFileNorTrailingArgs()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()));
  }



  /**
   * Tests the behavior when not reading any data from a file, and when only a
   * single trailing argument was provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoFileOneTrailingArg()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:top");
  }



  /**
   * Tests the behavior when an empty attribute-value assertion is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion does not have a
   * colon to separate the attribute name from the assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAMissingColon()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion starts with a colon,
   * indicating an empty attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAStartsWithColon()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         ":top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion has a single colon
   * immediately after the attribute name and nothing following that.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAEmptyStringValue()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_FALSE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion has two colons
   * immediately after the attribute name and nothing following them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAEmptyBase64Value()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_FALSE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass::",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion has a malformed
   * base64-encoded value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAMalformedBase64Value()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass::malformed base64-encoded value",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion has a colon followed
   * by a less-than sign and the path to a file from which the assertion
   * value should be read.  The file path will be valid and the assertion will
   * match.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAReadFromValidFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionValueFile = createTempFile();
    assertTrue(assertionValueFile.delete());
    try (FileOutputStream outputStream =
              new FileOutputStream(assertionValueFile))
    {
      outputStream.write(StaticUtils.getBytes("top"));
    }

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:<" + assertionValueFile.getAbsolutePath(),
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion has a colon followed
   * by a less-than sign and the path to a file from which the assertion
   * value should be read.  The path will refer to a file that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAReadFromNonexistentFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionValueFile = createTempFile();
    assertTrue(assertionValueFile.delete());

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:<" + assertionValueFile.getAbsolutePath(),
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when the attribute-value assertion has a colon followed
   * by a less-than sign and the path to a file from which the assertion
   * value should be read.  The path will refer to a directory rather than a
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAReadFromPathNotFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionValueFile = createTempDir();

    ldapCompare(ResultCode.LOCAL_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:<" + assertionValueFile.getAbsolutePath(),
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when a DN provided on the command line is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyTrailingDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "objectClass:top",
         "");
  }



  /**
   * Tests the behavior when a DN provided on the command line is malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedTrailingDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:top",
         "malformed DN");
  }



  /**
   * Tests the behavior when reading entry DNs from a file when that file
   * contains a single DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOneDNFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile(
         "dc=example,dc=com");

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath(),
         "--useCompareResultCodeAsExitCode",
         "objectClass:top");
  }



  /**
   * Tests the behavior when reading entry DNs from a file when that file
   * contains multiple DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMultipleDNsFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile(
         "dc=example,dc=com",
         "",
         "# The above line was blank, and this is a comment",
         "ou=People,dc=example,dc=com",
         "",
         "",
         "uid=test.user,ou=People,dc=example,dc=com",
         "# The file ends with a comment");

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath(),
         "objectClass:top");
  }



  /**
   * Tests the behavior when reading entry DNs from a file when that file is
   * empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMultipleDNsFromEmptyFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile();

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath(),
         "objectClass:top");
  }



  /**
   * Tests the behavior when reading entry DNs from a file when that file
   * contains a malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMalformedDNFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile(
         "this is not a valid DN");

    ldapCompare(ResultCode.DECODING_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath(),
         "objectClass:top");
  }



  /**
   * Tests the behavior when reading entry DNs from a file when no AVA was
   * provided as a trailing argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDNFromFileNoAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile(
         "dc=example,dc=com");

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading entry DNs from a file when a malformed AVA
   * was provided as a trailing argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDNFromFileMalformedAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile(
         "dc=example,dc=com");

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath(),
         "malformedAVA");
  }



  /**
   * Tests the behavior when reading entry DNs from a file when multiple
   * trailing arguments were provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDNFromFileMultipleTrailingArgs()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File dnFile = createTempFile(
         "dc=example,dc=com");

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--dnFile", dnFile.getAbsolutePath(),
         "objectClass:top",
         "ou=People,dc=example,dc=com");
  }



  /**
   * Tests the behavior when reading assertion data from a file when that file
   * contains information about a single compare request.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadOneAssertionFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com\tobjectClass:top");

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data from a file when that file
   * contains information about multiple assertions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadMultipleAssertionsFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "# The assertions are in this file.",
         "dc=example,dc=com\tobjectClass:domain",
         "",
         "ou=People,dc=example,dc=com\tobjectClass:organizationalUnit",
         "",
         "",
         "uid=test.user,ou=People,dc=example,dc=com\tobjectClass:inetOrgPerson",
         "# This is the last line of the file.");

    ldapCompare(ResultCode.SUCCESS, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data from an empty file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFromEmptyFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile();

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that does not have a tab
   * to separate the DN from the assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileMissingTab()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com");

    ldapCompare(ResultCode.DECODING_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that has multiple tabs to
   * separate the DN from the assertion value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileMultipleTabs()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com\t\t\t\tobjectClass:top");

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that has an empty DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileEmptyDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "\tobjectClass:top");

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that has a malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileMalformedDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "malformed\tobjectClass:top");

    ldapCompare(ResultCode.DECODING_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that has an empty
   * attribute-value assertion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileEmptyAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com\t");

    ldapCompare(ResultCode.DECODING_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that has a malformed
   * attribute-value assertion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileMalformedAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com\tmalformedAVA");

    ldapCompare(ResultCode.DECODING_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data that has a base64-encoded
   * attribute-value assertion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileBase64EncodedAVA()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com\tobjectClass::" + Base64.encode("top"));

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "--assertionFile", assertionFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when reading assertion data and trailing arguments were
   * provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAssertionsFileWithTrailingArgs()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File assertionFile = createTempFile(
         "dc=example,dc=com\tobjectClass:top");

    ldapCompare(ResultCode.PARAM_ERROR, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFile", assertionFile.getAbsolutePath(),
         "objectClass:domain");
  }



  /**
   * Tests the behavior when targeting a referral entry when not automatically
   * following referrals and not using the manageDsaIT requests control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralDefaultConfig()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://localhost:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");

    ldapCompare(ResultCode.REFERRAL, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "objectClass:organizationalUnit",
         "ou=Users,dc=example,dc=com");
  }



  /**
   * Tests the behavior when targeting a referral entry when automatically
   * following referrals.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralAutomaticallyFollow()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://localhost:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "--followReferrals",
         "objectClass:organizationalUnit",
         "ou=Users,dc=example,dc=com");
  }



  /**
   * Tests the behavior when targeting a referral entry when using the
   * manageDsaIT request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralWithManageDsaIT()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://localhost:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");

    ldapCompare(ResultCode.COMPARE_FALSE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--manageDsaIT",
         "--useCompareResultCodeAsExitCode",
         "objectClass:organizationalUnit",
         "ou=Users,dc=example,dc=com");
  }



  /**
   * Tests the behavior when using the assertion request control and the filter
   * matches the target entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertionControlSatisfied()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--useCompareResultCodeAsExitCode",
         "--assertionFilter", "(objectClass=domain)",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when using the assertion request control and the filter
   * does not match the target entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAssertionControlNotSatisfied()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.ASSERTION_FAILED, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--assertionFilter", "(objectClass=person)",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when trying to use an administrative session.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdministrativeSession()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final InMemoryDirectoryServerConfig ds2Cfg =
         new InMemoryDirectoryServerConfig(ds.getConfig());
    ds2Cfg.addExtendedOperationHandler(
         new AdministrativeSessionInMemoryExtendedOperationHandler());

    try (InMemoryDirectoryServer ds2 =  new InMemoryDirectoryServer(ds2Cfg))
    {
      ds2.startListening();
      try (LDAPConnection conn = ds2.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");
        conn.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");

        ldapCompare(ResultCode.COMPARE_TRUE, true, false,
             "--hostname", "localhost",
             "--port", String.valueOf(ds2.getListenPort()),
             "--useCompareResultCodeAsExitCode",
             "--useAdministrativeSession",
             "objectClass:top",
             "dc=example,dc=com");
      }
    }
  }



  /**
   * Tests the behavior when the attempt to connect to the server fails.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectFailure()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final int port = ds.getListenPort();

    try
    {
      ds.shutDown(true);
      ldapCompare(ResultCode.CONNECT_ERROR, false, true,
           "--hostname", "localhost",
           "--port", String.valueOf(port),
           "objectClass:top",
           "dc=example,dc=com");
    }
    finally
    {
      ds.startListening();
    }
  }



  /**
   * Tests the behavior when the authentication attempt fails.  Also, include
   * all bind controls in the request to get coverage for the code to generate
   * them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindFailure()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.INVALID_CREDENTIALS, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "wrong-password",
         "--bindControl", "1.2.3.4",
         "--authorizationIdentity",
         "--usePasswordPolicyControl",
         "--getAuthorizationEntryAttribute", "*",
         "--getAuthorizationEntryAttribute", "+",
         "--getUserResourceLimits",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when using compare controls.  Most of these are not
   * supported by the in-memory directory server, but this will at least get
   * coverage for the code that generates them.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    ldapCompare(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--compareControl", "1.2.3.4:true",
         "--proxyAs", "dn:",
         "--operationPurpose", "Testing",
         "objectClass:top",
         "dc=example,dc=com");

    ldapCompare(ResultCode.UNAVAILABLE_CRITICAL_EXTENSION, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--compareControl", "1.2.3.4:true",
         "--proxyV1As", "dc=example,dc=com",
         "--operationPurpose", "Testing",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used for a successful operation
   * when neither verbose nor terse output is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileSuccessfulNeitherTerseNorVerbose()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "--useCompareResultCodeAsExitCode",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used for a successful operation
   * when verbose output is requested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileSuccessfulVerbose()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.COMPARE_TRUE, true, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "--verbose",
         "--useCompareResultCodeAsExitCode",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used for a successful operation
   * when terse output is requested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileSuccessfulTerse()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.COMPARE_TRUE, false, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "--terse",
         "--useCompareResultCodeAsExitCode",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used for a failed operation
   * when neither verbose nor terse output is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileFailedNeitherTerseNorVerbose()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.NO_SUCH_OBJECT, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "objectClass:top",
         "ou=missing,dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used for a failed operation
   * when verbose output is requested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileFailedVerbose()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.NO_SUCH_OBJECT, false, true,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "--verbose",
         "objectClass:top",
         "ou=missing,dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used for a failed operation
   * when terse output is requested.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileFailedTerse()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.NO_SUCH_OBJECT, false, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "--terse",
         "objectClass:top",
         "ou=missing,dc=example,dc=com");
  }



  /**
   * Tests the behavior when an output file is used with --teeOutput.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputFileWithTeeOutput()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    ldapCompare(ResultCode.COMPARE_TRUE, true, false,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFile.getAbsolutePath(),
         "--outputFormat", "CSV",
         "--teeOutput",
         "--useCompareResultCodeAsExitCode",
         "objectClass:top",
         "dc=example,dc=com");
  }



  /**
   * Tests the behavior for the {@code handleUnsolicitedNotification} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnsolicitedNotification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    try (LDAPConnection conn = ds.getConnection())
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final ByteArrayOutputStream err = new ByteArrayOutputStream();

      final LDAPCompare tool = new LDAPCompare(out, err);
      tool.runTool(
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "objectClass:top",
           "ou=missing,dc=example,dc=com");
      out.reset();
      err.reset();

      tool.handleUnsolicitedNotification(conn,
           new NoticeOfDisconnectionExtendedResult(ResultCode.OTHER,
                "The connection will be closed"));

      assertEquals(out.toByteArray().length, 0);
      assertTrue(err.toByteArray().length > 0);
    }

    try (LDAPConnection conn = ds.getConnection())
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final ByteArrayOutputStream err = new ByteArrayOutputStream();

      final LDAPCompare tool = new LDAPCompare(out, err);
      tool.runTool(
           "--hostname", "localhost",
           "--port", String.valueOf(ds.getListenPort()),
           "--terse",
           "objectClass:top",
           "ou=missing,dc=example,dc=com");
      out.reset();
      err.reset();

      tool.handleUnsolicitedNotification(conn,
           new NoticeOfDisconnectionExtendedResult(ResultCode.OTHER,
                "The connection will be closed"));

      assertEquals(out.toByteArray().length, 0);
      assertEquals(err.toByteArray().length, 0);
    }
  }



  /**
   * Runs the {@code LDAPCompare} tool and verifies the result.
   *
   * @param  expectedResultCode  The result code the tool is expected to yield.
   * @param  expectStandardOut   Indicates whether the tool is expected to write
   *                             anything to standard output.
   * @param  expectStandardErr   Indicates whether the tool is expected to write
   *                             anything to standard error.
   * @param  args                The set of command-line arguments to provide
   *                             when running the tool.
   */
  private static void ldapCompare(final ResultCode expectedResultCode,
                                  final boolean expectStandardOut,
                                  final boolean expectStandardErr,
                                  final String... args)
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final LDAPCompare tool = new LDAPCompare(out, err);

    final ResultCode actualResultCode = tool.runTool(args);
    assertEquals(actualResultCode, expectedResultCode,
         formatResult("ldapcompare did not yield the expected result code",
              args, out, err, expectedResultCode, actualResultCode));

    final byte[] outBytes = out.toByteArray();
    if (expectStandardOut)
    {
      assertTrue((outBytes.length > 0),
           formatResult("ldapcompare did not yield the expected stdout",
                args, out, err, expectedResultCode, actualResultCode));
    }
    else
    {
      assertEquals(outBytes.length, 0,
           formatResult("ldapcompare yielded unexpected stdout",
                args, out, err, expectedResultCode, actualResultCode));
    }

    final byte[] errBytes = err.toByteArray();
    if (expectStandardErr)
    {
      assertTrue((errBytes.length > 0),
           formatResult("ldapcompare did not yield the expected stderr",
                args, out, err, expectedResultCode, actualResultCode));
    }
    else
    {
      assertEquals(errBytes.length, 0,
           formatResult("ldapcompare yielded unexpected stderr",
                args, out, err, expectedResultCode, actualResultCode));
    }
  }



  /**
   * Creates a string with a formatted representation of the result of
   * {@code LDAPCompare} tool processing.
   *
   * @param  message             A message providing additional context.
   * @param  args                The arguments used to run the tool.
   * @param  out                 The data written to standard output.
   * @param  err                 The data written to standard error.
   * @param  expectedResultCode  The result code that was expected.
   * @param  actualResultCode    The result code that was obtained from running
   *                             the tool.
   *
   * @return  A formatted representation of the result.
   */
  private static String formatResult(final String message,
                                     final String[] args,
                                     final ByteArrayOutputStream out,
                                     final ByteArrayOutputStream err,
                                     final ResultCode expectedResultCode,
                                     final ResultCode actualResultCode)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append(message);
    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.EOL);
    buffer.append("ldapcompare invoked with arguments:");
    buffer.append(StaticUtils.EOL);

    for (final String arg : args)
    {
      buffer.append("     ");
      buffer.append(StaticUtils.cleanExampleCommandLineArgument(arg));
      buffer.append(StaticUtils.EOL);
    }

    buffer.append(StaticUtils.EOL);
    buffer.append("Expected Result Code:  ");
    buffer.append(expectedResultCode);
    buffer.append(StaticUtils.EOL);
    buffer.append("Actual Result Code:  ");
    buffer.append(actualResultCode);
    buffer.append(StaticUtils.EOL);
    buffer.append(StaticUtils.EOL);
    buffer.append("Standard Output:");
    buffer.append(StaticUtils.EOL);

    for (final String line :
         StaticUtils.stringToLines(StaticUtils.toUTF8String(out.toByteArray())))
    {
      buffer.append("     ");
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }
    buffer.append(StaticUtils.EOL);

    buffer.append("Standard Error:");
    buffer.append(StaticUtils.EOL);

    for (final String line :
         StaticUtils.stringToLines(StaticUtils.toUTF8String(err.toByteArray())))
    {
      buffer.append("     ");
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }

    return buffer.toString();
  }



  /**
   * Reads the contents of the specified file as a set of JSON objects.
   *
   * @param  f  The file from which the JSON objects are to be read.
   *
   * @return  A map containing the JSON objects that were read, indexed by
   *          the DN of the target entry.
   *
   * @throws  Exception  If a problem is encountered while reading the file or
   *                     parsing its contents as JSON objects.
   */
  private static Map<DN,JSONObject> readJSONObjects(final File f)
          throws Exception
  {
    final Map<DN,JSONObject> m = new LinkedHashMap<>();
    try (FileInputStream inputStream = new FileInputStream(f);
         JSONObjectReader jsonObjectReader = new JSONObjectReader(inputStream))
    {
      while (true)
      {
        final JSONObject o = jsonObjectReader.readObject();
        if (o == null)
        {
          return m;
        }

        final DN dn = new DN(o.getFieldAsString("entry-dn"));
        m.put(dn, o);
      }
    }
  }
}
