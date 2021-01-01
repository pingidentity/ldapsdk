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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryDirectoryServerSnapshot;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.util.Base64;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the LDAP delete command-line tool.
 */
public final class LDAPDeleteTestCase
       extends LDAPSDKTestCase
{
  /**
   * An input stream that doesn't have any data.
   */
  private static final InputStream NO_INPUT_STREAM =
       new ByteArrayInputStream(StaticUtils.NO_BYTES);



  /**
   * An output stream that doesn't go anywhere.
   */
  private static final OutputStream NO_OUTPUT_STREAM =
       NullOutputStream.getInstance();



  /**
   * The passphrase to use when encrypting data.
   */
  private static final String ENCRYPTION_PASSPHRASE =
       "ThisIsTheEncryptionPassphrase";



  // A snapshot of an in-memory directory server instance that can be used for
  // testing.
  private volatile InMemoryDirectoryServerSnapshot snapshot = null;



  /**
   * Tests the behavior when trying to obtain usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    assertEquals(
         LDAPDelete.main(NO_INPUT_STREAM, NO_OUTPUT_STREAM, NO_OUTPUT_STREAM,
              "--help"),
         ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the various tool methods that can be invoked without
   * running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final LDAPDelete ldapDelete = new LDAPDelete(null, null);

    assertNotNull(ldapDelete.getToolName());
    assertEquals(ldapDelete.getToolName(), "ldapdelete");

    assertNotNull(ldapDelete.getToolDescription());
    assertFalse(ldapDelete.getToolDescription().isEmpty());

    assertNotNull(ldapDelete.getAdditionalDescriptionParagraphs());
    assertTrue(ldapDelete.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(ldapDelete.getToolVersion());
    assertEquals(ldapDelete.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertEquals(ldapDelete.getMinTrailingArguments(), 0);
    assertEquals(ldapDelete.getMaxTrailingArguments(), Integer.MAX_VALUE);

    assertNotNull(ldapDelete.getTrailingArgumentsPlaceholder());
    assertFalse(ldapDelete.getTrailingArgumentsPlaceholder().isEmpty());

    assertTrue(ldapDelete.supportsInteractiveMode());
    assertTrue(ldapDelete.defaultsToInteractiveMode());

    assertTrue(ldapDelete.supportsPropertiesFile());

    assertTrue(ldapDelete.supportsOutputFile());

    assertTrue(ldapDelete.logToolInvocationByDefault());

    assertNotNull(ldapDelete.getExampleUsages());
    assertFalse(ldapDelete.getExampleUsages().isEmpty());
  }



  /**
   * Tests the behavior when trying to delete entries whose DNs are specified
   * using trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryDNsViaTrailingArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    // Test when trying to delete an entry with a malformed DN.
    ldapDelete(ds, ResultCode.INVALID_DN_SYNTAX,
         "malformed");


    // Test when trying to delete an entry with a malformed DN and also trying
    // to use a client-side subtree delete.
    ldapDelete(ds, ResultCode.INVALID_DN_SYNTAX,
         "--clientSideSubtreeDelete",
         "malformed");


    // Test trying to delete a single entry that exists.
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "uid=user.1,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test trying to delete a single entry that does not exist.
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "uid=user.1,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries that exist.
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "uid=user.2,ou=People,dc=example,dc=com",
         "uid=user.3,ou=People,dc=example,dc=com",
         "uid=user.4,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries when the first doesnt't exist and
    // continueOnError is not present.  The tool should abort after the failure,
    // and no entries will be deleted.
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "uid=user.4,ou=People,dc=example,dc=com",
         "uid=user.5,ou=People,dc=example,dc=com",
         "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries when the first doesnt't exist and
    // continueOnError is present.  The tool should not abort after the failure,
    // and the remaining two entries should be deleted, but the tool will still
    // exit with a non-success result code.
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--continueOnError",
         "uid=user.4,ou=People,dc=example,dc=com",
         "uid=user.5,ou=People,dc=example,dc=com",
         "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that exists.
    assertTrue(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that does not
    // exist.
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--clientSideSubtreeDelete",
         "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that exists.
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dryRun",
         "uid=user.8,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that does not exist.
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dryRun",
         "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete for the remaining entries.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--searchPageSize", "2",
         "dc=example,dc=com");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to delete entries whose DNs are specified
   * using named arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryDNsViaNamedArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    // Test trying to delete a single entry that exists.
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--entryDN", "uid=user.1,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test trying to delete a single entry that does not exist.
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--entryDN", "uid=user.1,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries that exist.
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--entryDN", "uid=user.2,ou=People,dc=example,dc=com",
         "--entryDN", "uid=user.3,ou=People,dc=example,dc=com",
         "--entryDN", "uid=user.4,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries when the first doesnt't exist and
    // continueOnError is not present.  The tool should abort after the failure,
    // and no entries will be deleted.
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--entryDN", "uid=user.4,ou=People,dc=example,dc=com",
         "--entryDN", "uid=user.5,ou=People,dc=example,dc=com",
         "--entryDN", "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries when the first doesnt't exist and
    // continueOnError is present.  The tool should not abort after the failure,
    // and the remaining two entries should be deleted, but the tool will still
    // exit with a non-success result code.
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--continueOnError",
         "--entryDN", "uid=user.4,ou=People,dc=example,dc=com",
         "--entryDN", "uid=user.5,ou=People,dc=example,dc=com",
         "--entryDN", "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that exists.
    assertTrue(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--entryDN", "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that does not
    // exist.
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--clientSideSubtreeDelete",
         "--entryDN", "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that exists.
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dryRun",
         "--entryDN", "uid=user.8,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that does not exist.
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dryRun",
         "--entryDN", "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete for the remaining entries.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--entryDN", "dc=example,dc=com");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to delete entries whose DNs are read from a
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryDNsReadFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();
    final String encryptionPassphraseFile = createFile(ENCRYPTION_PASSPHRASE);


    // Test with an empty file that is not encrypted or compressed.
    String dnFile = createFile();
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dnFile", dnFile);


    // Test with an empty file that is encrypted and compressed.
    dnFile = createFile(true, true);
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dnFile", dnFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);


    // Test with an empty file that is encrypted but not compressed.
    dnFile = createFile(true, false);
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dnFile", dnFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);


    // Test with an empty file that is compressed but not encrypted.
    dnFile = createFile(false, true);
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dnFile", dnFile);


    // Test with a file containing a malformed DN.
    dnFile = createFile(
         "malformed");
    ldapDelete(ds, ResultCode.INVALID_DN_SYNTAX,
         "--dnFile", dnFile);


    // Test with an input stream containing a line with just "dn:".
    dnFile = createFile(
         "dn:");
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--dnFile", dnFile);


    // Test with an input stream containing a line with just "dn::".
    dnFile = createFile(
         "dn:: ");
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--dnFile", dnFile);


    // Test with an input stream containing a line that starts with "dn::" but
    // is not followed by valid base64-encoded data.
    dnFile = createFile(
         "dn:: this is not valid base64");
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--dnFile", dnFile);


    // Test trying to delete a single entry that exists.  The file will not be
    // encrypted or compressed.
    dnFile = createFile(
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dnFile", dnFile);
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Re-test with the same file.
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--dnFile", dnFile);
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries that exist.  This file will be
    // encrypted and compressed.  Provide the DNs without any prefix, with a
    // "dn:" prefix not followed by any space, and with a "dn:" prefix followed
    // by a single space.
    dnFile = createFile(true, true,
         "uid=user.2,ou=People,dc=example,dc=com",
         "",
         "dn:uid=user.3,ou=People,dc=example,dc=com",
         "",
         "# This is a comment",
         "dn: uid=user.4,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dnFile", dnFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries when the first doesnt't exist and
    // continueOnError is not present.  The tool should abort after the failure,
    // and no entries will be deleted.  This file will not be encrypted or
    // compressed.
    dnFile = createFile(
         "uid=user.4,ou=People,dc=example,dc=com",
         "uid=user.5,ou=People,dc=example,dc=com",
         "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--dnFile", dnFile);
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with the same file when continueOnError is present.  The tool should
    // not abort after the failure, and the remaining two entries should be
    // deleted, but the tool will still exit with a non-success result code.
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--continueOnError",
         "--dnFile", dnFile);
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that exists.
    // The file will be compressed and encrypted, and the DN will be
    // base64-encoded.
    dnFile = createFile(true, true,
         "dn::" + Base64.encode("uid=user.7,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--dnFile", dnFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that does not
    // exist.  Use the same file as last time.
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_SUCH_OBJECT,
         "--clientSideSubtreeDelete",
         "--dnFile", dnFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that exists.
    dnFile = createFile(
         "uid=user.8,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dryRun",
         "--dnFile", dnFile);
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that does not exist.
    dnFile = createFile(
         "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--dryRun",
         "--dnFile", dnFile);
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete for the remaining entries.
    dnFile = createFile(
         "dn:: " + Base64.encode("dc=example,dc=com"));
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--dnFile", dnFile);
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to delete entries whose DNs are read from
   * standard input.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryDNsReadFromStandardInput()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();
    final String encryptionPassphraseFile = createFile(ENCRYPTION_PASSPHRASE);


    // Test with an empty input stream that is not encrypted or compressed.
    InputStream in = createInputStream();
    ldapDelete(ds, in, null, ResultCode.SUCCESS);


    // Test with an empty input stream that is encrypted and compressed.
    in = createInputStream(true, true);
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--encryptionPassphraseFile", encryptionPassphraseFile);


    // Test with an empty input stream that is encrypted but not compressed.
    in = createInputStream(true, false);
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--encryptionPassphraseFile", encryptionPassphraseFile);


    // Test with an empty input stream that is compressed but not encrypted.
    in = createInputStream(false, true);
    ldapDelete(ds, in, null, ResultCode.SUCCESS);


    // Test with an input stream containing a malformed DN.
    in = createInputStream(
         "malformed");
    ldapDelete(ds, in, null, ResultCode.INVALID_DN_SYNTAX);


    // Test with an input stream containing a line with just "dn:".
    in = createInputStream(
         "dn:");
    ldapDelete(ds, in, null, ResultCode.PARAM_ERROR);


    // Test with an input stream containing a line with just "dn::".
    in = createInputStream(
         "dn:: ");
    ldapDelete(ds, in, null, ResultCode.PARAM_ERROR);


    // Test with an input stream containing a line that starts with "dn::" but
    // is not followed by valid base64-encoded data.
    in = createInputStream(
         "dn:: this is not valid base64");
    ldapDelete(ds, in, null, ResultCode.PARAM_ERROR);


    // Test trying to delete a single entry that exists.  The input stream will
    // not be encrypted or compressed.
    in = createInputStream(
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.SUCCESS);
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Re-test with the same input.
    in = createInputStream(
         "uid=user.1,ou=People,dc=example,dc=com");
    ldapDelete(ds, in, null, ResultCode.NO_SUCH_OBJECT);
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries that exist.  This input stream
    // will be encrypted and compressed.  Provide the DNs without any prefix,
    // with a "dn:" prefix not followed by any space, and with a "dn:" prefix
    // followed by a single space.
    in = createInputStream(true, true,
         "uid=user.2,ou=People,dc=example,dc=com",
         "",
         "dn:uid=user.3,ou=People,dc=example,dc=com",
         "",
         "# This is a comment",
         "dn: uid=user.4,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--encryptionPassphraseFile", encryptionPassphraseFile);
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));


    // Test trying to delete multiple entries when the first doesnt't exist and
    // continueOnError is not present.  The tool should abort after the failure,
    // and no entries will be deleted.  This input stream will not be encrypted
    // or compressed.
    in = createInputStream(
         "uid=user.4,ou=People,dc=example,dc=com",
         "uid=user.5,ou=People,dc=example,dc=com",
         "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.NO_SUCH_OBJECT);
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with the same content when continueOnError is present.  The tool
    // should not abort after the failure, and the remaining two entries should
    // be deleted, but the tool will still exit with a non-success result code.
    in = createInputStream(
         "uid=user.4,ou=People,dc=example,dc=com",
         "uid=user.5,ou=People,dc=example,dc=com",
         "uid=user.6,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.NO_SUCH_OBJECT,
         "--continueOnError");
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that exists.
    // The input stream will be compressed and encrypted, and the DN will be
    // base64-encoded.
    in = createInputStream(true, true,
         "dn::" + Base64.encode("uid=user.7,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--encryptionPassphraseFile", encryptionPassphraseFile);
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete with a single entry that does not
    // exist.  Use the same input as last time.
    in = createInputStream(true, true,
         "dn::" + Base64.encode("uid=user.7,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.NO_SUCH_OBJECT,
         "--clientSideSubtreeDelete",
         "--encryptionPassphraseFile", encryptionPassphraseFile);
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that exists.
    in = createInputStream(
         "uid=user.8,ou=People,dc=example,dc=com");
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--dryRun");
    assertTrue(ds.entryExists("uid=user.8,ou=People,dc=example,dc=com"));


    // Test a dry run for an entry that does not exist.
    in = createInputStream(
         "uid=user.7,ou=People,dc=example,dc=com");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--dryRun");
    assertFalse(ds.entryExists("uid=user.7,ou=People,dc=example,dc=com"));


    // Test a client-side subtree delete for the remaining entries.
    in = createInputStream(
         "dn:: " + Base64.encode("dc=example,dc=com"));
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, in, null, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to delete entries that match filters
   * provided in named arguments.  Do not use simple paged results for any of
   * the searches.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntriesMatchingFiltersFromArgumentsWithoutPaging()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    // Test with a filter that matches a single entry.
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFilter", "(uid=user.1)");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test with a filter that does not match any entries.
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--deleteEntriesMatchingFilter", "(uid=user.1)");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test with a filter that matches multiple entries.
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.12,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFilter", "(uid=user.*2)");
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.12,ou=People,dc=example,dc=com"));


    // Test with multiple filters that all match entries.
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFilter", "(uid=user.3)",
         "--deleteEntriesMatchingFilter", "(uid=user.4)",
         "--deleteEntriesMatchingFilter", "(uid=user.5)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));


    // Test with multiple filters when only the last one matches anything and
    // continueOnError is not provided.  This should fail after the first error,
    // so nothing will be deleted.
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--deleteEntriesMatchingFilter", "(uid=user.3)",
         "--deleteEntriesMatchingFilter", "(uid=user.4)",
         "--deleteEntriesMatchingFilter", "(uid=user.5)",
         "--deleteEntriesMatchingFilter", "(uid=user.6)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with multiple filters when only the last one matches anything and
    // continueOnError is provided.  This should continue processing in spite of
    // the earlier errors and delete the final matching entry, but will still
    // yield a non-success exit code.
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--continueOnError",
         "--deleteEntriesMatchingFilter", "(uid=user.3)",
         "--deleteEntriesMatchingFilter", "(uid=user.4)",
         "--deleteEntriesMatchingFilter", "(uid=user.5)",
         "--deleteEntriesMatchingFilter", "(uid=user.6)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with a filter that matches everything.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--searchBaseDN", "dc=example,dc=com",
         "--deleteEntriesMatchingFilter", "(&)");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to delete entries that match filters
   * provided in named arguments.  Use simple paged results for all of the
   * searches, although it will really only have an effect for the last one.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntriesMatchingFiltersFromArgumentsWithPaging()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    // Test with a filter that matches a single entry.
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--searchPageSize", "2",
         "--deleteEntriesMatchingFilter", "(uid=user.1)");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test with a filter that does not match any entries.
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--searchPageSize", "2",
         "--deleteEntriesMatchingFilter", "(uid=user.1)");
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test with a filter that matches multiple entries.
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.12,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--searchPageSize", "2",
         "--deleteEntriesMatchingFilter", "(uid=user.*2)");
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.12,ou=People,dc=example,dc=com"));


    // Test with multiple filters that all match entries.
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--searchPageSize", "2",
         "--deleteEntriesMatchingFilter", "(uid=user.3)",
         "--deleteEntriesMatchingFilter", "(uid=user.4)",
         "--deleteEntriesMatchingFilter", "(uid=user.5)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));


    // Test with multiple filters when only the last one matches anything and
    // continueOnError is not provided.  This should fail after the first error,
    // so nothing will be deleted.
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--searchPageSize", "2",
         "--deleteEntriesMatchingFilter", "(uid=user.3)",
         "--deleteEntriesMatchingFilter", "(uid=user.4)",
         "--deleteEntriesMatchingFilter", "(uid=user.5)",
         "--deleteEntriesMatchingFilter", "(uid=user.6)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with multiple filters when only the last one matches anything and
    // continueOnError is provided.  This should continue processing in spite of
    // the earlier errors and delete the final matching entry, but will still
    // yield a non-success exit code.
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--searchPageSize", "2",
         "--continueOnError",
         "--deleteEntriesMatchingFilter", "(uid=user.3)",
         "--deleteEntriesMatchingFilter", "(uid=user.4)",
         "--deleteEntriesMatchingFilter", "(uid=user.5)",
         "--deleteEntriesMatchingFilter", "(uid=user.6)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with a filter that matches everything.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--searchBaseDN", "dc=example,dc=com",
         "--searchPageSize", "2",
         "--deleteEntriesMatchingFilter", "(&)");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to delete entries that match filters
   * provided in a file.  We've already sufficiently covered using the simple
   * paged results control, so none of these searches will use paging.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntriesMatchingFiltersFromFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();
    final String encryptionPassphraseFile = createFile(ENCRYPTION_PASSPHRASE);


    // Test with an empty file that is not encrypted or compressed.
    String filterFile = createFile();
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);


    // Test with an empty file that is encrypted and compressed.
    filterFile = createFile(true, true);
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);


    // Test with an empty file that is encrypted but not compressed.
    filterFile = createFile(true, false);
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile,
         "--encryptionPassphraseFile", encryptionPassphraseFile);


    // Test with an empty file that is compressed but not encrypted.
    filterFile = createFile(false, true);
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);


    // Test with a file containing a malformed filter.
    filterFile = createFile(
         "malformed");
    ldapDelete(ds, ResultCode.FILTER_ERROR,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);


    // Test with a filter that matches a single entry.  Do not encrypt or
    // compress this filter file.
    filterFile = createFile(
         "(uid=user.1)");
    assertTrue(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test with the same filter file.
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("uid=user.1,ou=People,dc=example,dc=com"));


    // Test with a filter that matches multiple entries.  This file will be
    // compressed and encrypted.
    filterFile = createFile(true, true,
         "(uid=user.*2)");
    assertTrue(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.12,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--encryptionPassphraseFile", encryptionPassphraseFile,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("uid=user.2,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.12,ou=People,dc=example,dc=com"));


    // Test with multiple filters that all match entries.
    filterFile = createFile(
         "(uid=user.3)",
         "(uid=user.4)",
         "(uid=user.5)");
    assertTrue(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));


    // Test with multiple filters when only the last one matches anything and
    // continueOnError is not provided.  This should fail after the first error,
    // so nothing will be deleted.
    filterFile = createFile(
         "(uid=user.3)",
         "(uid=user.4)",
         "(uid=user.5)",
         "(uid=user.6)");
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with multiple filters when only the last one matches anything and
    // continueOnError is provided.  This should continue processing in spite of
    // the earlier errors and delete the final matching entry, but will still
    // yield a non-success exit code.
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertTrue(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NO_RESULTS_RETURNED,
         "--continueOnError",
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("uid=user.3,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.4,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.5,ou=People,dc=example,dc=com"));
    assertFalse(ds.entryExists("uid=user.6,ou=People,dc=example,dc=com"));


    // Test with a filter that matches everything.
    filterFile = createFile(
         "(&)");
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFiltersFromFile", filterFile);
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests to ensure that trailing arguments are not allowed when the entries to
   * delete are identified in some other way.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisallowedTrailingArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();


    // Test with a trailing argument combined with a named DN argument.
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--entryDN", "uid=user.1,ou=People,dc=example,dc=com",
         "uid=user.2,ou=People,dc=example,dc=com");


    // Test with a trailing argument combined with a DN file argument.
    final String dnFile = createFile(
         "uid=user.1,ou=People,dc=example,dc=com");
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--dnFile", dnFile,
         "uid=user.2,ou=People,dc=example,dc=com");


    // Test with a trailing argument combined with a filter argument.
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--deleteEntriesMatchingFilter", "(uid=user.1)",
         "uid=user.2,ou=People,dc=example,dc=com");


    // Test with a trailing argument combined with a filter file argument.
    final String filterFile = createFile(
         "(uid=user.1)");
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--deleteEntriesMatchingFiltersFromFile", filterFile,
         "uid=user.2,ou=People,dc=example,dc=com");
  }



  /**
   * Tests the behavior when a rate limiter is specified and not using a subtree
   * deleter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterWithoutSubtreeDeleter()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--deleteEntriesMatchingFilter", "(&)",
         "--ratePerSecond", "1000");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when a rate limiter is specified while using a subtree
   * deleter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRateLimiterWithSubtreeDeleter()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--clientSideSubtreeDelete",
         "--ratePerSecond", "1000",
         "dc=example,dc=com");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when a reject file is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    final File rejectFile = createTempFile();
    assertTrue(rejectFile.exists());
    assertTrue(rejectFile.isFile());
    assertTrue(rejectFile.delete());
    assertFalse(rejectFile.exists());

    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.NOT_ALLOWED_ON_NONLEAF,
         "--rejectFile", rejectFile.getAbsolutePath(),
         "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));
    assertTrue(rejectFile.exists());
    assertTrue(rejectFile.isFile());
    assertTrue(rejectFile.length() > 0L);

    assertTrue(rejectFile.delete());
    assertFalse(rejectFile.exists());
    ldapDelete(ds, ResultCode.NOT_ALLOWED_ON_NONLEAF,
         "--rejectFile", rejectFile.getAbsolutePath(),
         "--entryDN", "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));
    assertTrue(rejectFile.exists());
    assertTrue(rejectFile.isFile());
    assertTrue(rejectFile.length() > 0L);

    assertTrue(rejectFile.delete());
    assertFalse(rejectFile.exists());
    ldapDelete(ds, ResultCode.NOT_ALLOWED_ON_NONLEAF,
         "--rejectFile", rejectFile.getAbsolutePath(),
         "--deleteEntriesMatchingFilter", "(dc=example)");
    assertTrue(ds.entryExists("dc=example,dc=com"));
    assertTrue(rejectFile.exists());
    assertTrue(rejectFile.isFile());
    assertTrue(rejectFile.length() > 0L);
  }



  /**
   * Tests the behavior when trying to establish a connection to a server that
   * is offline.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectToOfflineServer()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    final int dsPort = ds.getListenPort();
    ds.shutDown(true);

    try
    {
      final ResultCode resultCode =
           LDAPDelete.main(NO_INPUT_STREAM, NO_OUTPUT_STREAM, NO_OUTPUT_STREAM,
                "--hostname", "localhost",
                "--port", String.valueOf(dsPort),
                "--bindDN", "cn=Directory Manager",
                "--bindPassword", "password",
                "dc=example,dc=com");
      assertEquals(resultCode, ResultCode.CONNECT_ERROR);
    }
    finally
    {
      ds.startListening();
    }
  }



  /**
   * Tests the behavior when trying to authenticate to the server with invalid
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindWithInvalidCredentials()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    final ResultCode resultCode =
         LDAPDelete.main(NO_INPUT_STREAM, NO_OUTPUT_STREAM, NO_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--bindDN", "cn=Directory Manager",
              "--bindPassword", "invalid-password",
              "dc=example,dc=com");
    assertEquals(resultCode, ResultCode.INVALID_CREDENTIALS);
  }



  /**
   * Tests the behavior when a referral is encountered.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferralBehavior()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();
    ds.add(
         "dn: ou=Persons,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Persons",
         "ref: ldap://localhost:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");


    // First, test the behavior when trying to delete an entry that will trigger
    // a referral when referral following is disabled.
    ldapDelete(ds, ResultCode.REFERRAL,
         "uid=user.1,ou=Persons,dc=example,dc=com");


    // Next, verify that we can successfully delete the entry when the
    // followReferrals argument is provided.
    ldapDelete(ds, ResultCode.SUCCESS,
         "--followReferrals",
         "uid=user.1,ou=Persons,dc=example,dc=com");
  }



  /**
   * Tests the behavior when trying to use all of the controls supported by the
   * in-memory directory server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllSupportedControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();


    // First, try with the no operation request control.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--retryFailedOperations",
         "--serverSideSubtreeDelete",
         "--useManageDSAIT",
         "--assertionFilter", "(objectClass=top)",
         "--preReadAttribute", "*",
         "--preReadAttribute", "+",
         "--authorizationIdentity",
         "--noOperation",
         "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));


    // Next, try without the no operation request control.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.SUCCESS,
         "--retryFailedOperations",
         "--serverSideSubtreeDelete",
         "--useManageDSAIT",
         "--assertionFilter", "(objectClass=top)",
         "--preReadAttribute", "*",
         "--preReadAttribute", "+",
         "--authorizationIdentity",
         "dc=example,dc=com");
    assertFalse(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when trying to use a variety of controls that are not
   * supported by the in-memory directory server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnsupportedControlsAndExtensions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();


    // Test with the soft delete request control and proxied authorization v2.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
         "--softDelete",
         "--proxyAs", "dn:uid=user.1,ou=People,dc=example,dc=com",
         "--getBackendSetID",
         "--routeToBackendSet", "ebrp1:bsid1",
         "--routeToBackendSet", "ebrp1:bsid2",
         "--routeToBackendSet", "ebrp2:bsid3",
         "--getServerID",
         "--routeToServer", "server-id",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "processed-all-servers",
         "--assuredReplicationRemoteLevel", "processed-all-remote-servers",
         "--assuredReplicationTimeout", "1234ms",
         "--replicationRepair",
         "--suppressReferentialIntegrityUpdates",
         "--operationPurpose", "just testing",
         "--getAuthorizationEntryAttribute", "*",
         "--getAuthorizationEntryAttribute", "+",
         "--getUserResourceLimits",
         "--deleteControl", "1.2.3.4",
         "--bindControl", "5.6.7.8",
         "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));


    // Test with the hard delete request control and proxied authorization v1.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
         "--hardDelete",
         "--proxyV1As", "uid=user.1,ou=People,dc=example,dc=com",
         "--getBackendSetID",
         "--routeToBackendSet", "ebrp1:bsid1",
         "--routeToBackendSet", "ebrp1:bsid2",
         "--routeToBackendSet", "ebrp2:bsid3",
         "--getServerID",
         "--routeToServer", "server-id",
         "--useAssuredReplication",
         "--assuredReplicationLocalLevel", "processed-all-servers",
         "--assuredReplicationRemoteLevel", "processed-all-remote-servers",
         "--assuredReplicationTimeout", "1234ms",
         "--replicationRepair",
         "--suppressReferentialIntegrityUpdates",
         "--operationPurpose", "just testing",
         "--getAuthorizationEntryAttribute", "*",
         "--getAuthorizationEntryAttribute", "+",
         "--getUserResourceLimits",
         "--deleteControl", "1.2.3.4",
         "--bindControl", "5.6.7.8",
         "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));


    // Test with a malformed routeToBackendSet value.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--routeToBackendSet", "invalid-value-missing-colon",
         "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));


    // Test with different assurance levels.
    for (final String localLevel :
         Arrays.asList("none", "received-any-server", "processed-all-servers"))
    {
      for (final String remoteLevel :
        Arrays.asList("none", "received-any-remote-location",
             "received-all-remote-locations", "processed-all-remote-servers"))
      {
        assertTrue(ds.entryExists("dc=example,dc=com"));
        ldapDelete(ds, ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
             "--useAssuredReplication",
             "--assuredReplicationLocalLevel", localLevel,
             "--assuredReplicationRemoteLevel", remoteLevel,
             "dc=example,dc=com");
        assertTrue(ds.entryExists("dc=example,dc=com"));
      }
    }


    // Test with an attempt to use an administrative session.
    assertTrue(ds.entryExists("dc=example,dc=com"));
    ldapDelete(ds, ResultCode.UNWILLING_TO_PERFORM,
         "--useAdministrativeSession",
         "dc=example,dc=com");
    assertTrue(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Tests the behavior when an invalid encryption passphrase file is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidEncryptionPassphraseFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    final String invalidEncryptionPassphraseFile = createFile(
         "This",
         "is",
         "invalid",
         "because",
         "it",
         "has",
         "multiple",
         "lines.");

    final String encryptedDNFile = createFile(true, true,
         "uid=user.1,ou=People,dc=example,dc=com");

    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--dnFile", encryptedDNFile,
         "--encryptionPassphraseFile", invalidEncryptionPassphraseFile);
  }



  /**
   * Tests the behavior when an invalid character set is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidCharacterSet()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    final String encryptedDNFile = createFile(
         "uid=user.1,ou=People,dc=example,dc=com");

    ldapDelete(ds, ResultCode.PARAM_ERROR,
         "--dnFile", encryptedDNFile,
         "--characterSet", "invalid-character-set-name");
  }



  /**
   * Tests the behavior of the tool when an unsolicited notification is
   * received.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleUnsolicitedNotification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getDS();

    try (LDAPConnection conn = ds.getConnection())
    {
      final ByteArrayOutputStream out = new ByteArrayOutputStream();

      final LDAPDelete ldapDelete = new LDAPDelete(NO_INPUT_STREAM, out, out);
      ldapDelete.handleUnsolicitedNotification(conn,
           new NoticeOfDisconnectionExtendedResult(ResultCode.SERVER_DOWN,
                "The server is shutting down."));

      assertNotNull(out.toByteArray());
      assertTrue(out.toByteArray().length > 0);
    }
  }



  /**
   * Tests the behavior of the client-side subtree delete operation when it
   * cannot be processed because of a search error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideSubtreeDeleteSearchError()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setAuthenticationRequiredOperationTypes(OperationType.SEARCH);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.restoreSnapshot(snapshot);
    ds.startListening();

    final ResultCode resultCode =
         LDAPDelete.main(NO_INPUT_STREAM, NO_OUTPUT_STREAM, NO_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--clientSideSubtreeDelete",
              "dc=example,dc=com");

    ds.shutDown(true);

    assertEquals(resultCode, ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
  }



  /**
   * Tests the behavior of the client-side subtree delete operation when it
   * cannot be processed because of a delete error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClientSideSubtreeDeleteDeleteError()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setAuthenticationRequiredOperationTypes(OperationType.DELETE);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg);
    ds.restoreSnapshot(snapshot);
    ds.startListening();

    final ResultCode resultCode =
         LDAPDelete.main(NO_INPUT_STREAM, NO_OUTPUT_STREAM, NO_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--clientSideSubtreeDelete",
              "dc=example,dc=com");

    ds.shutDown(true);

    assertEquals(resultCode, ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
  }



  /**
   * Retrieves an in-memory directory server instance that can be used for
   * testing.
   *
   * @return  The in-memory directory server instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private InMemoryDirectoryServer getDS()
          throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(false, false);

    if (snapshot == null)
    {
      ds.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      ds.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");

      for (int i=1; i <= 20; i++)
      {
        ds.add(
             "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: user." + i,
             "givenName: User",
             "sn: " + i,
             "cn: User " + i,
             "userPassword: password");
      }

      snapshot = ds.createSnapshot();
    }
    else
    {
      ds.restoreSnapshot(snapshot);
    }

    return ds;
  }



  /**
   * Runs the {@code ldapdelete} tool with the provided set of arguments.
   *
   * @param  ds                  The in-memory directory server instance to use
   *                             for testing.
   * @param  expectedResultCode  The result code that is expected from the
   *                             ldapdelete tool.
   * @param  args                The command-line arguments to provide to
   *                             ldapdelete. This method will include the
   *                             hostname, port, bindDN, bindPassword, and
   *                             verbose arguments, so those don't need to be
   *                             provided by the caller.
   */
  private void ldapDelete(final InMemoryDirectoryServer ds,
                          final ResultCode expectedResultCode,
                          final String... args)
  {
    ldapDelete(ds, NO_INPUT_STREAM, null, expectedResultCode, args);
  }



  /**
   * Runs the {@code ldapdelete} tool with the provided set of arguments.
   *
   * @param  ds                  The in-memory directory server instance to use
   *                             for testing.
   * @param  in                  The input stream to use for standard input.
   * @param  out                 The output stream to use for standard output
   *                             and standard error.  If this is {@code null},
   *                             then output will be captured in a local buffer
   *                             and only displayed if there is a failure.
   * @param  expectedResultCode  The result code that is expected from the
   *                             ldapdelete tool.
   * @param  args                The command-line arguments to provide to
   *                             ldapdelete. This method will include the
   *                             hostname, port, bindDN, bindPassword, and
   *                             verbose arguments, so those don't need to be
   *                             provided by the caller.
   */
  private void ldapDelete(final InMemoryDirectoryServer ds,
                          final InputStream in, final OutputStream out,
                          final ResultCode expectedResultCode,
                          final String... args)
  {
    final List<String> argList = new ArrayList<>(20);
    argList.addAll(Arrays.asList(
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--verbose"));
    argList.addAll(Arrays.asList(args));

    final OutputStream os;
    if (out == null)
    {
      os = new ByteArrayOutputStream();
    }
    else
    {
      os = out;
    }

    final ResultCode actualResultCode = LDAPDelete.main(in, os, os,
         StaticUtils.toArray(argList, String.class));

    if (out == null)
    {
      assertEquals(actualResultCode, expectedResultCode,
           StaticUtils.toUTF8String(
                ((ByteArrayOutputStream) os).toByteArray()));
    }
    else
    {
      assertEquals(actualResultCode, expectedResultCode);
    }
  }



  /**
   * Creates a temporary file with the specified content.  The file will not be
   * encrypted or compressed.
   *
   * @param  lines  The set of lines to include in the file.
   *
   * @return  The path to the file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private String createFile(final String... lines)
          throws Exception
  {
    return createTempFile(lines).getAbsolutePath();
  }



  /**
   * Creates a temporary file with the specified content.
   *
   * @param  encrypt   Indicates whether to encrypt the file contents.
   * @param  compress  Indicates whether to compress the file contents.
   * @param  lines     The set of lines to include in the file.
   *
   * @return  The path to the file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private String createFile(final boolean encrypt, final boolean compress,
                            final String... lines)
          throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    OutputStream out = new FileOutputStream(f);

    if (encrypt)
    {
      out = new PassphraseEncryptedOutputStream(ENCRYPTION_PASSPHRASE, out,
           null, false, true);
    }

    if (compress)
    {
      out = new GZIPOutputStream(out);
    }

    final PrintWriter w = new PrintWriter(out);
    for (final String line : lines)
    {
      w.println(line);
    }

    w.close();
    out.close();

    return f.getAbsolutePath();
  }



  /**
   * Creates a byte array input stream with the specified content that may be
   * used as standard input.  The data will not be encrypted or compressed.
   *
   * @param  lines  The set of lines to include in the file.
   *
   * @return  The input stream that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private ByteArrayInputStream createInputStream(final String... lines)
          throws Exception
  {
    return createInputStream(false, false, lines);
  }



  /**
   * Creates a byte array input stream with the specified content that may be
   * used as standard input.
   *
   * @param  encrypt   Indicates whether to encrypt the file contents.
   * @param  compress  Indicates whether to compress the file contents.
   * @param  lines     The set of lines to include in the file.
   *
   * @return  The input stream that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private ByteArrayInputStream createInputStream(final boolean encrypt,
                                                 final boolean compress,
                                                 final String... lines)
          throws Exception
  {
    final ByteArrayOutputStream byteArrayOutputStream =
         new ByteArrayOutputStream();
    OutputStream out = byteArrayOutputStream;

    if (encrypt)
    {
      out = new PassphraseEncryptedOutputStream(ENCRYPTION_PASSPHRASE, out,
           null, false, true);
    }

    if (compress)
    {
      out = new GZIPOutputStream(out);
    }

    final PrintWriter w = new PrintWriter(out);
    for (final String line : lines)
    {
      w.println(line);
    }

    w.close();
    out.close();

    return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
  }
}
