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
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.PassphraseEncryptedOutputStream;



/**
 * This class provides a set of test cases for the parallel-update tool.
 */
public final class ParallelUpdateTestCase
       extends LDAPSDKTestCase
{
  /**
   * An output stream to use when no output is required.
   */
  private static final OutputStream NO_OUTPUT = null;



  /**
   * Tests a number of tool methods that can be covered without invoking the
   * tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final ParallelUpdate tool = new ParallelUpdate(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "parallel-update");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsAuthentication());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertTrue(tool.supportsSASLHelp());

    assertTrue(tool.includeAlternateLongIdentifiers());

    assertTrue(tool.supportsMultipleServers());

    assertTrue(tool.supportsSSLDebugging());

    assertTrue(tool.logToolInvocationByDefault());

    tool.getToolCompletionMessage();

    assertTrue(tool.registerShutdownHook());

    tool.doShutdownHookProcessing(ResultCode.USER_CANCELED);

    final InMemoryDirectoryServer ds = getTestDS();
    try (LDAPConnection conn = ds.getConnection())
    {
      tool.handleUnsolicitedNotification(conn,
           new NoticeOfDisconnectionExtendedResult(ResultCode.SERVER_DOWN,
                null));

      tool.handleUnsolicitedNotification(conn,
           new NoticeOfDisconnectionExtendedResult(ResultCode.SERVER_DOWN,
                "This is the diagnostic message."));
    }

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Tests to ensure that it is possible to retrieve usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetToolUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(ParallelUpdate.main(out, out, "--help"), ResultCode.SUCCESS);
    assertTrue(out.size() > 0);
  }



  /**
   * Performs a test with a very basic set of operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperations()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: ou=Users",
         "deleteoldrdn: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: dc=example,dc=com",
         "changetype: delete");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);

    final ParallelUpdate parallelUpdate = new ParallelUpdate(null, null);
    assertEquals(
         parallelUpdate.runTool(
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--numThreads", "1"),
         ResultCode.SUCCESS);

    assertEquals(parallelUpdate.getTotalAttemptCount(), 6L);
    assertEquals(parallelUpdate.getInitialAttemptCount(), 6L);
    assertEquals(parallelUpdate.getRetryAttemptCount(), 0L);

    assertEquals(parallelUpdate.getTotalSuccessCount(), 6L);
    assertEquals(parallelUpdate.getInitialSuccessCount(), 6L);
    assertEquals(parallelUpdate.getRetrySuccessCount(), 0L);

    assertEquals(parallelUpdate.getRejectCount(), 0L);

    assertTrue(parallelUpdate.getTotalOpDurationMillis() > 0L);
  }



  /**
   * Tests with a rejected add operation because the parent entry does not
   * exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectedAdd()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode"),
         ResultCode.NO_SUCH_OBJECT);

    try (LDIFReader reader = new LDIFReader(rejectFile))
    {
      final LDIFChangeRecord changeRecord = reader.readChangeRecord(true);
      assertNotNull(changeRecord);

      assertTrue(changeRecord instanceof LDIFAddChangeRecord);

      assertDNsEqual(changeRecord.getDN(), "ou=People,dc=example,dc=com");

      assertNull(reader.readChangeRecord());
    }
  }



  /**
   * Tests with a rejected delete operation because the entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectedDelete()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode"),
         ResultCode.NO_SUCH_OBJECT);

    try (LDIFReader reader = new LDIFReader(rejectFile))
    {
      final LDIFChangeRecord changeRecord = reader.readChangeRecord(true);
      assertNotNull(changeRecord);

      assertTrue(changeRecord instanceof LDIFDeleteChangeRecord);

      assertDNsEqual(changeRecord.getDN(), "ou=People,dc=example,dc=com");

      assertNull(reader.readChangeRecord());
    }
  }



  /**
   * Tests with a rejected modify operation because the entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectedModify()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode"),
         ResultCode.NO_SUCH_OBJECT);

    try (LDIFReader reader = new LDIFReader(rejectFile))
    {
      final LDIFChangeRecord changeRecord = reader.readChangeRecord(true);
      assertNotNull(changeRecord);

      assertTrue(changeRecord instanceof LDIFModifyChangeRecord);

      assertDNsEqual(changeRecord.getDN(), "ou=People,dc=example,dc=com");

      assertNull(reader.readChangeRecord());
    }
  }



  /**
   * Tests with a rejected modify DN operation because the entry does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectedModifyDN()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: ou=Users",
         "deleteoldrdn: 1");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode"),
         ResultCode.NO_SUCH_OBJECT);

    try (LDIFReader reader = new LDIFReader(rejectFile))
    {
      final LDIFChangeRecord changeRecord = reader.readChangeRecord(true);
      assertNotNull(changeRecord);

      assertTrue(changeRecord instanceof LDIFModifyDNChangeRecord);

      assertDNsEqual(changeRecord.getDN(), "ou=People,dc=example,dc=com");

      assertNull(reader.readChangeRecord());
    }
  }



  /**
   * Tests with a pair of out-of-order add operations when retry is enabled.
   * The initial change should fail on the first pass, but the second should
   * succeed.  On the second pass, the retry should also succeed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutOfOrderAddsWithRetry()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode",
              "--numThreads", "1"),
         ResultCode.SUCCESS);

    assertTrue(ds.entryExists("dc=example,dc=com"));
    assertTrue(ds.entryExists("ou=People,dc=example,dc=com"));
  }



  /**
   * Tests with a pair of out-of-order add operations when retry is disabled.
   * Only one of the entries should be added.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutOfOrderAddsWithoutRetry()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode",
              "--numThreads", "1",
              "--neverRetry"),
         ResultCode.NO_SUCH_OBJECT);

    assertTrue(ds.entryExists("dc=example,dc=com"));
    assertFalse(ds.entryExists("ou=People,dc=example,dc=com"));
  }



  /**
   * Tests to ensure that the defaultAdd argument works as expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultAdd()
         throws Exception
  {
    // Create a file with an LDIF entry rather than a change record.
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File rejectFile = createTempFile();
    final File logFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);

    // Verify that the attempt to add the entry fails without defaultAdd.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode"),
         ResultCode.DECODING_ERROR);

    // Verify that the attempt to add the entry succeeds with defaultAdd.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode",
              "--defaultAdd"),
         ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when the input LDIF file contains an entry with a
   * malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedEntryDN()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: malformed",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File rejectFile = createTempFile();
    final File logFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--useFirstRejectResultCodeAsExitCode",
              "--followReferrals"),
         ResultCode.INVALID_DN_SYNTAX);
  }



  /**
   * Get test coverage for the code that creates all of the controls.  We can't
   * actually test most of these controls in the in-memory directory server, but
   * we can at least get coverage to ensure that the controls are being created.
   * But because we're not using --useFirstRejectedResultCodeAsExitCode, the
   * tool should still exit with a "success" result as long as all of the
   * arguments were acceptable, even though there were failures in the
   * attempted operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationControls()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUni",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "ds-undelete-from-dn: entryUUID=" +
              "00000000-0000-0000-0000-000000000000,dc=example,dc=com",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: ou=Users",
         "deleteoldrdn: 1");

    final File rejectFile = createTempFile();
    final File logFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);


    // Test with an initial set of controls.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--ratePerSecond", "100000",
              "--allowUndelete",
              "--softDelete",
              "--ignoreNoUserModification",
              "--nameWithEntryUUID",
              "--suppressReferentialIntegrityUpdates",
              "--useAssuredReplication",
              "--assuredReplicationLocalLevel", "none",
              "--assuredReplicationRemoteLevel", "none",
              "--assuredReplicationTimeout", "100ms",
              "--useManageDsaIT",
              "--usePermissiveModify",
              "--operationPurpose", "Testing",
              "--passwordUpdateBehavior", "is-self-change=true",
              "--passwordUpdateBehavior", "allow-pre-encoded-password=false",
              "--passwordUpdateBehavior", "skip-password-validation=true",
              "--passwordUpdateBehavior", "ignore-password-history=true",
              "--passwordUpdateBehavior", "ignore-password-history=false",
              "--passwordUpdateBehavior", "ignore-minimum-password-age=true",
              "--passwordUpdateBehavior", "password-storage-scheme=PBKDF2",
              "--passwordUpdateBehavior", "must-change-password=false",
              "--proxyAs", "u:test.user",
              "--suppressOperationalAttributeUpdates", "last-access-time",
              "--suppressOperationalAttributeUpdates", "last-login-time",
              "--suppressOperationalAttributeUpdates", "last-login-ip",
              "--suppressOperationalAttributeUpdates", "lastmod",
              "--addControl", "1.2.3.4",
              "--bindControl", "1.2.3.5",
              "--deleteControl", "1.2.3.6",
              "--modifyControl", "1.2.3.7",
              "--modifyDNControl", "1.2.3.8"),
         ResultCode.SUCCESS);


    // Test again with a second set of controls, and especially those that are
    // not compatible with the ones we provided the first time.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--hardDelete",
              "--replicationRepair",
              "--proxyV1As", "uid=test.user,ou=People,dc=example,dc=com"),
         ResultCode.SUCCESS);


    // Test with a password update behavior control that uses an unrecognized
    // property name.  Also, get coverage for some more assured replication
    // levels.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--useAssuredReplication",
              "--assuredReplicationLocalLevel", "received-any-server",
              "--assuredReplicationRemoteLevel", "received-any-remote-location",
              "--passwordUpdateBehavior", "unrecognized-name=true"),
         ResultCode.PARAM_ERROR);


    // Test with a password update behavior control that doesn't have an equal
    // sign to separate the names from the values.  Also, get coverage for some
    // more assured replication levels.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--useAssuredReplication",
              "--assuredReplicationLocalLevel", "received-any-server",
              "--assuredReplicationRemoteLevel",
                   "received-all-remote-locations",
              "--passwordUpdateBehavior", "is-self-changetrue"),
         ResultCode.PARAM_ERROR);


    // Test with a password update behavior control that uses a malformed
    // Boolean value.
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath(),
              "--useAssuredReplication",
              "--assuredReplicationLocalLevel", "processed-all-servers",
              "--assuredReplicationRemoteLevel", "processed-all-remote-servers",
              "--passwordUpdateBehavior", "is-self-change=malformed"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior when encountering malformed LDIF records, including both
   * when it is possible to continue processing and when it is not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedLDIFRecords()
         throws Exception
  {
    // Create a file with an LDIF entry rather than a change record.
    final File ldifFile = createTempFile(
         "malformed but can continue reading",
         "",
         " malformed but cannot continue because of the initial space",
         "the initial space indicates that it's a continued line, but",
         "there's nothing to continue because it's the first line of the",
         "record");

    final File rejectFile = createTempFile();
    final File logFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--logFile", logFile.getAbsolutePath()),
         ResultCode.DECODING_ERROR);
  }



  /**
   * Tests the behavior when the LDIF file is both compressed and encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedAndEncryptedLDIF()
         throws Exception
  {
    final String passphrase = "this-is-the-encryption-passphrase";
    final File passphraseFile = createTempFile(passphrase);

    final File ldifFile = createTempFile();
    try (FileOutputStream fos = new FileOutputStream(ldifFile);
         PassphraseEncryptedOutputStream peos =
              new PassphraseEncryptedOutputStream(passphrase, fos,
                   "keyIdentifier", true, true);
         GZIPOutputStream gos = new GZIPOutputStream(peos);
         PrintWriter w = new PrintWriter(gos))
    {
      w.println("dn: dc=example,dc=com");
      w.println("changetype: add");
      w.println("objectClass: top");
      w.println("objectClass: domain");
      w.println("dc: example");
    }

    final File rejectFile = createTempFile();

    final InMemoryDirectoryServer ds = getTestDS(false, false);
    assertEquals(
         ParallelUpdate.main(NO_OUTPUT, NO_OUTPUT,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--rejectFile", rejectFile.getAbsolutePath(),
              "--encryptionPassphraseFile", passphraseFile.getAbsolutePath()),
         ResultCode.SUCCESS);

    assertTrue(ds.entryExists("dc=example,dc=com"));
  }



  /**
   * Provides test coverage for the appendJustified method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendJustified()
         throws Exception
  {
    final StringBuilder buffer = new StringBuilder();
    ParallelUpdate.appendJustified(1L, buffer, false);
    assertEquals(buffer.toString(), "        1");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1L, buffer, true);
    assertEquals(buffer.toString(), "        1 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(12L, buffer, false);
    assertEquals(buffer.toString(), "       12");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(12L, buffer, true);
    assertEquals(buffer.toString(), "       12 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(123L, buffer, false);
    assertEquals(buffer.toString(), "      123");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(123L, buffer, true);
    assertEquals(buffer.toString(), "      123 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1234L, buffer, false);
    assertEquals(buffer.toString(), "     1234");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1234L, buffer, true);
    assertEquals(buffer.toString(), "     1234 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(12345L, buffer, false);
    assertEquals(buffer.toString(), "    12345");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(12345L, buffer, true);
    assertEquals(buffer.toString(), "    12345 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(123456L, buffer, false);
    assertEquals(buffer.toString(), "   123456");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(123456L, buffer, true);
    assertEquals(buffer.toString(), "   123456 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1234567L, buffer, false);
    assertEquals(buffer.toString(), "  1234567");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1234567L, buffer, true);
    assertEquals(buffer.toString(), "  1234567 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(12345678L, buffer, false);
    assertEquals(buffer.toString(), " 12345678");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(12345678L, buffer, true);
    assertEquals(buffer.toString(), " 12345678 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(123456789L, buffer, false);
    assertEquals(buffer.toString(), "123456789");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(123456789L, buffer, true);
    assertEquals(buffer.toString(), "123456789 ");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1234567890L, buffer, false);
    assertEquals(buffer.toString(), "1234567890");

    buffer.setLength(0);
    ParallelUpdate.appendJustified(1234567890L, buffer, true);
    assertEquals(buffer.toString(), "1234567890 ");
  }
}
