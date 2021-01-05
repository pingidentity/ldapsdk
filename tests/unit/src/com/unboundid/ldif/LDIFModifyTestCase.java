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
package com.unboundid.ldif;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
import com.unboundid.util.PassphraseEncryptedInputStream;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordFileReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code ldifmodify} tool.
 */
public final class LDIFModifyTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for methods that can be invoked without running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final LDIFModify tool = new LDIFModify(null, null);

    assertNotNull(tool.getToolName());
    assertFalse(tool.getToolName().isEmpty());

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertFalse(tool.getToolVersion().isEmpty());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertNull(tool.getToolCompletionMessage());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Tests to ensure that it's possible to obtain usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(LDIFSearch.main(out, out, "--help"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
  }



  /**
   * Tests to ensure that the tool works as expected for basic source and
   * changes files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperation()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3");

    final File changesLDIF = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: cn=User 2",
         "deleteOldRDN: 0",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "",
              "dn: uid=user.1,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.1",
              "givenName: User",
              "sn: 1",
              "cn: User 1",
              "description: foo",
              "",
              "dn: cn=User 2,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.2",
              "givenName: User",
              "sn: 2",
              "cn: User 2",
              "",
              "dn: uid=user.4,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.4",
              "givenName: User",
              "sn: 4",
              "cn: User 4"));


    // Make sure that the target LDIF file contains comment lines.
    for (final String line : readFileLines(targetLDIF))
    {
      if (line.startsWith("#"))
      {
        return;
      }
    }
  }



  /**
   * Tests the behavior when the source LDIF file is empty but the changes LDIF
   * file adds entries to it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFEmptyButEntriesAdded()
         throws Exception
  {
    final File sourceLDIF = createTempFile();

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when the source LDIF file is empty and the changes LDIF
   * file does not include any adds.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFEmpty()
         throws Exception
  {
    final File sourceLDIF = createTempFile();

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);
  }



  /**
   * Tests the behavior when the source LDIF file contains a malformed LDIF
   * record that we can ignore and keep reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFHasMalformedRecordCanContinue()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "malformed record",
         "",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the source LDIF file contains a malformed LDIF
   * record that prevents us from reading any more.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFHasMalformedRecordCannotContinue()
         throws Exception
  {
    // NOTE:  A line that starts with a space that doesn't follow an earlier
    // non-blank line is considered an unrecoverable problem.  It suggests
    // we're continuing the previous line, but there is no previous line to
    // continue reading.
    final File sourceLDIF = createTempFile(
         " malformed record",
         "",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertTrue(targetLDIF.exists());
    assertNotNull(readEntries(targetLDIF));
    assertTrue(readEntries(targetLDIF).isEmpty());
  }



  /**
   * Tests the behavior when the source LDIF file contains an entry with an
   * unparsable DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFHasEntryWithUnparsableDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: unparsable",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.INVALID_DN_SYNTAX);
  }



  /**
   * Tests the behavior when the source LDIF file contains an LDIF change record
   * rather than an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFHasChangeRecord()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertTrue(targetLDIF.exists());
    try (LDIFReader ldifReader = new LDIFReader(targetLDIF))
    {
      LDIFRecord record = ldifReader.readLDIFRecord();
      assertNotNull(record);
      assertTrue(record instanceof LDIFModifyChangeRecord);

      record = ldifReader.readLDIFRecord();
      assertNotNull(record);
      assertTrue(record instanceof Entry);

      record = ldifReader.readLDIFRecord();
      assertNull(record);
    }
  }



  /**
   * Tests the behavior when the source LDIF file is compressed but not
   * encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFCompressed()
         throws Exception
  {
    final File sourceLDIF = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the source LDIF file is encrypted but not
   * compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFEncrypted()
         throws Exception
  {
    final File sourceEncPWFile = createTempFile("source-encryption-passphrase");

    final File sourceLDIF = createTempFile(false, sourceEncPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--sourceEncryptionPassphraseFile", sourceEncPWFile.getAbsolutePath());

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the source LDIF file is encrypted but the wrong
   * passphrase is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFEncryptedWrongPassphrase()
         throws Exception
  {
    final File correctSourceEncPWFile =
         createTempFile("correct-source-encryption-passphrase");
    final File incorrectSourceEncPWFile =
         createTempFile("incorrect-source-encryption-passphrase");

    final File sourceLDIF = createTempFile(false, correctSourceEncPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.LOCAL_ERROR,
         "--sourceEncryptionPassphraseFile",
              incorrectSourceEncPWFile.getAbsolutePath());

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when the source LDIF file is both compressed and
   * encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSourceLDIFCompressedAndEncrypted()
         throws Exception
  {
    final File sourceEncPWFile = createTempFile("source-encryption-passphrase");

    final File sourceLDIF = createTempFile(true, sourceEncPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--sourceEncryptionPassphraseFile", sourceEncPWFile.getAbsolutePath());

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the changes LDIF file is empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFEmpty()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile();

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.PARAM_ERROR);

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when the changes LDIF file contains a malformed LDIF
   * record that we can ignore and keep reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFHasMalformedRecordCanContinue()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "malformed record",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the changes LDIF file only contains malformed
   * change records when we can keep reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFHasOnlyRecoverableMalformedEntries()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "malformed record 1",
         "",
         "malformed record 2");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when the changes LDIF file contains a malformed LDIF
   * record that we cannot ignore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFHasMalformedRecordCannotContinue()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    // NOTE:  A line that starts with a space that doesn't follow an earlier
    // non-blank line is considered an unrecoverable problem.  It suggests
    // we're continuing the previous line, but there is no previous line to
    // continue reading.
    final File changesLDIF = createTempFile(
         " malformed record",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when the changes LDIF file contains an LDIF change
   * record with an unparsable DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFHasRecordWithUnparsableDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: unparsable",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.INVALID_DN_SYNTAX);

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when the changes LDIF file contains an entry rather than
   * an LDIF change record.  That entry will just be interpreted as an add
   * change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFHasEntryRatherThanChangeRecord()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the changes LDIF file is compressed but not
   * encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFCompressed()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(true, null,
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the changes LDIF file is encrypted but not
   * compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFEncrypted()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesEncPWFile =
         createTempFile("changes-encryption-passphrase");

    final File changesLDIF = createTempFile(false, changesEncPWFile,
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--changesEncryptionPassphraseFile",
              changesEncPWFile.getAbsolutePath());

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the changes LDIF file is encrypted, but the wrong
   * passphrase is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFEncryptedWrongPassphrase()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File correctChangesEncPWFile =
         createTempFile("correct-changes-encryption-passphrase");
    final File incorrectChangesEncPWFile =
         createTempFile("incorrect-changes-encryption-passphrase");

    final File changesLDIF = createTempFile(false, correctChangesEncPWFile,
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.LOCAL_ERROR,
         "--changesEncryptionPassphraseFile",
              incorrectChangesEncPWFile.getAbsolutePath());

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when the changes LDIF file is both compressed and
   * encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangesLDIFCompressedAndEncrypted()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesEncPWFile =
         createTempFile("changes-encryption-passphrase");

    final File changesLDIF = createTempFile(true, changesEncPWFile,
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--changesEncryptionPassphraseFile",
              changesEncPWFile.getAbsolutePath());

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the target LDIF file is to be compressed but not
   * encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTargetLDIFCompressed()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--compressTarget");


    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the target LDIF file is to be encrypted but not
   * compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTargetLDIFEncrypted()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    final File targetEncPWFile = createTempFile("target-encryption-passphrase");

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--encryptTarget",
         "--targetEncryptionPassphraseFile", targetEncPWFile.getAbsolutePath());


    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"),
         targetEncPWFile);
  }



  /**
   * Tests the behavior when the target LDIF file is to be both compressed and
   * encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTargetLDIFCompressedAndEncrypted()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    final File targetEncPWFile = createTempFile("target-encryption-passphrase");

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--compressTarget",
         "--encryptTarget",
         "--targetEncryptionPassphraseFile", targetEncPWFile.getAbsolutePath());


    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"),
         targetEncPWFile);
  }



  /**
   * Tests the behavior when trying to add an entry that already exists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAlreadyExists()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to add multiple entries with the same DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMultipleEntriesWithSameDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to add an entry after a modify that targets
   * an entry with the same DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAfterModifyWithSameDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to add an entry after a modify DN would
   * rename an entry with the same new DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddAfterModifyDNWithSameNewDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to add an entry and then subsequently
   * modify it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddEntryThenModifyIt()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "description: foo",
              "description: bar"));
  }



  /**
   * Tests the behavior when trying to add an entry and then subsequently
   * delete it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddEntryThenDeleteIt()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=test,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=test,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: test"));
  }



  /**
   * Tests the behavior when trying to add an entry, then delete it, then
   * re-add it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddEntryThenDeleteThenReAdd()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when trying to add an entry, then subsequently rename
   * it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddEntryThenModifyDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.UNWILLING_TO_PERFORM);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when trying to delete an entry that has subordinates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteSubtree()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to delete an entry that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteNonexistentEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.SUCCESS, "--ignoreDeletesOfNonexistentEntries");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to delete the same entry multiple times.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryMultipleTimes()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.SUCCESS, "--ignoreDuplicateDeletes");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to delete an entry and then re-add it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteEntryThenReAddIt()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "description: bar"));
  }



  /**
   * Tests the behavior when trying to delete an entry that has previously been
   * modified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteModifiedEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to delete an entry that has previously been
   * renamed, using the old DN of that entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteRenamedEntryOldDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users"));
  }



  /**
   * Tests the behavior when trying to delete an entry that has previously been
   * renamed, using the new DN of that entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteRenamedEntryNewDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: delete");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to delete an entry and then modify it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDeletedEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to delete an entry and then rename it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameDeletedEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to modify an entry multiple times.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyEntryMultipleTimes()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: bar"));
  }



  /**
   * Tests the behavior when trying to modify an entry that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyNonexistentEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--ignoreModifiesOfNonexistentEntries");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to modify an entry that has been renamed
   * using the old DN of the entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyOfRenamedEntryOldDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users"));
  }



  /**
   * Tests the behavior when trying to rename an entry after it has been
   * modified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyThenRenameEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to rename an entry after it has been
   * modified, then modify it again after the rename.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyThenRenameThenModifyEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "description: foo",
              "description: bar"));
  }



  /**
   * Tests the behavior when trying to add an attribute value that already
   * exists when using strict mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAddExistingValueStrictMode()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ATTRIBUTE_OR_VALUE_EXISTS, "--strictModifications");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to add an attribute value that already
   * exists when explicitly using lenient mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAddExistingValueExplicitLenient()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--lenientModifications");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to add an attribute value that already
   * exists when using the default lenient mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyAddExistingValueDefaultLenient()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));
  }



  /**
   * Tests the behavior when trying to rename an entry that does not exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameNonExistentEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to rename an entry that does not exist, and
   * then modify the renamed entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameThenModifyNonExistentEntry()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
  }



  /**
   * Tests the behavior when trying to rename an entry when the new DN matches
   * the DN of an earlier add change record.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameNewDNConflictsWithAdd()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: ou=Users,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "description: bar",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "description: foo",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "description: bar"));
  }



  /**
   * Tests the behavior when trying to rename an entry multiple times using
   * the same old DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryMultipleTimesWithOldDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Persons",
         "deleteOldRDN: 1",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.NO_SUCH_OBJECT);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Persons,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Persons"));
  }



  /**
   * Tests the behavior when trying to rename an entry, and then rename it
   * again.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryMultipleTimesWithNewDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Persons",
         "deleteOldRDN: 1",
         "",
         "dn: ou=Persons,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.UNWILLING_TO_PERFORM);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Persons,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Persons"));
  }



  /**
   * Tests the behavior when trying to rename two different entries using the
   * same new DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameDifferentEntriesToSameNewDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: foo",
         "",
         "dn: ou=Persons,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Persons",
         "description: bar");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1",
         "",
         "dn: ou=Persons,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "description: foo",
              "",
              "dn: ou=Persons,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Persons",
              "description: bar"));
  }



  /**
   * Tests the behavior when trying to rename an entry when there is already a
   * modify that targets the new DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryWithPreviouslyModifiedNewDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=Users,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 1");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.ENTRY_ALREADY_EXISTS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when trying to rename an entry when providing a new
   * superior DN and not actually changing the RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryWithNewSuperiorPreserveRDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    final File changesLDIF = createTempFile(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: uid=test.user",
         "deleteOldRDN: 0",
         "newSuperior: ou=Users,dc=example,dc=com");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "",
              "dn: uid=test.user,ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: test.user",
              "givenName: Test",
              "sn: User",
              "cn: Test User"));
  }



  /**
   * Tests the behavior when trying to rename an entry when providing a new
   * superior DN while also changing the RDN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryWithNewSuperiorWithNewRDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User");

    final File changesLDIF = createTempFile(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: cn=Test User",
         "deleteOldRDN: 0",
         "newSuperior: ou=Users,dc=example,dc=com");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "",
              "dn: ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Users",
              "",
              "dn: cn=Test User,ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: test.user",
              "givenName: Test",
              "sn: User",
              "cn: Test User"));
  }



  /**
   * Tests the behavior when trying to rename an entry when providing a new RDN
   * that cannot be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryWithUnparsableNewRDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: unparsable",
         "deleteOldRDN: 0");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.INVALID_DN_SYNTAX);

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests the behavior when trying to rename an entry when providing a new
   * superior DN that cannot be parsed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameEntryWithUnparsableNewSuperiorDN()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: ou=Users",
         "deleteOldRDN: 0",
         "newSuperior: unparsable");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF,
         ResultCode.INVALID_DN_SYNTAX);

    assertFalse(targetLDIF.exists());
  }



  /**
   * Tests to ensure that the output will not have any comments if the
   * suppressComments argument is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuppressComments()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3");

    final File changesLDIF = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: cn=User 2",
         "deleteOldRDN: 0",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--suppressComments");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "",
              "dn: uid=user.1,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.1",
              "givenName: User",
              "sn: 1",
              "cn: User 1",
              "description: foo",
              "",
              "dn: cn=User 2,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.2",
              "givenName: User",
              "sn: 2",
              "cn: User 2",
              "",
              "dn: uid=user.4,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.4",
              "givenName: User",
              "sn: 4",
              "cn: User 4"));


    // Make sure that the target LDIF file does not contain any comment lines.
    for (final String line : readFileLines(targetLDIF))
    {
      if (line.startsWith("#"))
      {
        fail("Did not expect comment lines in the target file.  Target file " +
             "contents: " + StaticUtils.EOL + StaticUtils.EOL +
             StaticUtils.readFileAsString(targetLDIF, true));
      }
    }
  }



  /**
   * Tests the default behavior for an LDIF file when it contains really long
   * lines.  Since this is running without a terminal, a default maximum line
   * width of 80 characters should be used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongLinesDefaultBehavior()
         throws Exception
  {
    final StringBuilder longValue = new StringBuilder(1_000);
    for (int i=0; i < 1_000; i++)
    {
      longValue.append('x');
    }

    final File sourceLDIF = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: " + longValue);

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: " + longValue));

    for (final String line : readFileLines(targetLDIF))
    {
      if (line.length() > 80)
      {
        fail("Target LDIF file has a line that is longer than 80 " +
             "characters.  Target LDIF file contents:" + StaticUtils.EOL +
             StaticUtils.EOL + StaticUtils.readFileAsString(targetLDIF, true));
      }
    }
  }



  /**
   * Tests the behavior for an LDIF file when it contains really long lines and
   * the --doNotWrap argument is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongLinesDoNotWrap()
         throws Exception
  {
    final StringBuilder longValue = new StringBuilder(1_000);
    for (int i=0; i < 1_000; i++)
    {
      longValue.append('x');
    }

    final File sourceLDIF = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: " + longValue);

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--doNotWrap");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: " + longValue));

    int longestLineLength = 0;
    for (final String line : readFileLines(targetLDIF))
    {
      longestLineLength = Math.max(longestLineLength, line.length());
    }

    assertTrue((longestLineLength > 1_000),
         "Target LDIF file does not have the expected really long line.  The " +
              "longest line has a length of " + longestLineLength +
              "characters. Target LDIF file contents:" + StaticUtils.EOL +
              StaticUtils.EOL + StaticUtils.readFileAsString(targetLDIF, true));
  }



  /**
   * Tests the behavior for an LDIF file when it contains really long lines and
   * the --wrapColumn argument is provided to wrap at 50 columns.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLongLinesWithWrapColumn()
         throws Exception
  {
    final StringBuilder longValue = new StringBuilder(1_000);
    for (int i=0; i < 1_000; i++)
    {
      longValue.append('x');
    }

    final File sourceLDIF = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: " + longValue);

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--wrapColumn", "50");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: " + longValue));

    for (final String line : readFileLines(targetLDIF))
    {
      if (line.length() > 50)
      {
        fail("Target LDIF file has a line that is longer than 50 " +
             "characters.  Target LDIF file contents:" + StaticUtils.EOL +
             StaticUtils.EOL + StaticUtils.readFileAsString(targetLDIF, true));
      }
    }
  }



  /**
   * Tests the behavior when the source LDIF file contains an entry with illegal
   * trailing spaces when they will not be stripped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrailingSpacesNotSkipped()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com ",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.DECODING_ERROR);

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Tests the behavior when the source LDIF file contains an entry with illegal
   * trailing spaces when they will be stripped.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTrailingSpacesSkipped()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com ",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File changesLDIF = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    ldifModify(sourceLDIF, changesLDIF, targetLDIF, ResultCode.SUCCESS,
         "--stripTrailingSpaces");

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
  }



  /**
   * Test the behavior when using the constructor provided for legacy
   * compatibility support when there are no errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyCompatibilityWithoutErrors()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3");

    final File changesLDIF = createTempFile(
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newRDN: cn=User 2",
         "deleteOldRDN: 0",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    try (LDIFReader sourceReader = new LDIFReader(sourceLDIF);
         LDIFReader changesReader = new LDIFReader(changesLDIF);
         LDIFWriter targetWriter = new LDIFWriter(targetLDIF))
    {
      final List<String> errorMessages = new ArrayList<>();
      assertTrue(LDIFModify.main(sourceReader, changesReader, targetWriter,
           errorMessages));
      assertTrue(errorMessages.isEmpty());
    }

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "",
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People",
              "",
              "dn: uid=user.1,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.1",
              "givenName: User",
              "sn: 1",
              "cn: User 1",
              "description: foo",
              "",
              "dn: cn=User 2,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.2",
              "givenName: User",
              "sn: 2",
              "cn: User 2",
              "",
              "dn: uid=user.4,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: user.4",
              "givenName: User",
              "sn: 4",
              "cn: User 4"));


    // Make sure that the target LDIF file does not contain any comment lines.
    for (final String line : readFileLines(targetLDIF))
    {
      if (line.startsWith("#"))
      {
        fail("The target LDIF file contained unexpected comment line " + line);
      }
    }
  }



  /**
   * Test the behavior when using the constructor provided for legacy
   * compatibility support when there is an error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyCompatibilityWithError()
         throws Exception
  {
    final File sourceLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: foo");

    final File changesLDIF = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: bar");

    final File targetLDIF = createTempFile();
    assertTrue(targetLDIF.delete());

    try (LDIFReader sourceReader = new LDIFReader(sourceLDIF);
         LDIFReader changesReader = new LDIFReader(changesLDIF);
         LDIFWriter targetWriter = new LDIFWriter(targetLDIF))
    {
      final List<String> errorMessages = new ArrayList<>();
      assertFalse(LDIFModify.main(sourceReader, changesReader, targetWriter,
           errorMessages));
      assertFalse(errorMessages.isEmpty());
    }

    assertTrue(targetLDIF.exists());
    assertTargetLDIFEquals(targetLDIF,
         createTempFile(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example",
              "description: foo"));
  }



  /**
   * Invokes the {@code ldifmodify} tool and ensures that it completes with the
   * expected result code.
   *
   * @param  sourceLDIF           A file containing the source data.  It must
   *                              not be {@code null}.
   * @param  changesLDIF          A file containing the changes to apply.  It
   *                              must not be {@code null}.
   * @param  targetLDIF           A file to which the output should be written.
   *                              It must not be {@code null}.
   * @param  expectedResultCode   The result code that the tool is expected to
   *                              return.
   * @param  additionalArguments  An optional set of additional arguments to
   *                              provide to the tool.  It must not be
   *                              {@code null}, but may be empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void ldifModify(final File sourceLDIF, final File changesLDIF,
                                 final File targetLDIF,
                                 final ResultCode expectedResultCode,
                                 final String... additionalArguments)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final List<String> argList = new ArrayList<>(Arrays.asList(
         "--sourceLDIF", sourceLDIF.getAbsolutePath(),
         "--changesLDIF", changesLDIF.getAbsolutePath(),
         "--targetLDIF", targetLDIF.getAbsolutePath()));
    argList.addAll(Arrays.asList(additionalArguments));

    final String[] argArray = new String[argList.size()];
    argList.toArray(argArray);

    final ResultCode resultCode = LDIFModify.main(out, out, argArray);
    if (resultCode != expectedResultCode)
    {
      final StringBuilder error = new StringBuilder();
      error.append(StaticUtils.toUTF8String(out.toByteArray()));

      if (targetLDIF.exists() && (targetLDIF.length() > 0))
      {
        error.append(StaticUtils.EOL);
        error.append(StaticUtils.EOL);
        error.append("Target LDIF contents:");
        error.append(StaticUtils.EOL);

        for (final String line : StaticUtils.readFileLines(targetLDIF))
        {
          error.append("     ");
          error.append(line);
          error.append(StaticUtils.EOL);
        }
        error.append(StaticUtils.EOL);

        fail(error.toString());
      }
    }
  }



  /**
   * Ensures that the target LDIF file has the expected content.
   *
   * @param targetLDIF    A file that has the generated content.  It must not be
   *                      {@code null}.
   * @param expectedLDIF  A file that has the expected content.  It must not be
   *                      {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertTargetLDIFEquals(final File targetLDIF,
                                             final File expectedLDIF)
          throws Exception
  {
    assertTargetLDIFEquals(targetLDIF, expectedLDIF, null);
 }



  /**
   * Ensures that the target LDIF file has the expected content.
   *
   * @param targetLDIF        A file that has the generated content.  It must
   *                          not be {@code null}.
   * @param expectedLDIF      A file that has the expected content.  It must not
   *                          be {@code null}.
   * @param  targetEncPWFile  A file that contains the passphrase used to
   *                          encrypt the target LDIF file.  It may be
   *                          {@code null} if the target file is not expected
   *                          to be encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertTargetLDIFEquals(final File targetLDIF,
                                             final File expectedLDIF,
                                             final File targetEncPWFile)
          throws Exception
  {
    final SortedMap<DN,Entry> targetEntries =
         readEntries(targetLDIF, targetEncPWFile);
    final SortedMap<DN,Entry> expectedEntries = readEntries(expectedLDIF, null);

    final StringBuilder errors = new StringBuilder();

    for (final Map.Entry<DN,Entry> e : targetEntries.entrySet())
    {
      final Entry targetEntry = e.getValue();
      final Entry expectedEntry = expectedEntries.remove(e.getKey());

      if (expectedEntry == null)
      {
        appendError(errors,
             "The target LDIF file contained the following entry that was " +
                  "not in the expected LDIF file:",
             targetEntry);
        continue;
      }

      final List<Modification> mods = Entry.diff(targetEntry, expectedEntry,
           false);
      if (! mods.isEmpty())
      {
        appendError(errors,
             "Entry  '" + targetEntry.getDN() + "' was not the same between " +
                  "the target and expected LDIF files.",
             "Target entry:",
             targetEntry,
             "Expected entry:",
             expectedEntry,
             "Differences:",
             new LDIFModifyChangeRecord(targetEntry.getDN(), mods));
      }
    }

    for (final Entry expectedEntry : expectedEntries.values())
    {
      appendError(errors,
           "The expected LDIF file contained the following entry that was " +
                "not in the target LDIF file:",
           expectedEntry);
    }

    if (errors.length() > 0)
    {
      errors.append(StaticUtils.EOL);
      errors.append(StaticUtils.EOL);
      errors.append("Target LDIF contents:");
      errors.append(StaticUtils.EOL);

      for (final String line : StaticUtils.readFileLines(targetLDIF))
      {
        errors.append("     ");
        errors.append(line);
        errors.append(StaticUtils.EOL);
      }
      errors.append(StaticUtils.EOL);

      fail(errors.toString());
    }
  }



  /**
   * Reads the entries in the provided file into a map.
   *
   * @param  ldifFile  The LDIF file containing the entries to read.
   *
   * @return  A map containing the entries that were read, indexed by DN.  The
   *          map will be ordered hierarchically, so that parents will always be
   *          before children.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static SortedMap<DN,Entry> readEntries(final File ldifFile)
          throws Exception
  {
    final SortedMap<DN,Entry> entryMap = new TreeMap<>();
    try (LDIFReader reader = new LDIFReader(ldifFile))
    {
      while (true)
      {
        final Entry e = reader.readEntry();
        if (e == null)
        {
          return entryMap;
        }

        entryMap.put(e.getParsedDN(), e);
      }
    }
  }



  /**
   * Reads the entries in the provided file into a map.
   *
   * @param  ldifFile   The LDIF file containing the entries to read.
   * @param  encPWFile  A file containing the passphrase used to encrypt the
   *                    file.  It may be {@code null} if the file is not
   *                    expected to be encrypted.
   *
   * @return  A map containing the entries that were read, indexed by DN.  The
   *          map will be ordered hierarchically, so that parents will always be
   *          before children.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static SortedMap<DN,Entry> readEntries(final File ldifFile,
                                                 final File encPWFile)
          throws Exception
  {
    InputStream inputStream = new FileInputStream(ldifFile);
    try
    {
      if (encPWFile != null)
      {
        final char[] passphrase =
             new PasswordFileReader().readPassword(encPWFile);
        inputStream =
             new PassphraseEncryptedInputStream(passphrase, inputStream);
      }

      inputStream = ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);

      try (LDIFReader reader = new LDIFReader(inputStream))
      {
        final SortedMap<DN,Entry> entryMap = new TreeMap<>();
        while (true)
        {
          final Entry e = reader.readEntry();
          if (e == null)
          {
            return entryMap;
          }

          entryMap.put(e.getParsedDN(), e);
        }
      }
    }
    finally
    {
      inputStream.close();
    }
  }



  /**
   * Appends an error message to the provided buffer.
   *
   * @param  buffer             The buffer to which the message should be
   *                            appended.
   * @param  messageComponents  The components that make up the message to be
   *                            appended to the buffer.
   */
  private static void appendError(final StringBuilder buffer,
                                  final Object... messageComponents)
  {
    if (buffer.length() > 0)
    {
      buffer.append(StaticUtils.EOL);
    }
    buffer.append(StaticUtils.EOL);

    for (final Object o : messageComponents)
    {
      if (o instanceof LDIFRecord)
      {
        final LDIFRecord r = (LDIFRecord) o;
        for (final String s : r.toLDIF())
        {
          buffer.append("     ");
          buffer.append(s);
          buffer.append(StaticUtils.EOL);
        }
      }
      else
      {
        buffer.append(String.valueOf(o));
        buffer.append(StaticUtils.EOL);
      }
    }

    buffer.append(StaticUtils.EOL);
  }



  /**
   * Writes the provided lines to an optionally compressed and/or encrypted
   * output file.
   *
   * @param  compress   Indicates whether to compress the file.
   * @param  encPWFile  A file containing the passphrase to use to encrypt the
   *                    contents of the file.  It may be {@code null} if the
   *                    file should not be encrypted.
   * @param  lines      The lines to be written.
   *
   * @return  The file to which the lines were written.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File createTempFile(final boolean compress,
                                     final File encPWFile,
                                     final String... lines)
          throws Exception
  {
    File f = File.createTempFile("ldapsdk-", ".tmp");
    f.deleteOnExit();

    OutputStream outputStream = new FileOutputStream(f);
    try
    {
      if (encPWFile != null)
      {
        final char[] pwChars = new PasswordFileReader().readPassword(encPWFile);
        outputStream = new PassphraseEncryptedOutputStream(pwChars,
             outputStream);
      }

      if (compress)
      {
        outputStream = new GZIPOutputStream(outputStream);
      }

      try (PrintWriter printStream = new PrintWriter(outputStream))
      {
        for (final String line : lines)
        {
          printStream.println(line);
        }
      }
    }
    finally
    {
      outputStream.close();
    }

    return f;
  }
}
