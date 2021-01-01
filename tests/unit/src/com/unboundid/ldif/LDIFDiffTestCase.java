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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordFileReader;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the LDIFDiff tool.
 */
public final class LDIFDiffTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for methods that can be invoked without running the tool.
   */
  @Test()
  public void testToolMethods()
  {
    final LDIFDiff tool = new LDIFDiff(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "ldif-diff");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertFalse(tool.getToolVersion().isEmpty());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    tool.getToolCompletionMessage();

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Tests to ensure that it's possible to obtain usage information.
   */
  @Test()
  public void testUsage()
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(LDIFDiff.main(out, out, "--help"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to diff two empty files.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySourceEmptyTarget()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile();

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to diff an empty source and a non-empty
   * target.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptySourceNonEmptyTarget()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile(
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
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 3);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: People")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "uid: test.user",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password"))));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to diff a non-empty source and an empty
   * target.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptySourceEmptyTarget()
         throws Exception
  {
    final File source = createTempFile(
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
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");
    final File target = createTempFile();

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 3);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFDeleteChangeRecord(
                   "uid=test.user,ou=People,dc=example,dc=com"),
              new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com"),
              new LDIFDeleteChangeRecord("dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to diff equivalent source and target files.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquivalentSourceAndTarget()
         throws Exception
  {
    final File source = createTempFile(
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
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");
    final File target = createTempFile(
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
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to diff source and target files in which
   * they have entries in common but all of those entries have been modified.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEquivalentSourceAndTarget()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),

              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when output is sent to standard output rather than to a
   * file.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputToStandardOut()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    final List<LDIFChangeRecord> changeRecords = new ArrayList<>(10);
    try (LDIFReader reader = new
         LDIFReader(new ByteArrayInputStream(out.toByteArray())))
    {
      while (true)
      {
        final LDIFChangeRecord changeRecord = reader.readChangeRecord();
        if (changeRecord == null)
        {
          break;
        }

        changeRecords.add(changeRecord);
      }
    }

    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));
  }



  /**
   * Tests the behavior for multivalued attributes when using or not using the
   * singleValueChanges argument.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleValueChanges()
         throws Exception
  {
    // Create source and target files that differ only by the members of a
    // given group.
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups",
         "",
         "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Test Group",
         "member: uid=user.1,ou=People,dc=example,dc=com",
         "member: uid=user.2,ou=People,dc=example,dc=com",
         "member: uid=user.3,ou=People,dc=example,dc=com",
         "member: uid=user.4,ou=People,dc=example,dc=com",
         "description: source");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups",
         "",
         "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: groupOfNames",
         "cn: Test Group",
         "member: uid=user.4,ou=People,dc=example,dc=com",
         "member: uid=user.5,ou=People,dc=example,dc=com",
         "member: uid=user.6,ou=People,dc=example,dc=com",
         "member: uid=user.7,ou=People,dc=example,dc=com",
         "description: target");

    final File output = createTempFile();
    assertTrue(output.delete());


    // First, test with the default behavior, which should create a single
    // modification for the entire entry.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "delete: member",
                   "member: uid=user.1,ou=People,dc=example,dc=com",
                   "member: uid=user.2,ou=People,dc=example,dc=com",
                   "member: uid=user.3,ou=People,dc=example,dc=com",
                   "-",
                   "add: member",
                   "member: uid=user.5,ou=People,dc=example,dc=com",
                   "member: uid=user.6,ou=People,dc=example,dc=com",
                   "member: uid=user.7,ou=People,dc=example,dc=com",
                   "-",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-"))));

    assertTrue(out.size() > 0);


    // Now test with the singleValueChanges argument and verify that they are
    // now all separate modify change records.
    out.reset();
    assertTrue(output.delete());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--singleValueChanges"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "delete: member",
                   "member: uid=user.1,ou=People,dc=example,dc=com")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "delete: member",
                   "member: uid=user.2,ou=People,dc=example,dc=com")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "delete: member",
                   "member: uid=user.3,ou=People,dc=example,dc=com")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "add: member",
                   "member: uid=user.5,ou=People,dc=example,dc=com")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "add: member",
                   "member: uid=user.6,ou=People,dc=example,dc=com")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "add: member",
                   "member: uid=user.7,ou=People,dc=example,dc=com")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
                   "changetype: modify",
                   "add: description",
                   "description: target"))));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to diff source and target files in which
   * the only differences are to operational attributes with the
   * NO-USER-MODIFICATION constraint.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonSourceAndTargetDifferOnlyByEntryUUID()
         throws Exception
  {
    // Define a data set in which the base entry differs only by entryUUID, and
    // they contain different subordinate entries.
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "entryUUID: 11111111-1111-1111-1111-111111111111",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "entryUUID: 22222222-2222-2222-2222-222222222222");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "entryUUID: 33333333-3333-3333-3333-333333333333",
         "",
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "entryUUID: 44444444-4444-4444-4444-444444444444");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();


    // Invoke the ldif-diff tool with just the input and output files, so
    // operational attributes will be ignored.  This should include only a
    // delete of the People entry and an add of the Users entry, and the add
    // should not include the entryUUID attribute.
    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Users,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Users")),
              new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com")));

    assertTrue(out.size() > 0);


    // Invoke the tool again, but this time include operational attributes.  The
    // modification to entryUUID should now appear in the base entry.
    out.reset();
    assertTrue(output.delete());
    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeOperationalAttributes"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Users,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Users",
                   "entryUUID: 44444444-4444-4444-4444-444444444444")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: entryUUID",
                   "entryUUID: 11111111-1111-1111-1111-111111111111",
                   "-",
                   "add: entryUUID",
                   "entryUUID: 33333333-3333-3333-3333-333333333333")),
              new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com")));

    assertTrue(out.size() > 0);


    // Run it one more time, this time excluding operational attributes declared
    // with NO-USER-MODIFICATION.  The output from this should be the same as
    // when operational attributes were not included.
    out.reset();
    assertTrue(output.delete());
    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeOperationalAttributes",
              "--excludeNoUserModificationAttributes"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(

              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Users,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Users")),
              new LDIFDeleteChangeRecord("ou=People,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the source file is compressed and the target is
   * not.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedSource()
         throws Exception
  {
    final File source = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the target file is encrypted and the source is
   * not.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEncryptedTarget()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

    final File encPWFile = createTempFile("encryption-passphrase");
    final File target = createTempFile(false, encPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--targetEncryptionPassphraseFile", encPWFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the input files are both compressed and encrypted,
   * as well as the output.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressedAndEncryptedInputs()
         throws Exception
  {
    final File encPWFile = createTempFile("encryption-passphrase");
    final File source = createTempFile(true, encPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    final File target = createTempFile(true, encPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.exists());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Try a first attempt with the output file already there and when not
    // using the overwrite option.  This should fail.
    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--sourceEncryptionPassphraseFile", encPWFile.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--targetEncryptionPassphraseFile", encPWFile.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--compressOutput",
              "--encryptOutput",
              "--outputEncryptionPassphraseFile", encPWFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));


    // Try again with the overwrite option.
    out.reset();
    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--sourceEncryptionPassphraseFile", encPWFile.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--targetEncryptionPassphraseFile", encPWFile.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--compressOutput",
              "--encryptOutput",
              "--outputEncryptionPassphraseFile", encPWFile.getAbsolutePath(),
              "--overwriteExistingOutputLDIF"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords =
         readChangeRecords(output, encPWFile);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the output file should be encrypted but no
   * passphrase file is specified and the user should be prompted for it.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPromptForOutputEncryptionPassphrase()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    PasswordReader.setTestReaderLines(
         "encryption-passphrase",
         "encryption-passphrase");
    try
    {
      assertEquals(
           LDIFDiff.main(out, out,
                "--sourceLDIF", source.getAbsolutePath(),
                "--targetLDIF", target.getAbsolutePath(),
                "--outputLDIF", output.getAbsolutePath(),
                "--compressOutput",
                "--encryptOutput",
                "--overwriteExistingOutputLDIF"),
           ResultCode.SUCCESS,
           StaticUtils.toUTF8String(out.toByteArray()));
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    assertTrue(output.exists());

    final File encPWFile = createTempFile("encryption-passphrase");

    final List<LDIFChangeRecord> changeRecords =
         readChangeRecords(output, encPWFile);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the source file is encrypted and the source is
   * not.  The wrong password will be provided to the tool.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrongSourceEncryptionPassphrase()
         throws Exception
  {
    final File encPWFile = createTempFile("encryption-passphrase");
    final File source = createTempFile(false, encPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final File wrongPassphraseFile = createTempFile("wrong-passphrase");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--sourceEncryptionPassphraseFile",
                   wrongPassphraseFile.getAbsolutePath()),
         ResultCode.LOCAL_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the source file is encrypted and the source is
   * not.  The password file provided to the tool will have multiple lines.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiLinePassphraseFile()
         throws Exception
  {
    final File encPWFile = createTempFile("encryption-passphrase");
    final File source = createTempFile(false, encPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final File multiLinePassphraseFile = createTempFile(
         "encryption-passphrase",
         "another-line");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--sourceEncryptionPassphraseFile",
                   multiLinePassphraseFile.getAbsolutePath()),
         ResultCode.LOCAL_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the target file is encrypted and the source is
   * not.  The wrong password will be provided to the tool.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrongTargetEncryptionPassphrase()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");

    final File encPWFile = createTempFile("encryption-passphrase");
    final File target = createTempFile(false, encPWFile,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final File wrongPassphraseFile = createTempFile("wrong-passphrase");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--targetEncryptionPassphraseFile",
                   wrongPassphraseFile.getAbsolutePath()),
         ResultCode.LOCAL_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when appending to versus overwriting an existing output
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAppendVersusOverwrite()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile(
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
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    File output = createTempFile(
         "dn: dc=existing,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: existing",
         "");


    // Run the tool without the option to overwrite the existing file and
    // verify that the existing content is preserved.
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 4);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=existing,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: existing")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: People")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "uid: test.user",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password"))));

    assertTrue(out.size() > 0);


    // Recreate the original output file and run again with the option to
    // overwrite the existing file.
    output = createTempFile(
         "dn: dc=existing,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: existing",
         "");

    out.reset();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--overwriteExistingOutputLDIF"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 3);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: People")),
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: person",
                   "objectClass: organizationalPerson",
                   "objectClass: inetOrgPerson",
                   "uid: test.user",
                   "givenName: Test",
                   "sn: User",
                   "cn: Test User",
                   "userPassword: password"))));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the source LDIF file is malformed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedSourceLDIF()
         throws Exception
  {
    final File source = createTempFile(
         "This is not a valid LDIF file");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.LOCAL_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when the target LDIF file is malformed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedTargetLDIF()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    final File target = createTempFile(
         "This is not a valid LDIF file");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.LOCAL_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when specifying an alternate schema defined in a single
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleSchemaFile()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 2.5.4.0",
         "  NAME 'objectClass'",
         "  EQUALITY objectIdentifierMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.38",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.6",
         "  NAME 'objectClasses'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.37",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.5",
         "  NAME 'attributeTypes'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.3",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.4.41",
         "  NAME 'name'",
         "  EQUALITY caseIgnoreMatch",
         "  SUBSTR caseIgnoreSubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 2.5.4.3",
         "  NAME 'cn'",
         "  SUP name",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25",
         "  NAME 'dc'",
         "  EQUALITY caseIgnoreIA5Match",
         "  SUBSTR caseIgnoreIA5SubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.26",
         "  SINGLE-VALUE",
         "  X-ORIGIN 'RFC 4519' )",
         "objectClasses: ( 2.5.6.0",
         "  NAME 'top'",
         "  ABSTRACT",
         "  MUST objectClass",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 2.5.20.1",
         "  NAME 'subschema'",
         "  AUXILIARY",
         "  MAY ( objectClasses $",
         "        attributeTypes )",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13",
         "  NAME 'domain'",
         "  SUP top",
         "  STRUCTURAL",
         "  MUST dc",
         "  X-ORIGIN 'RFC 4524' )",
         "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1",
         "  NAME 'ldapSubEntry'",
         "  DESC 'LDAP Subentry class, version 1'",
         "  SUP top",
         "  STRUCTURAL",
         "  MAY ( cn )",
         "  X-ORIGIN 'draft-ietf-ldup-subentry' )");

    final File source = createTempFile(
         "dn: dc=source,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: source");
    final File target = createTempFile(
         "dn: dc=target,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--schemaPath", schemaFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 2);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=target,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: target")),
              new LDIFDeleteChangeRecord("dc=source,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when specifying an alternate schema defined in a single
   * file, but when it's specified as a directory rather than a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleSchemaFileInDirectory()
         throws Exception
  {
    final File schemaDir = createTempDir();
    final File schemaFile = new File(schemaDir, "schema.ldif");
    writeFile(schemaFile,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 2.5.4.0",
         "  NAME 'objectClass'",
         "  EQUALITY objectIdentifierMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.38",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.6",
         "  NAME 'objectClasses'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.37",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.5",
         "  NAME 'attributeTypes'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.3",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.4.41",
         "  NAME 'name'",
         "  EQUALITY caseIgnoreMatch",
         "  SUBSTR caseIgnoreSubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 2.5.4.3",
         "  NAME 'cn'",
         "  SUP name",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25",
         "  NAME 'dc'",
         "  EQUALITY caseIgnoreIA5Match",
         "  SUBSTR caseIgnoreIA5SubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.26",
         "  SINGLE-VALUE",
         "  X-ORIGIN 'RFC 4519' )",
         "objectClasses: ( 2.5.6.0",
         "  NAME 'top'",
         "  ABSTRACT",
         "  MUST objectClass",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 2.5.20.1",
         "  NAME 'subschema'",
         "  AUXILIARY",
         "  MAY ( objectClasses $",
         "        attributeTypes )",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13",
         "  NAME 'domain'",
         "  SUP top",
         "  STRUCTURAL",
         "  MUST dc",
         "  X-ORIGIN 'RFC 4524' )",
         "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1",
         "  NAME 'ldapSubEntry'",
         "  DESC 'LDAP Subentry class, version 1'",
         "  SUP top",
         "  STRUCTURAL",
         "  MAY ( cn )",
         "  X-ORIGIN 'draft-ietf-ldup-subentry' )");

    final File source = createTempFile(
         "dn: dc=source,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: source");
    final File target = createTempFile(
         "dn: dc=target,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--schemaPath", schemaDir.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 2);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=target,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: target")),
              new LDIFDeleteChangeRecord("dc=source,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when specifying an alternate schema defined in multiple
   * files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleSchemaFiles()
         throws Exception
  {
    final File attributeTypesFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 2.5.4.0",
         "  NAME 'objectClass'",
         "  EQUALITY objectIdentifierMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.38",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.6",
         "  NAME 'objectClasses'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.37",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.5",
         "  NAME 'attributeTypes'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.3",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.4.41",
         "  NAME 'name'",
         "  EQUALITY caseIgnoreMatch",
         "  SUBSTR caseIgnoreSubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 2.5.4.3",
         "  NAME 'cn'",
         "  SUP name",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25",
         "  NAME 'dc'",
         "  EQUALITY caseIgnoreIA5Match",
         "  SUBSTR caseIgnoreIA5SubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.26",
         "  SINGLE-VALUE",
         "  X-ORIGIN 'RFC 4519' )");
    final File objectClassesFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 2.5.6.0",
         "  NAME 'top'",
         "  ABSTRACT",
         "  MUST objectClass",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 2.5.20.1",
         "  NAME 'subschema'",
         "  AUXILIARY",
         "  MAY ( objectClasses $",
         "        attributeTypes )",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13",
         "  NAME 'domain'",
         "  SUP top",
         "  STRUCTURAL",
         "  MUST dc",
         "  X-ORIGIN 'RFC 4524' )",
         "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1",
         "  NAME 'ldapSubEntry'",
         "  DESC 'LDAP Subentry class, version 1'",
         "  SUP top",
         "  STRUCTURAL",
         "  MAY ( cn )",
         "  X-ORIGIN 'draft-ietf-ldup-subentry' )");

    final File source = createTempFile(
         "dn: dc=source,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: source");
    final File target = createTempFile(
         "dn: dc=target,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--schemaPath", attributeTypesFile.getAbsolutePath(),
              "--schemaPath", objectClassesFile.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 2);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=target,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: target")),
              new LDIFDeleteChangeRecord("dc=source,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when specifying an alternate schema defined in multiple
   * files in a directory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleSchemaFilesInDirectory()
         throws Exception
  {
    final File schemaDir = createTempDir();
    final File attributeTypesFile = new File(schemaDir, "attributeTypes.ldif");
    writeFile(attributeTypesFile,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 2.5.4.0",
         "  NAME 'objectClass'",
         "  EQUALITY objectIdentifierMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.38",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.6",
         "  NAME 'objectClasses'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.37",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.21.5",
         "  NAME 'attributeTypes'",
         "  EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.3",
         "  USAGE directoryOperation",
         "  X-ORIGIN 'RFC 4512' )",
         "attributeTypes: ( 2.5.4.41",
         "  NAME 'name'",
         "  EQUALITY caseIgnoreMatch",
         "  SUBSTR caseIgnoreSubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 2.5.4.3",
         "  NAME 'cn'",
         "  SUP name",
         "  X-ORIGIN 'RFC 4519' )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25",
         "  NAME 'dc'",
         "  EQUALITY caseIgnoreIA5Match",
         "  SUBSTR caseIgnoreIA5SubstringsMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.26",
         "  SINGLE-VALUE",
         "  X-ORIGIN 'RFC 4519' )");

    final File objectClassesFile = new File(schemaDir, "objectClasses.ldif");
    writeFile(objectClassesFile,
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "objectClasses: ( 2.5.6.0",
         "  NAME 'top'",
         "  ABSTRACT",
         "  MUST objectClass",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 2.5.20.1",
         "  NAME 'subschema'",
         "  AUXILIARY",
         "  MAY ( objectClasses $",
         "        attributeTypes )",
         "  X-ORIGIN 'RFC 4512' )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13",
         "  NAME 'domain'",
         "  SUP top",
         "  STRUCTURAL",
         "  MUST dc",
         "  X-ORIGIN 'RFC 4524' )",
         "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1",
         "  NAME 'ldapSubEntry'",
         "  DESC 'LDAP Subentry class, version 1'",
         "  SUP top",
         "  STRUCTURAL",
         "  MAY ( cn )",
         "  X-ORIGIN 'draft-ietf-ldup-subentry' )");

    final File source = createTempFile(
         "dn: dc=source,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: source");
    final File target = createTempFile(
         "dn: dc=target,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--schemaPath", schemaDir.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    final List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 2);

    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=target,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: target")),
              new LDIFDeleteChangeRecord("dc=source,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to use a malformed schema file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidSchemaFile()
         throws Exception
  {
    final File schemaFile = createTempFile("this is not a valid schema file");

    final File source = createTempFile(
         "dn: dc=source,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: source");
    final File target = createTempFile(
         "dn: dc=target,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--schemaPath", schemaFile.getAbsolutePath()),
         ResultCode.LOCAL_ERROR,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --changeType argument is provided.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testChangeType()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: source",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: source",
         "",
         "dn: ou=Groups,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Groups");
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "description: target",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description: target",
         "",
         "dn: ou=Applications,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Applications");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--changeType", "add",
              "--changeType", "modify",
              "--changeType", "delete"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),

              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--changeType", "add"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--changeType", "modify"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--changeType", "add",
              "--changeType", "modify",
              "--changeType", "delete"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Arrays.asList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: ou=Applications,dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: organizationalUnit",
                   "ou: Applications")),

              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFModifyChangeRecord(new ModifyRequest(
                   "dn: uid=test.user,ou=People,dc=example,dc=com",
                   "changetype: modify",
                   "delete: description",
                   "description: source",
                   "-",
                   "add: description",
                   "description: target",
                   "-")),
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--changeType", "delete"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("ou=Groups,dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --includeAttribute argument is
   * provided and an add operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeAttributeAdd()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "dc"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "dc: example"))));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "2.5.4.0", // objectClass
              "--includeAttribute", "dc",
              "--includeAttribute", "ou"), // ou isn't in the entry.
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "ou"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --includeAttribute argument is
   * provided and a modify operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeAttributeModify()
         throws Exception
  {
    final File source = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Source",
         "sn: User",
         "cn: Source User");
    final File target = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Target",
         "sn: User",
         "cn: Target User");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "givenName"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "givenName",
              "--includeAttribute", "sn"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "description"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());
  }



  /**
   * Tests the behavior for the tool when the --includeAttribute argument is
   * provided and a delete operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeAttributeDelete()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source");
    final File target = createTempFile();

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "dc"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeAttribute", "uid"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --excludeAttribute argument is
   * provided and an add operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAttributeAdd()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "dc"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "description: target"))));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "2.5.4.0", // objectClass
              "--excludeAttribute", "dc",
              "--excludeAttribute", "ou"), // ou isn't in the entry.
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "objectClass",
              "--excludeAttribute", "dc",
              "--excludeAttribute", "description"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --excludeAttribute argument is
   * provided and a modify operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAttributeModify()
         throws Exception
  {
    final File source = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Source",
         "sn: User",
         "cn: Source User");
    final File target = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Target",
         "sn: User",
         "cn: Target User");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "cn"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "givenName",
              "--excludeAttribute", "sn"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "givenName",
              "--excludeAttribute", "cn"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());
  }



  /**
   * Tests the behavior for the tool when the --excludeAttribute argument is
   * provided and a delete operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAttributeDelete()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source");
    final File target = createTempFile();

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "dc"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeAttribute", "objectClass",
              "--excludeAttribute", "dc",
              "--excludeAttribute", "description"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --includeFilter argument is
   * provided and an add operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeFilterAdd()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=domain)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=person)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=person)",
              "--includeFilter", "(objectClass=top)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --includeFilter argument is
   * provided and a modify operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeFilterModify()
         throws Exception
  {
    final File source = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Source",
         "sn: User",
         "cn: Source User");
    final File target = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Target",
         "sn: User",
         "cn: Target User");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=person)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(givenName=Source)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(givenName=Target)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=domain)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());
  }



  /**
   * Tests the behavior for the tool when the --includeFilter argument is
   * provided and a delete operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeFilterDelete()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source");
    final File target = createTempFile();

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=top)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--includeFilter", "(objectClass=person)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --excludeFilter argument is
   * provided and an add operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeFilterAdd()
         throws Exception
  {
    final File source = createTempFile();
    final File target = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: target");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=person)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFAddChangeRecord(new AddRequest(
                   "dn: dc=example,dc=com",
                   "objectClass: top",
                   "objectClass: domain",
                   "dc: example",
                   "description: target"))));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=domain)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=person)",
              "--excludeFilter", "(objectClass=top)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior for the tool when the --excludeFilter argument is
   * provided and a modify operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeFilterModify()
         throws Exception
  {
    final File source = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Source",
         "sn: User",
         "cn: Source User");
    final File target = createTempFile(
         "dn: uid=test,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Target",
         "sn: User",
         "cn: Target User");

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=person)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(givenName=Source)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(givenName=Target)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(givenName=Source)",
              "--excludeFilter", "(givenName=Target)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=groupOfNames)",
              "--excludeFilter", "(objectClass=groupOfUniqueNames)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords.size(), 1);
    assertChangeRecordContainsChanges(changeRecords.get(0),
         new Modification(ModificationType.DELETE, "givenName", "Source"),
         new Modification(ModificationType.ADD, "givenName", "Target"),
         new Modification(ModificationType.DELETE, "cn", "Source User"),
         new Modification(ModificationType.ADD, "cn", "Target User"));
  }



  /**
   * Tests the behavior for the tool when the --excludeFilter argument is
   * provided and a delete operation is to be performed.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeFilterDelete()
         throws Exception
  {
    final File source = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "description: source");
    final File target = createTempFile();

    final File output = createTempFile();
    assertTrue(output.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath()),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    List<LDIFChangeRecord> changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));

    assertTrue(out.size() > 0);


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=top)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertTrue(changeRecords.isEmpty());


    out.reset();
    assertTrue(output.delete());
    assertFalse(output.exists());

    assertEquals(
         LDIFDiff.main(out, out,
              "--sourceLDIF", source.getAbsolutePath(),
              "--targetLDIF", target.getAbsolutePath(),
              "--outputLDIF", output.getAbsolutePath(),
              "--excludeFilter", "(objectClass=person)"),
         ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));

    assertTrue(output.exists());

    changeRecords = readChangeRecords(output);
    assertNotNull(changeRecords);
    assertFalse(changeRecords.isEmpty());
    assertEquals(changeRecords,
         Collections.singletonList(
              new LDIFDeleteChangeRecord("dc=example,dc=com")));

    assertTrue(out.size() > 0);
  }



  /**
   * Reads the LDIF change records from the specified file.
   *
   * @param  ldifFile  The file from which to read the change records.  It may
   *                   optionally be compressed, but it must not be encrypted.
   *
   * @return  The list of LDIF change records that were read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<LDIFChangeRecord> readChangeRecords(final File ldifFile)
          throws Exception
  {
    return readChangeRecords(ldifFile, null);
  }



  /**
   * Reads the LDIF change records from the specified file.
   *
   * @param  ldifFile   The file from which to read the change records.  It may
   *                    optionally be compressed, and it may be encrypted if a
   *                    password file is provided.
   * @param  encPWFile  A file containing the encryption passphrase needed to
   *                    read the file.  It may be {@code null} if the file is
   *                    not encrypted.
   *
   * @return  The list of LDIF change records that were read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<LDIFChangeRecord> readChangeRecords(final File ldifFile,
                                                          final File encPWFile)
          throws Exception
  {
    InputStream inputStream = new FileInputStream(ldifFile);

    if (encPWFile != null)
    {
      final char[] pwChars = new PasswordFileReader().readPassword(encPWFile);
      inputStream = ToolUtils.getPossiblyPassphraseEncryptedInputStream(
           inputStream, Collections.singleton(pwChars), false,
           "Enter the passphrase:", "confirm the passphrase:", System.out,
           System.err).getFirst();
    }

    inputStream = ToolUtils.getPossiblyGZIPCompressedInputStream(inputStream);

    try (LDIFReader ldifReader = new LDIFReader(inputStream))
    {
      final List<LDIFChangeRecord> changeRecords = new ArrayList<>(10);
      while (true)
      {
        final LDIFChangeRecord changeRecord = ldifReader.readChangeRecord();
        if (changeRecord == null)
        {
          return changeRecords;
        }

        changeRecords.add(changeRecord);
      }
    }
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
    final File f = File.createTempFile("ldapsdk-", ".tmp");
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



  /**
   * Writes the specified lines to the given file.
   *
   * @param  file   The file to be written.
   * @param  lines  The lines to write to the file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void writeFile(final File file, final String... lines)
          throws Exception
  {
    try (PrintWriter w = new PrintWriter(file))
    {
      for (final String line : lines)
      {
        w.println(line);
      }
    }
  }



  /**
   * Ensures that the provided change record is a modify change record and that
   * it contains all of the provided changes.  Note that the expected
   * modifications do not necessarily need to be in the same order as the actual
   * modifications.
   *
   * @param  changeRecord           The change record to examine.
   * @param  expectedModifications  The set of expected modifications.
   */
  private static void assertChangeRecordContainsChanges(
                           final LDIFChangeRecord changeRecord,
                           final Modification... expectedModifications)
  {
    final LDIFModifyChangeRecord modRecord =
         (LDIFModifyChangeRecord) changeRecord;
    final Modification[] actualModifications = modRecord.getModifications();

    final Set<Modification> expectedSet =
         StaticUtils.setOf(expectedModifications);
    final Set<Modification> actualSet = StaticUtils.setOf(actualModifications);

    assertEquals(actualSet, expectedSet);
  }
}
