/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the ldap-diff tool.
 */
public final class LDAPDiffTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests a set of methods that can be called without running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final LDAPDiff ldapDiff = new LDAPDiff(null, null);

    assertNotNull(ldapDiff.getToolName());
    assertEquals(ldapDiff.getToolName(), "ldap-diff");

    assertNotNull(ldapDiff.getToolDescription());

    assertNotNull(ldapDiff.getAdditionalDescriptionParagraphs());
    assertFalse(ldapDiff.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(ldapDiff.getToolVersion());

    assertNotNull(ldapDiff.getConnectionOptions());

    assertEquals(ldapDiff.getMinTrailingArguments(), 0);

    assertEquals(ldapDiff.getMaxTrailingArguments(), Integer.MAX_VALUE);

    assertNotNull(ldapDiff.getTrailingArgumentsPlaceholder());

    assertTrue(ldapDiff.includeAlternateLongIdentifiers());

    assertTrue(ldapDiff.supportsPropertiesFile());

    assertFalse(ldapDiff.logToolInvocationByDefault());

    assertNull(ldapDiff.getToolCompletionMessage());

    assertNotNull(ldapDiff.getExampleUsages());
  }



  /**
   * Tests to ensure that the tool usage information can be obtained without
   * error.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    assertEquals(LDAPDiff.main(out, err, "--help"), ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
    assertEquals(err.size(), 0);
  }



  /**
   * Tests the behavior when trying to compare the contents of two empty
   * servers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareEmptyServers()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(false, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(false, false, 0))
    {
      final File outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS);

      final List<LDIFChangeRecord> changeRecords =
           readChangeRecords(outputFile);
      assertTrue(changeRecords.isEmpty(), String.valueOf(changeRecords));
    }
  }



  /**
   * Tests the behavior when trying to compare the contents of two servers with
   * just a base entry when that entry is identical.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareServersWithJustIdenticalBaseEntries()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(true, false, 0))
    {
      final File outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--numPasses", "3");

      final List<LDIFChangeRecord> changeRecords =
           readChangeRecords(outputFile);
      assertTrue(changeRecords.isEmpty(), String.valueOf(changeRecords));
    }
  }



  /**
   * Tests the behavior when trying to compare the contents of two servers with
   * just a base entry when that entry is not identical.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareServersWithJustNonIdenticalBaseEntries()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(true, false, 0))
    {
      sourceDS.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");

      final File outputFile = runTool(sourceDS, targetDS,
           ResultCode.COMPARE_FALSE,
           "--numPasses", "3");

      final List<LDIFChangeRecord> changeRecords =
           readChangeRecords(outputFile);
      assertFalse(changeRecords.isEmpty());
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));
      assertEquals(changeRecords.get(0),
           new LDIFModifyChangeRecord(
                "dc=example,dc=com",
                new Modification(ModificationType.DELETE, "description",
                     "source"),
                new Modification(ModificationType.ADD, "description",
                     "target")));
    }
  }



  /**
   * Tests the behavior when working with data set that is large enough to make
   * use of progress information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDataSetWithProgress()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 3_000);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 3_000))
    {
      // First, test with the servers in what should be identical.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS);
      assertTrue(readChangeRecords(outputFile).isEmpty());


      // Alter the contents of the servers to introduce differences.  This
      // includes:
      // - Add an entry only on the source server (resulting in a delete)
      // - Add an entry only on the target server (resulting in an add)
      // - Modify an entry differently on each server (resulting in a modify)
      sourceDS.add(generateUserEntry("source.only",
           "ou=People,dc=example,dc=com", "Source", "Only", "password"));

      targetDS.add(generateUserEntry("target.only",
           "ou=People,dc=example,dc=com", "Target", "Only", "password"));

      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Verify that the ldap-diff tool now sees all of the appropriate
      // differences, and in the appropriate order.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE);

      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertFalse(changeRecords.isEmpty());
      assertEquals(changeRecords.size(), 3, String.valueOf(changeRecords));

      assertEquals(changeRecords.get(0),
           new LDIFDeleteChangeRecord(
                "uid=source.only,ou=People,dc=example,dc=com"));

      assertEquals(changeRecords.get(1),
           new LDIFModifyChangeRecord(new ModifyRequest(
                "dn: uid=user.1,ou=People,dc=example,dc=com",
                "changetype: modify",
                "delete: description",
                "description: source",
                "-",
                "add: description",
                "description: target")));

      assertEquals(changeRecords.get(2),
           new LDIFAddChangeRecord(generateUserEntry("target.only",
                "ou=People,dc=example,dc=com", "Target", "Only", "password")));


      // Clear the target server and make sure that a diff contains only
      // delete records, and that they are in the appropriate order.
      targetDS.clear();

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE);

      changeRecords = readChangeRecords(outputFile);
      assertFalse(changeRecords.isEmpty());
      assertEquals(changeRecords.size(), 3_003);

      for (int i=0; i < 3_003; i++)
      {
        final LDIFChangeRecord changeRecord = changeRecords.get(i);
        assertTrue(changeRecord instanceof LDIFDeleteChangeRecord);
        switch (i)
        {
          case 3_001:
            assertEquals(changeRecord.getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));
            break;

          case 3_002:
            assertEquals(changeRecord.getParsedDN(),
                 new DN("dc=example,dc=com"));
            break;

          default:
            assertEquals(changeRecord.getParsedDN().getParent(),
                 new DN("ou=People,dc=example,dc=com"));
        }
      }


      // Run the same test, but with the source and target servers flipped.
      // This should result in all adds.
      outputFile = runTool(targetDS, sourceDS, ResultCode.COMPARE_FALSE);

      changeRecords = readChangeRecords(outputFile);
      assertFalse(changeRecords.isEmpty());
      assertEquals(changeRecords.size(), 3_003);

      for (int i=0; i < 3_003; i++)
      {
        final LDIFChangeRecord changeRecord = changeRecords.get(i);
        assertTrue(changeRecord instanceof LDIFAddChangeRecord);
        switch (i)
        {
          case 0:
            assertEquals(changeRecord.getParsedDN(),
                 new DN("dc=example,dc=com"));
            break;

          case 1:
            assertEquals(changeRecord.getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));
            break;

          default:
            assertEquals(changeRecord.getParsedDN().getParent(),
                 new DN("ou=People,dc=example,dc=com"));
        }
      }
    }
  }



  /**
   * Tests the behavior when specifying various values for the baseDN argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBaseDNAndScope()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 2);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 2))
    {
      // Alter a user entry in each server.
      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Test with the default base DN (added by the runTool method) and scope.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE);
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test with the default base DN, but with non-default scopes.
      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--searchScope", "base");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--searchScope", "one");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--searchScope", "sub");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--searchScope", "subordinates");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--searchScope", "subordinate"); // Legacy name for this scope.
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test with an empty base DN, which shouldn't be allowed by the tool.
      outputFile = runTool(sourceDS, targetDS, ResultCode.PARAM_ERROR,
           "--baseDN", "");


      // Test with base DNs that don't match the server's naming context.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--baseDN", "ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--baseDN", "uid=user.1,ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--baseDN", "uid=user.2,ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--baseDN", "uid=nonexistent,ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--baseDN", "dc=nonexistent,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));


      // Test with exclude branches.
      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--excludeBranch", "ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--excludeBranch", "uid=user.1,ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--excludeBranch", "uid=user.2,ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--excludeBranch", "uid=user.1,ou=People,dc=example,dc=com",
           "--excludeBranch", "uid=user.2,ou=People,dc=example,dc=com");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));


      // Test with DN files rather than searching for DNs.
      final File emptyFile = createTempFile();
      final File onlyBaseEntryFile = createTempFile(
           "dc=example,dc=com");
      final File onlyUser1EntryFile = createTempFile(
           "uid=user.1,ou=People,dc=example,dc=com");
      final File onlyUser2EntryFile = createTempFile(
           "uid=user.2,ou=People,dc=example,dc=com");
      final File allEntriesFile = createTempFile(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=user.1,ou=People,dc=example,dc=com",
           "uid=user.2,ou=People,dc=example,dc=com");
      final File malformedDNFile = createTempFile(
           "this is not a valid DN");

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--sourceDNsFile", emptyFile.getAbsolutePath(),
           "--targetDNsFile", emptyFile.getAbsolutePath());
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--sourceDNsFile", onlyBaseEntryFile.getAbsolutePath(),
           "--targetDNsFile", onlyBaseEntryFile.getAbsolutePath());
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--sourceDNsFile", allEntriesFile.getAbsolutePath(),
           "--targetDNsFile", allEntriesFile.getAbsolutePath());
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--sourceDNsFile", onlyUser1EntryFile.getAbsolutePath(),
           "--targetDNsFile", onlyUser2EntryFile.getAbsolutePath());
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.INVALID_DN_SYNTAX,
           "--sourceDNsFile", malformedDNFile.getAbsolutePath(),
           "--targetDNsFile", malformedDNFile.getAbsolutePath());
    }
  }



  /**
   * Tests the behavior when specifying a search filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchFilter()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 2);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 2))
    {
      // Alter a user entry in each server.
      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Test with the default "(objectClass=*)" filter.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE);
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test with alternative filters that still match the target user.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--searchFilter", "(objectClass=person)");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--searchFilter", "(uid=user.1)");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test with a filter that doesn't match the entry that has changed.
      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--searchFilter", "(uid=user.2)");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));
    }
  }



  /**
   * Tests the behavior for the byteForByte argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testByteForByte()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 1);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 1))
    {
      // Alter the user entry on each server to set description values that are
      // logically equivalent but not byte-for-byte equivalent.
      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: logically equivalent");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: Logically    Equivalent");


      // Test the tool without the --byteForByte argument and verify that the
      // servers are considered in sync.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS);
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));


      // Test with the --byteForByte argument and verify that the different
      // description value is identified.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--byteForByte");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));

      assertEquals(changeRecords.get(0),
           new LDIFModifyChangeRecord(new ModifyRequest(
                "dn: uid=user.1,ou=People,dc=example,dc=com",
                "changetype: modify",
                "delete: description",
                "description: logically equivalent",
                "-",
                "add: description",
                "description: Logically    Equivalent")),
           changeRecords.get(0).toLDIFString());
    }
  }



  /**
   * Tests the behavior for the missingOnly argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingOnly()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 1);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 1))
    {
      // Alter the contents of the servers to introduce differences.  This
      // includes:
      // - Add an entry only on the source server (resulting in a delete)
      // - Add an entry only on the target server (resulting in an add)
      // - Modify an entry differently on each server (resulting in a modify)
      sourceDS.add(generateUserEntry("source.only",
           "ou=People,dc=example,dc=com", "Source", "Only", "password"));

      targetDS.add(generateUserEntry("target.only",
           "ou=People,dc=example,dc=com", "Target", "Only", "password"));

      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Test without the --missingOnly argument and verify that all three
      // differences are identified.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE);
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 3, String.valueOf(changeRecords));
      assertEquals(changeRecords.get(0).getChangeType(), ChangeType.DELETE);
      assertEquals(changeRecords.get(1).getChangeType(), ChangeType.MODIFY);
      assertEquals(changeRecords.get(2).getChangeType(), ChangeType.ADD);


      // Test with the --missingOnly argument and verify that now only two
      // differences are identified.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--missingOnly");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 2, String.valueOf(changeRecords));
      assertEquals(changeRecords.get(0).getChangeType(), ChangeType.DELETE);
      assertEquals(changeRecords.get(1).getChangeType(), ChangeType.ADD);


      // Test the --missingOnly option in conjunction with a DN file.
      final File sourceDNFile = createTempFile(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=user.1,ou=People,dc=example,dc=com",
           "uid=source.only,ou=People,dc=example,dc=com");
      final File targetDNFile = createTempFile(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=user.1,ou=People,dc=example,dc=com",
           "uid=target.only,ou=People,dc=example,dc=com");
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "--sourceDNsFile", sourceDNFile.getAbsolutePath(),
           "--targetDNsFile", targetDNFile.getAbsolutePath(),
           "--missingOnly");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 2, String.valueOf(changeRecords));
      assertEquals(changeRecords.get(0).getChangeType(), ChangeType.DELETE);
      assertEquals(changeRecords.get(1).getChangeType(), ChangeType.ADD);
    }
  }



  /**
   * Tests the behavior when specifying attributes to compare.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributesToCompare()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 2);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 2))
    {
      // Alter a user entry in each server.
      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Test without requesting any attributes.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE);
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test with requesting the "*" attribute, which means all user
      // attributes.  This should be equivalent to the default behavior.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "*");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test when only requesting the "description" attribute, which is the
      // only one that's different.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "description");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Test when only requesting "@person, which means all attributes
      // associated with the person object class.  This includes description,
      // so the difference should be identified.
      outputFile = runTool(sourceDS, targetDS, ResultCode.COMPARE_FALSE,
           "@person");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));
    }
  }



  /**
   * Tests the behavior for the case in which the tool is invoked in a manner
   * that it attempts to compare entries that do not actually exist in either
   * server.
   *
   * @throws  Exception  If an  unexpected problem occurs.
   */
  @Test()
  public void testEntryMissing()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 1);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 1))
    {
      // Make sure that the servers are in sync when running without any DN
      // files.
      File outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS);
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));


      // Create source and target DN files that each contain a different entry
      // that doesn't exist on either server.  Verify that the tool still
      // reports that the servers are in sync even when using those DN files.
      // But this will at least get coverage for the code used to report on
      // missing entries.
      final File sourceDNFile = createTempFile(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=user.1,ou=People,dc=example,dc=com",
           "uid=source.nonexistent,ou=People,dc=example,dc=com");
      final File targetDNFile = createTempFile(
           "dc=example,dc=com",
           "ou=People,dc=example,dc=com",
           "uid=user.1,ou=People,dc=example,dc=com",
           "uid=target.nonexistent,ou=People,dc=example,dc=com");

      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--sourceDNsFile", sourceDNFile.getAbsolutePath(),
           "--targetDNsFile", targetDNFile.getAbsolutePath());
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));


      // Run the same test, but this time add the --missingOnly argument.  This
      // still shouldn't change the result, but it will exercise a slightly
      // different code path for some of the processing.
      outputFile = runTool(sourceDS, targetDS, ResultCode.SUCCESS,
           "--sourceDNsFile", sourceDNFile.getAbsolutePath(),
           "--targetDNsFile", targetDNFile.getAbsolutePath(),
           "--missingOnly");
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 0, String.valueOf(changeRecords));
    }
  }



  /**
   * Tests the behavior when using legacy arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyArguments()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 2);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 2))
    {
      // Alter a user entry in each server.
      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Use legacy identifiers for arguments when possible.  Also, omit
      // credentials for the target server, which should cause the tool to use
      // the same credentials as for the source server.
      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());
      runTool(ResultCode.COMPARE_FALSE,
         "-h", "localhost",
         "-p", String.valueOf(sourceDS.getListenPort()),
         "-D", "cn=Directory Manager",
         "-w", "password",
         "-O", "localhost",
         "--targetPort", String.valueOf(targetDS.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath());
      List<LDIFChangeRecord> changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));


      // Repeat the same command, but get the source password from a file
      // rather than providing it on the command line.
      assertTrue(outputFile.delete());
      final File passwordFile = createTempFile("password");
      runTool(ResultCode.COMPARE_FALSE,
         "-h", "localhost",
         "-p", String.valueOf(sourceDS.getListenPort()),
         "-D", "cn=Directory Manager",
         "--sourceBindPasswordFile", passwordFile.getAbsolutePath(),
         "-O", "localhost",
         "--targetPort", String.valueOf(targetDS.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath());
      changeRecords = readChangeRecords(outputFile);
      assertEquals(changeRecords.size(), 1, String.valueOf(changeRecords));
    }
  }



  /**
   * Tests the behavior when failures are encountered when attempting to
   * connect or authenticate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectAndAuthenticateFailures()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(true, true, 2);
         InMemoryDirectoryServer targetDS = createTestDS(true, true, 2))
    {
      // Alter a user entry in each server.
      sourceDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: source");
      targetDS.modify(
           "dn: uid=user.1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: target");


      // Shut down the source instance and verify that we get an expected
      // error when trying to use it.
      final int sourcePort = sourceDS.getListenPort();
      final int targetPort = targetDS.getListenPort();
      sourceDS.shutDown(true);

      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());
      runTool(ResultCode.CONNECT_ERROR,
         "--sourceHostname", "localhost",
         "--sourcePort", String.valueOf(sourcePort),
         "--sourceBindDN", "cn=Directory Manager",
         "--sourceBindPassword", "password",
         "--targetHostname", "localhost",
         "--targetPort", String.valueOf(targetPort),
         "--targetBindDN", "cn=Directory Manager",
         "--targetBindPassword", "password",
         "--baseDN", "dc=example,dc=com",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath());


      // Re-start the source instance and shut down the target instance.  Verify
      // that this fails, too.
      sourceDS.startListening();
      targetDS.shutDown(true);

      runTool(ResultCode.CONNECT_ERROR,
         "--sourceHostname", "localhost",
         "--sourcePort", String.valueOf(sourcePort),
         "--sourceBindDN", "cn=Directory Manager",
         "--sourceBindPassword", "password",
         "--targetHostname", "localhost",
         "--targetPort", String.valueOf(targetPort),
         "--targetBindDN", "cn=Directory Manager",
         "--targetBindPassword", "password",
         "--baseDN", "dc=example,dc=com",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath());


      // Re-start the target instance and verify that we get a failure when
      // we provide invalid credentials for the source server.
      targetDS.startListening();

      runTool(ResultCode.INVALID_CREDENTIALS,
         "--sourceHostname", "localhost",
         "--sourcePort", String.valueOf(sourcePort),
         "--sourceBindDN", "cn=Directory Manager",
         "--sourceBindPassword", "wrong-password",
         "--targetHostname", "localhost",
         "--targetPort", String.valueOf(targetPort),
         "--targetBindDN", "cn=Directory Manager",
         "--targetBindPassword", "password",
         "--baseDN", "dc=example,dc=com",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath());


      // Verify that we also get a failure when providing invalid credentials
      // for the target server.
      targetDS.startListening();

      runTool(ResultCode.INVALID_CREDENTIALS,
         "--sourceHostname", "localhost",
         "--sourcePort", String.valueOf(sourcePort),
         "--sourceBindDN", "cn=Directory Manager",
         "--sourceBindPassword", "password",
         "--targetHostname", "localhost",
         "--targetPort", String.valueOf(targetPort),
         "--targetBindDN", "cn=Directory Manager",
         "--targetBindPassword", "wrong-password",
         "--baseDN", "dc=example,dc=com",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath());
    }
  }



  /**
   * Tests to ensure that the appropriate exit code is used when processing
   * is successful, no differences are identified, and legacy exit codes should
   * be used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyExitCodeSuccess()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(false, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(false, false, 0))
    {
      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());

      final List<String> argsList = new ArrayList<>();
      argsList.addAll(Arrays.asList(
           "--sourceHostname", "localhost",
           "--sourcePort", String.valueOf(sourceDS.getListenPort()),
           "--sourceBindDN", "cn=Directory Manager",
           "--sourceBindPassword", "password",
           "--targetHostname", "localhost",
           "--targetPort", String.valueOf(targetDS.getListenPort()),
           "--targetBindDN", "cn=Directory Manager",
           "--targetBindPassword", "password",
           "--baseDN", "dc=example,dc=com",
           "--secondsBetweenPasses", "0",
           "--outputLDIF", outputFile.getAbsolutePath()));
      String[] argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.SUCCESS);

      assertTrue(outputFile.delete());
      argsList.add("--useLegacyExitCode");
      argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.SUCCESS);
    }
  }



  /**
   * Tests to ensure that the appropriate exit code is used when processing
   * is successful, differences are identified, and legacy exit codes should
   * be used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyExitCodeOutOfSync()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(false, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(false, false, 0))
    {
      sourceDS.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example",
           "description: source description");
      targetDS.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example",
           "description: target description");

      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());

      final List<String> argsList = new ArrayList<>();
      argsList.addAll(Arrays.asList(
           "--sourceHostname", "localhost",
           "--sourcePort", String.valueOf(sourceDS.getListenPort()),
           "--sourceBindDN", "cn=Directory Manager",
           "--sourceBindPassword", "password",
           "--targetHostname", "localhost",
           "--targetPort", String.valueOf(targetDS.getListenPort()),
           "--targetBindDN", "cn=Directory Manager",
           "--targetBindPassword", "password",
           "--baseDN", "dc=example,dc=com",
           "--secondsBetweenPasses", "0",
           "--outputLDIF", outputFile.getAbsolutePath()));
      String[] argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.COMPARE_FALSE);

      assertTrue(outputFile.delete());
      argsList.add("--useLegacyExitCode");
      argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.TIME_LIMIT_EXCEEDED);
    }
  }



  /**
   * Tests to ensure that the appropriate exit code is used when an argument
   * processing error occurs and legacy exit codes should be used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyExitCodeArgParsingError()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(false, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(false, false, 0))
    {
      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());

      final List<String> argsList = new ArrayList<>();
      argsList.addAll(Arrays.asList(
           "--sourceHostname", "localhost",
           "--sourcePort", String.valueOf(sourceDS.getListenPort()),
           "--sourceBindDN", "cn=Directory Manager",
           "--sourceBindPassword", "password",
           "--targetHostname", "localhost",
           "--targetPort", String.valueOf(targetDS.getListenPort()),
           "--targetBindDN", "cn=Directory Manager",
           "--targetBindPassword", "password",
           "--baseDN", "",
           "--secondsBetweenPasses", "0",
           "--outputLDIF", outputFile.getAbsolutePath()));
      String[] argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.PARAM_ERROR);

      argsList.add("--useLegacyExitCode");
      argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.PROTOCOL_ERROR);
    }
  }



  /**
   * Tests to ensure that the appropriate exit code is used when a
   * non-argument-related error occurs during processing and legacy exit codes
   * should be used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLegacyExitCodeUnknownError()
         throws Exception
  {
    try (InMemoryDirectoryServer sourceDS = createTestDS(false, false, 0);
         InMemoryDirectoryServer targetDS = createTestDS(false, false, 0))
    {
      final File outputFile = createTempFile();
      assertTrue(outputFile.delete());

      final List<String> argsList = new ArrayList<>();
      argsList.addAll(Arrays.asList(
           "--sourceHostname", "localhost",
           "--sourcePort", String.valueOf(sourceDS.getListenPort()),
           "--sourceBindDN", "cn=Directory Manager",
           "--sourceBindPassword", "password",
           "--targetHostname", "localhost",
           "--targetPort", String.valueOf(targetDS.getListenPort()),
           "--targetBindDN", "cn=Directory Manager",
           "--targetBindPassword", "password",
           "--baseDN", "dc=example,dc=com",
           "--secondsBetweenPasses", "0",
           "--outputLDIF", outputFile.getAbsolutePath()));
      String[] argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      sourceDS.shutDown(true);
      targetDS.shutDown(true);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.CONNECT_ERROR);

      argsList.add("--useLegacyExitCode");
      argsArray = argsList.toArray(StaticUtils.NO_STRINGS);

      assertEquals(LDAPDiff.main(null, null, argsArray),
           ResultCode.OPERATIONS_ERROR);
    }
  }



  /**
   * Creates a new in-memory directory server instance with the specified
   * number of entries.
   *
   * @param  createBaseEntry  Indicates whether to create the base
   *                          "dc=example,dc=com" entry.
   * @param  createOUEntry    Indicates whether to create the
   *                          "ou=People,dc=example,dc=com" entry.
   * @param  numTestEntries   The number of test entries to create below the
   *                          "ou=People,dc=example,dc=com" entry.
   *
   * @return  The in-memory directory server instance that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static InMemoryDirectoryServer createTestDS(
               final boolean createBaseEntry,
               final boolean createOUEntry,
               final int numTestEntries)
          throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    if (createBaseEntry)
    {
      ds.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      if (createOUEntry)
      {
        ds.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

        for (int i=1; i <= numTestEntries; i++)
        {
          ds.add(generateUserEntry("user." + i, "ou=People,dc=example,dc=com",
               "User", String.valueOf(i), "userPassword"));
        }
      }
    }

    ds.startListening();
    return ds;
  }



  /**
   * Runs the ldap-diff tool to compare the contents of the specified servers.
   *
   * @param  sourceDS            The source directory server instance.
   * @param  targetDS            The target directory server instance.
   * @param  expectedResultCode  The result code that is expected when running
   *                             the tool.
   * @param  additionalArgs      An optional set of additional arguments to use
   *                             when running the instance.
   *
   * @return  The output file generated by the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File runTool(final InMemoryDirectoryServer sourceDS,
                              final InMemoryDirectoryServer targetDS,
                              final ResultCode expectedResultCode,
                              final String... additionalArgs)
          throws Exception
  {
    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final List<String> args = new ArrayList<>();
    args.addAll(Arrays.asList(
         "--sourceHostname", "localhost",
         "--sourcePort", String.valueOf(sourceDS.getListenPort()),
         "--sourceBindDN", "cn=Directory Manager",
         "--sourceBindPassword", "password",
         "--targetHostname", "localhost",
         "--targetPort", String.valueOf(targetDS.getListenPort()),
         "--targetBindDN", "cn=Directory Manager",
         "--targetBindPassword", "password",
         "--secondsBetweenPasses", "0",
         "--outputLDIF", outputFile.getAbsolutePath()));

    final List<String> additionalArgsList = Arrays.asList(additionalArgs);
    if (! additionalArgsList.contains("--baseDN"))
    {
      args.add("--baseDN");
      args.add("dc=example,dc=com");
    }

    if (! additionalArgsList.contains("--numPasses"))
    {
      args.add("--numPasses");
      args.add("1");
    }

    args.addAll(additionalArgsList);

    final String[] argsArray = args.toArray(StaticUtils.NO_STRINGS);

    runTool(expectedResultCode, argsArray);

    return outputFile;
  }



  /**
   * Runs the ldap-diff tool to compare the contents of the specified servers.
   *
   * @param  expectedResultCode  The result code that is expected when running
   *                             the tool.
   * @param  args                The exact set of arguments that should be used
   *                             when running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void runTool(final ResultCode expectedResultCode,
                              final String... args)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final LDAPDiff ldapDiff = new LDAPDiff(out, out);

    assertEquals(ldapDiff.runTool(args),
         expectedResultCode,
         "Arguments:  " + args + StaticUtils.EOL + "Output:" + StaticUtils.EOL +
         StaticUtils.toUTF8String(out.toByteArray()));

    assertNotNull(ldapDiff.getToolCompletionMessage());
  }



  /**
   * Reads the LDIF change records from the specified file.
   *
   * @param  f  The file from which to read the change records.
   *
   * @return  The change records read from the file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<LDIFChangeRecord> readChangeRecords(final File f)
          throws Exception
  {
    try (LDIFReader ldifReader = new LDIFReader(f))
    {
      final List<LDIFChangeRecord> changeRecords = new ArrayList<>();
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
}
