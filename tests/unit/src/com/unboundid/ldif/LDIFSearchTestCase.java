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
import java.util.Collections;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.tools.ToolUtils;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.PasswordFileReader;



/**
 * This class provides a set of test cases for the LDIFSearch tool.
 */
public final class LDIFSearchTestCase
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
    final LDIFSearch tool = new LDIFSearch(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "ldifsearch");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertTrue(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertFalse(tool.getToolVersion().isEmpty());

    assertEquals(tool.getMinTrailingArguments(), 0);

    assertEquals(tool.getMaxTrailingArguments(), -1);

    assertNotNull(tool.getTrailingArgumentsPlaceholder());
    assertFalse(tool.getTrailingArgumentsPlaceholder().isEmpty());

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    tool.getToolCompletionMessage();

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
   * Tests with a minimal set of valid arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalArguments()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "(objectClass=*)"),
         ResultCode.SUCCESS);

    final List<Entry> entries = readEntries(outputFile);
    assertNotNull(entries);
    assertFalse(entries.isEmpty());
    assertEquals(entries.size(), 1);
    assertDNsEqual(entries.get(0).getDN(), "dc=example,dc=com");
  }



  /**
   * Tests the behavior when issuing a basic search with an output file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicSearchOutputFile()
         throws Exception
  {
    final File ldifFile = createTempFile(
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
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "",
         "dn: uid=user.2,ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2");

    final File outputFile = createTempFile();
    assertTrue(outputFile.exists());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--baseDN", "ou=People,dc=example,dc=com",
              "--scope", "sub",
              "(objectClass=person)",
              "uid",
              "cn"),
         ResultCode.SUCCESS);

    assertEquals(readEntries(outputFile),
         Collections.singletonList(
              new Entry(
                   "dn: uid=user.1,ou=People,dc=example,dc=com",
                   "uid: user.1",
                   "cn: User 1")));
  }



  /**
   * Tests the behavior when issuing a basic search with output going to
   * standard out.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicSearchStandardOut()
         throws Exception
  {
    final File ldifFile = createTempFile(
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
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "",
         "dn: uid=user.2,ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--baseDN", "ou=People,dc=example,dc=com",
              "--scope", "sub",
              "(objectClass=person)",
              "uid",
              "cn"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when using a more complete set of options and when using
   * a filter file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoreCompleteSearchWithFilterFile()
         throws Exception
  {
    final File inputEncryptionPassphraseFile =
         createTempFile("input-passphrase");

    final File ldifFile1 = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File ldifFile2 = createTempFile(false, inputEncryptionPassphraseFile,
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
         "cn: User 1");

    final File ldifFile3 = createTempFile(true, inputEncryptionPassphraseFile,
         "dn: ou=Users,dc=example,dc=com ", // Note the trailing space.
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "",
         "dn: uid=user.2,ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2");

    final File filterFile = createTempFile(
         "# This is a comment.  The next line is blank",
         "",
         "(objectClass=*)",
         "(objectClass=person)",
         "(uid=user.1)");

    final File outputEncryptionPassphraseFile =
         createTempFile("output-passphrase");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile1.getAbsolutePath(),
              "--ldifFile", ldifFile2.getAbsolutePath(),
              "--ldifFile", ldifFile3.getAbsolutePath(),
              "--ldifEncryptionPassphraseFile",
                   inputEncryptionPassphraseFile.getAbsolutePath(),
              "--stripTrailingSpaces",
              "--checkSchema",
              "--outputFile", outputFile.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--compressOutput",
              "--encryptOutput",
              "--outputEncryptionPassphraseFile",
                   outputEncryptionPassphraseFile.getAbsolutePath(),
              "--doNotWrap",
              "--filterFile", filterFile.getAbsolutePath(),
              "*",
              "+"),
         ResultCode.SUCCESS);

    assertFalse(outputFile.exists());

    final File outputFile1 = new File(outputFile.getAbsolutePath() + ".1");
    assertTrue(outputFile1.exists());


    final List<Entry> entries1 =
         readEntries(outputFile1, outputEncryptionPassphraseFile);
    assertNotNull(entries1);
    assertFalse(entries1.isEmpty());
    assertEquals(entries1.size(), 5);

    assertDNsEqual(entries1.get(0).getDN(), "dc=example,dc=com");
    assertTrue(entries1.get(0).hasAttribute("objectClass"));
    assertTrue(entries1.get(0).hasAttribute("dc"));

    assertDNsEqual(entries1.get(1).getDN(),  "ou=People,dc=example,dc=com");
    assertTrue(entries1.get(1).hasAttribute("objectClass"));
    assertTrue(entries1.get(1).hasAttribute("ou"));

    assertDNsEqual(entries1.get(2).getDN(),
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(entries1.get(2).hasAttribute("objectClass"));
    assertTrue(entries1.get(2).hasAttribute("uid"));

    assertDNsEqual(entries1.get(3).getDN(),  "ou=Users,dc=example,dc=com");
    assertTrue(entries1.get(3).hasAttribute("objectClass"));
    assertTrue(entries1.get(3).hasAttribute("ou"));

    assertDNsEqual(entries1.get(4).getDN(),
         "uid=user.2,ou=Users,dc=example,dc=com");
    assertTrue(entries1.get(4).hasAttribute("objectClass"));
    assertTrue(entries1.get(4).hasAttribute("uid"));


    final File outputFile2 = new File(outputFile.getAbsolutePath() + ".2");
    assertTrue(outputFile2.exists());

    final List<Entry> entries2 =
         readEntries(outputFile2, outputEncryptionPassphraseFile);
    assertNotNull(entries2);
    assertFalse(entries2.isEmpty());
    assertEquals(entries2.size(), 2);

    assertDNsEqual(entries2.get(0).getDN(),
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(entries2.get(0).hasAttribute("objectClass"));
    assertTrue(entries2.get(0).hasAttribute("uid"));

    assertDNsEqual(entries2.get(1).getDN(),
         "uid=user.2,ou=Users,dc=example,dc=com");
    assertTrue(entries2.get(1).hasAttribute("objectClass"));
    assertTrue(entries2.get(1).hasAttribute("uid"));


    final File outputFile3 = new File(outputFile.getAbsolutePath() + ".3");
    assertTrue(outputFile3.exists());

    final List<Entry> entries3 =
         readEntries(outputFile3, outputEncryptionPassphraseFile);
    assertNotNull(entries3);
    assertFalse(entries3.isEmpty());
    assertEquals(entries3.size(), 1);

    assertDNsEqual(entries3.get(0).getDN(),
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(entries3.get(0).hasAttribute("objectClass"));
    assertTrue(entries3.get(0).hasAttribute("uid"));
  }



  /**
   * Tests the behavior when using a more complete set of options and when using
   * an LDAP URL file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoreCompleteSearchWithLDAPURLFile()
         throws Exception
  {
    final File inputEncryptionPassphraseFile =
         createTempFile("input-passphrase");

    final File ldifFile1 = createTempFile(true, null,
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File ldifFile2 = createTempFile(false, inputEncryptionPassphraseFile,
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
         "cn: User 1");

    final File ldifFile3 = createTempFile(true, inputEncryptionPassphraseFile,
         "dn: ou=Users,dc=example,dc=com ", // Note the trailing space.
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Users",
         "",
         "dn: uid=user.2,ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2");

    final File ldapURLFile = createTempFile(
         "# This is a comment.  The next line is blank",
         "",
         "ldap:///dc=example,dc=com?*,+?sub?(objectClass=*)",
         "ldap:///dc=example,dc=com?*?sub?(objectClass=person)",
         "ldap:///dc=example,dc=com??sub?(uid=user.1)");

    final File outputEncryptionPassphraseFile =
         createTempFile("output-passphrase");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile1.getAbsolutePath(),
              "--ldifFile", ldifFile2.getAbsolutePath(),
              "--ldifFile", ldifFile3.getAbsolutePath(),
              "--ldifEncryptionPassphraseFile",
                   inputEncryptionPassphraseFile.getAbsolutePath(),
              "--stripTrailingSpaces",
              "--checkSchema",
              "--outputFile", outputFile.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--compressOutput",
              "--encryptOutput",
              "--outputEncryptionPassphraseFile",
                   outputEncryptionPassphraseFile.getAbsolutePath(),
              "--doNotWrap",
              "--ldapURLFile", ldapURLFile.getAbsolutePath()),
         ResultCode.SUCCESS);

    assertFalse(outputFile.exists());

    final File outputFile1 = new File(outputFile.getAbsolutePath() + ".1");
    assertTrue(outputFile1.exists());


    final List<Entry> entries1 =
         readEntries(outputFile1, outputEncryptionPassphraseFile);
    assertNotNull(entries1);
    assertFalse(entries1.isEmpty());
    assertEquals(entries1.size(), 5);

    assertDNsEqual(entries1.get(0).getDN(), "dc=example,dc=com");
    assertTrue(entries1.get(0).hasAttribute("objectClass"));
    assertTrue(entries1.get(0).hasAttribute("dc"));

    assertDNsEqual(entries1.get(1).getDN(),  "ou=People,dc=example,dc=com");
    assertTrue(entries1.get(1).hasAttribute("objectClass"));
    assertTrue(entries1.get(1).hasAttribute("ou"));

    assertDNsEqual(entries1.get(2).getDN(),
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(entries1.get(2).hasAttribute("objectClass"));
    assertTrue(entries1.get(2).hasAttribute("uid"));

    assertDNsEqual(entries1.get(3).getDN(),  "ou=Users,dc=example,dc=com");
    assertTrue(entries1.get(3).hasAttribute("objectClass"));
    assertTrue(entries1.get(3).hasAttribute("ou"));

    assertDNsEqual(entries1.get(4).getDN(),
         "uid=user.2,ou=Users,dc=example,dc=com");
    assertTrue(entries1.get(4).hasAttribute("objectClass"));
    assertTrue(entries1.get(4).hasAttribute("uid"));


    final File outputFile2 = new File(outputFile.getAbsolutePath() + ".2");
    assertTrue(outputFile2.exists());

    final List<Entry> entries2 =
         readEntries(outputFile2, outputEncryptionPassphraseFile);
    assertNotNull(entries2);
    assertFalse(entries2.isEmpty());
    assertEquals(entries2.size(), 2);

    assertDNsEqual(entries2.get(0).getDN(),
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(entries2.get(0).hasAttribute("objectClass"));
    assertTrue(entries2.get(0).hasAttribute("uid"));

    assertDNsEqual(entries2.get(1).getDN(),
         "uid=user.2,ou=Users,dc=example,dc=com");
    assertTrue(entries2.get(1).hasAttribute("objectClass"));
    assertTrue(entries2.get(1).hasAttribute("uid"));


    final File outputFile3 = new File(outputFile.getAbsolutePath() + ".3");
    assertTrue(outputFile3.exists());

    final List<Entry> entries3 =
         readEntries(outputFile3, outputEncryptionPassphraseFile);
    assertNotNull(entries3);
    assertFalse(entries3.isEmpty());
    assertEquals(entries3.size(), 1);

    assertDNsEqual(entries3.get(0).getDN(),
         "uid=user.1,ou=People,dc=example,dc=com");
    assertTrue(entries3.get(0).hasAttribute("objectClass"));
    assertTrue(entries3.get(0).hasAttribute("uid"));
  }



  /**
   * Tests to ensure that when compression is used with an existing output file,
   * the overwrite existing output file argument is required.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompressExistingOutputFileWithoutOverwrite()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File outputFile = createTempFile();
    assertTrue(outputFile.exists());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--compressOutput",
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with a filter file containing malformed filters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedFiltersFromFile()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File filterFile = createTempFile(
         "(objectClass=*)",
         "malformed",
         "(objectClass=top)");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "--filterFile", filterFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with an empty filter file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyFromFile()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File filterFile = createTempFile();

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "--filterFile", filterFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with a filter file and a first trailing argument that is also a
   * filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterFileWithTrailingFilterArgument()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File filterFile = createTempFile(
         "(objectClass=*)");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "--filterFile", filterFile.getAbsolutePath(),
              "(objectClass=person)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with an LDAP URL file containing malformed LDAP URLs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedLDAPURLsFromFile()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File ldapURLFile = createTempFile(
         "ldap:///dc=example,dc=com??sub?(objectClass=*)",
         "malformed",
         "ldap:///dc=example,dc=com??sub?(objectClass=*person)");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--ldapURLFile", ldapURLFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with an empty LDAP URL file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyLDAPURLsFromFile()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File ldapURLFile = createTempFile();

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--ldapURLFile", ldapURLFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with an LDAP URL file combined with trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPURLsFromFileWithTrailingArgs()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File ldapURLFile = createTempFile(
         "ldap:///dc=example,dc=com??sub?(objectClass=*)");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--ldapURLFile", ldapURLFile.getAbsolutePath(),
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests when attempting to search without providing any kind of filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoFilterProvided()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests with an LDAP URL file that contains multiple sets of requested
   * attributes withotuseparate output files per search.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleLDAPURLRequestedAttributesWithoutSeparateOutputFiles()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final File ldapURLFile = createTempFile(
         "ldap:///dc=example,dc=com??sub?(objectClass=*)",
         "ldap:///dc=example,dc=com?*?sub?(objectClass=top)",
         "ldap:///dc=example,dc=com?*,+?sub?(objectClass=person)");

    final File outputFile = createTempFile();
    assertTrue(outputFile.delete());

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--outputFile", outputFile.getAbsolutePath(),
              "--ldapURLFile", ldapURLFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior when trying to use a single schema file.
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

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--schemaPath", schemaFile.getAbsolutePath(),
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "(objectClass=*)"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to use multiple schema files specified
   * individually.
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

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--schemaPath", attributeTypesFile.getAbsolutePath(),
              "--schemaPath", objectClassesFile.getAbsolutePath(),
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "(objectClass=*)"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when trying to use multiple schema files specified
   * as the path to a directory.
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

    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDIFSearch.main(out, out,
              "--ldifFile", ldifFile.getAbsolutePath(),
              "--schemaPath", schemaDir.getAbsolutePath(),
              "--baseDN", "dc=example,dc=com",
              "--scope", "base",
              "(objectClass=*)"),
         ResultCode.SUCCESS);

    assertTrue(out.size() > 0);
  }



  /**
   * Tests the behavior when rejecting entries that don't conform to the
   * schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaCompliance()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: undefined",
         "dc: example",
         "undefined; foo");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = LDIFSearch.main(out, out,
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--checkSchema",
         "--baseDN", "dc=example,dc=com",
         "--scope", "base",
         "(objectClass=*)");

    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to read data from a file that contains an
   * invalid entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidEntry()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "This is not a valid LDIF entry");

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = LDIFSearch.main(out, out,
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--checkSchema",
         "--baseDN", "dc=example,dc=com",
         "--scope", "base",
         "(objectClass=*)");

    assertFalse(resultCode == ResultCode.SUCCESS);
  }



  /**
   * Reads the LDIF entries from the specified file.
   *
   * @param  ldifFile  The file from which to read the change records.  It may
   *                   optionally be compressed, but it must not be encrypted.
   *
   * @return  The list of LDIF change records that were read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static List<Entry> readEntries(final File ldifFile)
          throws Exception
  {
    return readEntries(ldifFile, null);
  }



  /**
   * Reads the LDIF entries from the specified file.
   *
   * @param  ldifFile   The file from which to read the entries.  It may
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
  private static List<Entry> readEntries(final File ldifFile,
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

    final List<Entry> entries = new ArrayList<>();
    try (LDIFReader ldifReader = new LDIFReader(inputStream))
    {
      while (true)
      {
        final Entry entry = ldifReader.readEntry();
        if (entry == null)
        {
          return entries;
        }

        entries.add(entry);
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



  /**
   * Writes the specified lines to the given file.
   *
   * @param  file   The file to be written.
   * @param  lines  The lines to write to the file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private void writeFile(final File file, final String... lines)
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
}
