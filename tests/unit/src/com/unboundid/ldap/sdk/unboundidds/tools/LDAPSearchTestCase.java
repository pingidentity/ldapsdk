/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.extensions.NoticeOfDisconnectionExtendedResult;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.PassphraseEncryptedInputStream;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONObjectReader;



/**
 * This class provides a set of test cases for the {@code LDAPSearch} tool.
 */
public final class LDAPSearchTestCase
       extends LDAPSDKTestCase
{
  /**
   * A {@code null} {@code OutputStream} object.
   */
  private static final OutputStream NULL_OUTPUT_STREAM = null;



  // The in-memory directory server instance that will be used for testing.
  private volatile InMemoryDirectoryServer ds = null;



  /**
   * Performs the necessary setup to run the tests.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    ds = getTestDS(false, false);

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
    ds.add(
         "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: aaron.adams",
         "givenName: Aaron",
         "sn: Adams",
         "cn: Aaron Adams");
    ds.add(
         "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: brenda.brown",
         "givenName: Brenda",
         "sn: Brown",
         "cn: Brenda Brown");
    ds.add(
         "dn: uid=chester.cooper,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: chester.cooper",
         "givenName: Chester",
         "sn: Cooper",
         "cn: Chester Cooper");
    ds.add(
         "dn: uid=dolly.duke,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: dolly.duke",
         "givenName: Dolly",
         "sn: Duke",
         "cn: Dolly Duke");
    ds.add(
         "dn: uid=ezra.edwards,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: ezra.edwards",
         "givenName: Ezra",
         "sn: Edwards",
         "cn: Ezra Edwards");
  }



  /**
   * Provides test coverage for the tool methods that don't require running the
   * tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    assertNotNull(ldapSearch.getToolName());
    assertEquals(ldapSearch.getToolName(), "ldapsearch");

    assertNotNull(ldapSearch.getToolDescription());

    assertNotNull(ldapSearch.getToolVersion());
    assertEquals(ldapSearch.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertEquals(ldapSearch.getMinTrailingArguments(), 0);

    assertEquals(ldapSearch.getMaxTrailingArguments(), -1);

    assertNotNull(ldapSearch.getTrailingArgumentsPlaceholder());

    assertTrue(ldapSearch.supportsInteractiveMode());

    assertTrue(ldapSearch.defaultsToInteractiveMode());

    assertTrue(ldapSearch.supportsPropertiesFile());

    assertTrue(ldapSearch.defaultToPromptForBindPassword());

    assertTrue(ldapSearch.includeAlternateLongIdentifiers());

    assertTrue(ldapSearch.supportsMultipleServers());

    assertNotNull(ldapSearch.getExampleUsages());
    assertFalse(ldapSearch.getExampleUsages().isEmpty());

    ldapSearch.getOutStream();
    ldapSearch.getErrStream();
  }



  /**
   * Tests the ability to get usage information for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM, "--help"),
         ResultCode.SUCCESS);
  }



  /**
   * Tests the ability to get SASL help information for the tool when no
   * mechanism was specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLHelpWithoutMechanism()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPSearch.main(out, out, "--help-sasl"),
         ResultCode.SUCCESS);

    boolean externalFound = false;
    boolean gssapiFound = false;
    boolean plainFound = false;
    for (final String line :
         StaticUtils.stringToLines(StaticUtils.toUTF8String(out.toByteArray())))
    {
      if (line.contains("The EXTERNAL SASL Mechanism"))
      {
        externalFound = true;
      }
      else if (line.contains("The GSSAPI SASL Mechanism"))
      {
        gssapiFound = true;
      }
      else if (line.contains("The PLAIN SASL Mechanism"))
      {
        plainFound = true;
      }
    }

    assertTrue(externalFound);
    assertTrue(gssapiFound);
    assertTrue(plainFound);
  }



  /**
   * Tests the ability to get SASL help information for the tool when the GSSAPI
   * mechanism was specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLHelpWithGSSAPIMechanism()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPSearch.main(out, out,
              "--help-sasl",
              "--saslOption", "mech=GSSAPI"),
         ResultCode.SUCCESS);

    boolean externalFound = false;
    boolean gssapiFound = false;
    boolean plainFound = false;
    for (final String line :
         StaticUtils.stringToLines(StaticUtils.toUTF8String(out.toByteArray())))
    {
      if (line.contains("The EXTERNAL SASL Mechanism"))
      {
        externalFound = true;
      }
      else if (line.contains("The GSSAPI SASL Mechanism"))
      {
        gssapiFound = true;
      }
      else if (line.contains("The PLAIN SASL Mechanism"))
      {
        plainFound = true;
      }
    }

    assertFalse(externalFound);
    assertTrue(gssapiFound);
    assertFalse(plainFound);
  }



  /**
   * Tests the ability to get SASL help information for the tool when an
   * unsupported mechanism is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLHelpWithUnsupportedMechanism()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPSearch.main(out, out,
              "--help-sasl",
              "--saslOption", "mech=UNSUPPORTED"),
         ResultCode.SUCCESS);

    boolean externalFound = false;
    boolean gssapiFound = false;
    boolean plainFound = false;
    for (final String line :
         StaticUtils.stringToLines(StaticUtils.toUTF8String(out.toByteArray())))
    {
      if (line.contains("The EXTERNAL SASL Mechanism"))
      {
        externalFound = true;
      }
      else if (line.contains("The GSSAPI SASL Mechanism"))
      {
        gssapiFound = true;
      }
      else if (line.contains("The PLAIN SASL Mechanism"))
      {
        plainFound = true;
      }
    }

    assertTrue(externalFound);
    assertTrue(gssapiFound);
    assertTrue(plainFound);
  }



  /**
   * Tests the ability to get SASL help information for the tool when a SASL
   * option is specified without a mechanism name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLHelpWithNonMechOption()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    assertEquals(
         LDAPSearch.main(out, out,
              "--help-sasl",
              "--saslOption", "qop=auth"),
         ResultCode.SUCCESS);

    boolean externalFound = false;
    boolean gssapiFound = false;
    boolean plainFound = false;
    for (final String line :
         StaticUtils.stringToLines(StaticUtils.toUTF8String(out.toByteArray())))
    {
      if (line.contains("The EXTERNAL SASL Mechanism"))
      {
        externalFound = true;
      }
      else if (line.contains("The GSSAPI SASL Mechanism"))
      {
        gssapiFound = true;
      }
      else if (line.contains("The PLAIN SASL Mechanism"))
      {
        plainFound = true;
      }
    }

    assertTrue(externalFound);
    assertTrue(gssapiFound);
    assertTrue(plainFound);
  }



  /**
   * Tests the basic operation of the tool when communicating with a server
   * over LDAP.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperation()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--sizeLimit", "0",
              "--timeLimitSeconds", "0",
              "--dereferencePolicy", "never",
              "--retryFailedOperations",
              "--continueOnError",
              "--ratePerSecond", "1000000",
              "--wrapColumn", "100",
              "--terse",
              "(objectClass=*)"),
         ResultCode.SUCCESS);
  }



  /**
   * Provides test coverage for arguments that allow creating bind controls.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCoverageForBindControls()
         throws Exception
  {
    // NOTE:  This won't succeed because the in-memory directory server doesn't
    // support all of these controls.  But it will at least get coverage.
    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--scope", "base",
         "--bindControl", "1.2.3.4",
         "--authorizationIdentity",
         "--getAuthorizationEntryAttribute", "*",
         "--getRecentLoginHistory",
         "--getUserResourceLimits",
         "--usePasswordPolicyControl",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip",
         "--dontWrap",
         "--dereferencePolicy", "always",
         "(objectClass=*)",
         "*",
         "+",
         // NOTE:  This will be treated as a trailing argument and not a named
         // argument, which will cause the tool to generate a warning.
         "--help");
  }



  /**
   * Provides test coverage for arguments that allow creating search controls.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCoverageForSearchControls()
         throws Exception
  {
    // NOTE:  This won't succeed because the in-memory directory server doesn't
    // support all of these controls.  But it will at least get coverage.
    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "",
         "--scope", "base",
         "--searchControl", "1.2.3.4",
         "--assertionFilter", "(objectClass=*)",
         "--accountUsable",
         "--excludeBranch", "ou=whatever,dc=example,dc=com",
         "--getEffectiveRightsAuthzID", "u:jdoe",
         "--getEffectiveRightsAttribute", "uid",
         "--includeReplicationConflictEntries",
         "--draftLDUPSubentries",
         "--joinRule", "dn:isMemberOf",
         "--joinBaseDN", "dc=example,dc=com",
         "--joinScope", "sub",
         "--joinSizeLimit", "100",
         "--joinFilter", "(objectClass=*)",
         "--joinRequestedAttribute", "*",
         "--joinRequireMatch",
         "--manageDsaIT",
         "--matchedValuesFilter", "(objectClass=top)",
         "--matchingEntryCountControl",
              "examineCount=100:alwaysExamine:allowUnindexed" +
                   ":skipResolvingExplodedIndexes:fastShortCircuitThreshold=5" +
                   ":slowShortCircuitThreshold=100:debug",
         "--overrideSearchLimit", "name1=value1",
         "--overrideSearchLimit", "name2=value2",
         "--operationPurpose", "Testing",
         "--persistentSearch", "ps:add,del,mod,moddn:true:true",
         "--proxyAs", "u:jdoe",
         "--suppressOperationalAttributeUpdates", "last-access-time",
         "--suppressOperationalAttributeUpdates", "last-login-time",
         "--suppressOperationalAttributeUpdates", "last-login-ip",
         "--suppressOperationalAttributeUpdates", "lastmod",
         "--realAttributesOnly",
         "--rejectUnindexedSearch",
         "--wrapColumn", "0",
         "--dereferencePolicy", "search",
         "(objectClass=*)",
         "*",
         "+",
         // NOTE:  This will be treated as a trailing argument and not a named
         // argument, which will cause the tool to generate a warning.
         "--help");

    // Perform another search that includes arguments that aren't compatible
    // with those used in the first search.
    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "",
         "--scope", "base",
         "--permitUnindexedSearch",
         "--rfc3672Subentries", "false",
         "(objectClass=*)",
         "*",
         "+",
         // NOTE:  This will be treated as a trailing argument and not a named
         // argument, which will cause the tool to generate a warning.
         "--help");
  }



  /**
   * Provides test coverage for the case in which the server is asked to sort
   * the results before returning them.  It will also provide basic coverage for
   * VLV.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testSortResults()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--dereferencePolicy", "find",
              "--outputFile", outputFile.getAbsolutePath(),
              "--teeResultsToStandardOut",
              "--sortOrder", "-sn,+givenName,uid",
              "--virtualListView", "0:100:1:0",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=ezra.edwards,ou=People,dc=example,dc=com",
              "givenName: Ezra",
              "sn: Edwards"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=dolly.duke,ou=People,dc=example,dc=com",
              "givenName: Dolly",
              "sn: Duke"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=chester.cooper,ou=People,dc=example,dc=com",
              "givenName: Chester",
              "sn: Cooper"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
              "givenName: Brenda",
              "sn: Brown"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "givenName: Aaron",
              "sn: Adams"));
    assertNull(ldifReader.readEntry());

    ldifReader.close();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--sortOrder", "+sn:caseIgnoreOrderingMatch,+" +
                   "givenName:caseIgnoreOrderingMatch",
              "(objectClass=person)"),
         ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to run the tool with an LDAP URL file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithLDAPURLFile()
         throws Exception
  {
    // Make sure that we can perform a search with a URL file.
    final File outputFileBase = createTempFile();

    final File ldapURLFile = createTempFile(
         "# This is a comment.",
         "# The next line is blank.",
         "",
         "ldap:///dc=example,dc=com??sub?(objectClass=*)",
         "",
         "ldap:///dc=example,dc=com?uid?sub?(objectClass=person)",
         "# Another comment",
         "This is not a valid LDAP URL");

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFileBase.getAbsolutePath(),
         "--separateOutputFilePerSearch",
         "--teeResultsToStandardOut",
         "--ldapURLFile", ldapURLFile.getAbsolutePath(),
         "--continueOnError");

    assertTrue(new File(outputFileBase.getAbsolutePath() + ".1").exists());
    assertTrue(new File(outputFileBase.getAbsolutePath() + ".2").exists());


    // Make sure that the tool doesn't allow trailing arguments with the LDAP
    // URL file argument.
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFile", outputFileBase.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--teeResultsToStandardOut",
              "--ldapURLFile", ldapURLFile.getAbsolutePath(),
              "--continueOnError",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior when trying to run the tool with a filter file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithFilterFile()
         throws Exception
  {
    // Make sure that we can perform a search with a URL file.
    final File outputFileBase = createTempFile();

    final File filterFile = createTempFile(
         "# This is a comment.",
         "# The next line is blank.",
         "",
         "(objectClass=person)",
         "(objectClass=inetOrgPerson)",
         "malformed");

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--outputFile", outputFileBase.getAbsolutePath(),
         "--separateOutputFilePerSearch",
         "--baseDN", "dc=example,dc=com",
         "--searchScope", "sub",
         "--filterFile", filterFile.getAbsolutePath(),
         "--continueOnError",
         "*",
         "+");

    assertTrue(new File(outputFileBase.getAbsolutePath() + ".1").exists());
    assertTrue(new File(outputFileBase.getAbsolutePath() + ".2").exists());


    // Make sure that the tool doesn't allow the first trailing argument to be
    // a filter when using the filterFile argument.
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFile", outputFileBase.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--filterFile", filterFile.getAbsolutePath(),
              "--continueOnError",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior when trying to run the tool with a filter argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithFilterArgument()
         throws Exception
  {
    // Make sure that we can perform a search with a URL file.
    final File outputFileBase = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFile", outputFileBase.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--filter", "(objectClass=person)",
              "--filter", "(objectClass=inetOrgPerson)",
              "--continueOnError",
              "*",
              "+"),
         ResultCode.SUCCESS);

    assertTrue(new File(outputFileBase.getAbsolutePath() + ".1").exists());
    assertTrue(new File(outputFileBase.getAbsolutePath() + ".2").exists());


    // Make sure that the tool doesn't allow the first trailing argument to be
    // a filter when using the filter argument.
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFile", outputFileBase.getAbsolutePath(),
              "--separateOutputFilePerSearch",
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--filter", "(objectClass=*)",
              "--continueOnError",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that there must be at least one trailing argument provided
   * when running with the ldapURLFile, filterFile, or filter argument, and the
   * first trailing argument must be a valid filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFilterAsTrailingArgument()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "notAValidFilter"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that the tool properly handles the case in which the
   * matched values filter argument is used to specify a filter that can't be
   * used in that control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidMatchedValuesFilter()
         throws Exception
  {
    // An OR filter cannot be used as a matched values filter.
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--matchedValuesFilter",
                   "(&(objectClass=person)(objectClass=groupOfNames))",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that the tool properly handles invalid values for the
   * --matchingEntryCountControl argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidMatchingEntryCountControl()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--matchingEntryCountControl", "",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--matchingEntryCountControl", "examineCount=NotAnInteger",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--matchingEntryCountControl", "debug",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--matchingEntryCountControl", "examineCount=0:unrecognized",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that the tool properly handles invalid values for the
   * --overrideSearchLimit argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidOverrideSearchLimitsControl()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--overrideSearchLimit", "noEqualSign",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--overrideSearchLimit", "=startsWithEqualSign",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--overrideSearchLimit", "endsWithEqualSign=",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--overrideSearchLimit", "duplicatePropertyName=value1",
              "--overrideSearchLimit", "duplicatePropertyName=value2",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that the tool properly handles invalid values for the
   * --persistentSearch argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidPersistentSearchControl()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--persistentSearch", "",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--persistentSearch", "invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--persistentSearch", "ps:invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--persistentSearch", "ps:any:invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--persistentSearch", "ps:any:false:invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--searchScope", "sub",
         "--persistentSearch", "ps:any:false:false",
         "--dryRun",
         "(objectClass=*)");
  }



  /**
   * Tests to ensure that the tool properly handles invalid values for the
   * --sortOrder argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidSortOrder()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--sortOrder", "",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--sortOrder", "_not_a_valid_attribute_name_",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that the tool properly handles invalid values for the
   * --virtualListView argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithInvalidVirtualListViewControl()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--sortOrder", "cn",
              "--virtualListView", "",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--sortOrder", "cn",
              "--virtualListView", "invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--sortOrder", "cn",
              "--virtualListView", "invalid:invalid:invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--sortOrder", "cn",
              "--virtualListView", "invalid:invalid:invalid:invalid",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests to ensure that the tool properly handles a number of different
   * join-related scenarios.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithJoinControl()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--joinRule", "invalid",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--joinRule", "dn",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--joinRule", "reverse-dn",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--joinRule", "equals",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--joinRule", "contains",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--searchScope", "sub",
              "--joinRule", "reverse-dn:secretary",
              "--joinBaseDN", "invalid",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.PARAM_ERROR);

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--searchScope", "sub",
         "--joinRule", "equals:description:description",
         "--joinBaseDN", "search-base",
         "--dryRun",
         "(objectClass=*)");

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--searchScope", "sub",
         "--joinRule", "contains:description:description",
         "--joinBaseDN", "source-entry-dn",
         "--joinRequireMatch",
         "--dryRun",
         "(objectClass=*)");

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--searchScope", "sub",
         "--joinRule", "contains:description:description",
         "--suppressBase64EncodedValueComments",
         "--dryRun",
         "--virtualAttributesOnly",
         "--getEffectiveRightsAuthzID", "u:jdoe",
         "--proxyV1As", "uid=jdoe,ou=People,dc=example,dc=com",
         "(objectClass=*)");
  }



  /**
   * Tests the behavior when using the simple paged results control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimplePagedResults()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--sortOrder", "-sn,+givenName,uid",
              "--simplePageSize", "2",
              "--outputFile", outputFile.getAbsolutePath(),
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=ezra.edwards,ou=People,dc=example,dc=com",
              "givenName: Ezra",
              "sn: Edwards"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=dolly.duke,ou=People,dc=example,dc=com",
              "givenName: Dolly",
              "sn: Duke"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=chester.cooper,ou=People,dc=example,dc=com",
              "givenName: Chester",
              "sn: Cooper"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
              "givenName: Brenda",
              "sn: Brown"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "givenName: Aaron",
              "sn: Adams"));
    assertNull(ldifReader.readEntry());

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--sortOrder", "-sn,+givenName,uid",
              "--simplePageSize", "2",
              "--terse",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--sortOrder", "-sn,+givenName,uid",
              "--simplePageSize", "2",
              "--verbose",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--scope", "sub",
         "--sortOrder", "-sn,+givenName,uid",
         "--simplePageSize", "2",
         "--verbose",
         "--countEntries",
         "(objectClass=person)");

    ldifReader.close();
  }



  /**
   * Tests the behavior when using the --includeSoftDeletedEntries argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncludeSoftDeletedEntries()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--includeSoftDeletedEntries", "with-non-deleted-entries",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.SUCCESS);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--includeSoftDeletedEntries", "without-non-deleted-entries",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.SUCCESS);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--includeSoftDeletedEntries",
                   "deleted-entries-in-undeleted-form",
              "--dryRun",
              "(objectClass=*)"),
         ResultCode.SUCCESS);
  }




  /**
   * Tests the behavior when processing a search request that includes
   * referrals.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithReferrals()
         throws Exception
  {
    ds.add(
         "dn: ou=Users,dc=example,dc=com",
         "objectClass: top",
         "objectClass: referral",
         "objectClass: extensibleObject",
         "ou: Users",
         "ref: ldap://localhost:" + ds.getListenPort() +
              "/ou=People,dc=example,dc=com");

    try
    {
      // First, try a search based at the referral.
      assertEquals(
           LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
                "--hostname", "localhost",
                "--port", String.valueOf(ds.getListenPort()),
                "--baseDN", "ou=Users,dc=example,dc=com",
                "--scope", "sub",
                "(objectClass=*)"),
           ResultCode.REFERRAL);

      assertEquals(
           LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
                "--hostname", "localhost",
                "--port", String.valueOf(ds.getListenPort()),
                "--baseDN", "ou=Users,dc=example,dc=com",
                "--scope", "sub",
                "--followReferrals",
                "(objectClass=*)"),
           ResultCode.SUCCESS);

      // Next, try a search based above the referral.
      assertEquals(
           LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
                "--hostname", "localhost",
                "--port", String.valueOf(ds.getListenPort()),
                "--baseDN", "dc=example,dc=com",
                "--scope", "sub",
                "(objectClass=*)"),
           ResultCode.SUCCESS);

      assertEquals(
           LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
                "--hostname", "localhost",
                "--port", String.valueOf(ds.getListenPort()),
                "--baseDN", "dc=example,dc=com",
                "--scope", "sub",
                "--followReferrals",
                "(objectClass=*)"),
           ResultCode.SUCCESS);
    }
    finally
    {
      final DeleteRequest deleteRequest =
           new DeleteRequest("ou=Users,dc=example,dc=com");
      deleteRequest.addControl(new ManageDsaITRequestControl());
      ds.delete(deleteRequest);
    }
  }



  /**
   * Provides test coverage for the {@code useAdministrativeSession} argument.
   * The in-memory directory server doesn't support this capability, but we'll
   * at least get coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseAdministrativeSession()
         throws Exception
  {
    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "ou=Users,dc=example,dc=com",
         "--scope", "sub",
         "--useAdministrativeSession",
         "(objectClass=person)");
  }



  /**
   * Provides test coverage for the {@code handleUnsolicitedNotification}
   * method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleUnsolicitedNotification()
         throws Exception
  {
    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final LDAPConnection conn = ds.getConnection();

    ldapSearch.handleUnsolicitedNotification(conn,
         new NoticeOfDisconnectionExtendedResult(ResultCode.OTHER,
              "The connection will be closed."));

    conn.close();
  }



  /**
   * Provides test coverage for the tool when configured to use the JSON output
   * format.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJSONOutputFormat()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "JSON",
              "--requestedAttribute", "uid",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "--outputFile", outputFile.getAbsolutePath(),
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    final JSONObjectReader reader =
         new JSONObjectReader(new FileInputStream(outputFile));

    while (true)
    {
      final JSONObject o = reader.readObject();
      if (o == null)
      {
        break;
      }
    }

    reader.close();
  }



  /**
   * Provides test coverage for the tool when configured to use the CSV output
   * format.  This method is just intended to get coverage; it doesn't actually
   * attempt to verify that the output is properly formatted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCSVOutputFormat()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "CSV",
              "--requestedAttribute", "uid",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    final File urlFile = createTempFile();
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFormat", "CSV",
              "--ldapURLFile", urlFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "CSV",
              "--filter", "(objectClass=person)",
              "uid",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "CSV",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "--filter", "(objectClass=person)",
              "uid"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "CSV",
              "--requestedAttribute", "uid",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Provides test coverage for the tool when configured to use the multi-valued
   * CSV output format.  This method is just intended to get coverage; it
   * doesn't actually attempt to verify that the output is properly formatted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiValuedCSVOutputFormat()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-csv",
              "--requestedAttribute", "uid",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    final File urlFile = createTempFile();
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFormat", "multi-valued-csv",
              "--ldapURLFile", urlFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-csv",
              "--filter", "(objectClass=person)",
              "uid",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-csv",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "--filter", "(objectClass=person)",
              "uid"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-csv",
              "--requestedAttribute", "uid",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Provides test coverage for the tool when configured to use the
   * tab-delimited text output format.  This method is just intended to get
   * coverage; it doesn't actually attempt to verify that the output is properly
   * formatted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTabDelimitedOutputFormat()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "tab-delimited",
              "--requestedAttribute", "uid",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    final File urlFile = createTempFile();
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFormat", "tab-delimited",
              "--ldapURLFile", urlFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "tab-delimited",
              "--filter", "(objectClass=person)",
              "uid",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "tab-delimited",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "--filter", "(objectClass=person)",
              "uid"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "tab-delimited",
              "--requestedAttribute", "uid",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Provides test coverage for the tool when configured to use the
   * multi-valued tab-delimited text output format.  This method is just
   * intended to get coverage; it doesn't actually attempt to verify that the
   * output is properly formatted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiValuedTabDelimitedOutputFormat()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-tab-delimited",
              "--requestedAttribute", "uid",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    final File urlFile = createTempFile();
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--outputFormat", "multi-valued-tab-delimited",
              "--ldapURLFile", urlFile.getAbsolutePath()),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-tab-delimited",
              "--filter", "(objectClass=person)",
              "uid",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-tab-delimited",
              "--requestedAttribute", "givenName",
              "--requestedAttribute", "sn",
              "--filter", "(objectClass=person)",
              "uid"),
         ResultCode.PARAM_ERROR);

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "multi-valued-tab-delimited",
              "--requestedAttribute", "uid",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Provides test coverage for the tool when configured to use the dns-only
   * output format and an output file is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNsOnlyOutputFormatWithOutputFile()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "dns-only",
              "--requestedAttribute", "uid",
              "--outputFile", outputFile.getAbsolutePath(),
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    try (FileReader fileReader = new FileReader(outputFile);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      assertEquals(bufferedReader.readLine(),
           "uid=aaron.adams,ou=People,dc=example,dc=com");
      assertEquals(bufferedReader.readLine(),
           "uid=brenda.brown,ou=People,dc=example,dc=com");
      assertEquals(bufferedReader.readLine(),
           "uid=chester.cooper,ou=People,dc=example,dc=com");
      assertEquals(bufferedReader.readLine(),
           "uid=dolly.duke,ou=People,dc=example,dc=com");
      assertEquals(bufferedReader.readLine(),
           "uid=ezra.edwards,ou=People,dc=example,dc=com");
      assertNull(bufferedReader.readLine());
    }
  }



  /**
   * Provides test coverage for the tool when configured to use the values-only
   * output format and an output file is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValuesOnlyOutputFormatWithOutputFile()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "values-only",
              "--requestedAttribute", "uid",
              "--outputFile", outputFile.getAbsolutePath(),
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    try (FileReader fileReader = new FileReader(outputFile);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      assertEquals(bufferedReader.readLine(), "aaron.adams");
      assertEquals(bufferedReader.readLine(), "brenda.brown");
      assertEquals(bufferedReader.readLine(), "chester.cooper");
      assertEquals(bufferedReader.readLine(), "dolly.duke");
      assertEquals(bufferedReader.readLine(), "ezra.edwards");
      assertNull(bufferedReader.readLine());
    }
  }



  /**
   * Provides test coverage for the tool when configured to use the values-only
   * output format and no output file is used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVaulesOnlyOutputFormatWithoutOutputFile()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    assertEquals(
         LDAPSearch.main(out, out,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--outputFormat", "values-only",
              "--requestedAttribute", "uid",
              "(objectClass=person)"),
         ResultCode.SUCCESS);

    try (InputStreamReader inputStreamReader = new InputStreamReader(
              new ByteArrayInputStream(out.toByteArray()));
         BufferedReader bufferedReader = new BufferedReader(inputStreamReader))
    {
      assertEquals(bufferedReader.readLine(), "aaron.adams");
      assertEquals(bufferedReader.readLine(), "brenda.brown");
      assertEquals(bufferedReader.readLine(), "chester.cooper");
      assertEquals(bufferedReader.readLine(), "dolly.duke");
      assertEquals(bufferedReader.readLine(), "ezra.edwards");
      assertNull(bufferedReader.readLine());
    }
  }



  /**
   * Tests the behavior of the excludeAttribute transformation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeAttribute()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--excludeAttribute", "objectClass",
              "--excludeAttribute", "givenName",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertEquals(entry,
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "uid: aaron.adams",
              "sn: Adams",
              "cn: Aaron Adams"));
  }



  /**
   * Tests the behavior of the redactAttribute transformation when retaining the
   * redacted value count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedactAttributeRetainValueCount()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--redactAttribute", "objectClass",
              "--redactAttribute", "givenName",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertEquals(entry,
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "objectClass: ***REDACTED1***",
              "objectClass: ***REDACTED2***",
              "objectClass: ***REDACTED3***",
              "objectClass: ***REDACTED4***",
              "uid: aaron.adams",
              "givenName: ***REDACTED***",
              "sn: Adams",
              "cn: Aaron Adams"));
  }



  /**
   * Tests the behavior of the redactAttribute transformation when hiding the
   * redacted value count.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRedactAttributeHideValueCount()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--redactAttribute", "objectClass",
              "--redactAttribute", "givenName",
              "--hideRedactedValueCount",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertEquals(entry,
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "objectClass: ***REDACTED***",
              "uid: aaron.adams",
              "givenName: ***REDACTED***",
              "sn: Adams",
              "cn: Aaron Adams"));
  }



  /**
   * Tests the behavior of the scrambleAttribute transformation when a random
   * seed is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleAttributeWithRandomSeed()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--scrambleAttribute", "givenName",
              "--scrambleRandomSeed", "0",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertDNsEqual(entry.getDN(),
         "uid=aaron.adams,ou=People,dc=example,dc=com");
    assertTrue(entry.hasAttribute("givenName"));
    assertFalse(entry.hasAttributeValue("givenName", "Aaron"));
  }



  /**
   * Tests the behavior of the scrambleAttribute transformation when no random
   * seed is provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScrambleAttributeWithoutRandomSeed()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--scrambleAttribute", "givenName",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertDNsEqual(entry.getDN(),
         "uid=aaron.adams,ou=People,dc=example,dc=com");
    assertTrue(entry.hasAttribute("givenName"));
    assertFalse(entry.hasAttributeValue("givenName", "Aaron"));
  }



  /**
   * Tests the behavior of the renameAttribute transformation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameAttribute()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--renameAttributeFrom", "uid",
              "--renameAttributeTo", "userName",
              "--renameAttributeFrom", "givenName",
              "--renameAttributeTo", "firstName",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertEquals(entry,
         new Entry(
              "dn: userName=aaron.adams,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "userName: aaron.adams",
              "firstName: Aaron",
              "sn: Adams",
              "cn: Aaron Adams"));
  }



  /**
   * Tests the behavior of the renameAttribute transformation when there is a
   * mismatch between the number of source and target names.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameAttributeMismatch()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--renameAttributeFrom", "uid",
              "--renameAttributeTo", "userName",
              "--renameAttributeFrom", "givenName",
              "(uid=aaron.adams)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the behavior of the moveSubtree transformation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoveSubtree()
         throws Exception
  {
    final File outputFile = createTempFile();

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--moveSubtreeFrom", "ou=People,dc=example,dc=com",
              "--moveSubtreeTo", "ou=Users,dc=example,dc=com",
              "--outputFile", outputFile.getAbsolutePath(),
              "(uid=aaron.adams)"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(outputFile);

    final Entry entry = ldifReader.readEntry();

    assertNull(ldifReader.readEntry());
    ldifReader.close();

    assertEquals(entry,
         new Entry(
              "dn: uid=aaron.adams,ou=Users,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: aaron.adams",
              "givenName: Aaron",
              "sn: Adams",
              "cn: Aaron Adams"));
  }



  /**
   * Tests the behavior of the moveSubtree transformation when there is a
   * mismatch between the number of source and target DNs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoveSubtreeMismatch()
         throws Exception
  {
    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--moveSubtreeFrom", "ou=People,dc=example,dc=com",
              "--moveSubtreeTo", "ou=Users,dc=example,dc=com",
              "--moveSubtreeFrom", "ou=Groups,dc=example,dc=com",
              "(uid=aaron.adams)"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Provides test coverage for the ability to compress and encrypt the LDIF
   * output when the encryption passphrase is provided in a file that is
   * malformed.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCompressAndEncryptOutputWithPassphraseFromMalformedFile()
         throws Exception
  {
    final File outputFile = createTempFile();
    final File passphraseFile = createTempFile(); // Shouldn't be empty.

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--dereferencePolicy", "find",
              "--outputFile", outputFile.getAbsolutePath(),
              "--compressOutput",
              "--encryptOutput",
              "--encryptionPassphraseFile", passphraseFile.getAbsolutePath(),
              "--sortOrder", "-sn,+givenName,uid",
              "--virtualListView", "0:100:1:0",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Provides test coverage for the ability to compress and encrypt the LDIF
   * output when the encryption passphrase is provided in a file.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCompressAndEncryptOutputWithPassphraseFromFile()
         throws Exception
  {
    final File outputFile = createTempFile();
    final File passphraseFile = createTempFile("passphrase");

    assertEquals(
         LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
              "--hostname", "localhost",
              "--port", String.valueOf(ds.getListenPort()),
              "--baseDN", "dc=example,dc=com",
              "--scope", "sub",
              "--dereferencePolicy", "find",
              "--outputFile", outputFile.getAbsolutePath(),
              "--compressOutput",
              "--encryptOutput",
              "--encryptionPassphraseFile", passphraseFile.getAbsolutePath(),
              "--sortOrder", "-sn,+givenName,uid",
              "--virtualListView", "0:100:1:0",
              "(objectClass=person)",
              "givenName",
              "sn"),
         ResultCode.SUCCESS);

    final LDIFReader ldifReader = new LDIFReader(new GZIPInputStream(
         new PassphraseEncryptedInputStream("passphrase",
              new FileInputStream(outputFile))));

    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=ezra.edwards,ou=People,dc=example,dc=com",
              "givenName: Ezra",
              "sn: Edwards"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=dolly.duke,ou=People,dc=example,dc=com",
              "givenName: Dolly",
              "sn: Duke"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=chester.cooper,ou=People,dc=example,dc=com",
              "givenName: Chester",
              "sn: Cooper"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
              "givenName: Brenda",
              "sn: Brown"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "givenName: Aaron",
              "sn: Adams"));
    assertNull(ldifReader.readEntry());

    ldifReader.close();
  }



  /**
   * Provides test coverage for the ability to compress and encrypt the LDIF
   * output when the encryption passphrase is provided at an interactive prompt.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @Test()
  public void testCompressAndEncryptOutputWithPassphraseFromPrompt()
         throws Exception
  {
    final File outputFile = createTempFile();

    try
    {
      PasswordReader.setTestReaderLines("passphrase", "passphrase");

      assertEquals(
           LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
                "--hostname", "localhost",
                "--port", String.valueOf(ds.getListenPort()),
                "--baseDN", "dc=example,dc=com",
                "--scope", "sub",
                "--dereferencePolicy", "find",
                "--outputFile", outputFile.getAbsolutePath(),
                "--compressOutput",
                "--encryptOutput",
                "--sortOrder", "-sn,+givenName,uid",
                "--virtualListView", "0:100:1:0",
                "(objectClass=person)",
                "givenName",
                "sn"),
           ResultCode.SUCCESS);
    }
    finally
    {
      PasswordReader.setTestReader(null);
    }

    final LDIFReader ldifReader = new LDIFReader(new GZIPInputStream(
         new PassphraseEncryptedInputStream("passphrase",
              new FileInputStream(outputFile))));

    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=ezra.edwards,ou=People,dc=example,dc=com",
              "givenName: Ezra",
              "sn: Edwards"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=dolly.duke,ou=People,dc=example,dc=com",
              "givenName: Dolly",
              "sn: Duke"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=chester.cooper,ou=People,dc=example,dc=com",
              "givenName: Chester",
              "sn: Cooper"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=brenda.brown,ou=People,dc=example,dc=com",
              "givenName: Brenda",
              "sn: Brown"));
    assertEquals(ldifReader.readEntry(),
         new Entry(
              "dn: uid=aaron.adams,ou=People,dc=example,dc=com",
              "givenName: Aaron",
              "sn: Adams"));
    assertNull(ldifReader.readEntry());

    ldifReader.close();
  }



  /**
   * Provides test coverage for the controls used to get and request routing
   * information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRoutingControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");
    ds.startListening();
    final int dsPort = ds.getListenPort();
    ds.shutDown(true);

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(dsPort),
         "--getBackendSetID",
         "--getServerID",
         "--routeToBackendSet", "rp1:bs1",
         "--routeToBackendSet", "rp1:bs2",
         "--routeToBackendSet", "rp2:bs3",
         "--routeToServer", "server-id",
         "--baseDN", "dc=example,dc=com",
         "--scope", "base",
         "(objectClass=*)");

    LDAPSearch.main(NULL_OUTPUT_STREAM, NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(dsPort),
         "--routeToBackendSet", "malformed",
         "--baseDN", "dc=example,dc=com",
         "--scope", "base",
         "(objectClass=*)");
  }



  /**
   * Provides test coverage for the --requireMatch argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireMatch()
         throws Exception
  {
    ResultCode resultCode = LDAPSearch.main(NULL_OUTPUT_STREAM,
         NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--scope", "sub",
         "(uid=nonexistent)");
    assertEquals(resultCode, ResultCode.SUCCESS);

    resultCode = LDAPSearch.main(NULL_OUTPUT_STREAM,
         NULL_OUTPUT_STREAM,
         "--hostname", "localhost",
         "--port", String.valueOf(ds.getListenPort()),
         "--baseDN", "dc=example,dc=com",
         "--scope", "sub",
         "--requireMatch",
         "(uid=nonexistent)");
    assertEquals(resultCode, ResultCode.NO_RESULTS_RETURNED);
  }
}
