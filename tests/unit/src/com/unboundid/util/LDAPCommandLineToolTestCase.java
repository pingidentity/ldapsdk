/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.TestLDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.TestPostConnectProcessor;
import com.unboundid.ldap.sdk.examples.LDAPSearch;
import com.unboundid.ldap.sdk.unboundidds.MoveSubtree;
import com.unboundid.util.args.ArgumentParser;



/**
 * This class provides a set of test cases for the CommandLineTool and
 * LDAPCommandLineTool classes, using the LDAPSearch subclass.
 */
public class LDAPCommandLineToolTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the general methods in the CommandLineTool
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCommandLineTool()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(System.out, System.err);

    assertNotNull(ldapSearch.getToolName());

    assertNotNull(ldapSearch.getToolDescription());

    assertTrue(ldapSearch.getMaxTrailingArguments() < 0);

    assertNotNull(ldapSearch.getTrailingArgumentsPlaceholder());

    assertNotNull(ldapSearch.getOut());

    assertNotNull(ldapSearch.getErr());

    assertNotNull(
         LDAPCommandLineTool.getLongLDAPArgumentIdentifiers(ldapSearch));
    assertFalse(
         LDAPCommandLineTool.getLongLDAPArgumentIdentifiers(ldapSearch).
              isEmpty());

    assertFalse(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Provides test coverage for the method used to get a connection pool.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionPool()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-q",
         "-X",
         "-D", getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    LDAPConnectionPool pool = ldapSearch.getConnectionPool(1, 5);
    assertNotNull(pool);
    assertNotNull(pool.getRootDSE());

    LDAPConnection conn = pool.getConnection();
    assertNotNull(conn);
    assertNotNull(conn.getRootDSE());

    LDAPConnection conn2 = pool.getConnection();
    assertNotNull(conn2);
    assertNotNull(conn2.getRootDSE());

    pool.releaseConnection(conn);
    pool.releaseConnection(conn2);

    pool.close();

    assertTrue(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Provides test coverage for the method used to get a connection pool with an
   * extended set of options.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetConnectionPoolExtendedOptions()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-q",
         "-X",
         "-D", getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    LDAPConnectionPool pool = ldapSearch.getConnectionPool(1, 5, 1,
         new TestPostConnectProcessor(null, null),
         new TestPostConnectProcessor(null, null), false,
         new TestLDAPConnectionPoolHealthCheck());

    assertNotNull(pool);
    assertNotNull(pool.getRootDSE());

    LDAPConnection conn = pool.getConnection();
    assertNotNull(conn);
    assertNotNull(conn.getRootDSE());

    LDAPConnection conn2 = pool.getConnection();
    assertNotNull(conn2);
    assertNotNull(conn2.getRootDSE());

    pool.releaseConnection(conn);
    pool.releaseConnection(conn2);

    pool.close();

    assertTrue(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Provides test coverage for SSL-based communication.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSL()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestSSLPort()),
         "-Z",
         "-X",
         "-D", getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Provides test coverage for StartTLS-based communication.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLS()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-q",
         "-X",
         "-D", getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Provides test coverage for SASL authentication using the PLAIN method.  The
   * password will be read from a file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLPlain()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File f = createTempFile(getTestBindPassword());

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-o", "mech=PLAIN",
         "-o", "authID=dn:" + getTestBindDN(),
         "-j", f.getAbsolutePath(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    f.delete();

    assertTrue(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Provides a test with a malformed SASL option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLMalformedOption()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-o", "mech=PLAIN",
         "-o", "malformed",
         "-o", "authID=dn:" + getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Provides a test with an invalid SASL option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLInvalidOption()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-o", "mech=PLAIN",
         "-o", "invalid=foo",
         "-o", "authID=dn:" + getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Provides a test with SASL option but no mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLNoMechanism()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-o", "authID=dn:" + getTestBindDN(),
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Provides a test with an invalid SASL mechanism.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLInvalidMechanism()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-o", "mech=UNSUPPORTED",
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Provides a test with a missing required option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLMissingRequiredOption()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "-o", "mech=PLAIN",
         "-w", getTestBindPassword(),
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Provides a test that uses the useSASLExternal argument in a manner that
   * cannot succeed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseSASLExternalFailure()
         throws Exception
  {
    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    ResultCode rc = ldapSearch.runTool(
         "-h", getTestHost(),
         "-p", String.valueOf(getTestPort()),
         "--useSASLExternal",
         "-b", "",
         "-s", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to generate a properties file when no other
   * arguments are provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneratePropertiesFileWithoutArguments()
         throws Exception
  {
    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.delete());
    assertFalse(propertiesFile.exists());

    final ResultCode rc = ldapSearch.runTool(
         "--generatePropertiesFile", propertiesFile.getAbsolutePath());
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.length() > 0);

    assertFileHasLine(propertiesFile, "# ldapsearch.hostname={host}");
    assertFileHasLine(propertiesFile, "# ldapsearch.port={port}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindDN={dn}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindPassword={password}");

    assertFalse(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Tests the behavior when trying to generate a properties file when values
   * are provided for a number of arguments, and then verify the ability to use
   * that properties file to actually run the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateAndUsePropertiesFileWithArguments()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.delete());
    assertFalse(propertiesFile.exists());

    ResultCode rc = ldapSearch.runTool(
         "--generatePropertiesFile", propertiesFile.getAbsolutePath(),
         "--hostname", "127.0.0.1",
         "--port", String.valueOf(ds.getListenPort()),
         "--useSSL",
         "--trustAll",
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password");
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.length() > 0);

    assertFileHasLine(propertiesFile, "# ldapsearch.hostname={host}");
    assertFileHasLine(propertiesFile, "# ldapsearch.port={port}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindDN={dn}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindPassword={password}");

    assertFileHasLine(propertiesFile, "ldapsearch.hostname=127.0.0.1");
    assertFileHasLine(propertiesFile, "ldapsearch.port=" + ds.getListenPort());
    assertFileHasLine(propertiesFile, "ldapsearch.bindDN=cn=Directory Manager");
    assertFileHasLine(propertiesFile, "ldapsearch.bindPassword=password");


    ldapSearch = new LDAPSearch(null, null);

    rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--suppressPropertiesFileComment",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(ldapSearch.anyLDAPArgumentsProvided());
  }



  /**
   * Test the behavior when trying to using a properties file that has a value
   * set for an argument in an exclusive argument set when another argument in
   * that set was provided on the command line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileHandlingOfArgumentsInAnExclusiveSet()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File wrongPasswordFile = createTempFile("wrong-password");

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.delete());
    assertFalse(propertiesFile.exists());

    ResultCode rc = ldapSearch.runTool(
         "--generatePropertiesFile", propertiesFile.getAbsolutePath(),
         "--hostname", "127.0.0.1",
         "--port", String.valueOf(ds.getListenPort()),
         "--useSSL",
         "--trustAll",
         "--bindDN", "cn=Directory Manager",
         "--bindPasswordFile", wrongPasswordFile.getAbsolutePath());
    assertEquals(rc, ResultCode.SUCCESS);


    // Make sure that an attempt to run ldapsearch with that properties file and
    // values for other necessary arguments (but no password) will fail with an
    // "invalid credentials" result because it's picking up the wrong password
    // from the bindPasswordFile property set in the properties file.
    ldapSearch = new LDAPSearch(null, null);
    rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.INVALID_CREDENTIALS);


    // Issue the same command, but this time provide the right password as a
    // command-line argument.  This should succeed because the bind password
    // provided on the command line will override the value of the bind password
    // file set in the properties file because they're part of an exclusive
    // argument set.
    ldapSearch = new LDAPSearch(null, null);
    rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--bindPassword", "password",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that covers a range of use cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidPropertiesFileWithALotOfVariance()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final File propertiesFile = createTempFile(
         "# Hostname and port specified as properties general to any tool.",
         "# Hostname split across multiple lines.",
         "hostname=127.\\",
         " 0.\\",
         " 0.\\",
         " 1",
         "port=" + ds.getListenPort(),
         "",
         "# A port number specific to an unrelated tool.",
         "ldapmodify.port=12345",
         "",
         "# General property for no SSL, but tool-specific property with SSL",
         "useSSL=false",
         "ldapsearch.useSSL=true",
         "",
         "# Use a two-dash identifier to indicate trusting all certificates",
         "--trustAll=true",
         "",
         "# Use a one-dash identifier to specify the bind DN.",
         "-D=cn\\=Directory Manager",
         "",
         "# Use a one-dash tool-specific identifier to specify the password.",
         "ldapsearch.-w=password",
         "",
         "# A property that doesn't have a value",
         "ldapsearch.followReferrals=",
         "",
         "# A property that isn't valid for any tool.",
         "notValidForAnyTool=who cares");

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when an empty properties file is specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyPropertiesFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.delete());

    OutputStream outputStream = new FileOutputStream(propertiesFile);
    outputStream = new PassphraseEncryptedOutputStream("encryption-password",
         outputStream);
    outputStream = new GZIPOutputStream(outputStream);
    outputStream.flush();
    outputStream.close();

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);
    ldapSearch.getPasswordFileReader().addToEncryptionPasswordCache(
         "encryption-password");

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--hostname", "127.0.0.1",
         "--port", String.valueOf(ds.getListenPort()),
         "--bindDN", "cn=Directory Manager",
         "--bindPassword", "password",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that ends when a continued line
   * was expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileEndsWithExpectedContinuation()
         throws Exception
  {
    final File propertiesFile = createTempFile(
         "hostname=\\");

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that has a comment line when a
   * continuation was expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileCommentWithExpectedContinuation()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final File propertiesFile = createTempFile(
         "# The hostname",
         "hostname=\\",
         "# The port",
         "port=" + ds.getListenPort());

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that has a blank line when a
   * continuation was expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileBlankWithExpectedContinuation()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final File propertiesFile = createTempFile(
         "# The hostname",
         "hostname=\\",
         "",
         "# The port",
         "port=" + ds.getListenPort());

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that has a line that starts with
   * whitespace when no continuation was expected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileUnexpectedInitialWhitespace()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final File propertiesFile = createTempFile(
         "# The hostname",
         "hostname=127.0.0.1",
         "",
         "# The port",
         " port=" + ds.getListenPort());

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that has a property line that
   * does not include an equal sign to separate the property name from the
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFilePropertyMissingEquals()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final File propertiesFile = createTempFile(
         "# The hostname",
         "hostname=127.0.0.1",
         "",
         "# The port",
         "--port " + ds.getListenPort());

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that has a property line that has
   * an invalid value for a property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFilePropertyInvalidValue()
         throws Exception
  {
    final File propertiesFile = createTempFile(
         "# The hostname",
         "hostname=127.0.0.1",
         "",
         "# The port",
         "port=invalid");

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior with a properties file that is missing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileMissing()
         throws Exception
  {
    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.delete());

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--baseDN", "",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when trying to generate a properties file when values
   * are provided for a number of arguments, and then verify the ability to use
   * that properties file to actually run the tool when the properties file is
   * inferred via a system property rather than a command-line argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileSpecifiedByJavaProperty()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.delete());
    assertFalse(propertiesFile.exists());

    ResultCode rc = ldapSearch.runTool(
         "--generatePropertiesFile", propertiesFile.getAbsolutePath(),
         "-h", "127.0.0.1",
         "-p", String.valueOf(ds.getListenPort()),
         "-Z",
         "-X",
         "-D", "cn=Directory Manager",
         "-w", "password");
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.length() > 0);

    assertFileHasLine(propertiesFile, "# ldapsearch.hostname={host}");
    assertFileHasLine(propertiesFile, "# ldapsearch.port={port}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindDN={dn}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindPassword={password}");

    assertFileHasLine(propertiesFile, "ldapsearch.hostname=127.0.0.1");
    assertFileHasLine(propertiesFile, "ldapsearch.port=" + ds.getListenPort());
    assertFileHasLine(propertiesFile, "ldapsearch.bindDN=cn=Directory Manager");
    assertFileHasLine(propertiesFile, "ldapsearch.bindPassword=password");


    System.setProperty(ArgumentParser.PROPERTY_DEFAULT_PROPERTIES_FILE_PATH,
         propertiesFile.getAbsolutePath());
    ldapSearch = new LDAPSearch(null, null);

    rc = ldapSearch.runTool(
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    System.clearProperty(ArgumentParser.PROPERTY_DEFAULT_PROPERTIES_FILE_PATH);
  }



  /**
   * Tests the behavior when a properties file is specified by a system property
   * but when the noPropertiesFile option is used to prevent that properties
   * file from being used.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileSpecifiedByJavaPropertyButNoPropertiesOption()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.delete());
    assertFalse(propertiesFile.exists());

    ResultCode rc = ldapSearch.runTool(
         "--generatePropertiesFile", propertiesFile.getAbsolutePath(),
         "-h", "127.0.0.1",
         "-p", String.valueOf(getTestDSWithSSL().getListenPort()), // Not valid.
         "-Z",
         "-X",
         "-D", "cn=Directory Manager",
         "-w", "password");
    assertEquals(rc, ResultCode.SUCCESS);

    assertTrue(propertiesFile.exists());
    assertTrue(propertiesFile.length() > 0);

    assertFileHasLine(propertiesFile, "# ldapsearch.hostname={host}");
    assertFileHasLine(propertiesFile, "# ldapsearch.port={port}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindDN={dn}");
    assertFileHasLine(propertiesFile, "# ldapsearch.bindPassword={password}");

    assertFileHasLine(propertiesFile, "ldapsearch.hostname=127.0.0.1");
    assertFileHasLine(propertiesFile, "ldapsearch.port=" +
         getTestDSWithSSL().getListenPort());
    assertFileHasLine(propertiesFile, "ldapsearch.bindDN=cn=Directory Manager");
    assertFileHasLine(propertiesFile, "ldapsearch.bindPassword=password");


    System.setProperty(ArgumentParser.PROPERTY_DEFAULT_PROPERTIES_FILE_PATH,
         propertiesFile.getAbsolutePath());
    ldapSearch = new LDAPSearch(null, null);

    rc = ldapSearch.runTool(
         "--noPropertiesFile",
         "-h", "127.0.0.1",
         "-p", String.valueOf(ds.getListenPort()),
         "-D", "cn=Directory Manager",
         "-w", "password",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertEquals(rc, ResultCode.SUCCESS);

    System.clearProperty(ArgumentParser.PROPERTY_DEFAULT_PROPERTIES_FILE_PATH);
  }



  /**
   * Tests the behavior when both the propertiesFilePath and noPropertiesFile
   * arguments are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFilePathWithNoPropertiesFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File propertiesFile = createTempFile();

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", propertiesFile.getAbsolutePath(),
         "--noPropertiesFile",
         "-h", "127.0.0.1",
         "-p", String.valueOf(ds.getListenPort()),
         "-D", "cn=Directory Manager",
         "-w", "password",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when both the propertiesFilePath and
   * generatePropertiesFile arguments are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFilePathWithGeneratePropertiesFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File f1 = createTempFile();
    final File f2 = createTempFile();
    assertTrue(f2.delete());

    final ResultCode rc = ldapSearch.runTool(
         "--propertiesFilePath", f1.getAbsolutePath(),
         "--generatePropertiesFile", f2.getAbsolutePath(),
         "-h", "127.0.0.1",
         "-p", String.valueOf(ds.getListenPort()),
         "-D", "cn=Directory Manager",
         "-w", "password",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior when both the generatePropertiesFile and
   * noPropertiesFile arguments are specified.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGeneratePropertiesFileWithNoPropertiesFile()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final LDAPSearch ldapSearch = new LDAPSearch(null, null);

    final File propertiesFile = createTempFile();
    assertTrue(propertiesFile.delete());

    final ResultCode rc = ldapSearch.runTool(
         "--generatePropertiesFile", propertiesFile.getAbsolutePath(),
         "--noPropertiesFile",
         "-h", "127.0.0.1",
         "-p", String.valueOf(ds.getListenPort()),
         "-D", "cn=Directory Manager",
         "-w", "password",
         "--baseDN", "",
         "--scope", "base",
         "(objectClass=*)");
    assertFalse(rc == ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the command-line tool framework when setting a
   * usage argument for the case in which the help argument is provided through
   * a properties file and the usage would otherwise fail without that argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesFileSetsUsageArgument()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final MoveSubtree moveSubtree = new MoveSubtree(out, out);

    final File propertiesFile = createTempFile("help=true");
    final ResultCode rc = moveSubtree.runTool(
         "--propertiesFilepath", propertiesFile.getAbsolutePath());
    assertEquals(rc, ResultCode.SUCCESS);
    assertTrue(out.toByteArray().length > 0);
  }



  /**
   * Ensures that the specified file has the given line.
   *
   * @param  f  The file to examine.
   * @param  s  The line expected to be present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertFileHasLine(final File f, final String s)
          throws Exception
  {
    final BufferedReader reader = new BufferedReader(new FileReader(f));

    try
    {
      while (true)
      {
        final String line = reader.readLine();
        if (line == null)
        {
          throw new AssertionError(
               "Line '" + s + "' not found in file " + f.getAbsolutePath());
        }

        if (line.equals(s))
        {
          return;
        }
      }
    }
    finally
    {
      reader.close();
    }
  }
}
