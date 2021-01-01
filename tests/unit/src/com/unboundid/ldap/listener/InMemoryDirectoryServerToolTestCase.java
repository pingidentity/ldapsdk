/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.util.EnumSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.NullOutputStream;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a basic set of test coverage for the in-memory
 * directory server tool.
 */
public final class InMemoryDirectoryServerToolTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    final InMemoryDirectoryServerTool tool =
         new InMemoryDirectoryServerTool(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Provides test coverage for the default main method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultMain()
         throws Exception
  {
    InMemoryDirectoryServerTool.main(
         "--baseDN", "dc=example,dc=com",
         "--dontStart");
  }



  /**
   * Provides basic coverage when invoking the tool with the usage argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUsage()
         throws Exception
  {
    final String[] args = { "--help" };
    assertEquals(InMemoryDirectoryServerTool.main(args, null, null),
         ResultCode.SUCCESS);
  }



  /**
   * Tests methods to obtain basic coverage for the class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicCoverage()
         throws Exception
  {
    final InMemoryDirectoryServerTool tool =
         new InMemoryDirectoryServerTool(null, null);

    assertNotNull(tool.getToolName());
    assertNotNull(tool.getToolDescription());
    assertNotNull(tool.getExampleUsages());
  }



  /**
   * Tests the in-memory server with a full set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConfig()
         throws Exception
  {
    final File accessLogFile = createTempFile();
    final File jsonAccessLogFile = createTempFile();
    final File ldapDebugLogFile = createTempFile();
    final File codeLogFile = createTempFile();

    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "server.keystore");
    final File trustStoreFile = new File(resourceDir, "server.truststore");

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
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: user",
         "cn: Test User",
         "userPassword: password");

    final InMemoryDirectoryServerTool tool =
         new InMemoryDirectoryServerTool(null, null);

    assertNull(tool.getDirectoryServer());

    tool.runTool(
         "--baseDN", "dc=example,dc=com",
         "--ldifFile", ldifFile.getAbsolutePath(),
         "--additionalBindDN", "cn=Directory Manager",
         "--additionalBindPassword", "password",
         "--maxChangeLogEntries", "100",
         "--accessLogFile", accessLogFile.getAbsolutePath(),
         "--jsonAccessLogFile", jsonAccessLogFile.getAbsolutePath(),
         "--ldapDebugLogFile", ldapDebugLogFile.getAbsolutePath(),
         "--codeLogFile", codeLogFile.getAbsolutePath(),
         "--useDefaultSchema",
         "--useSSL",
         "--keyStorePath", keyStoreFile.getAbsolutePath(),
         "--keyStoreType", "JKS",
         "--keyStorePassword", "password",
         "--trustStorePath", trustStoreFile.getAbsolutePath(),
         "--trustStoreType", "JKS",
         "--vendorName", "Example Corp.",
         "--vendorVersion", "1.2.3",
         "--dontStart");

    final InMemoryDirectoryServer ds = tool.getDirectoryServer();
    assertNotNull(ds);

    assertEquals(ds.getListenPort(), -1);

    ds.startListening();

    assertTrue(ds.getListenPort() > 0);

    final LDAPConnection conn = ds.getConnection();

    conn.bind("cn=Directory Manager", "password");

    conn.add(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");

    assertEntryExists(conn, "");
    assertEntryExists(conn, "cn=changelog");
    assertEntryExists(conn, "dc=example,dc=com");
    assertEntryExists(conn, "ou=People,dc=example,dc=com");
    assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");

    conn.close();

    assertTrue(accessLogFile.exists());
    assertTrue(accessLogFile.length() > 0L);

    assertTrue(jsonAccessLogFile.exists());
    assertTrue(jsonAccessLogFile.length() > 0L);

    assertTrue(ldapDebugLogFile.exists());
    assertTrue(ldapDebugLogFile.length() > 0L);

    ds.shutDown(true);
  }



  /**
   * Tests the in-memory server with a full set of arguments and using StartTLS
   * instead of SSL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullConfigStartTLS()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "server.keystore");
    final File trustStoreFile = new File(resourceDir, "server.truststore");

    final PrintStream originalSystemOut = System.out;
    try
    {
      System.setOut(NullOutputStream.getPrintStream());
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
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: user",
           "cn: Test User",
           "userPassword: password");

      final InMemoryDirectoryServerTool tool =
           new InMemoryDirectoryServerTool(null, null);

      assertNull(tool.getDirectoryServer());

      tool.runTool(
           "--baseDN", "dc=example,dc=com",
           "--ldifFile", ldifFile.getAbsolutePath(),
           "--additionalBindDN", "cn=Directory Manager",
           "--additionalBindPassword", "password",
           "--maxChangeLogEntries", "100",
           "--accessLogToStandardOut",
           "--ldapDebugLogToStandardOut",
           "--useDefaultSchema",
           "--useStartTLS",
           "--keyStorePath", keyStoreFile.getAbsolutePath(),
           "--keyStoreType", "JKS",
           "--keyStorePassword", "password",
           "--trustStorePath", trustStoreFile.getAbsolutePath(),
           "--trustStoreType", "JKS",
           "--vendorName", "Example Corp.",
           "--vendorVersion", "1.2.3",
           "--maxConcurrentConnections", "1234",
           "--passwordAttribute", "userPassword",
           "--defaultPasswordEncoding", "SSHA256",
           "--sizeLimit", "5678",
           "--allowedOperationType", "add",
           "--allowedOperationType", "bind",
           "--allowedOperationType", "delete",
           "--allowedOperationType", "modify",
           "--allowedOperationType", "search",
           "--authenticationRequiredOperationType", "add",
           "--authenticationRequiredOperationType", "delete",
           "--authenticationRequiredOperationType", "modify",
           "--dontStart");

      final InMemoryDirectoryServer ds = tool.getDirectoryServer();
      assertNotNull(ds);

      assertEquals(ds.getListenPort(), -1);

      ds.startListening();

      assertTrue(ds.getListenPort() > 0);

      final LDAPConnection conn = ds.getConnection();

      conn.bind("cn=Directory Manager", "password");

      conn.add(
           "dn: ou=test,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test");

      assertEntryExists(conn, "");
      assertEntryExists(conn, "cn=changelog");
      assertEntryExists(conn, "dc=example,dc=com");
      assertEntryExists(conn, "ou=People,dc=example,dc=com");
      assertEntryExists(conn, "uid=test.user,ou=People,dc=example,dc=com");

      final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

      final ExtendedResult startTLSResult = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));

      assertEquals(startTLSResult.getResultCode(),
           ResultCode.SUCCESS);

      assertEntryExists(conn, "");
      assertEntryExists(conn, "dc=example,dc=com");

      conn.close();

      ds.shutDown(true);

      final InMemoryDirectoryServerConfig config = ds.getConfig();

      assertNotNull(ds.getPrimaryPasswordEncoder());
      assertEquals(ds.getPrimaryPasswordEncoder().getPrefix(), "{SSHA256}");

      assertNotNull(config.getSecondaryPasswordEncoders());
      assertFalse(config.getSecondaryPasswordEncoders().isEmpty());

      assertEquals(config.getMaxConnections(), 1234);

      assertEquals(config.getMaxSizeLimit(), 5678);

      assertNotNull(config.getAllowedOperationTypes());
      assertEquals(config.getAllowedOperationTypes(),
           EnumSet.of(OperationType.ADD, OperationType.BIND,
                OperationType.DELETE, OperationType.MODIFY,
                OperationType.SEARCH));

      assertNotNull(config.getAuthenticationRequiredOperationTypes());
      assertEquals(config.getAuthenticationRequiredOperationTypes(),
           EnumSet.of(OperationType.ADD, OperationType.DELETE,
                OperationType.MODIFY));
    }
    finally
    {
      System.setOut(originalSystemOut);
    }
  }



  /**
   * Tests the behavior when using a self-signed certificate for SSL-based
   * communication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateSelfSignedCertificateWithSSL()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final PrintStream originalSystemOut = System.out;
    try
    {
      System.setOut(NullOutputStream.getPrintStream());
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
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: user",
           "cn: Test User",
           "userPassword: password");

      final InMemoryDirectoryServerTool tool =
           new InMemoryDirectoryServerTool(null, null);

      assertNull(tool.getDirectoryServer());

      final File schemaFile = createTempFile(
           Schema.getDefaultStandardSchema().getSchemaEntry().toLDIF());

      tool.runTool(
           "--baseDN", "dc=example,dc=com",
           "--ldifFile", ldifFile.getAbsolutePath(),
           "--additionalBindDN", "cn=Directory Manager",
           "--additionalBindPassword", "password",
           "--maxChangeLogEntries", "100",
           "--jsonAccessLogToStandardOut",
           "--ldapDebugLogToStandardOut",
           "--useSchemaFile", schemaFile.getAbsolutePath(),
           "--useSSL",
           "--generateSelfSignedCertificate",
           "--vendorName", "Example Corp.",
           "--vendorVersion", "1.2.3",
           "--dontStart");

      final InMemoryDirectoryServer ds = tool.getDirectoryServer();
      assertNotNull(ds);

      assertEquals(ds.getListenPort(), -1);

      ds.startListening();

      assertTrue(ds.getListenPort() > 0);

      final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      final LDAPConnection conn = new LDAPConnection(
           sslUtil.createSSLSocketFactory(), "127.0.0.1", ds.getListenPort());

      assertNotNull(conn.getRootDSE());

      conn.close();

      ds.shutDown(true);
    }
    finally
    {
      System.setOut(originalSystemOut);
    }
  }



  /**
   * Tests the behavior when using a custom schema file that has issues when
   * validation messages are not suppressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaFileWithIssuesValidationMessagesNotSuppressed()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.15 " +
              "DESC 'Directory String' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.16 " +
              "DESC 'DIT Content Rule Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.17 " +
              "DESC 'DIT Structure Rule Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.31 " +
              "DESC 'Matching Rule Use Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring " +
              "Assertion' )",
         "matchingRules: ( 1.3.6.1.4.1.1466.109.114.2 " +
              "NAME 'caseIgnoreIA5Match' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
         "matchingRules: ( 1.3.6.1.4.1.1466.109.114.3 NAME " +
              "'caseIgnoreIA5SubstringsMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
         "matchingRules: ( 2.5.13.0 NAME 'objectIdentifierMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "matchingRules: ( 2.5.13.2 NAME 'caseIgnoreMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRules: ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRules: ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
         "matchingRules: ( 2.5.13.29 NAME 'integerFirstComponentMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
         "matchingRules: ( 2.5.13.30 " +
              "NAME 'objectIdentifierFirstComponentMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "attributeTypes: ( 2.5.4.0 NAME 'objectClass' " +
              "EQUALITY objectIdentifierMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "attributeTypes: ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch " +
              "SUBSTR caseIgnoreSubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 2.5.4.3 NAME 'cn' SUP name )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25 NAME 'dc' " +
              "EQUALITY caseIgnoreIA5Match " +
              "SUBSTR caseIgnoreIA5SubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
         "attributeTypes: ( 2.5.21.6 NAME 'objectClasses' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.5 NAME 'attributeTypes' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.4 NAME 'matchingRules' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.8 NAME 'matchingRuleUse' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )",
         "attributeTypes: ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' " +
              "EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.2 NAME 'dITContentRules' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.1 NAME 'dITStructureRules' " +
              "EQUALITY integerFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.17",
         "  USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.7 NAME 'nameForms' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.35",
         "  USAGE directoryOperation )",
         "objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
         "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1 NAME 'ldapSubEntry' " +
              "SUP top STRUCTURAL MAY cn )",
         "objectClasses: ( 2.5.20.1 NAME 'subschema' AUXILIARY " +
              "MAY ( dITStructureRules $ nameForms $ ditContentRules $ " +
              "objectClasses $ attributeTypes $ matchingRules $ " +
              "matchingRuleUse ) )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top " +
              "STRUCTURAL MUST dc )",
         "objectClasses: ( 1.2.3.4 NAME 'custom-oc' SUP top " +
              "STRUCTURAL MAY undefined-at )");

    final PrintStream originalSystemOut = System.out;
    try
    {
      System.setOut(NullOutputStream.getPrintStream());
      final File ldifFile = createTempFile(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final InMemoryDirectoryServerTool tool =
           new InMemoryDirectoryServerTool(out, out);

      assertNull(tool.getDirectoryServer());

      tool.runTool(
           "--baseDN", "dc=example,dc=com",
           "--ldifFile", ldifFile.getAbsolutePath(),
           "--additionalBindDN", "cn=Directory Manager",
           "--additionalBindPassword", "password",
           "--useSchemaFile", schemaFile.getAbsolutePath(),
           "--vendorName", "Example Corp.",
           "--vendorVersion", "1.2.3",
           "--dontStart");

      boolean foundBulletPoint = false;
      assertTrue(out.size() > 0);
      final String outString = StaticUtils.toUTF8String(out.toByteArray());
      for (final String line : StaticUtils.stringToLines(outString))
      {
        if (line.startsWith("* "))
        {
          foundBulletPoint = true;
          break;
        }
      }

      assertTrue(foundBulletPoint,
           "Did not find a bullet point in the output, which suggests that " +
                "either no attempt was made to validate schema definitions, " +
                "or that no issues were found.");
    }
    finally
    {
      System.setOut(originalSystemOut);
    }
  }



  /**
   * Tests the behavior when using a custom schema file that has issues when
   * validation messages are suppressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaFileWithIssuesValidationMessagesSuppressed()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.15 " +
              "DESC 'Directory String' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.16 " +
              "DESC 'DIT Content Rule Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.17 " +
              "DESC 'DIT Structure Rule Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.31 " +
              "DESC 'Matching Rule Use Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax " +
              "Description' )",
         "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring " +
              "Assertion' )",
         "matchingRules: ( 1.3.6.1.4.1.1466.109.114.2 " +
              "NAME 'caseIgnoreIA5Match' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
         "matchingRules: ( 1.3.6.1.4.1.1466.109.114.3 NAME " +
              "'caseIgnoreIA5SubstringsMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
         "matchingRules: ( 2.5.13.0 NAME 'objectIdentifierMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "matchingRules: ( 2.5.13.2 NAME 'caseIgnoreMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRules: ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "matchingRules: ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
         "matchingRules: ( 2.5.13.29 NAME 'integerFirstComponentMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
         "matchingRules: ( 2.5.13.30 " +
              "NAME 'objectIdentifierFirstComponentMatch' " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "attributeTypes: ( 2.5.4.0 NAME 'objectClass' " +
              "EQUALITY objectIdentifierMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "attributeTypes: ( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch " +
              "SUBSTR caseIgnoreSubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 2.5.4.3 NAME 'cn' SUP name )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25 NAME 'dc' " +
              "EQUALITY caseIgnoreIA5Match " +
              "SUBSTR caseIgnoreIA5SubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
         "attributeTypes: ( 2.5.21.6 NAME 'objectClasses' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.5 NAME 'attributeTypes' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.4 NAME 'matchingRules' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.8 NAME 'matchingRuleUse' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )",
         "attributeTypes: ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' " +
              "EQUALITY objectIdentifierFirstComponentMatch",
         "  SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.2 NAME 'dITContentRules' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.1 NAME 'dITStructureRules' " +
              "EQUALITY integerFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.17",
         "  USAGE directoryOperation )",
         "attributeTypes: ( 2.5.21.7 NAME 'nameForms' " +
              "EQUALITY objectIdentifierFirstComponentMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.35",
         "  USAGE directoryOperation )",
         "objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
         "objectClasses: ( 2.16.840.1.113719.2.142.6.1.1 NAME 'ldapSubEntry' " +
              "SUP top STRUCTURAL MAY cn )",
         "objectClasses: ( 2.5.20.1 NAME 'subschema' AUXILIARY " +
              "MAY ( dITStructureRules $ nameForms $ ditContentRules $ " +
              "objectClasses $ attributeTypes $ matchingRules $ " +
              "matchingRuleUse ) )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top " +
              "STRUCTURAL MUST dc )",
         "objectClasses: ( 1.2.3.4 NAME 'custom-oc' SUP top " +
              "STRUCTURAL MAY undefined-at )");

    final PrintStream originalSystemOut = System.out;
    try
    {
      System.setOut(NullOutputStream.getPrintStream());
      final File ldifFile = createTempFile(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final InMemoryDirectoryServerTool tool =
           new InMemoryDirectoryServerTool(out, out);

      assertNull(tool.getDirectoryServer());

      tool.runTool(
           "--baseDN", "dc=example,dc=com",
           "--ldifFile", ldifFile.getAbsolutePath(),
           "--additionalBindDN", "cn=Directory Manager",
           "--additionalBindPassword", "password",
           "--useSchemaFile", schemaFile.getAbsolutePath(),
           "--vendorName", "Example Corp.",
           "--vendorVersion", "1.2.3",
           "--doNotValidateSchemaDefinitions",
           "--dontStart");

      boolean foundBulletPoint = false;
      assertTrue(out.size() > 0);
      final String outString = StaticUtils.toUTF8String(out.toByteArray());
      for (final String line : StaticUtils.stringToLines(outString))
      {
        if (line.startsWith("* "))
        {
          fail("Found what appears to be a message about a schema issue, " +
               "even through schema validation should have been disabled.  " +
               "The first line of the message is:  " + line);
        }
      }
    }
    finally
    {
      System.setOut(originalSystemOut);
    }
  }
}
