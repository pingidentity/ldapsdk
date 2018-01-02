/*
 * Copyright 2011-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2018 Ping Identity Corporation
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



import java.io.File;
import java.io.PrintStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.NullOutputStream;
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
    }
    finally
    {
      System.setOut(originalSystemOut);
    }
  }
}
