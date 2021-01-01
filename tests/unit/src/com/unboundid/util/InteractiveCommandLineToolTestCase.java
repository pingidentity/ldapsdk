/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.examples.LDAPSearch;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides test coverage for invoking tools in interactive mode.
 * These tests use the version of {@link LDAPSearch} provided as a core LDAP
 * SDK example rather than the full bells-and-whistles version in the
 * {@code com.unboundid.ldap.sdk.unboundidds.tools} package because the minimal
 * version is more simple and its arguments are much less likely to change in a
 * way that would affect menu choices.
 */
public final class InteractiveCommandLineToolTestCase
       extends LDAPSDKTestCase
{
  // The original input stream used for System.in.
  private final InputStream originalSystemIn = System.in;



  /**
   * Performs any necessary setup for this test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    CommandLineToolInteractiveModeProcessor.setInUnitTest(true);
  }



  /**
   * Cleans up after testing is completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    System.setIn(originalSystemIn);
    CommandLineToolInteractiveModeProcessor.setInUnitTest(false);
  }



  /**
   * Tests the ldapsearch tool with a minimal set of arguments.  Default values
   * for all of the arguments will be provided when possible, and the tool will
   * quit before actually attempting a search.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSearchDefaultValuesQuitBeforeSearch()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    System.setIn(getInputStream(
         "", //  Default to localhost for the server address.
         "5", // Do not attempt to communicate securely.
         String.valueOf(ds.getListenPort()), // Server port
         "3", // Do not attempt to authenticate.
         "dc=example,dc=com", // Search base DN.
         "(objectClass=*)", // First trailing argument.
         "", // No more trailing arguments
         "q")); // Quit.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final LDAPSearch tool = new LDAPSearch(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the ldapsearch tool to run a full search to retrieve the root DSE.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSearchAuthenticatedRootDSESearch()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    System.setIn(getInputStream(
         "localhost", // Server address
         "5", // Do not attempt to communicate securely.
         String.valueOf(ds.getListenPort()), // Server port
         "", // Default to simple authentication.
         "cn=Directory Manager", // Bind DN
         "password", // Bind password
         "", // Empty base DN
         "(objectClass=*)", // First trailing argument
         "*", // Second trailing argument
         "+", // Third trailing argument
         "", // No more trailing arguments
         "3", // Select the scope argument
         "1", // Select a baseObject scope.
         "d", // Display the command that will be run.
         "", // Return from displaying the command.
         "r")); // Run the tool.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final LDAPSearch tool = new LDAPSearch(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the ldapsearch tool to establish a secure connection over SSL with no
   * client certificate and blind trust of the server certificate.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSearchSSLBlindTrust()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    System.setIn(getInputStream(
         "localhost", // Server address
         "2", // Use SSL with non-default settings
         "1", // Do not provide a client certificate
         "4", // Blindly trust any server certificate
         String.valueOf(ds.getListenPort()), // Server port
         "1", //  Use simple authentication.
         "cn=Directory Manager", // Bind DN
         "password", // Bind password
         "", // Base DN
         "(objectClass=*)", // First trailing argument -- filter
         "*", // Second trailing argument -- return all user attributes
         "+", // Second trailing argument -- return all operational attributes
         "", // No more trailing arguments.
         "3", // Change scope
         "1", // BaseObject scope.
         "4", // Change follow referrals
         "1", // Yes to follow referrals
         "d", // Display the arguments.
         "", // Return from displaying the arguments.
         "r")); // Run the tool with the selected arguments.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final LDAPSearch tool = new LDAPSearch(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the ldapsearch tool to establish a secure connection over StartTLS
   * with a client certificate and trust based on a JKS keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSearchStartTLSWithJKSTrust()
         throws Exception
  {
    // Create the SSL socket factory to use for StartTLS.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File clientKeyStore   = new File(resourceDir, "client.keystore");
    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"), new TrustAllTrustManager());

    // Create the in-memory directory server instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(
         "LDAP+StartTLS", null, 0, serverSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    System.setIn(getInputStream(
         "localhost", // Server address
         "4", // Use StartTLS with non-default settings
         "2", // Present a client certificate from a JKS keystore
         clientKeyStore.getAbsolutePath(),
         "password", // PIN for the client keystore
         "", // No certificate nickname
         "2", // Don't authenticate via SASL external
         "2", // Trust using a JKS truststore
         serverKeyStore.getAbsolutePath(),
         "", // No trust store PIN required
         String.valueOf(ds.getListenPort()), // Server port
         "2", // Use SASL authentication
         "3", // Use SASL PLAIN authentication
         "dn:cn=Directory Manager", // Authentication ID
         "", // No authorization ID
         "password", // Bind password
         "", // Base DN
         "(objectClass=*)", // First trailing argument -- filter
         "*", // Second trailing argument -- return all user attributes
         "+", // Second trailing argument -- return all operational attributes
         "", // No more trailing arguments.
         "3", // Change scope
         "1", // BaseObject scope.
         "4", // Change follow referrals
         "1", // Yes to follow referrals
         "d", // Display the arguments.
         "", // Return from displaying the arguments.
         "r")); // Run the tool with the selected arguments.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final LDAPSearch tool = new LDAPSearch(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));

    ds.shutDown(true);
  }



  /**
   * Tests the ldapsearch tool to establish a secure connection over StartTLS
   * with a client certificate and trust based on a PKCS#12 keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSearchStartTLSWithPKCS12Trust()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    // Create the SSL socket factory to use for StartTLS.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore = new File(resourceDir, "keystore.p12");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(keyStore, "password".toCharArray(),
              "PKCS12", "server-cert"), new TrustAllTrustManager());

    System.setIn(getInputStream(
         "localhost", // Server address
         "4", // Use StartTLS with non-default settings
         "2", // Present a client certificate from a JKS keystore
         keyStore.getAbsolutePath(),
         "password", // PIN for the client keystore
         "server-cert", // Certificate nickname
         "2", // Don't authenticate via SASL external
         "3", // Trust using a JKS truststore
         keyStore.getAbsolutePath(),
         "password", // Trust store PIN
         String.valueOf(ds.getListenPort()), // Server port
         "3", // Use SASL authentication
         "3", // Use SASL PLAIN authentication
         "dn:cn=Directory Manager", // Authentication ID
         "dn:cn=Directory Manager", // Authorization ID
         "password", // Bind password
         "q")); // Quit.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final LDAPSearch tool = new LDAPSearch(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the ldapsearch tool with failed attempts at CRAM-MD5 and DIGEST-MD5
   * before successful simple authentication.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSearchMD5Coverage()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    System.setIn(getInputStream(
         "localhost", // Server address
         "5", // No communication encryption
         String.valueOf(ds.getListenPort()),
         "2", // Use SASL authentication
         "1", // Use CRAM-MD5
         "dn:cn=Directory Manager", // Authentication ID
         "password", // Password
         "1", // Re-try LDAP settings
         "localhost", // Directory server address.
         "5", // No communication encryption
         String.valueOf(ds.getListenPort()),
         "2", // Use SASL authentication
         "2", // Use DIGEST-MD5
         "dn:cn=Directory Manager", // Authentication ID
         "dn:cn=Directory Manager", // Authorization ID
         "EXAMPLE-REALM", // Example realm
         "password", // Password
         "1", // Re-try LDAP settings
         "localhost", // Directory server address.
         "5", // No communication encryption
         String.valueOf(ds.getListenPort()),
         "1", // Use LDAP simple authentication
         "", // Bind DN is no DN -- there won't be a password prompt
         "invalid", // Invalid base DN
         "", // Empty base DN
         "t", // Trailing arguments
         "(objectClass=*)", // First trailing argument
         "", // No more trailing arguments.
         "3", // Change scope
         "1", // BaseObject scope.
         "t", // Specify trailing arguments again.
         "(objectClass=*)", // First trailing argument -- the filter
         "*", // Second trailing argument -- all user attributes
         "+", // Third trailing argument -- all operational attributes
         "", // No more trailing arguments
         "d", // Display the arguments.
         "", // Return from displaying the arguments.
         "r")); // Run the tool with the selected arguments.

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final LDAPSearch tool = new LDAPSearch(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the behavior with a custom tool that uses all argument types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllArgumentTypes()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final File testDir = createTempDir();
    final File testFile = createTempFile();

    System.setIn(getInputStream(
         "", // Default directory server address
         "5", // No communication encryption
         String.valueOf(ds.getListenPort()),
         "3", // No authentication
         "0", // The result code value

         "1", // Select the argument list argument
         "", // No argument list value
         "1", // Select the single-valued argument list argument
         "invalid", // Invalid argument list value
         "--foo fooValue", // Valid argument list value

         "2", // Select the multi-valued argument list argument
         "--bar value1", // The first value
         "--bar value2", // The second value
         "", // No more values

         "3", // Select the boolean argument
         "", // No boolean value
         "3", // Select the boolean argument
         "invalid", // Invalid boolean value
         "1", // Valid boolean value

         "4", // Select the boolean value argument
         "", // No boolean value
         "4", // Select the boolean value argument
         "invalid", // Invalid boolean argument value
         "2", // Valid boolean argument value

         "5", // Select the single-valued control argument
         "", // No control value
         "5", // Select the control argument
         "1.2.3.4", // A valid control value

         "6", // Select the multi-valued control argument
         "1.2.3.4", // The first value
         "1.2.3.5:true", // The second value
         "", // No more values

         "7", // Select the single-valued DN argument
         "invalid", // An invalid DN value
         "dc=example,dc=com", // A valid DN value

         "8", // Select the multi-valued DN argument
         "invalid", // An invalid DN value
         "dc=example,dc=com", // A valid DN value
         "o=example.com", // Another valid DN value
         "", // No more values


         "9", // Select the duration argument
         "", // No duration value
         "9", // Select the duration argument
         "invalid", // An invalid duration value
         "10 seconds", // A valid duration value

         "10", // Select the single-valued file argument,
         "", // No file value
         "10", // Select the single-valued file argument,
         testDir.getAbsolutePath(), // An invalid valid file value
         testFile.getAbsolutePath(), // A valid file value

         "11", // Select the multi-valued file argument,
         testDir.getAbsolutePath(), // A valid file value
         testFile.getAbsolutePath(), // Another valid file value
         "", // No more values

         "12", // Select the single-valued filter argument
         "", // No filter value
         "12", // Select the filter argument
         "invalid", // An invalid filter value
         "(objectClass=*)", // A valid filter value

         "13", // Select the multi-valued filter argument
         "(objectClass=*)", // A valid filter value
         "(objectClass=ldapSubentry)", // Another valid filter value
         "", // No more filter values

         "14", // Select the single-valued integer argument
         "", // No integer value
         "14", // Select the single-valued integer argument
         "invalid", // An invalid integer value
         "1234", // A valid integer value

         "15", // Select the multi-valued integer argument
         "1234", // A valid integer value
         "5678", // Another valid integer value
         "", // No more values

         "16", // Select the scope argument
         "invalid", // An invalid scope value
         "1", // The baseObject scope

         "17", // Select the single-valued string argument
         "", // No string value
         "17", // Select the string argument
         "valid", // A valid string value

         "18", // Select the multi-valued string argument with open options
         "value1", // The first valid value
         "value2", // A second first valid value
         "", // No more values

         "19", // Select the multi-valued string argument with fixed options
         "1", // The first valid value
         "2", // A second first valid value
         "", // No more values

         "t", // Invalid choice -- the tool doesn't support trailing arguments
         "invalid", // Invalid choice in any case
         "r")); // Run the tool with the selected arguments

    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    final TestLDAPCommandLineTool tool = new TestLDAPCommandLineTool(out, out);
    final ResultCode resultCode = tool.runTool();

    assertEquals(resultCode, ResultCode.SUCCESS,
         "Tool output:  " + StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Retrieves an input stream that may be used as standard input to supply the
   * specified set of lines.
   *
   * @param  lines  The lines that will be supplied to the input stream.
   *
   * @return  The input stream that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static InputStream getInputStream(final String... lines)
          throws Exception
  {
    final ByteStringBuffer buffer = new ByteStringBuffer();
    for (final String s : lines)
    {
      buffer.append(s);
      buffer.append(StaticUtils.EOL_BYTES);
    }

    return new ByteArrayInputStream(buffer.toByteArray());
  }
}
