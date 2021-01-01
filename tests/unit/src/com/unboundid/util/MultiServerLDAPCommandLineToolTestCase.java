/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.SingleServerSet;



/**
 * This class provides a set of test cases for the multi-server LDAP command
 * line tool.
 */
public final class MultiServerLDAPCommandLineToolTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to work with two servers using only a name prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTwoServersWithPrefix()
         throws Exception
  {
    final String[] prefixes = { "source", "target" };
    final String[] suffixes = null;

    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--sourceHostname", "source.example.com",
         "--sourcePort", "123",
         "--sourceBindDN", "cn=Source Bind DN",
         "--sourceBindPassword", "sourcePassword",

         "--targetHostname", "target.example.com",
         "--targetPort", "456",
         "--targetUseSSL",
         "--targetTrustAll",
         "--targetBindDN", "",
         "--targetSASLOption", "mech=PLAIN",
         "--targetSASLOption", "authID=dn:cn=Target Bind DN",
         "--targetBindPassword", "targetPassword");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(t.getConnectionOptions());

    final ServerSet sourceSet = t.createServerSet(0);
    assertNotNull(sourceSet);
    assertTrue(sourceSet instanceof SingleServerSet);

    final SingleServerSet sourceSingleSet = (SingleServerSet) sourceSet;
    assertEquals(sourceSingleSet.getAddress(), "source.example.com");
    assertEquals(sourceSingleSet.getPort(), 123);
    assertNotNull(sourceSingleSet.getSocketFactory());

    final ServerSet targetSet = t.createServerSet(1);
    assertNotNull(targetSet);
    assertTrue(targetSet instanceof SingleServerSet);

    final SingleServerSet targetSingleSet = (SingleServerSet) targetSet;
    assertEquals(targetSingleSet.getAddress(), "target.example.com");
    assertEquals(targetSingleSet.getPort(), 456);
    assertNotNull(targetSingleSet.getSocketFactory());

    assertNull(t.createSSLUtil(0));

    assertNotNull(t.createSSLUtil(1));

    final BindRequest sourceBindRequest = t.createBindRequest(0);
    assertTrue(sourceBindRequest instanceof SimpleBindRequest);

    final SimpleBindRequest sourceSimpleRequest =
         (SimpleBindRequest) sourceBindRequest;
    assertEquals(new DN(sourceSimpleRequest.getBindDN()),
         new DN("cn=Source Bind DN"));
    assertEquals(sourceSimpleRequest.getPassword().stringValue(),
         "sourcePassword");

    final BindRequest targetBindRequest = t.createBindRequest(1);
    assertTrue(targetBindRequest instanceof PLAINBindRequest);

    final PLAINBindRequest targetPLAINRequest =
         (PLAINBindRequest) targetBindRequest;
    assertEquals(targetPLAINRequest.getAuthenticationID(),
         "dn:cn=Target Bind DN");
    assertEquals(targetPLAINRequest.getPasswordString(),
         "targetPassword");
  }



  /**
   * Tests the ability to work with three servers using only a name suffix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testThreeServersWithSuffix()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File passwordFile2   = createTempFile("password2");
    final File keyStoreFile2   = new File(resourceDir, "client.keystore");
    final File trustStoreFile2 = new File(resourceDir, "client.truststore");
    final File keyStoreFile3   = new File(resourceDir, "keystore.p12");
    final File pinFile3        = createTempFile("password");
    final File trustStoreFile3 = new File(resourceDir, "client.truststore");

    final String[] prefixes = null;
    final String[] suffixes = { "1", "2", "3" };

    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--hostname1", "ds1.example.com",
         "--port1", "1389",
         "--bindDN1", "uid=user.1,ou=People,dc=example,dc=com",
         "--bindPassword1", "password1",

         "--hostname2", "ds2.example.com",
         "--port2", "2636",
         "--useSSL2",
         "--saslOption2", "mech=PLAIN",
         "--saslOption2", "authID=dn:uid=user.2,ou=People,dc=example,dc=com",
         "--bindPasswordFile2", passwordFile2.getAbsolutePath(),
         "--keyStorePath2", keyStoreFile2.getAbsolutePath(),
         "--keyStorePassword2", "password",
         "--keyStoreFormat2", "JKS",
         "--trustStorePath2", trustStoreFile2.getAbsolutePath(),
         "--trustStorePassword2", "password",
         "--trustStoreFormat2", "JKS",
         "--certNickname2", "client-cert",

         "--hostname3", "ds3.example.com",
         "--port3", "3389",
         "--useStartTLS3",
         "--keyStorePath3", keyStoreFile3.getAbsolutePath(),
         "--keyStorePasswordFile3", pinFile3.getAbsolutePath(),
         "--keyStoreFormat3", "PKCS12",
         "--trustStorePath3", trustStoreFile3.getAbsolutePath(),
         "--trustStorePasswordFile3", pinFile3.getAbsolutePath(),
         "--trustStoreFormat3", "PKCS12");
    assertEquals(resultCode, ResultCode.SUCCESS);

    assertNotNull(t.getConnectionOptions());

    final ServerSet set1 = t.createServerSet(0);
    assertNotNull(set1);
    assertTrue(set1 instanceof SingleServerSet);

    final SingleServerSet singleSet1 = (SingleServerSet) set1;
    assertEquals(singleSet1.getAddress(), "ds1.example.com");
    assertEquals(singleSet1.getPort(), 1389);
    assertNotNull(singleSet1.getSocketFactory());

    final ServerSet set2 = t.createServerSet(1);
    assertNotNull(set2);
    assertTrue(set2 instanceof SingleServerSet);

    final SingleServerSet singleSet2 = (SingleServerSet) set2;
    assertEquals(singleSet2.getAddress(), "ds2.example.com");
    assertEquals(singleSet2.getPort(), 2636);
    assertNotNull(singleSet2.getSocketFactory());

    final ServerSet set3 = t.createServerSet(2);
    assertNotNull(set3);
    assertTrue(set3 instanceof SingleServerSet);

    final SingleServerSet singleSet3 = (SingleServerSet) set3;
    assertEquals(singleSet3.getAddress(), "ds3.example.com");
    assertEquals(singleSet3.getPort(), 3389);
    assertNotNull(singleSet3.getSocketFactory());

    assertNull(t.createSSLUtil(0));

    assertNotNull(t.createSSLUtil(1));

    assertNotNull(t.createSSLUtil(2));

    final BindRequest sourceBindRequest = t.createBindRequest(0);
    assertTrue(sourceBindRequest instanceof SimpleBindRequest);

    final SimpleBindRequest sourceSimpleRequest =
         (SimpleBindRequest) sourceBindRequest;
    assertEquals(new DN(sourceSimpleRequest.getBindDN()),
         new DN("uid=user.1,ou=People,dc=example,dc=com"));
    assertEquals(sourceSimpleRequest.getPassword().stringValue(),
         "password1");

    final BindRequest targetBindRequest = t.createBindRequest(1);
    assertTrue(targetBindRequest instanceof PLAINBindRequest);

    final PLAINBindRequest targetPLAINRequest =
         (PLAINBindRequest) targetBindRequest;
    assertEquals(targetPLAINRequest.getAuthenticationID(),
         "dn:uid=user.2,ou=People,dc=example,dc=com");
    assertEquals(targetPLAINRequest.getPasswordString(),
         "password2");

    assertNull(t.createBindRequest(2));
  }



  /**
   * Tests the behavior when the sets of name prefixes and suffixes are both
   * {@code null}.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPrefixesAndSuffixesNull()
         throws Exception
  {
    new TestMultiServerLDAPCommandLineTool(null, null);
  }



  /**
   * Tests the behavior when the sets of name prefixes and suffixes are both
   * empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPrefixesAndSuffixesEmpty()
         throws Exception
  {
    new TestMultiServerLDAPCommandLineTool(new String[0], new String[0]);
  }



  /**
   * Tests the behavior when the sets of name prefixes and suffixes have
   * different sizes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testPrefixesAndSuffixesSizeMismatch()
         throws Exception
  {
    final String[] prefixes = { "source", "target" };
    final String[] suffixes = { "1", "2", "3" };

    new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);
  }



  /**
   * Tests the ability to create an unencrypted LDAP connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateConnection()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnectionPool pool = t.getConnectionPool(0, 1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();
  }



  /**
   * Tests the ability to create an SSL-encrypted LDAP connection.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSSLConnection()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestSSLPort()),
         "--testUseSSL",
         "--testTrustAll",
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();

    final LDAPConnectionPool pool = t.getConnectionPool(0, 1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the ability to create a StartTLS-encrypted LDAP connection.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateStartTLSConnection()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testUseStartTLS",
         "--testTrustAll",
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();

    final LDAPConnectionPool pool = t.getConnectionPool(0, 1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a connection with invalid
   * credentials.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testCreateConnectionInvalidCredentials()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           "Simulating a failure because no server is available.");
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", "wrong-" + getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();
  }



  /**
   * Tests the behavior when trying to create a connection with an empty
   * password file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testCreateConnectionEmptyPasswordFile()
         throws Exception
  {
    final File passwordFile = createTempFile();

    if (! isDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           "Simulating a failure because no server is available.");
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testBindDN", getTestBindDN(),
         "--testBindPasswordFile", passwordFile.getAbsolutePath());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();
  }



  /**
   * Tests the behavior when trying to create a StartTLS-encrypted LDAP
   * connection when the server certificate isn't trusted.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testCreateStartTLSConnectionUntrusted()
         throws Exception
  {
    final File trustStoreFile = createTempFile();

    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           "Simulating a failure because no server is available.");
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testUseStartTLS",
         "--testTrustStorePath", trustStoreFile.getAbsolutePath(),
         "--testTrustStorePassword", "password",
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();
  }



  /**
   * Tests the behavior when trying to create a StartTLS-encrypted LDAP
   * connection when the key store password file is empty.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testCreateStartTLSConnectionEmptyKeyStorePasswordFile()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStoreFile = new File(resourceDir, "client.keystore");
    final File keyStorePasswordFile = createTempFile();

    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           "Simulating a failure because no server is available.");
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testUseStartTLS",
         "--testTrustAll",
         "--testKeyStorePath", keyStoreFile.getAbsolutePath(),
         "--testKeyStorePasswordFile", keyStorePasswordFile.getAbsolutePath(),
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();
  }



  /**
   * Tests the behavior when trying to create a StartTLS-encrypted LDAP
   * connection when the trust store password file is empty.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions =  { LDAPException.class })
  public void testCreateStartTLSConnectionEmptyTrustStorePasswordFile()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStoreFile = new File(resourceDir, "client.truststore");
    final File trustStorePasswordFile = createTempFile();

    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           "Simulating a failure because no server is available.");
    }

    final String[] prefixes = { "test" };
    final String[] suffixes = null;
    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--testHostname", getTestHost(),
         "--testPort", String.valueOf(getTestPort()),
         "--testUseStartTLS",
         "--testTrustStorePath", trustStoreFile.getAbsolutePath(),
         "--testTrustStorePasswordFile",
              trustStorePasswordFile.getAbsolutePath(),
         "--testBindDN", getTestBindDN(),
         "--testBindPassword", getTestBindPassword());
    assertEquals(resultCode, ResultCode.SUCCESS);

    final LDAPConnection conn = t.getConnection(0);
    assertNotNull(conn.getRootDSE());
    conn.close();
  }



  /**
   * Tests the behavior of the tool when displaying usage information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisplayUsage()
         throws Exception
  {
    final String[] prefixes = { "source", "target" };
    final String[] suffixes = null;

    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--help");
    assertEquals(resultCode, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the tool when displaying version information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDisplayVersion()
         throws Exception
  {
    final String[] prefixes = { "source", "target" };
    final String[] suffixes = null;

    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);

    final ResultCode resultCode = t.runTool(
         "--version");
    assertEquals(resultCode, ResultCode.SUCCESS);
  }



  /**
   * Tests the behavior of the default doShutdownHookProcessing method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testDoShutdownHookProcessing()
         throws Exception
  {
    final String[] prefixes = { "source", "target" };
    final String[] suffixes = null;

    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);
    t.doShutdownHookProcessing(null);
  }



  /**
   * Tests the behavior of the default getExampleUsages method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExampleUsages()
         throws Exception
  {
    final String[] prefixes = { "source", "target" };
    final String[] suffixes = null;

    final TestMultiServerLDAPCommandLineTool t =
         new TestMultiServerLDAPCommandLineTool(prefixes, suffixes);
    assertNull(t.getExampleUsages());
  }
}
