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
package com.unboundid.util.json;



import java.io.File;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the security options class.
 */
public final class SecurityOptionsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for the case in which the JSON object does not have the
   * communication-security field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertFalse(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * communication-security field whose value is an empty object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEmptyOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject()));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * communication-security field whose value is an object with a security-type
   * value of none.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeNone()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "none"))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertFalse(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * communication-security field whose value is an object with a security-type
   * value of none but contains other fields.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeNoneWithOtherFields()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "none"),
              new JSONField("trust-all-certificates", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that trusts all certificates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLTrustAll()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-all-certificates", true),
              new JSONField("trust-expired-certificates", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertFalse(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that trust certificates signed by a JVM-default isseur.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLJVMDefaultIssuer()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("use-jvm-default-trust-store", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertFalse(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that trust all certificates but also includes a trust store
   * path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = {LDAPException.class })
  public void testSecurityTypeSSLTrustAllWithTrustStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-all-certificates", true),
              new JSONField("trust-store-file",
                   trustStore.getAbsolutePath()))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that use a trust store without a PIN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLTrustStoreWithoutPIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that use a trust store with a PIN provided directly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLTrustStoreWithPIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-pin", "password"),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that use a trust store with a PIN read from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLTrustStoreWithPINFromFile()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");
    final File pinFile     = createTempFile("password");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-pin-file", pinFile.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * with an invalid trust store type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeSSLInvalidTrustStoreType()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "invalid"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * with a missing trust store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLMissingTrustStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = createTempFile();
    assertTrue(trustStore.delete());

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("verify-address-in-certificate", true))));

    try
    {
      final SecurityOptions securityOptions = new SecurityOptions(o);
    }
    catch (final Exception e)
    {
      // An attempt to create a trust store may not fail if the trust store file
      // does not exist.
    }
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that uses both a trust store file and the JVM-default trust
   * store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLTrustStoreFileAndJVMDefaultTrust()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("use-jvm-default-trust-store", true),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that use both a key and trust store with the PIN provided
   * directly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLKeyAndTrustStoreWithPIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-type", "JKS"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that use both a key and trust store with the PIN provided in a
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLKeyAndTrustStoreWithPINFile()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");
    final File pinFile     = createTempFile("password");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-type", "JKS"),
              new JSONField("key-store-pin-file", pinFile.getAbsolutePath()),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertTrue(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that is configured to use PKCS11.  This may or may not succeed
   * based on the underlying system, so we'll just try to get coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeSSLPKCS11()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-type", "PKCS11"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    try
    {
      final SecurityOptions securityOptions = new SecurityOptions(o);

      assertTrue(securityOptions.verifyAddressInCertificate());

      assertTrue(
           securityOptions.getSocketFactory() instanceof SSLSocketFactory);

      assertNull(securityOptions.getPostConnectProcessor());
    }
    catch (final LDAPException e)
    {
      // This is fine.
    }
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that has an invalid key store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeSSLMissingKeyStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = createTempFile();
    final File trustStore  = new File(resourceDir, "client.truststore");
    assertTrue(keyStore.delete());

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that has an invalid key store PIN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeSSLInvalidKeyStorePIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-pin", "wrong"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that has an invalid key store type with a key store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeSSLInvalidKeyStoreTypeWithKeyStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-type", "invalid"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * in a manner that has an invalid key store type without a key store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeSSLInvalidKeyStoreTypeWithoutKeyStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("key-store-type", "invalid"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use SSL
   * but has a client certificate alias without being configured to use a
   * keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeSSLClientAliasWithoutKeystore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDSWithSSL();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that trust all certificates.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSTrustAll()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-all-certificates", true),
              new JSONField("trust-expired-certificates", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertFalse(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that trusts certificates signed by one of the JVM's
   * default trusted issuers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSUseJVMDefaultTrustStore()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("use-jvm-default-trust-store", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertFalse(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that trust all certificates but also includes a trust
   * store path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = {LDAPException.class })
  public void testSecurityTypeStartTLSTrustAllWithTrustStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-all-certificates", true),
              new JSONField("trust-store-file",
                   trustStore.getAbsolutePath()))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that use a trust store without a PIN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSTrustStoreWithoutPIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that use a trust store with a PIN provided directly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSTrustStoreWithPIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-pin", "password"),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that use a trust store with a PIN read from a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSTrustStoreWithPINFromFile()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");
    final File pinFile     = createTempFile("password");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-pin-file", pinFile.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS with an invalid trust store type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeStartTLSInvalidTrustStoreType()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "invalid"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS with a missing trust store file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSMissingTrustStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = createTempFile();
    assertTrue(trustStore.delete());

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("verify-address-in-certificate", true))));

    try
    {
      final SecurityOptions securityOptions = new SecurityOptions(o);
    }
    catch (final Exception e)
    {
      // An attempt to create a trust store may not fail if the trust store file
      // does not exist.
    }
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that uses a trust store file and the JVM-default trust
   * store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSTrustStoreFileAndJVMDefaultTrust()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("use-jvm-default-trust-store", true),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that use both a key and trust store with the PIN
   * provided directly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSKeyAndTrustStoreWithPIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-type", "JKS"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that use both a key and trust store with the PIN
   * provided in a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSKeyAndTrustStoreWithPINFile()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");
    final File pinFile     = createTempFile("password");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-type", "JKS"),
              new JSONField("key-store-pin-file", pinFile.getAbsolutePath()),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    final SecurityOptions securityOptions = new SecurityOptions(o);

    assertTrue(securityOptions.verifyAddressInCertificate());

    assertFalse(securityOptions.getSocketFactory() instanceof SSLSocketFactory);

    assertNotNull(securityOptions.getPostConnectProcessor());
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that is configured to use PKCS11.  This may or may not
   * succeed based on the underlying system, so we'll just try to get coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSecurityTypeStartTLSPKCS11()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-type", "PKCS11"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    try
    {
      final SecurityOptions securityOptions = new SecurityOptions(o);

      assertTrue(securityOptions.verifyAddressInCertificate());

      assertFalse(
           securityOptions.getSocketFactory() instanceof SSLSocketFactory);

      assertNotNull(securityOptions.getPostConnectProcessor());
    }
    catch (final LDAPException e)
    {
      // This is fine.
    }
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that has an invalid key store.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeStartTLSMissingKeyStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = createTempFile();
    final File trustStore  = new File(resourceDir, "client.truststore");
    assertTrue(keyStore.delete());

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that has an invalid key store PIN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeStartTLSInvalidKeyStorePIN()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-pin", "wrong"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that has an invalid key store type with a key store
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeStartTLSInvalidKeyStoreTypeWithKeyStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-type", "invalid"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS in a manner that has an invalid key store type without a key store
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeStartTLSInvalidKeyStoreTypeWithoutKeyStore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("key-store-type", "invalid"),
              new JSONField("key-store-pin", "password"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the spec is configured to use
   * StartTLS but has a client certificate alias without being configured to use
   * a keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeStartTLSClientAliasWithoutKeystore()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File trustStore  = new File(resourceDir, "client.truststore");

    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("client-certificate-alias", "client-cert"),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("trust-store-type", "JKS"),
              new JSONField("verify-address-in-certificate", true))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * communication-security field whose value is an object with a security-type
   * value that is invalid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testSecurityTypeInvalid()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "invalid"))));

    new LDAPConnectionDetailsJSONSpecification(o);
  }
}
