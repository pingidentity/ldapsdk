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



import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.MemoryBasedLogHandler;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class provides a set of test cases for the in-memory directory server
 * configuration.
 */
public final class InMemoryDirectoryServerConfigTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a single DN string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsSingleBaseDNString()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    final DN[] baseDNs = cfg.getBaseDNs();
    assertNotNull(baseDNs);
    assertEquals(baseDNs.length, 1);
    assertEquals(baseDNs[0], new DN("dc=example,dc=com"));

    assertNotNull(cfg.getAllowedOperationTypes());
    assertEquals(cfg.getAllowedOperationTypes(),
         EnumSet.allOf(OperationType.class));

    assertNotNull(cfg.getAuthenticationRequiredOperationTypes());
    assertEquals(cfg.getAuthenticationRequiredOperationTypes(),
         EnumSet.noneOf(OperationType.class));

    assertNotNull(cfg.getAdditionalBindCredentials());
    assertTrue(cfg.getAdditionalBindCredentials().isEmpty());

    assertNotNull(cfg.getListenerConfigs());
    assertFalse(cfg.getListenerConfigs().isEmpty());

    assertNull(cfg.getListenerExceptionHandler());

    assertNull(cfg.getRootDSEEntry());

    assertNotNull(cfg.getSchema());

    assertTrue(cfg.enforceAttributeSyntaxCompliance());

    assertTrue(cfg.enforceSingleStructuralObjectClass());

    assertNull(cfg.getAccessLogHandler());

    assertNull(cfg.getLDAPDebugLogHandler());

    assertNull(cfg.getCodeLogPath());

    assertFalse(cfg.includeRequestProcessingInCodeLog());

    assertNotNull(cfg.getExtendedOperationHandlers());
    assertFalse(cfg.getExtendedOperationHandlers().isEmpty());
    assertEquals(cfg.getExtendedOperationHandlers().size(), 3);

    assertNotNull(cfg.getSASLBindHandlers());
    assertFalse(cfg.getSASLBindHandlers().isEmpty());
    assertEquals(cfg.getSASLBindHandlers().size(), 1);

    assertTrue(cfg.generateOperationalAttributes());

    assertEquals(cfg.getMaxChangeLogEntries(), 0);

    assertEquals(cfg.getMaxConnections(), 0);

    assertEquals(cfg.getMaxMessageSizeBytes(),
         new LDAPConnectionOptions().getMaxMessageSize());

    assertNotNull(cfg.getEqualityIndexAttributes());
    assertTrue(cfg.getEqualityIndexAttributes().isEmpty());

    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertTrue(cfg.getReferentialIntegrityAttributes().isEmpty());

    assertNotNull(cfg.getVendorName());
    assertEquals(cfg.getVendorName(), "Ping Identity Corporation");

    assertNotNull(cfg.getVendorVersion());
    assertEquals(cfg.getVendorVersion(), Version.FULL_VERSION_STRING);

    assertNotNull(cfg.toString());
  }



  /**
   * Provides test coverage for the constructor with multiple base DN strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorsMultipleBaseDNStrings()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");

    final DN[] baseDNs = cfg.getBaseDNs();
    assertNotNull(baseDNs);
    assertEquals(baseDNs.length, 2);
    assertEquals(baseDNs[0], new DN("dc=example,dc=com"));
    assertEquals(baseDNs[1], new DN("o=example.com"));

    assertNotNull(cfg.getAdditionalBindCredentials());
    assertTrue(cfg.getAdditionalBindCredentials().isEmpty());

    assertNotNull(cfg.getListenerConfigs());
    assertFalse(cfg.getListenerConfigs().isEmpty());

    assertNull(cfg.getListenerExceptionHandler());

    assertNull(cfg.getRootDSEEntry());

    assertNotNull(cfg.getSchema());

    assertTrue(cfg.enforceAttributeSyntaxCompliance());

    assertTrue(cfg.enforceSingleStructuralObjectClass());

    assertNull(cfg.getAccessLogHandler());

    assertNull(cfg.getLDAPDebugLogHandler());

    assertNull(cfg.getCodeLogPath());

    assertFalse(cfg.includeRequestProcessingInCodeLog());

    assertNotNull(cfg.getExtendedOperationHandlers());
    assertFalse(cfg.getExtendedOperationHandlers().isEmpty());
    assertEquals(cfg.getExtendedOperationHandlers().size(), 3);

    assertNotNull(cfg.getSASLBindHandlers());
    assertFalse(cfg.getSASLBindHandlers().isEmpty());
    assertEquals(cfg.getSASLBindHandlers().size(), 1);

    assertTrue(cfg.generateOperationalAttributes());

    assertEquals(cfg.getMaxChangeLogEntries(), 0);

    assertEquals(cfg.getMaxConnections(), 0);

    assertEquals(cfg.getMaxMessageSizeBytes(),
         new LDAPConnectionOptions().getMaxMessageSize());

    assertNotNull(cfg.getEqualityIndexAttributes());
    assertTrue(cfg.getEqualityIndexAttributes().isEmpty());

    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertTrue(cfg.getReferentialIntegrityAttributes().isEmpty());

    assertNotNull(cfg.toString());
  }



  /**
   * Provides test coverage for the constructor with a null set of base DN
   * strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructorsNullBaseDNStrings()
         throws Exception
  {
    new InMemoryDirectoryServerConfig((String[]) null);
  }



  /**
   * Provides test coverage for the constructor with a null set of base DN
   * strings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructorsEmptyBaseDNStrings()
         throws Exception
  {
    new InMemoryDirectoryServerConfig(new String[0]);
  }



  /**
   * Provides test coverage for the constructor with a malformed base DN
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConstructorsMalformedBaseDN()
         throws Exception
  {
    new InMemoryDirectoryServerConfig("not-a-valid-dn");
  }



  /**
   * Tests the behavior when interacting with the base DN configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBaseDNs()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    DN[] baseDNs = cfg.getBaseDNs();
    assertNotNull(baseDNs);
    assertEquals(baseDNs.length, 1);
    assertEquals(baseDNs[0], new DN("dc=example,dc=com"));

    assertNotNull(cfg.toString());

    cfg.setBaseDNs("o=example.com");

    baseDNs = cfg.getBaseDNs();
    assertNotNull(baseDNs);
    assertEquals(baseDNs.length, 1);
    assertEquals(baseDNs[0], new DN("o=example.com"));

    assertNotNull(cfg.toString());

    cfg.setBaseDNs("dc=example,dc=com", "o=example.com");

    baseDNs = cfg.getBaseDNs();
    assertNotNull(baseDNs);
    assertEquals(baseDNs.length, 2);
    assertEquals(baseDNs[0], new DN("dc=example,dc=com"));
    assertEquals(baseDNs[1], new DN("o=example.com"));

    assertNotNull(cfg.toString());

    try
    {
      cfg.setBaseDNs((String[]) null);
      fail("Expected an exception for a null base DN array.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.setBaseDNs(new String[0]);
      fail("Expected an exception for an empty base DN array.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.setBaseDNs("not-a-valid-dn");
      fail("Expected an exception for a malformed base DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the allowed operation types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowedOperationTypes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getAllowedOperationTypes());
    assertEquals(cfg.getAllowedOperationTypes(),
         EnumSet.allOf(OperationType.class));

    cfg.setAllowedOperationTypes(OperationType.BIND, OperationType.COMPARE,
         OperationType.SEARCH);
    assertNotNull(cfg.getAllowedOperationTypes());
    assertEquals(cfg.getAllowedOperationTypes(),
         EnumSet.of(OperationType.BIND, OperationType.COMPARE,
              OperationType.SEARCH));

    cfg.setAllowedOperationTypes((OperationType[]) null);
    assertNotNull(cfg.getAllowedOperationTypes());
    assertEquals(cfg.getAllowedOperationTypes(),
         EnumSet.noneOf(OperationType.class));

    cfg.setAllowedOperationTypes(EnumSet.allOf(OperationType.class));
    assertNotNull(cfg.getAllowedOperationTypes());
    assertEquals(cfg.getAllowedOperationTypes(),
         EnumSet.allOf(OperationType.class));
  }



  /**
   * Tests the behavior of the authentication required operation types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticationRequiredOperationTypes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getAuthenticationRequiredOperationTypes());
    assertEquals(cfg.getAuthenticationRequiredOperationTypes(),
         EnumSet.noneOf(OperationType.class));

    cfg.setAuthenticationRequiredOperationTypes(OperationType.ADD,
         OperationType.DELETE, OperationType.MODIFY, OperationType.MODIFY_DN);
    assertNotNull(cfg.getAuthenticationRequiredOperationTypes());
    assertEquals(cfg.getAuthenticationRequiredOperationTypes(),
         EnumSet.of(OperationType.ADD, OperationType.DELETE,
              OperationType.MODIFY, OperationType.MODIFY_DN));

    cfg.setAuthenticationRequiredOperationTypes((OperationType[]) null);
    assertNotNull(cfg.getAuthenticationRequiredOperationTypes());
    assertEquals(cfg.getAuthenticationRequiredOperationTypes(),
         EnumSet.noneOf(OperationType.class));

    cfg.setAuthenticationRequiredOperationTypes(
         EnumSet.allOf(OperationType.class));
    assertNotNull(cfg.getAuthenticationRequiredOperationTypes());
    assertEquals(cfg.getAuthenticationRequiredOperationTypes(),
         EnumSet.allOf(OperationType.class));

    cfg.setAuthenticationRequiredOperationTypes(
         EnumSet.noneOf(OperationType.class));
    assertNotNull(cfg.getAuthenticationRequiredOperationTypes());
    assertEquals(cfg.getAuthenticationRequiredOperationTypes(),
         EnumSet.noneOf(OperationType.class));
  }



  /**
   * Tests the behavior of the methods for additional bind credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdditionalBindCredentials()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getAdditionalBindCredentials());
    assertTrue(cfg.getAdditionalBindCredentials().isEmpty());

    assertNotNull(cfg.toString());

    cfg.addAdditionalBindCredentials("cn=DN 1", "password1");
    assertEquals(cfg.getAdditionalBindCredentials().get(new DN("cn=DN 1")),
         StaticUtils.getBytes("password1"));

    assertNotNull(cfg.toString());

    cfg.addAdditionalBindCredentials("cn=DN 2",
         StaticUtils.getBytes("password2"));
    assertEquals(cfg.getAdditionalBindCredentials().get(new DN("cn=DN 2")),
         StaticUtils.getBytes("password2"));

    assertNotNull(cfg.toString());

    assertNotNull(cfg.getAdditionalBindCredentials());
    assertFalse(cfg.getAdditionalBindCredentials().isEmpty());

    cfg.getAdditionalBindCredentials().put(new DN("cn=DN 1"),
         StaticUtils.getBytes("password1a"));
    assertEquals(cfg.getAdditionalBindCredentials().get(new DN("cn=DN 1")),
         StaticUtils.getBytes("password1a"));

    assertNotNull(cfg.toString());

    cfg.getAdditionalBindCredentials().remove(new DN("cn=DN 1"));
    assertNull(cfg.getAdditionalBindCredentials().get(new DN("cn=DN 1")));

    assertNotNull(cfg.toString());

    assertNotNull(cfg.getAdditionalBindCredentials());
    assertFalse(cfg.getAdditionalBindCredentials().isEmpty());

    cfg.getAdditionalBindCredentials().clear();
    assertNotNull(cfg.getAdditionalBindCredentials());
    assertTrue(cfg.getAdditionalBindCredentials().isEmpty());

    assertNotNull(cfg.toString());

    try
    {
      cfg.addAdditionalBindCredentials(null, "password");
      fail("Expected an exception with a null bind DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.addAdditionalBindCredentials("", "password");
      fail("Expected an exception with an empty bind DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.addAdditionalBindCredentials("not-a-valid-dn", "password");
      fail("Expected an exception with an invalid bind DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.addAdditionalBindCredentials("cn=Test", (String) null);
      fail("Expected an exception with a null password");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.addAdditionalBindCredentials("cn=Test", "");
      fail("Expected an exception with an empty password");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the methods for the listener configurations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerConfigs()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());


    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getListenerConfigs());
    assertFalse(cfg.getListenerConfigs().isEmpty());
    assertEquals(cfg.getListenerConfigs().size(), 1);
    assertEquals(cfg.getListenerConfigs().get(0).getListenerName(), "default");

    assertNotNull(cfg.toString());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("LDAP"));
    assertNotNull(cfg.getListenerConfigs());
    assertFalse(cfg.getListenerConfigs().isEmpty());
    assertEquals(cfg.getListenerConfigs().size(), 1);
    assertEquals(cfg.getListenerConfigs().get(0).getListenerName(), "LDAP");

    assertNotNull(cfg.toString());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("LDAP", 0),
         InMemoryListenerConfig.createLDAPSConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              clientSSLUtil.createSSLSocketFactory()));
    assertNotNull(cfg.getListenerConfigs());
    assertFalse(cfg.getListenerConfigs().isEmpty());
    assertEquals(cfg.getListenerConfigs().size(), 2);
    assertEquals(cfg.getListenerConfigs().get(0).getListenerName(), "LDAP");
    assertEquals(cfg.getListenerConfigs().get(1).getListenerName(), "LDAPS");

    assertNotNull(cfg.toString());

    try
    {
      cfg.setListenerConfigs((InMemoryListenerConfig[]) null);
      fail("Expected an exception with a null set of listener configs.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.setListenerConfigs();
      fail("Expected an exception with an empty set of listener configs.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("LDAP"),
           InMemoryListenerConfig.createLDAPConfig("LDAP"));
      fail("Expected an exception with a set of listener configs with " +
           "duplicate names.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the methods for the listener exception handler.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListenerExceptionHandler()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNull(cfg.getListenerExceptionHandler());

    assertNotNull(cfg.toString());

    cfg.setListenerExceptionHandler(new TestLDAPListenerExceptionHandler());
    assertNotNull(cfg.getListenerExceptionHandler());

    assertNotNull(cfg.toString());

    cfg.setListenerExceptionHandler(null);
    assertNull(cfg.getListenerExceptionHandler());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for the schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchema()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getSchema());

    assertNotNull(cfg.toString());

    cfg.setSchema(Schema.getDefaultStandardSchema());
    assertNotNull(cfg.getSchema());

    assertNotNull(cfg.toString());

    cfg.setSchema(null);
    assertNull(cfg.getSchema());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for enforcing attribute syntax
   * compliance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnforceAttributeSyntaxCompliance()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertTrue(cfg.enforceAttributeSyntaxCompliance());

    assertNotNull(cfg.toString());

    cfg.setEnforceAttributeSyntaxCompliance(false);
    assertFalse(cfg.enforceAttributeSyntaxCompliance());

    assertNotNull(cfg.toString());

    cfg.setEnforceAttributeSyntaxCompliance(true);
    assertTrue(cfg.enforceAttributeSyntaxCompliance());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for enforcing single structural object
   * class compliance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEnforceSingleStructuralObjectClass()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertTrue(cfg.enforceSingleStructuralObjectClass());

    assertNotNull(cfg.toString());

    cfg.setEnforceSingleStructuralObjectClass(false);
    assertFalse(cfg.enforceSingleStructuralObjectClass());

    assertNotNull(cfg.toString());

    cfg.setEnforceSingleStructuralObjectClass(true);
    assertTrue(cfg.enforceSingleStructuralObjectClass());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for the access log handler.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAccessLogHandler()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNull(cfg.getAccessLogHandler());

    assertNotNull(cfg.toString());

    cfg.setAccessLogHandler(new MemoryBasedLogHandler());
    assertNotNull(cfg.getAccessLogHandler());

    assertNotNull(cfg.toString());

    cfg.setAccessLogHandler(null);
    assertNull(cfg.getAccessLogHandler());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for the LDAP debug log handler.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPDebugLogHandler()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNull(cfg.getLDAPDebugLogHandler());

    assertNotNull(cfg.toString());

    cfg.setLDAPDebugLogHandler(new MemoryBasedLogHandler());
    assertNotNull(cfg.getLDAPDebugLogHandler());

    assertNotNull(cfg.toString());

    cfg.setLDAPDebugLogHandler(null);
    assertNull(cfg.getLDAPDebugLogHandler());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for the code log handler.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCodeLogHandler()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNull(cfg.getCodeLogPath());

    assertFalse(cfg.includeRequestProcessingInCodeLog());

    final String path = createTempFile().getAbsolutePath();
    cfg.setCodeLogDetails(path, true);

    assertNotNull(cfg.getCodeLogPath());
    assertEquals(cfg.getCodeLogPath(), path);

    assertTrue(cfg.includeRequestProcessingInCodeLog());

    assertNotNull(cfg.toString());

    cfg.setCodeLogDetails(null, false);

    assertFalse(cfg.includeRequestProcessingInCodeLog());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for the extended operation handlers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtendedOperationHandlers()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getExtendedOperationHandlers());
    assertFalse(cfg.getExtendedOperationHandlers().isEmpty());
    assertEquals(cfg.getExtendedOperationHandlers().size(), 3);

    assertNotNull(cfg.toString());

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    RootDSE rootDSE = RootDSE.getRootDSE(ds);
    assertTrue(rootDSE.supportsExtendedOperation(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID));
    assertTrue(rootDSE.supportsExtendedOperation(
         StartTransactionExtendedRequest.START_TRANSACTION_REQUEST_OID));
    assertTrue(rootDSE.supportsExtendedOperation(
         EndTransactionExtendedRequest.END_TRANSACTION_REQUEST_OID));
    assertTrue(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

    cfg.getExtendedOperationHandlers().clear();
    assertTrue(cfg.getExtendedOperationHandlers().isEmpty());

    assertNotNull(cfg.toString());

    ds = new InMemoryDirectoryServer(cfg);
    rootDSE = RootDSE.getRootDSE(ds);
    assertFalse(rootDSE.supportsExtendedOperation(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID));
    assertFalse(rootDSE.supportsExtendedOperation(
         StartTransactionExtendedRequest.START_TRANSACTION_REQUEST_OID));
    assertFalse(rootDSE.supportsExtendedOperation(
         EndTransactionExtendedRequest.END_TRANSACTION_REQUEST_OID));
    assertFalse(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

    cfg.addExtendedOperationHandler(
         new PasswordModifyExtendedOperationHandler());

    assertNotNull(cfg.toString());

    ds = new InMemoryDirectoryServer(cfg);
    rootDSE = RootDSE.getRootDSE(ds);
    assertTrue(rootDSE.supportsExtendedOperation(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID));
    assertFalse(rootDSE.supportsExtendedOperation(
         StartTransactionExtendedRequest.START_TRANSACTION_REQUEST_OID));
    assertFalse(rootDSE.supportsExtendedOperation(
         EndTransactionExtendedRequest.END_TRANSACTION_REQUEST_OID));
    assertFalse(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));
  }



  /**
   * Tests the behavior of the methods for the SASL bind handlers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLBindHandlers()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getSASLBindHandlers());
    assertFalse(cfg.getSASLBindHandlers().isEmpty());
    assertEquals(cfg.getSASLBindHandlers().size(), 1);

    assertNotNull(cfg.toString());

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    RootDSE rootDSE = RootDSE.getRootDSE(ds);
    assertTrue(rootDSE.supportsSASLMechanism("PLAIN"));

    cfg.addSASLBindHandler(new TestSASLBindHandler());
    assertFalse(cfg.getSASLBindHandlers().isEmpty());
    assertEquals(cfg.getSASLBindHandlers().size(), 2);

    ds = new InMemoryDirectoryServer(cfg);
    rootDSE = RootDSE.getRootDSE(ds);
    assertTrue(rootDSE.supportsSASLMechanism("PLAIN"));
    assertTrue(rootDSE.supportsSASLMechanism("TEST"));

    cfg.getSASLBindHandlers().clear();
    assertTrue(cfg.getSASLBindHandlers().isEmpty());

    assertNotNull(cfg.toString());

    ds = new InMemoryDirectoryServer(cfg);
    rootDSE = RootDSE.getRootDSE(ds);
    assertFalse(rootDSE.supportsSASLMechanism("PLAIN"));

    cfg.addSASLBindHandler(new PLAINBindHandler());

    assertNotNull(cfg.toString());

    ds = new InMemoryDirectoryServer(cfg);
    rootDSE = RootDSE.getRootDSE(ds);
    assertTrue(rootDSE.supportsSASLMechanism("PLAIN"));
  }



  /**
   * Tests the behavior of the methods for ability to generate operational
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateOperationalAttributes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertTrue(cfg.generateOperationalAttributes());

    assertNotNull(cfg.toString());

    cfg.setGenerateOperationalAttributes(false);
    assertFalse(cfg.generateOperationalAttributes());

    assertNotNull(cfg.toString());

    cfg.setGenerateOperationalAttributes(true);
    assertTrue(cfg.generateOperationalAttributes());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for maintaining a changelog.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxChangeLogEntries()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertEquals(cfg.getMaxChangeLogEntries(), 0);

    assertNotNull(cfg.toString());

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));
    assertFalse(ds.getBaseDNs().contains(new DN("cn=changelog")));

    cfg.setMaxChangeLogEntries(1000);
    assertEquals(cfg.getMaxChangeLogEntries(), 1000);

    assertNotNull(cfg.toString());

    ds = new InMemoryDirectoryServer(cfg);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));
    assertTrue(ds.getBaseDNs().contains(new DN("cn=changelog")));

    cfg.setMaxChangeLogEntries(-1);
    assertEquals(cfg.getMaxChangeLogEntries(), 0);

    assertNotNull(cfg.toString());

    ds = new InMemoryDirectoryServer(cfg);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));
    assertFalse(ds.getBaseDNs().contains(new DN("cn=changelog")));
  }



  /**
   * Tests the behavior of the methods for limiting the number of connections
   * that may be established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxConnections()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertEquals(cfg.getMaxConnections(), 0);

    assertNotNull(cfg.toString());

    cfg.setMaxConnections(1234);
    assertEquals(cfg.getMaxConnections(), 1234);

    assertNotNull(cfg.toString());

    cfg.setMaxConnections(-1);
    assertEquals(cfg.getMaxConnections(), 0);

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for limiting the maximum message size.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxMessageSize()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertEquals(cfg.getMaxMessageSizeBytes(),
         new LDAPConnectionOptions().getMaxMessageSize());

    assertNotNull(cfg.toString());

    cfg.setMaxMessageSizeBytes(123_456_789);
    assertEquals(cfg.getMaxMessageSizeBytes(), 123_456_789);

    assertNotNull(cfg.toString());

    cfg.setMaxMessageSizeBytes(-1);
    assertEquals(cfg.getMaxMessageSizeBytes(), Integer.MAX_VALUE);

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for interacting with the equality index
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualityIndexAttributes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getEqualityIndexAttributes());
    assertTrue(cfg.getEqualityIndexAttributes().isEmpty());

    assertNotNull(cfg.toString());

    cfg.setEqualityIndexAttributes("member");
    assertNotNull(cfg.getEqualityIndexAttributes());
    assertEquals(cfg.getEqualityIndexAttributes().size(), 1);
    assertTrue(cfg.getEqualityIndexAttributes().contains("member"));

    assertNotNull(cfg.toString());

    cfg.setEqualityIndexAttributes((String[]) null);
    assertNotNull(cfg.getEqualityIndexAttributes());
    assertTrue(cfg.getEqualityIndexAttributes().isEmpty());

    assertNotNull(cfg.toString());

    cfg.setEqualityIndexAttributes("member", "uniqueMember", "owner",
         "seeAlso");
    assertNotNull(cfg.getEqualityIndexAttributes());
    assertEquals(cfg.getEqualityIndexAttributes().size(), 4);
    assertTrue(cfg.getEqualityIndexAttributes().contains("member"));
    assertTrue(
         cfg.getEqualityIndexAttributes().contains("uniqueMember"));
    assertTrue(cfg.getEqualityIndexAttributes().contains("owner"));
    assertTrue(cfg.getEqualityIndexAttributes().contains("seeAlso"));

    assertNotNull(cfg.toString());

    cfg.setEqualityIndexAttributes();
    assertNotNull(cfg.getEqualityIndexAttributes());
    assertTrue(cfg.getEqualityIndexAttributes().isEmpty());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for interacting with the referential
   * integrity attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReferentialIntegrityAttributes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertTrue(cfg.getReferentialIntegrityAttributes().isEmpty());

    assertNotNull(cfg.toString());

    cfg.setReferentialIntegrityAttributes("member");
    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertEquals(cfg.getReferentialIntegrityAttributes().size(), 1);
    assertTrue(cfg.getReferentialIntegrityAttributes().contains("member"));

    assertNotNull(cfg.toString());

    cfg.setReferentialIntegrityAttributes((String[]) null);
    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertTrue(cfg.getReferentialIntegrityAttributes().isEmpty());

    assertNotNull(cfg.toString());

    cfg.setReferentialIntegrityAttributes("member", "uniqueMember", "owner",
         "seeAlso");
    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertEquals(cfg.getReferentialIntegrityAttributes().size(), 4);
    assertTrue(cfg.getReferentialIntegrityAttributes().contains("member"));
    assertTrue(
         cfg.getReferentialIntegrityAttributes().contains("uniqueMember"));
    assertTrue(cfg.getReferentialIntegrityAttributes().contains("owner"));
    assertTrue(cfg.getReferentialIntegrityAttributes().contains("seeAlso"));

    assertNotNull(cfg.toString());

    cfg.setReferentialIntegrityAttributes();
    assertNotNull(cfg.getReferentialIntegrityAttributes());
    assertTrue(cfg.getReferentialIntegrityAttributes().isEmpty());

    assertNotNull(cfg.toString());
  }



  /**
   * Tests the behavior of the methods for interacting with the server vendor
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVendorName()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getVendorName());
    assertEquals(cfg.getVendorName(), "Ping Identity Corporation");

    cfg.setVendorName(null);
    assertNull(cfg.getVendorName());

    cfg.setVendorName("Example Corp.");
    assertNotNull(cfg.getVendorName());
    assertEquals(cfg.getVendorName(), "Example Corp.");
  }



  /**
   * Tests the behavior of the methods for interacting with the server vendor
   * version.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testVendorVersion()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getVendorVersion());
    assertEquals(cfg.getVendorVersion(), Version.FULL_VERSION_STRING);

    cfg.setVendorVersion(null);
    assertNull(cfg.getVendorVersion());

    cfg.setVendorVersion("1.2.3");
    assertNotNull(cfg.getVendorVersion());
    assertEquals(cfg.getVendorVersion(), "1.2.3");
  }



  /**
   * Tests the behavior of the methods that make it possible to get and set a
   * specific root DSE entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRootDSEEntry()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNull(cfg.getRootDSEEntry());

    cfg.setRootDSEEntry(new Entry(
         "dn: ",
         "objectClass: top",
         "objectClass: rootDSE",
         "description: Test root DSE"));
    assertNotNull(cfg.getRootDSEEntry());
    assertEquals(cfg.getRootDSEEntry(),
         new ReadOnlyEntry(
              "dn: ",
              "objectClass: top",
              "objectClass: rootDSE",
              "description: Test root DSE"));

    cfg.setRootDSEEntry(null);
    assertNull(cfg.getRootDSEEntry());
  }



  /**
   * Tests the behavior of the methods that make it possible to get and set
   * custom root DSE attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCustomRootDSEAttributes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    assertNotNull(cfg.getCustomRootDSEAttributes());
    assertTrue(cfg.getCustomRootDSEAttributes().isEmpty());

    cfg.setCustomRootDSEAttributes(
         Collections.singletonList(new Attribute("description", "foo")));

    assertNotNull(cfg.getCustomRootDSEAttributes());
    assertFalse(cfg.getCustomRootDSEAttributes().isEmpty());
    assertEquals(cfg.getCustomRootDSEAttributes().size(), 1);
    assertEquals(cfg.getCustomRootDSEAttributes(),
         Collections.singletonList(new Attribute("description", "foo")));

    cfg.setCustomRootDSEAttributes(Collections.<Attribute>emptyList());

    assertNotNull(cfg.getCustomRootDSEAttributes());
    assertTrue(cfg.getCustomRootDSEAttributes().isEmpty());

    cfg.setCustomRootDSEAttributes(
         Arrays.asList(
              new Attribute("description", "bar", "baz"),
              new Attribute("displayName", "Root DSE")));

    assertNotNull(cfg.getCustomRootDSEAttributes());
    assertFalse(cfg.getCustomRootDSEAttributes().isEmpty());
    assertEquals(cfg.getCustomRootDSEAttributes().size(), 2);
    assertEquals(cfg.getCustomRootDSEAttributes(),
         Arrays.asList(
              new Attribute("description", "bar", "baz"),
              new Attribute("displayName", "Root DSE")));

    cfg.setCustomRootDSEAttributes(null);

    assertNotNull(cfg.getCustomRootDSEAttributes());
    assertTrue(cfg.getCustomRootDSEAttributes().isEmpty());
  }
}
