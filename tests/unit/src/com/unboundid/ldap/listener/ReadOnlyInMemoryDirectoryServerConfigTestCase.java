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



import java.util.Arrays;
import java.util.EnumSet;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.TestLogHandler;



/**
 * This class provides a set of test cases for the read-only in-memory directory
 * server configuration.
 */
public final class ReadOnlyInMemoryDirectoryServerConfigTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides a set of tests with a minimal configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConfig()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    ReadOnlyInMemoryDirectoryServerConfig readOnlyConfig =
         new ReadOnlyInMemoryDirectoryServerConfig(config);


    // Make sure that it is possible to create a directory server instance using
    // the read-only configuration, and get the read-only configuration from it.
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer(readOnlyConfig);
    assertNotNull(ds);

    readOnlyConfig = ds.getConfig();


    // Test methods related to the set of base DNs.
    assertNotNull(readOnlyConfig.getBaseDNs());
    assertEquals(readOnlyConfig.getBaseDNs().length, 1);
    assertEquals(readOnlyConfig.getBaseDNs()[0],
         new DN("dc=example,dc=com"));

    try
    {
      readOnlyConfig.setBaseDNs("o=example.com");
      fail("Expected an exception when trying to call setBaseDNs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setBaseDNs(new DN("o=example.com"));
      fail("Expected an exception when trying to call setBaseDNs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the set of allowed operation types.
    assertNotNull(readOnlyConfig.getAllowedOperationTypes());
    assertEquals(readOnlyConfig.getAllowedOperationTypes(),
         EnumSet.allOf(OperationType.class));

    try
    {
      readOnlyConfig.getAllowedOperationTypes().add(
           OperationType.ADD);
      fail("Expected an exception when trying to alter the set returned by " +
           "getAllowedOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAllowedOperationTypes(OperationType.BIND,
           OperationType.COMPARE, OperationType.SEARCH);
      fail("Expected an exception when trying to call " +
           "setAllowedOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAllowedOperationTypes(EnumSet.of(OperationType.BIND,
           OperationType.COMPARE, OperationType.SEARCH));
      fail("Expected an exception when trying to call " +
           "setAllowedOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the set of authentication required operation
    // types.
    assertNotNull(readOnlyConfig.getAuthenticationRequiredOperationTypes());
    assertEquals(readOnlyConfig.getAuthenticationRequiredOperationTypes(),
         EnumSet.noneOf(OperationType.class));

    try
    {
      readOnlyConfig.getAuthenticationRequiredOperationTypes().add(
           OperationType.ADD);
      fail("Expected an exception when trying to alter the set returned by " +
           "getAuthenticationRequiredOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAuthenticationRequiredOperationTypes(OperationType.ADD,
           OperationType.DELETE, OperationType.MODIFY,
           OperationType.MODIFY_DN);
      fail("Expected an exception when trying to call " +
           "setAuthenticationRequiredOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAuthenticationRequiredOperationTypes(EnumSet.of
           (OperationType.ADD, OperationType.DELETE, OperationType.MODIFY,
                OperationType.MODIFY_DN));
      fail("Expected an exception when trying to call " +
           "setAuthenticationRequiredOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the additional bind credentials.
    assertNotNull(readOnlyConfig.getAdditionalBindCredentials());
    assertTrue(readOnlyConfig.getAdditionalBindCredentials().isEmpty());

    try
    {
      readOnlyConfig.getAdditionalBindCredentials().put(
           new DN("cn=Directory Manager"), "password".getBytes("UTF-8"));
      fail("Expected an exception when trying to alter the map returned by " +
           "getAdditionalBindCredentials");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addAdditionalBindCredentials("cn=Directory Manager",
           "password");
      fail("Expected an exception when trying to call " +
           "addAdditionalBindCredentials");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addAdditionalBindCredentials("cn=Directory Manager",
           "password".getBytes("UTF-8"));
      fail("Expected an exception when trying to call " +
           "addAdditionalBindCredentials");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the listener configs.
    assertNotNull(readOnlyConfig.getListenerConfigs());
    assertFalse(readOnlyConfig.getListenerConfigs().isEmpty());

    try
    {
      readOnlyConfig.getListenerConfigs().clear();
      fail("Expected an exception when trying to call " +
           "getListenerConfigs.clear");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setListenerConfigs(
           InMemoryListenerConfig.createLDAPConfig("LDAP"));
      fail("Expected an exception when trying to call setListenerConfigs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setListenerConfigs(Arrays.asList(
           InMemoryListenerConfig.createLDAPConfig("LDAP")));
      fail("Expected an exception when trying to call setListenerConfigs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the exception handler.
    assertNull(readOnlyConfig.getListenerExceptionHandler());

    try
    {
      readOnlyConfig.setListenerExceptionHandler(
           new TestLDAPListenerExceptionHandler());
      fail("Expected an exception when trying to call " +
           "setListenerExceptionHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the schema.
    assertNotNull(readOnlyConfig.getSchema());

    try
    {
      readOnlyConfig.setSchema(null);
      fail("Expected an exception when trying to call setSchema");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to attribute syntax enforcement.
    assertTrue(readOnlyConfig.enforceAttributeSyntaxCompliance());

    try
    {
      readOnlyConfig.setEnforceAttributeSyntaxCompliance(false);
      fail("Expected an exception when trying to call " +
           "setEnforceAttributeSyntaxCompliance");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to single structural object class enforcement.
    assertTrue(readOnlyConfig.enforceSingleStructuralObjectClass());

    try
    {
      readOnlyConfig.setEnforceSingleStructuralObjectClass(false);
      fail("Expected an exception when trying to call " +
           "setEnforceSingleStructuralObjectClass");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the access log handler.
    assertNull(readOnlyConfig.getAccessLogHandler());

    try
    {
      readOnlyConfig.setAccessLogHandler(new TestLogHandler());
      fail("Expected an exception when trying to call setAccessLogHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the LDAP debug log handler.
    assertNull(readOnlyConfig.getLDAPDebugLogHandler());

    try
    {
      readOnlyConfig.setLDAPDebugLogHandler(new TestLogHandler());
      fail("Expected an exception when trying to call setLDAPDebugLogHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the extended operation handlers.
    assertNotNull(readOnlyConfig.getExtendedOperationHandlers());
    assertFalse(readOnlyConfig.getExtendedOperationHandlers().isEmpty());

    try
    {
      readOnlyConfig.getExtendedOperationHandlers().add(
           new TestExtendedOperationHandler());
      fail("Expected an exception when trying to alter the list returned by " +
           "getExtendedOperationHandlers");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addExtendedOperationHandler(
           new TestExtendedOperationHandler());
      fail("Expected an exception when trying to call " +
           "addExtendedOperationHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the SASL bind handlers.
    assertNotNull(readOnlyConfig.getSASLBindHandlers());
    assertFalse(readOnlyConfig.getSASLBindHandlers().isEmpty());

    try
    {
      readOnlyConfig.getSASLBindHandlers().add(new TestSASLBindHandler());
      fail("Expected an exception when trying to alter the list returned by " +
           "getSASLBindHandlers");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addSASLBindHandler(new TestSASLBindHandler());
      fail("Expected an exception when trying to call addSASLBindHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the generation of operational attributes.
    assertTrue(readOnlyConfig.generateOperationalAttributes());

    try
    {
      readOnlyConfig.setGenerateOperationalAttributes(false);
      fail("Expected an exception when trying to call " +
           "setGenerateOperationalAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to changelog entries.
    assertEquals(readOnlyConfig.getMaxChangeLogEntries(), 0);

    try
    {
      readOnlyConfig.setMaxChangeLogEntries(100);
      fail("Expected an exception when trying to call " +
           "setMaxChangeLogEntries");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to equality index attributes.
    assertNotNull(readOnlyConfig.getEqualityIndexAttributes());
    assertTrue(readOnlyConfig.getEqualityIndexAttributes().isEmpty());

    try
    {
      readOnlyConfig.setEqualityIndexAttributes("member");
      fail("Expected an exception when trying to call " +
           "setEqualityIndexAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected
    }

    try
    {
      readOnlyConfig.setEqualityIndexAttributes(Arrays.asList(
           "member", "uniqueMember", "owner", "seeAlso"));
      fail("Expected an exception when trying to call " +
           "setEqualityIndexAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected
    }


    // Test methods related to referential integrity attributes.
    assertNotNull(readOnlyConfig.getReferentialIntegrityAttributes());
    assertTrue(readOnlyConfig.getReferentialIntegrityAttributes().isEmpty());

    try
    {
      readOnlyConfig.setReferentialIntegrityAttributes("member");
      fail("Expected an exception when trying to call " +
           "setReferentialIntegrityAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected
    }

    try
    {
      readOnlyConfig.setReferentialIntegrityAttributes(Arrays.asList(
           "member", "uniqueMember", "owner", "seeAlso"));
      fail("Expected an exception when trying to call " +
           "setReferentialIntegrityAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected
    }

    try
    {
      readOnlyConfig.setVendorName(null);
      fail("Expected an exception when trying to call setVendorName");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setVendorName("foo");
      fail("Expected an exception when trying to call setVendorName");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setVendorVersion(null);
      fail("Expected an exception when trying to call setVendorVersion");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setVendorVersion("foo");
      fail("Expected an exception when trying to call setVendorVersion");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test the toString method.
    assertNotNull(readOnlyConfig.toString());
  }



  /**
   * Provides a set of tests with a more extensive configuration.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensiveConfig()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    config.setAllowedOperationTypes(OperationType.BIND,  OperationType.COMPARE,
         OperationType.SEARCH);
    config.setAuthenticationRequiredOperationTypes(OperationType.ADD,
         OperationType.DELETE, OperationType.MODIFY, OperationType.MODIFY_DN);
    config.addAdditionalBindCredentials("cn=Directory Manager", "password");
    config.setListenerExceptionHandler(new TestLDAPListenerExceptionHandler());
    config.setSchema(Schema.getDefaultStandardSchema());
    config.setEnforceAttributeSyntaxCompliance(false);
    config.setEnforceSingleStructuralObjectClass(false);
    config.setAccessLogHandler(new TestLogHandler());
    config.setLDAPDebugLogHandler(new TestLogHandler());
    config.addExtendedOperationHandler(new TestExtendedOperationHandler());
    config.addSASLBindHandler(new TestSASLBindHandler());
    config.setGenerateOperationalAttributes(false);
    config.setMaxChangeLogEntries(100);
    config.setEqualityIndexAttributes("uid", "cn");
    config.setReferentialIntegrityAttributes("member", "uniqueMember", "owner",
         "seeAlso");

    ReadOnlyInMemoryDirectoryServerConfig readOnlyConfig =
         new ReadOnlyInMemoryDirectoryServerConfig(config);


    // Make sure that it is possible to create a directory server instance using
    // the read-only configuration, and get the read-only configuration from it.
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer(readOnlyConfig);
    assertNotNull(ds);

    readOnlyConfig = ds.getConfig();


    // Test methods related to the set of base DNs.
    assertNotNull(readOnlyConfig.getBaseDNs());
    assertEquals(readOnlyConfig.getBaseDNs().length, 2);
    assertEquals(readOnlyConfig.getBaseDNs()[0],
         new DN("dc=example,dc=com"));
    assertEquals(readOnlyConfig.getBaseDNs()[1],
         new DN("o=example.com"));

    try
    {
      readOnlyConfig.setBaseDNs("c=US");
      fail("Expected an exception when trying to call setBaseDNs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setBaseDNs(new DN("c=US"));
      fail("Expected an exception when trying to call setBaseDNs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the set of allowed operation types.
    assertNotNull(readOnlyConfig.getAllowedOperationTypes());
    assertEquals(readOnlyConfig.getAllowedOperationTypes(),
         EnumSet.of(OperationType.BIND, OperationType.COMPARE,
              OperationType.SEARCH));

    try
    {
      readOnlyConfig.getAllowedOperationTypes().add(
           OperationType.ADD);
      fail("Expected an exception when trying to alter the set returned by " +
           "getAllowedOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAllowedOperationTypes(OperationType.BIND,
           OperationType.COMPARE, OperationType.SEARCH);
      fail("Expected an exception when trying to call " +
           "setAllowedOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAllowedOperationTypes(EnumSet.of(OperationType.BIND,
           OperationType.COMPARE, OperationType.SEARCH));
      fail("Expected an exception when trying to call " +
           "setAllowedOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the set of authentication required operation
    // types.
    assertNotNull(readOnlyConfig.getAuthenticationRequiredOperationTypes());
    assertEquals(readOnlyConfig.getAuthenticationRequiredOperationTypes(),
         EnumSet.of(OperationType.ADD, OperationType.DELETE,
              OperationType.MODIFY, OperationType.MODIFY_DN));

    try
    {
      readOnlyConfig.getAuthenticationRequiredOperationTypes().add(
           OperationType.ADD);
      fail("Expected an exception when trying to alter the set returned by " +
           "getAuthenticationRequiredOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAuthenticationRequiredOperationTypes(OperationType.ADD,
           OperationType.DELETE, OperationType.MODIFY,
           OperationType.MODIFY_DN);
      fail("Expected an exception when trying to call " +
           "setAuthenticationRequiredOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setAuthenticationRequiredOperationTypes(EnumSet.of
           (OperationType.ADD, OperationType.DELETE, OperationType.MODIFY,
                OperationType.MODIFY_DN));
      fail("Expected an exception when trying to call " +
           "setAuthenticationRequiredOperationTypes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the additional bind credentials.
    assertNotNull(readOnlyConfig.getAdditionalBindCredentials());
    assertFalse(readOnlyConfig.getAdditionalBindCredentials().isEmpty());

    try
    {
      readOnlyConfig.getAdditionalBindCredentials().put(
           new DN("cn=Directory Manager 2"), "password".getBytes("UTF-8"));
      fail("Expected an exception when trying to alter the map returned by " +
           "getAdditionalBindCredentials");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addAdditionalBindCredentials("cn=Directory Manager 2",
           "password");
      fail("Expected an exception when trying to call " +
           "addAdditionalBindCredentials");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addAdditionalBindCredentials("cn=Directory Manager 2",
           "password".getBytes("UTF-8"));
      fail("Expected an exception when trying to call " +
           "addAdditionalBindCredentials");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the listener configs.
    assertNotNull(readOnlyConfig.getListenerConfigs());
    assertFalse(readOnlyConfig.getListenerConfigs().isEmpty());

    try
    {
      readOnlyConfig.getListenerConfigs().clear();
      fail("Expected an exception when trying to call " +
           "getListenerConfigs.clear");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setListenerConfigs(
           InMemoryListenerConfig.createLDAPConfig("LDAP"));
      fail("Expected an exception when trying to call setListenerConfigs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.setListenerConfigs(Arrays.asList(
           InMemoryListenerConfig.createLDAPConfig("LDAP")));
      fail("Expected an exception when trying to call setListenerConfigs");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the exception handler.
    assertNotNull(readOnlyConfig.getListenerExceptionHandler());

    try
    {
      readOnlyConfig.setListenerExceptionHandler(null);
      fail("Expected an exception when trying to call " +
           "setListenerExceptionHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the schema.
    assertNotNull(readOnlyConfig.getSchema());

    try
    {
      readOnlyConfig.setSchema(null);
      fail("Expected an exception when trying to call setSchema");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to attribute syntax enforcement.
    assertFalse(readOnlyConfig.enforceAttributeSyntaxCompliance());

    try
    {
      readOnlyConfig.setEnforceAttributeSyntaxCompliance(true);
      fail("Expected an exception when trying to call " +
           "setEnforceAttributeSyntaxCompliance");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to single structural object class enforcement.
    assertFalse(readOnlyConfig.enforceSingleStructuralObjectClass());

    try
    {
      readOnlyConfig.setEnforceSingleStructuralObjectClass(true);
      fail("Expected an exception when trying to call " +
           "setEnforceSingleStructuralObjectClass");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the access log handler.
    assertNotNull(readOnlyConfig.getAccessLogHandler());

    try
    {
      readOnlyConfig.setAccessLogHandler(null);
      fail("Expected an exception when trying to call setAccessLogHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the LDAP debug log handler.
    assertNotNull(readOnlyConfig.getLDAPDebugLogHandler());

    try
    {
      readOnlyConfig.setLDAPDebugLogHandler(null);
      fail("Expected an exception when trying to call setLDAPDebugLogHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the extended operation handlers.
    assertNotNull(readOnlyConfig.getExtendedOperationHandlers());
    assertFalse(readOnlyConfig.getExtendedOperationHandlers().isEmpty());

    try
    {
      readOnlyConfig.getExtendedOperationHandlers().add(
           new TestExtendedOperationHandler());
      fail("Expected an exception when trying to alter the list returned by " +
           "getExtendedOperationHandlers");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addExtendedOperationHandler(
           new TestExtendedOperationHandler());
      fail("Expected an exception when trying to call " +
           "addExtendedOperationHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the SASL bind handlers.
    assertNotNull(readOnlyConfig.getSASLBindHandlers());
    assertFalse(readOnlyConfig.getSASLBindHandlers().isEmpty());

    try
    {
      readOnlyConfig.getSASLBindHandlers().add(new TestSASLBindHandler());
      fail("Expected an exception when trying to alter the list returned by " +
           "getSASLBindHandlers");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }

    try
    {
      readOnlyConfig.addSASLBindHandler(new TestSASLBindHandler());
      fail("Expected an exception when trying to call addSASLBindHandler");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to the generation of operational attributes.
    assertFalse(readOnlyConfig.generateOperationalAttributes());

    try
    {
      readOnlyConfig.setGenerateOperationalAttributes(true);
      fail("Expected an exception when trying to call " +
           "setGenerateOperationalAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to changelog entries.
    assertEquals(readOnlyConfig.getMaxChangeLogEntries(), 100);

    try
    {
      readOnlyConfig.setMaxChangeLogEntries(0);
      fail("Expected an exception when trying to call " +
           "setMaxChangeLogEntries");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected.
    }


    // Test methods related to equality index attributes.
    assertNotNull(readOnlyConfig.getEqualityIndexAttributes());
    assertFalse(readOnlyConfig.getEqualityIndexAttributes().isEmpty());
    assertEquals(readOnlyConfig.getEqualityIndexAttributes().size(), 2);
    assertTrue(readOnlyConfig.getEqualityIndexAttributes().contains("uid"));
    assertTrue(readOnlyConfig.getEqualityIndexAttributes().contains("cn"));


    // Test methods related to referential integrity attributes.
    assertNotNull(readOnlyConfig.getReferentialIntegrityAttributes());
    assertFalse(readOnlyConfig.getReferentialIntegrityAttributes().isEmpty());
    assertEquals(readOnlyConfig.getReferentialIntegrityAttributes().size(), 4);
    assertTrue(readOnlyConfig.getReferentialIntegrityAttributes().contains(
         "member"));
    assertTrue(readOnlyConfig.getReferentialIntegrityAttributes().contains(
         "uniqueMember"));
    assertTrue(readOnlyConfig.getReferentialIntegrityAttributes().contains(
         "owner"));
    assertTrue(readOnlyConfig.getReferentialIntegrityAttributes().contains(
         "seeAlso"));

    try
    {
      readOnlyConfig.setReferentialIntegrityAttributes("member");
      fail("Expected an exception when trying to call " +
           "setReferentialIntegrityAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected
    }

    try
    {
      readOnlyConfig.setReferentialIntegrityAttributes(Arrays.asList(
           "member", "uniqueMember", "owner", "seeAlso"));
      fail("Expected an exception when trying to call " +
           "setReferentialIntegrityAttributes");
    }
    catch (final UnsupportedOperationException e)
    {
      // This was expected
    }


    // Test the toString method.
    assertNotNull(readOnlyConfig.toString());
  }
}
