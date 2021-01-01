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
package com.unboundid.ldap.sdk.unboundidds;



import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the code capable of parsing LDAP
 * connection handler configuration objects from a Ping Identity Directory
 * Server configuration file.
 */
public final class LDAPConnectionHandlerConfigurationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to parse a configuration that only uses SSL.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPSConfiguration()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertTrue(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior when trying to parse a configuration that uses LDAP that
   * supports StartTLS.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPConfigurationWithStartTLS()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAP Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAP Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-address: 0.0.0.0",
         "ds-cfg-listen-address: ::0",
         "ds-cfg-listen-port: 389",
         "ds-cfg-use-ssl: false",
         "ds-cfg-allow-start-tls: true");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAP Connection Handler");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertTrue(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 389);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior when trying to parse a configuration that uses LDAP that
   * does not support StartTLS.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPConfigurationWithoutStartTLS()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAP Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAP Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-address: 1.2.3.4",
         "ds-cfg-listen-address: 5.6.7.8",
         "ds-cfg-listen-address: ::0",
         "ds-cfg-listen-port: 389",
         "ds-cfg-use-ssl: false",
         "ds-cfg-allow-start-tls: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAP Connection Handler");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertFalse(config.getListenAddresses().isEmpty());
    assertEquals(config.getListenAddresses(),
         Arrays.asList("1.2.3.4", "5.6.7.8"));

    assertEquals(config.getPort(), 389);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior when trying to parse a configuration that includes
   * multiple connection handlers.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleConnectionHandlers()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false",
         "",
         "dn: cn=LDAP Without StartTLS,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAP Without StartTLS",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 1389",
         "ds-cfg-use-ssl: false",
         "ds-cfg-allow-start-tls: false",
         "",
         "dn: cn=LDAP With StartTLS,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAP With StartTLS",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 2389",
         "ds-cfg-use-ssl: false",
         "ds-cfg-allow-start-tls: true");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 3);

    LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS");

    assertTrue(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());


    config = configs.get(1);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAP With StartTLS");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertTrue(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 2389);

    assertNotNull(config.toString());


    config = configs.get(2);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAP Without StartTLS");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 1389);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler that is not enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerNotEnabled()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: false",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertFalse(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler that does not have an enabled
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerWithoutEnabled()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertFalse(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler that has a malformed enabled
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerMalformedEnabled()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: malformed",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertFalse(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler that does not have a name
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerWithoutName()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());
  }



  /**
   * Tests the behavior for a connection handler that does not have a listen
   * port attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerWithoutListenPort()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());
  }



  /**
   * Tests the behavior for a connection handler that has a malformed listen
   * port attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerMalformedListenPort()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: malformed",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());
  }



  /**
   * Tests the behavior for a connection handler that has a listen port value
   * that is out of range.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerListenPortOutOfRange()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 123456",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());

    configs = LDAPConnectionHandlerConfiguration.readConfiguration(configFile,
         false);

    assertNotNull(configs);
    assertTrue(configs.isEmpty());
  }



  /**
   * Tests the behavior for a connection handler without a useSSL attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerWithoutUseSSL()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 636",
         "ds-cfg-allow-start-tls: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler with a malformed useSSL
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerMalformedUseSSL()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: malformed",
         "ds-cfg-allow-start-tls: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler without an allow StartTLS
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerMalformedWithoutStartTLS()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAP Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAP Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 389",
         "ds-cfg-use-ssl: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAP Connection Handler");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 389);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler with a malformed allow StartTLS
   * attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerMalformedAllowStartTLS()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAP Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAP Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 389",
         "ds-cfg-use-ssl: false",
         "ds-cfg-allow-start-tls: malformed");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAP Connection Handler");

    assertTrue(config.isEnabled());

    assertFalse(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 389);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler with both useSSL and allow
   * StartTLS set to true.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerUseSSLAndAllowStartTLS()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: true");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertTrue(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertTrue(config.getListenAddresses().isEmpty());

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler with a malformed listen
   * address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandlerMalformedListenAddress()
         throws Exception
  {
    final File configFile = createTempFile(
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-address: 345.456.567.678",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertTrue(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertFalse(config.getListenAddresses().isEmpty());
    assertEquals(config.getListenAddresses(),
         Collections.singletonList("345.456.567.678"));

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler with a malformed entry that is
   * recoverable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRecoverableMalformedEntry()
         throws Exception
  {
    final File configFile = createTempFile(
         "malformed",
         "",
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-address: 1.2.3.4",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    final List<LDAPConnectionHandlerConfiguration> configs =
         LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);

    assertNotNull(configs);
    assertFalse(configs.isEmpty());
    assertEquals(configs.size(), 1);

    final LDAPConnectionHandlerConfiguration config = configs.get(0);

    assertNotNull(config.getName());
    assertEquals(config.getName(), "LDAPS Connection Handler");

    assertTrue(config.isEnabled());

    assertTrue(config.usesSSL());

    assertFalse(config.supportsStartTLS());

    assertNotNull(config.getListenAddresses());
    assertFalse(config.getListenAddresses().isEmpty());
    assertEquals(config.getListenAddresses(),
         Collections.singletonList("1.2.3.4"));

    assertEquals(config.getPort(), 636);

    assertNotNull(config.toString());
  }



  /**
   * Tests the behavior for a connection handler with a malformed entry that is
   * not recoverable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testUnrecoverableMalformedEntry()
         throws Exception
  {
    final File configFile = createTempFile(
         " malformed with leading space -- unrecoverable",
         "",
         "dn: cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-root-config",
         "cn: config",
         "",
         "dn: cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-branch",
         "cn: Connection Handlers",
         "",
         "dn: cn=LDAPS Connection Handler,cn=Connection Handlers,cn=config",
         "objectClass: top",
         "objectClass: ds-cfg-connection-handler",
         "objectClass: ds-cfg-ldap-connection-handler",
         "cn: LDAPS Connection Handler",
         "ds-cfg-enabled: true",
         "ds-cfg-listen-address: 1.2.3.4",
         "ds-cfg-listen-port: 636",
         "ds-cfg-use-ssl: true",
         "ds-cfg-allow-start-tls: false");

    LDAPConnectionHandlerConfiguration.readConfiguration(configFile, true);
  }



  /**
   * Provides test coverage for the equals and hashCode methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsAndHashCode()
         throws Exception
  {
    LDAPConnectionHandlerConfiguration c1 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, true, false);
    assertTrue(c1.equals(c1));
    assertEquals(c1.hashCode(), c1.hashCode());

    LDAPConnectionHandlerConfiguration c2 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, true, false);
    assertTrue(c1.equals(c2));
    assertEquals(c1.hashCode(), c2.hashCode());

    LDAPConnectionHandlerConfiguration c3 =
         new LDAPConnectionHandlerConfiguration("ldaps", true,
              Collections.<String>emptyList(), 636, true, false);
    assertTrue(c1.equals(c3));
    assertEquals(c1.hashCode(), c3.hashCode());

    LDAPConnectionHandlerConfiguration c4 =
         new LDAPConnectionHandlerConfiguration("different name", true,
              Collections.<String>emptyList(), 636, true, false);
    assertFalse(c1.equals(c4));

    LDAPConnectionHandlerConfiguration c5 =
         new LDAPConnectionHandlerConfiguration("LDAPS", false,
              Collections.<String>emptyList(), 636, true, false);
    assertFalse(c1.equals(c5));

    LDAPConnectionHandlerConfiguration c6 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.singletonList("1.2.3.4"), 636, true, false);
    assertFalse(c1.equals(c6));

    LDAPConnectionHandlerConfiguration c7 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 1636, true, false);
    assertFalse(c1.equals(c7));

    LDAPConnectionHandlerConfiguration c8 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, false, false);
    assertFalse(c1.equals(c8));

    LDAPConnectionHandlerConfiguration c9 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, true, true);
    assertFalse(c1.equals(c9));

    assertFalse(c1.equals(null));

    assertFalse(c1.equals("foo"));
  }



  /**
   * Provides test coverage for the compareTo method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareTo()
         throws Exception
  {
    LDAPConnectionHandlerConfiguration c1 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, true, false);
    assertEquals(c1.compareTo(c1), 0);


    LDAPConnectionHandlerConfiguration c2 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, true, false);
    assertEquals(c1.compareTo(c2), 0);
    assertEquals(c2.compareTo(c1), 0);


    LDAPConnectionHandlerConfiguration c3 =
         new LDAPConnectionHandlerConfiguration("LDAPS", false,
              Collections.<String>emptyList(), 636, true, false);
    assertTrue(c1.compareTo(c3) < 0);
    assertTrue(c3.compareTo(c1) > 0);


    LDAPConnectionHandlerConfiguration c4 =
         new LDAPConnectionHandlerConfiguration("LDAPS", true,
              Collections.<String>emptyList(), 636, false, false);
    assertTrue(c1.compareTo(c4) < 0);
    assertTrue(c4.compareTo(c1) > 0);


    LDAPConnectionHandlerConfiguration c5 =
         new LDAPConnectionHandlerConfiguration("LDAP", true,
              Collections.<String>emptyList(), 389, false, false);
    LDAPConnectionHandlerConfiguration c6 =
         new LDAPConnectionHandlerConfiguration("LDAP", true,
              Collections.<String>emptyList(), 389, false, true);
    assertTrue(c5.compareTo(c6) > 0);
    assertTrue(c6.compareTo(c5) < 0);


    LDAPConnectionHandlerConfiguration c7 =
         new LDAPConnectionHandlerConfiguration("LDAP Connection Handler", true,
              Collections.<String>emptyList(), 389, false, true);
    assertTrue(c6.compareTo(c7) > 0);
    assertTrue(c7.compareTo(c6) < 0);


    LDAPConnectionHandlerConfiguration c8 =
         new LDAPConnectionHandlerConfiguration("LDAPS Connection Handler",
              true, Collections.<String>emptyList(), 636, true, false);
    assertTrue(c1.compareTo(c8) > 0);
    assertTrue(c8.compareTo(c1) < 0);


    LDAPConnectionHandlerConfiguration c9 =
         new LDAPConnectionHandlerConfiguration("LDAPS Connection Handler",
              true, Collections.singletonList("1.2.3.4"), 636, true, false);
    assertTrue(c8.compareTo(c9) < 0);
    assertTrue(c9.compareTo(c8) > 0);


    LDAPConnectionHandlerConfiguration c10 =
         new LDAPConnectionHandlerConfiguration("LDAPS Connection Handler",
              true, Arrays.asList("1.2.3.4", "1.2.3.5"), 636, true, false);
    assertTrue(c8.compareTo(c10) < 0);
    assertTrue(c10.compareTo(c8) > 0);


    LDAPConnectionHandlerConfiguration c11 =
         new LDAPConnectionHandlerConfiguration("LDAPS Connection Handler",
              true, Collections.<String>emptyList(), 1636, true, false);
    assertTrue(c8.compareTo(c11) < 0);
    assertTrue(c11.compareTo(c8) > 0);


    assertTrue(c1.compareTo(null) < 0);
  }
}
