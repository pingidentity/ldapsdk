/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the GSSAPIBindRequest class.
 * Note that this class does not expect any GSSAPI environment to be configured,
 * so it will not verify the results of any authentication attempt.
 */
public class GSSAPIBindRequestTestCase
       extends LDAPSDKTestCase
{
  // The path to a default config file path.
  private String configFilePath;



  /**
   * Gets the default config file path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void initialize()
         throws Exception
  {
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "password");
    configFilePath = r.getConfigFilePath();
    assertNotNull(configFilePath);
    assertTrue(new File(configFilePath).exists());

    final GSSAPIBindRequestProperties gssapiProperties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");
    gssapiProperties.setEnableGSSAPIDebugging(true);
    r = new GSSAPIBindRequest(gssapiProperties);
    final String configFilePathWithDebugging = r.getConfigFilePath();
    assertNotNull(configFilePathWithDebugging);
    assertTrue(new File(configFilePathWithDebugging).exists());

    assertFalse(configFilePath.equals(configFilePathWithDebugging));
  }



  /**
   * Provides test coverage for the first constructor, which takes an
   * authentication ID and string password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "password");
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNull(r.getRealm());

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNull(r.getKDCAddress());

    assertNotNull(r.getConfigFilePath());

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the second constructor, which takes an
   * authentication ID and byte array password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM",
                               "password".getBytes("UTF-8"));
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNull(r.getRealm());

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNull(r.getKDCAddress());

    assertNotNull(r.getConfigFilePath());

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the third constructor, which takes an
   * authentication ID, string password, and set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "password", controls);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNull(r.getRealm());

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNull(r.getKDCAddress());

    assertNotNull(r.getConfigFilePath());

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the fourth constructor, which takes an
   * authentication ID, byte array password, and set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM",
                               "password".getBytes("UTF-8"), controls);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNull(r.getAuthorizationID());

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNull(r.getRealm());

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNull(r.getKDCAddress());

    assertNotNull(r.getConfigFilePath());

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the fifth constructor, which takes an
   * authentication ID, authorization ID, string password, realm, KDC address,
   * and config file path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5()
         throws Exception
  {
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "alt.user@EXAMPLE.COM",
                  "password", "EXAMPLE.COM", "localhost", configFilePath);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "alt.user@EXAMPLE.COM");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNotNull(r.getRealm());
    assertEquals(r.getRealm(), "EXAMPLE.COM");

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(r.getKDCAddress());
    assertEquals(r.getKDCAddress(), "localhost");

    assertNotNull(r.getConfigFilePath());
    assertEquals(r.getConfigFilePath(), configFilePath);

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the sixth constructor, which takes an
   * authentication ID, authorization ID, byte array password, realm, KDC
   * address, and config file path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6()
         throws Exception
  {
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "alt.user@EXAMPLE.COM",
                  "password".getBytes("UTF-8"), "EXAMPLE.COM", "localhost",
                  configFilePath);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "alt.user@EXAMPLE.COM");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNotNull(r.getRealm());
    assertEquals(r.getRealm(), "EXAMPLE.COM");

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(r.getKDCAddress());
    assertEquals(r.getKDCAddress(), "localhost");

    assertNotNull(r.getConfigFilePath());
    assertEquals(r.getConfigFilePath(), configFilePath);

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the seventh constructor, which takes an
   * authentication ID, authorization ID, string password, realm, KDC address,
   * config file path, and set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "alt.user@EXAMPLE.COM",
                  "password", "EXAMPLE.COM", "localhost", configFilePath,
                  controls);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "alt.user@EXAMPLE.COM");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNotNull(r.getRealm());
    assertEquals(r.getRealm(), "EXAMPLE.COM");

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(r.getKDCAddress());
    assertEquals(r.getKDCAddress(), "localhost");

    assertNotNull(r.getConfigFilePath());
    assertEquals(r.getConfigFilePath(), configFilePath);

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the eighth constructor, which takes an
   * authentication ID, authorization ID, byte array password, realm, KDC
   * address, config file path, and controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };
    GSSAPIBindRequest r =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "alt.user@EXAMPLE.COM",
                  "password".getBytes("UTF-8"), "EXAMPLE.COM", "localhost",
                  configFilePath, controls);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNotNull(r.getAuthenticationID());
    assertEquals(r.getAuthenticationID(), "test.user@EXAMPLE.COM");

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "alt.user@EXAMPLE.COM");

    assertNotNull(r.getPasswordString());
    assertEquals(r.getPasswordString(), "password");

    assertNotNull(r.getPasswordBytes());
    assertTrue(Arrays.equals(r.getPasswordBytes(),
                             "password".getBytes("UTF-8")));

    assertNotNull(r.getRealm());
    assertEquals(r.getRealm(), "EXAMPLE.COM");

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    assertNotNull(r.getKDCAddress());
    assertEquals(r.getKDCAddress(), "localhost");

    assertNotNull(r.getConfigFilePath());
    assertEquals(r.getConfigFilePath(), configFilePath);

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "ldap");

    assertFalse(r.refreshKrb5Config());

    assertFalse(r.useKeyTab());
    assertNull(r.getKeyTabPath());

    assertTrue(r.useTicketCache());

    assertFalse(r.requireCachedCredentials());

    assertFalse(r.renewTGT());

    assertNull(r.getTicketCachePath());

    assertNull(r.getIsInitiator());

    assertNotNull(r.getSuppressedSystemProperties());
    assertTrue(r.getSuppressedSystemProperties().isEmpty());

    assertFalse(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides test coverage for the constructor which takes a GSSAPI bind
   * request properties object and optional set of controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertiesConstructor()
         throws Exception
  {
    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", false, null)
    };

    final GSSAPIBindRequestProperties gssapiProperties =
         new GSSAPIBindRequestProperties(null, (String) null);
    gssapiProperties.setAuthorizationID("alt.user@EXAMPLE.COM");
    gssapiProperties.setRealm("EXAMPLE.COM");
    gssapiProperties.setAllowedQoP(SASLQualityOfProtection.AUTH_CONF);
    gssapiProperties.setKDCAddress("localhost");
    gssapiProperties.setServicePrincipalProtocol("testproto");
    gssapiProperties.setRefreshKrb5Config(true);
    gssapiProperties.setUseKeyTab(true);
    gssapiProperties.setKeyTabPath("keytab");
    gssapiProperties.setUseTicketCache(true);
    gssapiProperties.setRequireCachedCredentials(true);
    gssapiProperties.setRenewTGT(true);
    gssapiProperties.setSASLClientServerName("ldap.example.com");
    gssapiProperties.setTicketCachePath("ticket.cache");
    gssapiProperties.setIsInitiator(false);
    gssapiProperties.setSuppressedSystemProperties(Arrays.asList(
         "java.security.auth.login.config",
         "java.security.krb5.realm",
         "java.security.krb5.kdc",
         "javax.security.auth.useSubjectCredsOnly"));
    gssapiProperties.setEnableGSSAPIDebugging(true);

    GSSAPIBindRequest r = new GSSAPIBindRequest(gssapiProperties, controls);
    r = r.duplicate();

    assertNotNull(r);

    assertNotNull(r.getSASLMechanismName());
    assertEquals(r.getSASLMechanismName(), "GSSAPI");

    assertNull(r.getAuthenticationID());

    assertNotNull(r.getAuthorizationID());
    assertEquals(r.getAuthorizationID(), "alt.user@EXAMPLE.COM");

    assertNull(r.getPasswordString());

    assertNull(r.getPasswordBytes());

    assertNotNull(r.getRealm());
    assertEquals(r.getRealm(), "EXAMPLE.COM");

    assertNotNull(r.getAllowedQoP());
    assertEquals(r.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF));

    assertNotNull(r.getKDCAddress());
    assertEquals(r.getKDCAddress(), "localhost");

    assertNotNull(r.getConfigFilePath());

    assertNotNull(r.getServicePrincipalProtocol());
    assertEquals(r.getServicePrincipalProtocol(), "testproto");

    assertTrue(r.refreshKrb5Config());

    assertTrue(r.useKeyTab());
    assertNotNull(r.getKeyTabPath());
    assertEquals(r.getKeyTabPath(), "keytab");

    assertTrue(r.useTicketCache());

    assertTrue(r.requireCachedCredentials());

    assertTrue(r.renewTGT());

    assertNotNull(r.getTicketCachePath());
    assertEquals(r.getTicketCachePath(), "ticket.cache");

    assertNotNull(r.getIsInitiator());
    assertEquals(r.getIsInitiator(), Boolean.FALSE);

    assertNotNull(r.getSuppressedSystemProperties());
    assertFalse(r.getSuppressedSystemProperties().isEmpty());
    assertEquals(
         new ArrayList<String>(r.getSuppressedSystemProperties()),
         Arrays.asList(
              "java.security.auth.login.config",
              "java.security.krb5.realm",
              "java.security.krb5.kdc",
              "javax.security.auth.useSubjectCredsOnly"));

    assertTrue(r.enableGSSAPIDebugging());

    assertNotNull(r.getRebindRequest("127.0.0.1", 389));

    r.getLastMessageID();

    assertNotNull(r.duplicate());

    assertNotNull(r.duplicate(controls));

    assertNotNull(r.toString());

    final ArrayList<String> toCodeLines = new ArrayList<String>(10);
    r.toCode(toCodeLines, "foo", 0, false);
    assertFalse(toCodeLines.isEmpty());

    toCodeLines.clear();
    r.toCode(toCodeLines, "bar", 4, true);
    assertFalse(toCodeLines.isEmpty());
  }



  /**
   * Provides coverage for the method used to handle callbacks.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHandleCallbacks()
         throws Exception
  {
    GSSAPIBindRequest request =
         new GSSAPIBindRequest("test.user@EXAMPLE.COM", "alt.user@EXAMPLE.COM",
                  "password", "EXAMPLE.COM", "localhost", configFilePath);

    NameCallback n = new NameCallback("What is your name?");
    PasswordCallback p = new PasswordCallback("What is your password?", false);
    RealmCallback r = new RealmCallback("Where are you going?");
    LanguageCallback l = new LanguageCallback();

    Callback[] callbacks = { n, p, r, l };
    request.handle(callbacks);

    assertNotNull(n.getName());
    assertEquals(n.getName(), "test.user@EXAMPLE.COM");

    assertNotNull(p.getPassword());
    assertTrue(Arrays.equals(p.getPassword(), "password".toCharArray()));

    assertNotNull(r.getText());
    assertEquals(r.getText(), "EXAMPLE.COM");
  }
}
