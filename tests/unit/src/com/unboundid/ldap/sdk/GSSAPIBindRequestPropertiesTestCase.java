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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the GSSAPIBindRequestProperties
 * class.
 */
public final class GSSAPIBindRequestPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for methods dealing with the authentication ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticationID()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNotNull(properties.getAuthenticationID());
    assertEquals(properties.getAuthenticationID(),
         "test.user@EXAMPLE.COM");

    properties.setAuthenticationID("test.2@EXAMPLE.COM");
    assertNotNull(properties.getAuthenticationID());
    assertEquals(properties.getAuthenticationID(),
         "test.2@EXAMPLE.COM");

    assertNotNull(properties.toString());

    properties.setAuthenticationID(null);
    assertNull(properties.getAuthenticationID());
    assertNotNull(properties.toString());

    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the authorization ID.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationID()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM",
              "password".getBytes("UTF-8"));

    assertNotNull(properties.toString());

    assertNull(properties.getAuthorizationID());

    properties.setAuthorizationID("test.2@EXAMPLE.COM");
    assertNotNull(properties.getAuthorizationID());
    assertEquals(properties.getAuthorizationID(),
         "test.2@EXAMPLE.COM");

    assertNotNull(properties.toString());

    properties.setAuthorizationID(null);
    assertNull(properties.getAuthorizationID());

    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the password.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPassword()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword(),
         new ASN1OctetString("password"));

    properties.setPassword("stringPassword");
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword(),
         new ASN1OctetString("stringPassword"));

    assertNotNull(properties.toString());

    properties.setPassword("bytesPassword".getBytes("UTF-8"));
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword(),
         new ASN1OctetString("bytesPassword"));

    assertNotNull(properties.toString());

    properties.setPassword(new ASN1OctetString("octetStringPassword"));
    assertNotNull(properties.getPassword());
    assertEquals(properties.getPassword(),
         new ASN1OctetString("octetStringPassword"));

    assertNotNull(properties.toString());

    properties.setPassword((String) null);
    assertNull(properties.getPassword());
    assertNotNull(properties.toString());

    properties.setPassword((byte[]) null);
    assertNull(properties.getPassword());
    assertNotNull(properties.toString());

    properties.setPassword((ASN1OctetString) null);
    assertNull(properties.getPassword());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the realm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRealm()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNull(properties.getRealm());

    properties.setRealm("EXAMPLE.COM");
    assertNotNull(properties.getRealm());
    assertEquals(properties.getRealm(), "EXAMPLE.COM");

    assertNotNull(properties.toString());

    properties.setRealm(null);
    assertNull(properties.getRealm());

    assertNotNull(properties.toString());
  }



  /**
   * Tests properties related to the allowed qualities of protection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowedQoP()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP(SASLQualityOfProtection.AUTH_CONF);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF));

    properties.setAllowedQoP();
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP(SASLQualityOfProtection.AUTH_CONF,
         SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP((List<SASLQualityOfProtection>) null);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH));

    properties.setAllowedQoP(SASLQualityOfProtection.AUTH,
         SASLQualityOfProtection.AUTH_INT, SASLQualityOfProtection.AUTH_CONF);
    assertNotNull(properties.getAllowedQoP());
    assertEquals(properties.getAllowedQoP(),
         Arrays.asList(SASLQualityOfProtection.AUTH,
              SASLQualityOfProtection.AUTH_INT,
              SASLQualityOfProtection.AUTH_CONF));
  }



  /**
   * Provides test coverage for methods dealing with the KDC address.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKDCAddress()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNull(properties.getKDCAddress());

    properties.setKDCAddress("kdc.example.com");
    assertNotNull(properties.getKDCAddress());
    assertEquals(properties.getKDCAddress(), "kdc.example.com");

    assertNotNull(properties.toString());

    properties.setKDCAddress(null);
    assertNull(properties.getKDCAddress());

    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the config file path.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConfigFilePath()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNull(properties.getConfigFilePath());

    properties.setConfigFilePath("/tmp/gssapi-jaas.config");
    assertNotNull(properties.getConfigFilePath());
    assertEquals(properties.getConfigFilePath(), "/tmp/gssapi-jaas.config");

    assertNotNull(properties.toString());

    properties.setConfigFilePath(null);
    assertNull(properties.getConfigFilePath());

    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the JAAS client name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testJAASClientName()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNotNull(properties.getJAASClientName());
    assertEquals(properties.getJAASClientName(), "GSSAPIBindRequest");

    properties.setJAASClientName("TestGSSAPIBind");
    assertEquals(properties.getJAASClientName(), "TestGSSAPIBind");
  }



  /**
   * Provides test coverage for methods dealing with the SASL client server
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLClientServerName()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNull(properties.getSASLClientServerName());

    properties.setSASLClientServerName("ldap.example.com");
    assertNotNull(properties.getSASLClientServerName());
    assertEquals(properties.getSASLClientServerName(), "ldap.example.com");
    assertNotNull(properties.toString());

    properties.setSASLClientServerName(null);
    assertNull(properties.getSASLClientServerName());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the service principal
   * protocol.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServicePrincipalProtocol()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNotNull(properties.getServicePrincipalProtocol());

    properties.setServicePrincipalProtocol("test");
    assertNotNull(properties.getServicePrincipalProtocol());
    assertEquals(properties.getServicePrincipalProtocol(), "test");

    assertNotNull(properties.toString());

    try
    {
      properties.setServicePrincipalProtocol(null);
      fail("Expected a usage exception for a null service principal protocol");
    }
    catch (final LDAPSDKUsageException lue)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for methods dealing with the use of a ticket cache.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUseTicketCache()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertTrue(properties.useTicketCache());

    properties.setUseTicketCache(false);
    assertFalse(properties.useTicketCache());
    assertNotNull(properties.toString());

    properties.setUseTicketCache(true);
    assertTrue(properties.useTicketCache());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with the path to the ticket
   * cache.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTicketCachePath()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNull(properties.getTicketCachePath());

    properties.setTicketCachePath("ticket.cache");
    assertNotNull(properties.getTicketCachePath());
    assertEquals(properties.getTicketCachePath(), "ticket.cache");
    assertNotNull(properties.toString());

    properties.setTicketCachePath(null);
    assertNull(properties.getTicketCachePath());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with requiring the use of cached
   * credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequireCachedCredentials()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertFalse(properties.requireCachedCredentials());

    properties.setRequireCachedCredentials(true);
    assertTrue(properties.requireCachedCredentials());
    assertNotNull(properties.toString());

    properties.setRequireCachedCredentials(false);
    assertFalse(properties.requireCachedCredentials());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with renewing the TGT.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenewTGT()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertFalse(properties.renewTGT());

    properties.setRenewTGT(true);
    assertTrue(properties.renewTGT());
    assertNotNull(properties.toString());

    properties.setRenewTGT(false);
    assertFalse(properties.renewTGT());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for the refreshKrb5Config property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRefreshKrb5Config()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertFalse(properties.refreshKrb5Config());

    properties.setRefreshKrb5Config(true);
    assertTrue(properties.refreshKrb5Config());
    assertNotNull(properties.toString());

    properties.setRefreshKrb5Config(false);
    assertFalse(properties.refreshKrb5Config());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for properties related to the use of a keytab.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testKeyTab()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertFalse(properties.useKeyTab());
    assertNull(properties.getKeyTabPath());

    properties.setUseKeyTab(true);
    assertTrue(properties.useKeyTab());
    assertNull(properties.getKeyTabPath());

    final String path = createTempFile().getAbsolutePath();
    properties.setUseKeyTab(false);
    properties.setKeyTabPath(path);
    assertFalse(properties.useKeyTab());
    assertNotNull(properties.getKeyTabPath());
    assertEquals(properties.getKeyTabPath(), path);

    assertNotNull(properties.toString());

    properties.setUseKeyTab(true);
    assertTrue(properties.useKeyTab());
    assertNotNull(properties.getKeyTabPath());
    assertEquals(properties.getKeyTabPath(), path);

    assertNotNull(properties.toString());

    properties.setUseKeyTab(false);
    properties.setKeyTabPath(null);
    assertFalse(properties.useKeyTab());
    assertNull(properties.getKeyTabPath());
  }



  /**
   * Provides test coverage for properties related to the client's explicit
   * indication about whether it is an initiator or an acceptor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInitiator()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNull(properties.getIsInitiator());

    properties.setIsInitiator(true);
    assertNotNull(properties.getIsInitiator());
    assertEquals(properties.getIsInitiator(), Boolean.TRUE);
    assertNotNull(properties.toString());

    properties.setIsInitiator(false);
    assertNotNull(properties.getIsInitiator());
    assertEquals(properties.getIsInitiator(), Boolean.FALSE);
    assertNotNull(properties.toString());

    properties.setIsInitiator(null);
    assertNull(properties.getIsInitiator());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods that can be used to suppress system
   * properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuppressedProperties()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertNotNull(properties.getSuppressedSystemProperties());
    assertTrue(properties.getSuppressedSystemProperties().isEmpty());

    properties.setSuppressedSystemProperties(Arrays.asList(
         "java.security.auth.login.config",
         "java.security.krb5.realm",
         "java.security.krb5.kdc",
         "javax.security.auth.useSubjectCredsOnly"));
    assertNotNull(properties.getSuppressedSystemProperties());
    assertFalse(properties.getSuppressedSystemProperties().isEmpty());
    assertEquals(properties.getSuppressedSystemProperties().size(), 4);
    assertTrue(properties.getSuppressedSystemProperties().contains(
         "java.security.auth.login.config"));
    assertTrue(properties.getSuppressedSystemProperties().contains(
         "java.security.krb5.realm"));
    assertTrue(properties.getSuppressedSystemProperties().contains(
         "java.security.krb5.kdc"));
    assertTrue(properties.getSuppressedSystemProperties().contains(
         "javax.security.auth.useSubjectCredsOnly"));
    assertNotNull(properties.toString());

    properties.setSuppressedSystemProperties(null);
    assertNotNull(properties.getSuppressedSystemProperties());
    assertTrue(properties.getSuppressedSystemProperties().isEmpty());
    assertNotNull(properties.toString());
  }



  /**
   * Provides test coverage for methods dealing with GSSAPI debugging.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebug()
         throws Exception
  {
    final GSSAPIBindRequestProperties properties =
         new GSSAPIBindRequestProperties("test.user@EXAMPLE.COM", "password");

    assertNotNull(properties.toString());

    assertFalse(properties.enableGSSAPIDebugging());

    properties.setEnableGSSAPIDebugging(true);
    assertTrue(properties.enableGSSAPIDebugging());

    assertNotNull(properties.toString());

    properties.setEnableGSSAPIDebugging(false);
    assertFalse(properties.enableGSSAPIDebugging());

    assertNotNull(properties.toString());
  }
}
