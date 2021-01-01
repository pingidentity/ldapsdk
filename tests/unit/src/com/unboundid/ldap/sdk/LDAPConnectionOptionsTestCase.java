/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.net.InetAddress;
import java.util.Arrays;
import java.util.EnumSet;
import javax.net.ssl.SSLSocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeregisterYubiKeyOTPDeviceExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            EndAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GenerateTOTPSharedSecretExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetConnectionIDExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetPasswordQualityRequirementsExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            RegisterYubiKeyOTPDeviceExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            RevokeTOTPSharedSecretExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            ValidateTOTPPasswordExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.SynchronizedSocketFactory;
import com.unboundid.util.SynchronizedSSLSocketFactory;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllSSLSocketVerifier;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class defines a set of test cases for the LDAPConnectionOptions class.
 */
public class LDAPConnectionOptionsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default behavior for all connection options.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testDefaultSettings()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.autoReconnect());
    assertTrue(opts.bindWithDNRequiresPassword());
    assertFalse(opts.followReferrals());
    assertEquals(opts.getReferralHopLimit(), 5);
    assertNull(opts.getReferralConnector());
    assertTrue(opts.useKeepAlive());
    assertTrue(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 5);
    assertTrue(opts.useReuseAddress());
    assertFalse(opts.useSynchronousMode());
    assertTrue(opts.useTCPNoDelay());
    assertEquals(opts.getConnectTimeoutMillis(), 10_000L);
    assertEquals(opts.getResponseTimeoutMillis(), 300_000L);
    assertFalse(opts.abandonOnTimeout());
    assertEquals(opts.getMaxMessageSize(), (20 * 1024 * 1024));
    assertNull(opts.getConnectionLogger());
    assertNull(opts.getDisconnectHandler());
    assertNull(opts.getUnsolicitedNotificationHandler());
    assertFalse(opts.captureConnectStackTrace());
    assertFalse(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 10_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED),
         300_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN),
         30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 300_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 10_000L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid),
           30_000L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"),
           300_000L);
    }

    assertTrue(opts.allowConcurrentSocketFactoryUse());

    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);

    assertNotNull(opts.getNameResolver());
  }



  /**
   * Tests duplicate functionality.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testDuplicate()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    opts.setAutoReconnect(true);
    opts.setBindWithDNRequiresPassword(false);
    opts.setCaptureConnectStackTrace(true);
    opts.setConnectTimeoutMillis(1234);
    opts.setFollowReferrals(true);
    opts.setMaxMessageSize(1234);
    opts.setReferralHopLimit(10);
    opts.setReferralConnector(new TestReferralConnector());
    opts.setResponseTimeoutMillis(1234L);
    opts.setAbandonOnTimeout(true);
    opts.setConnectionLogger(new TestLDAPConnectionLogger());
    opts.setDisconnectHandler(new TestDisconnectHandler());
    opts.setUnsolicitedNotificationHandler(
         new TestUnsolicitedNotificationHandler());
    opts.setUseKeepAlive(false);
    opts.setUseLinger(false, 1234);
    opts.setUseReuseAddress(false);
    opts.setUseTCPNoDelay(false);
    opts.setReceiveBufferSize(1234);
    opts.setSendBufferSize(1234);
    opts.setUseSynchronousMode(true);
    opts.setUseSchema(true);
    opts.setAllowConcurrentSocketFactoryUse(false);
    opts.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));

    final LDAPConnectionOptions dup = opts.duplicate();

    assertEquals(dup.autoReconnect(), opts.autoReconnect());
    assertEquals(dup.bindWithDNRequiresPassword(),
                 opts.bindWithDNRequiresPassword());
    assertEquals(dup.captureConnectStackTrace(),
                 opts.captureConnectStackTrace());
    assertEquals(dup.getConnectTimeoutMillis(), opts.getConnectTimeoutMillis());
    assertEquals(dup.followReferrals(), opts.followReferrals());
    assertEquals(dup.getReferralHopLimit(), opts.getReferralHopLimit());
    assertNotNull(dup.getReferralConnector());
    assertEquals(dup.getMaxMessageSize(), opts.getMaxMessageSize());
    assertEquals(dup.getResponseTimeoutMillis(),
                 opts.getResponseTimeoutMillis());
    assertEquals(dup.abandonOnTimeout(), opts.abandonOnTimeout());
    assertEquals(dup.getConnectionLogger(), opts.getConnectionLogger());
    assertEquals(dup.getDisconnectHandler(), opts.getDisconnectHandler());
    assertEquals(dup.getUnsolicitedNotificationHandler(),
                 opts.getUnsolicitedNotificationHandler());
    assertEquals(dup.useKeepAlive(), opts.useKeepAlive());
    assertEquals(dup.useLinger(), opts.useLinger());
    assertEquals(dup.getLingerTimeoutSeconds(), opts.getLingerTimeoutSeconds());
    assertEquals(dup.useReuseAddress(), opts.useReuseAddress());
    assertEquals(dup.useTCPNoDelay(), opts.useTCPNoDelay());
    assertEquals(dup.getReceiveBufferSize(), 1234);
    assertEquals(dup.getSendBufferSize(), 1234);
    assertEquals(dup.useSynchronousMode(), opts.useSynchronousMode());
    assertEquals(dup.useSchema(), opts.useSchema());
    assertEquals(dup.usePooledSchema(), opts.usePooledSchema());
    assertEquals(dup.allowConcurrentSocketFactoryUse(),
         opts.allowConcurrentSocketFactoryUse());
    assertTrue(dup.getSSLSocketVerifier() instanceof HostNameSSLSocketVerifier);

    assertNotNull(opts.getNameResolver());
  }



  /**
   * Tests autoReconnect functionality.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testAutoReconnect()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.autoReconnect());
    assertNotNull(opts.toString());

    opts.setAutoReconnect(true);
    assertTrue(opts.autoReconnect());
    assertNotNull(opts.toString());

    opts.setAutoReconnect(false);
    assertFalse(opts.autoReconnect());
    assertNotNull(opts.toString());
  }



  /**
   * Tests followReferrals functionality.
   */
  @Test()
  public void testFollowReferrals()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.followReferrals());
    assertNotNull(opts.toString());

    opts.setFollowReferrals(true);
    assertTrue(opts.followReferrals());
    assertNotNull(opts.toString());

    opts.setFollowReferrals(false);
    assertFalse(opts.followReferrals());
    assertNotNull(opts.toString());
  }



  /**
   * Tests referral hop limit functionality.
   */
  @Test()
  public void testReferralHopLimit()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getReferralHopLimit(), 5);
    assertNotNull(opts.toString());

    opts.setReferralHopLimit(10);
    assertEquals(opts.getReferralHopLimit(), 10);
    assertNotNull(opts.toString());

    boolean caught = false;
    try
    {
      opts.setReferralHopLimit(0);
    }
    catch (final LDAPSDKUsageException ae)
    {
      caught = true;
    }
    assertTrue(caught, "Expected an error when trying to set a zero hop limit");

    caught = false;
    try
    {
      opts.setReferralHopLimit(-1);
    }
    catch (final LDAPSDKUsageException ae)
    {
      caught = true;
    }
    assertTrue(caught,
         "Expected an error when trying to set a negative hop limit");
  }



  /**
   * Tests behavior related to getting and setting the referral connector.
   */
  @Test()
  public void testReferralConnector()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getReferralConnector());
    assertNotNull(opts.toString());

    opts.setReferralConnector(new TestReferralConnector());
    assertNotNull(opts.getReferralConnector());
    assertNotNull(opts.toString());

    opts.setReferralConnector(null);
    assertNull(opts.getReferralConnector());
    assertNotNull(opts.toString());
  }



  /**
   * Tests KeepAlive functionality.
   */
  @Test()
  public void testKeepAlive()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertTrue(opts.useKeepAlive());
    assertNotNull(opts.toString());

    opts.setUseKeepAlive(false);
    assertFalse(opts.useKeepAlive());
    assertNotNull(opts.toString());

    opts.setUseKeepAlive(true);
    assertTrue(opts.useKeepAlive());
    assertNotNull(opts.toString());
  }



  /**
   * Tests linger functionality.
   */
  @Test()
  public void testLinger()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertTrue(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 5);
    assertNotNull(opts.toString());

    opts.setUseLinger(false, 0);
    assertFalse(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 0);
    assertNotNull(opts.toString());

    opts.setUseLinger(true, 3);
    assertTrue(opts.useLinger());
    assertEquals(opts.getLingerTimeoutSeconds(), 3);
    assertNotNull(opts.toString());
  }



  /**
   * Tests ReuseAddress functionality.
   */
  @Test()
  public void testReuseAddress()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertTrue(opts.useReuseAddress());
    assertNotNull(opts.toString());

    opts.setUseReuseAddress(false);
    assertFalse(opts.useReuseAddress());
    assertNotNull(opts.toString());

    opts.setUseReuseAddress(true);
    assertTrue(opts.useReuseAddress());
    assertNotNull(opts.toString());
  }



  /**
   * Tests TCP NoDelay functionality.
   */
  @Test()
  public void testTCPNoDelay()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertTrue(opts.useTCPNoDelay());
    assertNotNull(opts.toString());

    opts.setUseTCPNoDelay(false);
    assertFalse(opts.useTCPNoDelay());
    assertNotNull(opts.toString());

    opts.setUseTCPNoDelay(true);
    assertTrue(opts.useTCPNoDelay());
    assertNotNull(opts.toString());
  }



  /**
   * Tests capture connect stack trace functionality.
   */
  @Test()
  public void testCaptureConnectStackTrace()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.captureConnectStackTrace());
    assertNotNull(opts.toString());

    opts.setCaptureConnectStackTrace(true);
    assertTrue(opts.captureConnectStackTrace());
    assertNotNull(opts.toString());

    opts.setCaptureConnectStackTrace(false);
    assertFalse(opts.captureConnectStackTrace());
    assertNotNull(opts.toString());
  }



  /**
   * Tests connect timeout functionality.
   */
  @Test()
  public void testConnectTimeout()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getConnectTimeoutMillis(), 10_000);
    assertNotNull(opts.toString());

    opts.setConnectTimeoutMillis(0);
    assertEquals(opts.getConnectTimeoutMillis(), 0);
    assertNotNull(opts.toString());

    opts.setConnectTimeoutMillis(5000);
    assertEquals(opts.getConnectTimeoutMillis(), 5000);
    assertNotNull(opts.toString());
  }



  /**
   * Tests response timeout functionality.
   */
  @Test()
  public void testResponseTimeout()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getResponseTimeoutMillis(), 300_000L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 10_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED),
         300_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN),
         30_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 300_000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 10_000L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid),
           30_000L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"),
           300_000L);
    }


    opts.setResponseTimeoutMillis(0L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 0L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid), 0L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"), 0L);
    }


    opts.setResponseTimeoutMillis(5000L);
    assertEquals(opts.getResponseTimeoutMillis(), 5000L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 5000L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 5000L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid), 5000L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"),
           5000L);
    }


    opts.setResponseTimeoutMillis(-1L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 0L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid), 0L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"), 0L);
    }


    opts.setResponseTimeoutMillis(OperationType.SEARCH, 1234L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 1234L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 0L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid), 0L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"), 0L);
    }


    opts.setResponseTimeoutMillis(OperationType.EXTENDED, 5678L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED), 5678L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 1234L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 0L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid), 5678L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"),
           5678L);
    }


    opts.setExtendedOperationResponseTimeoutMillis(
         CancelExtendedRequest.CANCEL_REQUEST_OID, 9999L);
    assertEquals(opts.getResponseTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    assertEquals(opts.getResponseTimeoutMillis(OperationType.ABANDON), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.ADD), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.BIND), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.COMPARE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.DELETE), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.EXTENDED), 5678L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.MODIFY_DN), 0L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.SEARCH), 1234L);
    assertEquals(opts.getResponseTimeoutMillis(OperationType.UNBIND), 0L);

    for (final String oid :
      Arrays.asList(
           PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID,
           StartTLSExtendedRequest.STARTTLS_REQUEST_OID,
           WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID,
           DeregisterYubiKeyOTPDeviceExtendedRequest.
                DEREGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           EndAdministrativeSessionExtendedRequest.
                END_ADMIN_SESSION_REQUEST_OID,
           GenerateTOTPSharedSecretExtendedRequest.
                GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
           GetConnectionIDExtendedRequest.GET_CONNECTION_ID_REQUEST_OID,
           GetPasswordQualityRequirementsExtendedRequest.
                OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
           PasswordPolicyStateExtendedRequest.
                PASSWORD_POLICY_STATE_REQUEST_OID,
           RegisterYubiKeyOTPDeviceExtendedRequest.
                REGISTER_YUBIKEY_OTP_DEVICE_REQUEST_OID,
           RevokeTOTPSharedSecretExtendedRequest.
                REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
           StartAdministrativeSessionExtendedRequest.
                START_ADMIN_SESSION_REQUEST_OID,
           ValidateTOTPPasswordExtendedRequest.
                VALIDATE_TOTP_PASSWORD_REQUEST_OID))
    {
      assertEquals(opts.getExtendedOperationResponseTimeoutMillis(oid), 5678L);
      assertEquals(
           opts.getExtendedOperationResponseTimeoutMillis(oid + ".12345"),
           5678L);
    }

    assertEquals(
         opts.getExtendedOperationResponseTimeoutMillis(
              CancelExtendedRequest.CANCEL_REQUEST_OID),
         9999L);
  }



  /**
   * Tests abandon on timeout functionality.
   */
  @Test()
  public void testAbandonOnTimeout()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.abandonOnTimeout(), false);
    assertNotNull(opts.toString());

    opts.setAbandonOnTimeout(true);
    assertTrue(opts.abandonOnTimeout());
    assertNotNull(opts.toString());

    opts.setAbandonOnTimeout(false);
    assertFalse(opts.abandonOnTimeout());
    assertNotNull(opts.toString());
  }



  /**
   * Tests maximum message size functionality.
   */
  @Test()
  public void testMaxMessageSize()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getMaxMessageSize(), 20_971_520);
    assertNotNull(opts.toString());

    opts.setMaxMessageSize(0);
    assertEquals(opts.getMaxMessageSize(), 0);
    assertNotNull(opts.toString());

    opts.setMaxMessageSize(5000);
    assertEquals(opts.getMaxMessageSize(), 5000);
    assertNotNull(opts.toString());

    opts.setMaxMessageSize(-1);
    assertEquals(opts.getMaxMessageSize(), 0);
    assertNotNull(opts.toString());
  }



  /**
   * Tests connection logger functionality.
   */
  @Test()
  public void testConnectionLogger()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getConnectionLogger());
    assertNotNull(opts.toString());

    opts.setConnectionLogger(new TestLDAPConnectionLogger());
    assertNotNull(opts.getConnectionLogger());
    assertNotNull(opts.toString());

    opts.setConnectionLogger(null);
    assertNull(opts.getConnectionLogger());
    assertNotNull(opts.toString());
  }



  /**
   * Tests disconnect handler functionality.
   */
  @Test()
  public void testDisconnectHandler()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getDisconnectHandler());
    assertNotNull(opts.toString());

    opts.setDisconnectHandler(new TestDisconnectHandler());
    assertNotNull(opts.getDisconnectHandler());
    assertNotNull(opts.toString());

    opts.setDisconnectHandler(null);
    assertNull(opts.getDisconnectHandler());
    assertNotNull(opts.toString());
  }



  /**
   * Tests unsolicited notification handler functionality.
   */
  @Test()
  public void testUnsolicitedNotificationHandler()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNull(opts.getUnsolicitedNotificationHandler());
    assertNotNull(opts.toString());

    opts.setUnsolicitedNotificationHandler(
         new TestUnsolicitedNotificationHandler());
    assertNotNull(opts.getUnsolicitedNotificationHandler());
    assertNotNull(opts.toString());

    opts.setUnsolicitedNotificationHandler(null);
    assertNull(opts.getUnsolicitedNotificationHandler());
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to get and set send and receive buffer sizes.
   */
  @Test()
  public void testBufferSizes()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);
    assertNotNull(opts.toString());

    opts.setReceiveBufferSize(1234);
    opts.setSendBufferSize(5678);
    assertNotNull(opts.toString());

    assertEquals(opts.getReceiveBufferSize(), 1234);
    assertEquals(opts.getSendBufferSize(), 5678);
    assertNotNull(opts.toString());

    opts.setReceiveBufferSize(-1234);
    opts.setSendBufferSize(-5678);
    assertNotNull(opts.toString());

    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);
    assertNotNull(opts.toString());

    opts.setReceiveBufferSize(0);
    opts.setSendBufferSize(0);
    assertNotNull(opts.toString());

    assertEquals(opts.getReceiveBufferSize(), 0);
    assertEquals(opts.getSendBufferSize(), 0);
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to get and set the flag that controls synchronous mode.
   */
  @Test()
  public void testUseSynchronousMode()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.useSynchronousMode());
    assertNotNull(opts.toString());

    opts.setUseSynchronousMode(true);
    assertTrue(opts.useSynchronousMode());
    assertNotNull(opts.toString());

    opts.setUseSynchronousMode(false);
    assertFalse(opts.useSynchronousMode());
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to get and set the flag that controls whether to use
   * schema information when reading data from the server.
   */
  @Test()
  public void testUseSchema()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertFalse(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 3600000L);
    assertNotNull(opts.toString());

    opts.setUseSchema(true);
    assertTrue(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 3600000L);
    assertNotNull(opts.toString());

    opts.setUsePooledSchema(true);
    opts.setPooledSchemaTimeoutMillis(12345L);
    assertFalse(opts.useSchema());
    assertTrue(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 12345L);
    assertNotNull(opts.toString());

    opts.setUseSchema(true);
    opts.setPooledSchemaTimeoutMillis(-12345L);
    assertTrue(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 0L);
    assertNotNull(opts.toString());

    opts.setUseSchema(false);
    assertFalse(opts.useSchema());
    assertFalse(opts.usePooledSchema());
    assertEquals(opts.getPooledSchemaTimeoutMillis(), 0L);
    assertNotNull(opts.toString());
  }



  /**
   * Tests the ability to indicate whether the associated socket factory should
   * allow concurrent use of the socket factory by multiple threads.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowConcurrentSocketFactoryUse()
         throws Exception
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    final SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    opts.setAllowConcurrentSocketFactoryUse(false);
    assertFalse(opts.allowConcurrentSocketFactoryUse());

    LDAPConnection conn = new LDAPConnection(opts);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSocketFactory);

    conn = new LDAPConnection(sslUtil.createSSLSocketFactory(), opts);
    assertTrue(conn.getSocketFactory() instanceof SSLSocketFactory);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSSLSocketFactory);


    opts.setAllowConcurrentSocketFactoryUse(true);
    assertTrue(opts.allowConcurrentSocketFactoryUse());

    conn = new LDAPConnection(opts);
    assertFalse(conn.getSocketFactory() instanceof SynchronizedSocketFactory);

    conn = new LDAPConnection(sslUtil.createSSLSocketFactory(), opts);
    assertTrue(conn.getSocketFactory() instanceof SSLSocketFactory);
    assertFalse(conn.getSocketFactory()
         instanceof SynchronizedSSLSocketFactory);


    opts.setAllowConcurrentSocketFactoryUse(false);
    assertFalse(opts.allowConcurrentSocketFactoryUse());

    conn = new LDAPConnection(opts);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSocketFactory);

    conn = new LDAPConnection(sslUtil.createSSLSocketFactory(), opts);
    assertTrue(conn.getSocketFactory() instanceof SSLSocketFactory);
    assertTrue(conn.getSocketFactory() instanceof SynchronizedSSLSocketFactory);
  }



  /**
   * Tests methods related to SSL socket verifiers.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLSocketVerifiers()
         throws Exception
  {
    // Create an in-memory directory server instance with support for SSL and
    // StartTLS.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");

    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");

    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP",
              InetAddress.getLocalHost(), 0,
              serverSSLUtil.createSSLSocketFactory()),
         InMemoryListenerConfig.createLDAPSConfig("LDAPS",
              InetAddress.getLocalHost(), 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              clientSSLUtil.createSSLSocketFactory()));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();


    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);

    LDAPConnection conn = new LDAPConnection(
         clientSSLUtil.createSSLSocketFactory(), opts,
         ds.getListenAddress("LDAPS").getHostAddress(),
         ds.getListenPort("LDAPS"));
    assertNotNull(conn.getRootDSE());
    assertTrue(TrustAllSSLSocketVerifier.getInstance().verify("127.0.0.1",
         conn.getSSLSession()));
    assertTrue(TrustAllSSLSocketVerifier.getInstance().verify(
         "disallowed.example.com", conn.getSSLSession()));
    conn.close();

    conn = new LDAPConnection(opts,
         ds.getListenAddress("LDAP").getHostAddress(),
         ds.getListenPort("LDAP"));
    assertNotNull(conn.getRootDSE());
    assertResultCodeEquals(conn,
         new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()),
         ResultCode.SUCCESS);
    assertNotNull(conn.getRootDSE());
    conn.close();


    opts.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));
    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof HostNameSSLSocketVerifier);

    try
    {
      conn = new LDAPConnection(clientSSLUtil.createSSLSocketFactory(), opts,
           "localhost", ds.getListenPort("LDAPS"));
      conn.close();
      fail("Expected an exception due to hostname validation failure");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      conn.close();
    }

    try
    {
      conn = new LDAPConnection(opts, "localhost", ds.getListenPort("LDAP"));
      assertNotNull(conn.getRootDSE());
      conn.processExtendedOperation(
           new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()));
      conn.close();
      fail("Expected an exception due to hostname validation failure");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      conn.close();
    }


    opts.setSSLSocketVerifier(null);
    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);


    conn = new LDAPConnection(clientSSLUtil.createSSLSocketFactory(), opts,
         ds.getListenAddress("LDAPS").getHostAddress(),
         ds.getListenPort("LDAPS"));
    assertNotNull(conn.getRootDSE());
    assertTrue(new HostNameSSLSocketVerifier(true).verify("127.0.0.1",
         conn.getSSLSession()));
    assertFalse(new HostNameSSLSocketVerifier(true).verify(
         "disallowed.example.com", conn.getSSLSession()));
    conn.close();

    conn = new LDAPConnection(opts,
         ds.getListenAddress("LDAP").getHostAddress(),
         ds.getListenPort("LDAP"));
    assertNotNull(conn.getRootDSE());
    assertResultCodeEquals(conn,
         new StartTLSExtendedRequest(clientSSLUtil.createSSLSocketFactory()),
         ResultCode.SUCCESS);
    assertNotNull(conn.getRootDSE());
    conn.close();

    ds.shutDown(true);
  }



  /**
   * Tests the methods for interacting with the configured name resolver.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNameResolver()
  {
    final LDAPConnectionOptions opts = new LDAPConnectionOptions();

    assertNotNull(opts.getNameResolver());
    assertTrue(opts.getNameResolver() instanceof DefaultNameResolver);

    assertNotNull(opts.toString());

    opts.setNameResolver(new CachingNameResolver());

    assertNotNull(opts.getNameResolver());
    assertTrue(opts.getNameResolver() instanceof CachingNameResolver);

    assertNotNull(opts.toString());

    opts.setNameResolver(null);

    assertNotNull(opts.getNameResolver());
    assertTrue(opts.getNameResolver() instanceof DefaultNameResolver);

    assertNotNull(opts.toString());
  }



  /**
   * Provides test coverage for the {@code getSystemProperty} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSystemProperty()
         throws Exception
  {
    final boolean originalDebugEnabled = Debug.debugEnabled();
    final EnumSet<DebugType> originalDebugTypes = Debug.getDebugTypes();
    Debug.setEnabled(true, EnumSet.of(DebugType.LDAP));

    try
    {
      System.setProperty("booleanPropertyName", "true");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName", true),
           true);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName",
                false),
           true);

      System.setProperty("booleanPropertyName", "false");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName", true),
           false);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName",
                false),
           false);

      System.setProperty("booleanPropertyName", "malformed");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName", true),
           true);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName",
                false),
           false);

      System.clearProperty("booleanPropertyName");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName", true),
           true);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("booleanPropertyName",
                false),
           false);


      System.setProperty("intPropertyName", "1234");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", 1234),
           1234);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", 5678),
           1234);

      System.setProperty("intPropertyName", "-5678");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", -1234),
           -5678);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", -5678),
           -5678);

      System.setProperty("intPropertyName", "malformed");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", 1234),
           1234);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", 5678),
           5678);

      System.clearProperty("intPropertyName");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", 1234),
           1234);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("intPropertyName", 5678),
           5678);


      System.setProperty("longPropertyName", "1234");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                1234L).longValue(),
           1234L);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                5678L).longValue(),
           1234L);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                null).longValue(),
           1234L);

      System.setProperty("longPropertyName", "-5678");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                -1234L).longValue(),
           -5678L);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                -5678L).longValue(),
           -5678L);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                null).longValue(),
           -5678L);

      System.setProperty("longPropertyName", "malformed");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                1234L).longValue(),
           1234L);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName",
                5678L).longValue(),
           5678L);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName", null),
           null);

      System.clearProperty("longPropertyName");
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName", null),
           null);
      assertEquals(
           LDAPConnectionOptions.getSystemProperty("longPropertyName", null),
           null);
    }
    finally
    {
      Debug.setEnabled(originalDebugEnabled, originalDebugTypes);
    }
  }
}
