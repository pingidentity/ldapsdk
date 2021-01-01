/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

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
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.ssl.SSLSocketVerifier;
import com.unboundid.util.ssl.TrustAllSSLSocketVerifier;



/**
 * This class provides a data structure that may be used to configure a number
 * of connection-related properties.  Elements included in the set of connection
 * options include:
 * <UL>
 *   <LI>A flag that indicates whether the SDK should attempt to automatically
 *       re-establish a connection if it is unexpectedly closed.  By default,
 *       it will not attempt to do so.</LI>
 *   <LI>A flag that indicates whether simple bind attempts that contain a
 *       non-empty DN will be required to have a non-empty password.  By
 *       default, a password will be required in such cases.</LI>
 *   <LI>A flag that indicates whether to automatically attempt to follow any
 *       referrals that may be returned by the server.  By default, it will not
 *       automatically attempt to follow referrals.</LI>
 *   <LI>A referral hop limit, which indicates the maximum number of hops that
 *       the connection may take when trying to follow a referral.  The default
 *       referral hop limit is five.</LI>
 *   <LI>The referral connector that should be used to create and optionally
 *       authenticate connections used to follow referrals encountered during
 *       processing.  By default, referral connections will use the same socket
 *       factory and bind request as the client connection on which the referral
 *       was received.</LI>
 *   <LI>A flag that indicates whether to use the SO_KEEPALIVE socket option to
 *       attempt to more quickly detect when idle TCP connections have been lost
 *       or to prevent them from being unexpectedly closed by intermediate
 *       network hardware.  By default, the SO_KEEPALIVE socket option will be
 *       used.</LI>
 *   <LI>A flag that indicates whether to use the SO_LINGER socket option to
 *       indicate how long a connection should linger after it has been closed,
 *       and a value that specifies the length of time that it should linger.
 *       By default, the SO_LINGER option will be used with a timeout of 5
 *       seconds.</LI>
 *   <LI>A flag that indicates whether to use the SO_REUSEADDR socket option to
 *       indicate that a socket in a TIME_WAIT state may be reused.  By default,
 *       the SO_REUSEADDR socket option will be used.</LI>
 *   <LI>A flag that indicates whether to operate in synchronous mode, in which
 *       connections may exhibit better performance and will not require a
 *       separate reader thread, but will not allow multiple concurrent
 *       operations to be used on the same connection.</LI>
 *   <LI>A flag that indicates whether to use the TCP_NODELAY socket option to
 *       indicate that any data written to the socket will be sent immediately
 *       rather than delaying for a short amount of time to see if any more data
 *       is to be sent that could potentially be included in the same packet.
 *       By default, the TCP_NODELAY socket option will be used.</LI>
 *   <LI>A value that specifies the maximum length of time in milliseconds that
 *       an attempt to establish a connection should be allowed to block before
 *       failing.  By default, a timeout of 10,000 milliseconds (10 seconds)
 *       will be used.</LI>
 *   <LI>A value that specifies the default timeout in milliseconds that the SDK
 *       should wait for a response from the server before failing.  This can be
 *       defined on a per-operation-type basis, with a default of 300,000
 *       milliseconds (5 minutes) for search and extended operations, and a
 *       default timeout of 30,000 milliseconds (30 seconds) for all other types
 *       of operations.  Further, the extended operation timeout can be
 *       customized on a per-operation-type basis, and a number of extended
 *       operation types have been configured with a 30,000 millisecond timeout
 *       by default.  Individual requests can also be configured with their own
 *       response timeouts, and if provided, that timeout will override the
 *       default timeout from the connection options.</LI>
 *   <LI>A flag that indicates whether to attempt to abandon any request for
 *       which no response is received after waiting for the maximum response
 *       timeout.  By default, no abandon request will be sent.</LI>
 *   <LI>A value which specifies the largest LDAP message size that the SDK will
 *       be willing to read from the directory server.  By default, the SDK will
 *       not allow responses larger than 20,971,520 bytes (20MB).  If it
 *       encounters a message that may be larger than the maximum allowed
 *       message size, then the SDK will terminate the connection to the
 *       server.</LI>
 *   <LI>The {@link LDAPConnectionLogger} that should be used to record
 *       information about requests sent and responses received over
 *       connections with this set of options.  By default, no
 *       {@code LDAPConnectionLogger} will be used.</LI>
 *   <LI>The {@link DisconnectHandler} that should be used to receive
 *       notification if connection is disconnected for any reason.  By default,
 *       no {@code DisconnectHandler} will be used.</LI>
 *   <LI>The {@link UnsolicitedNotificationHandler} that should be used to
 *       receive notification about any unsolicited notifications returned by
 *       the server.  By default, no {@code UnsolicitedNotificationHandler} will
 *       be used.</LI>
 *   <LI>A flag that indicates whether to capture a thread stack trace whenever
 *       a new connection is established.  Capturing a thread stack trace when
 *       establishing a connection may be marginally expensive, but can be
 *       useful for debugging certain kinds of problems like leaked connections
 *       (connections that are established but never explicitly closed).  By
 *       default, connect stack traces will not be captured.</LI>
 *   <LI>A flag that indicates whether connections should try to retrieve schema
 *       information from the server, which may be used to better determine
 *       which matching rules should be used when comparing attribute values.
 *       By default, server schema information will not be retrieved.</LI>
 *   <LI>The size of the socket receive buffer, which may be used for
 *       temporarily holding data received from the directory server until it
 *       can be read and processed by the LDAP SDK.  By default, the receive
 *       buffer size will be automatically determined by the JVM based on the
 *       underlying system settings.</LI>
 *   <LI>The size of the socket send buffer, which may be used for temporarily
 *       holding data to be sent to the directory server until it can actually
 *       be transmitted over the network.  By default, the send buffer size will
 *       be automatically determined by the JVM based on the underlying system
 *       settings.</LI>
 *  <LI>A flag which indicates whether to allow a single socket factory instance
 *      (which may be shared across multiple connections) to be used to create
 *      multiple concurrent connections.  This offers better and more
 *      predictable performance on some JVM implementations (especially when
 *      connection attempts fail as a result of a connection timeout), but some
 *      JVMs are known to use non-threadsafe socket factory implementations and
 *      may fail from concurrent use (for example, at least some IBM JVMs
 *      exhibit this behavior).  By default, Sun/Oracle JVMs will allow
 *      concurrent socket factory use, but JVMs from other vendors will use
 *      synchronization to ensure that a socket factory will only be allowed to
 *      create one connection at a time.</LI>
 *  <LI>A class that may be used to perform additional verification (e.g.,
 *      hostname validation) for any {@code SSLSocket} instances created.  By
 *      default, no special verification will be performed.</LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPConnectionOptions
{
  /**
   * The prefix that will be used in conjunction with all system properties.
   */
  @NotNull private static final String PROPERTY_PREFIX =
       LDAPConnectionOptions.class.getName() + '.';



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "abandon on timeout" behavior.  If this property is
   * set at the time that this class is loaded, then its value must be either
   * "true" or "false".  If this property is not set, then a default value of
   * "false" will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultAbandonTimeout".
   */
  @NotNull public static final String PROPERTY_DEFAULT_ABANDON_ON_TIMEOUT =
       PROPERTY_PREFIX + "defaultAbandonOnTimeout";



  /**
   * The default value for the setting that controls whether to automatically
   * attempt to abandon any request for which no response is received within the
   * maximum response timeout.  If the
   * {@link #PROPERTY_DEFAULT_ABANDON_ON_TIMEOUT} system property is set at the
   * time this class is loaded, then its value will be used.  Otherwise, a
   * default of {@code false} will be used.
   */
  private static final boolean DEFAULT_ABANDON_ON_TIMEOUT =
       getSystemProperty(PROPERTY_DEFAULT_ABANDON_ON_TIMEOUT, false);



  /**
   * The default value ({@code false}) for the setting that controls whether to
   * automatically attempt to reconnect if a connection is unexpectedly lost.
   */
  private static final boolean DEFAULT_AUTO_RECONNECT = false;



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "bind with DN requires password" behavior.  If this
   * property is set at the time that this class is loaded, then its value must
   * be either "true" or "false".  If this property is not set, then a default
   * value of "true" will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.
   * defaultBindWithDNRequiresPassword".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD =
            PROPERTY_PREFIX + "defaultBindWithDNRequiresPassword";



  /**
   * The default value for the setting that controls whether simple bind
   * requests with a DN will also be required to contain a password.  If the
   * {@link #PROPERTY_DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD} system property is
   * set at the time this class is loaded, then its value will be used.
   * Otherwise, a default of {@code true} will be used.
   */
  private static final boolean DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD =
       getSystemProperty(PROPERTY_DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD, true);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "capture connect stack trace" behavior.  If this
   * property is set at the time that this class is loaded, then its value must
   * be either "true" or "false".  If this property is not set, then a default
   * value of "false" will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultCaptureConnectStackTrace".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_CAPTURE_CONNECT_STACK_TRACE =
            PROPERTY_PREFIX + "defaultCaptureConnectStackTrace";



  /**
   * The default value for the setting that controls whether to capture a thread
   * stack trace whenever an attempt is made to establish a connection.  If the
   * {@link #PROPERTY_DEFAULT_CAPTURE_CONNECT_STACK_TRACE} system property is
   * set at the time this class is loaded, then its value will be used.
   * Otherwise, a default of {@code false} will be used.
   */
  private static final boolean DEFAULT_CAPTURE_CONNECT_STACK_TRACE =
       getSystemProperty(PROPERTY_DEFAULT_CAPTURE_CONNECT_STACK_TRACE, false);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "follow referrals" behavior.  If this property is set
   * at the time that this class is loaded, then its value must be either
   * "true" or "false".  If this property is not set, then a default value of
   * "false" will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultFollowReferrals".
   */
  @NotNull public static final String PROPERTY_DEFAULT_FOLLOW_REFERRALS =
       PROPERTY_PREFIX + "defaultFollowReferrals";



  /**
   * The default value for the setting that controls whether to attempt to
   * automatically follow referrals.  If the
   * {@link #PROPERTY_DEFAULT_FOLLOW_REFERRALS} system property is set at the
   * time this class is loaded, then its value will be used.  Otherwise, a
   * default of {@code false} will be used.
   */
  private static final boolean DEFAULT_FOLLOW_REFERRALS =
       getSystemProperty(PROPERTY_DEFAULT_FOLLOW_REFERRALS, false);



  /**
   * The name of a system property that can be used to specify the maximum
   * number of hops to make when following a referral.  If this property is set
   * at the time that this class is loaded, then its value must be parseable as
   * an integer.  If this property is not set, then a default value of "5" will
   * be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultReferralHopLimit".
   */
  @NotNull public static final String PROPERTY_DEFAULT_REFERRAL_HOP_LIMIT =
       PROPERTY_PREFIX + "defaultReferralHopLimit";



  /**
   * The default value for the setting that controls the referral hop limit.  If
   * the {@link #PROPERTY_DEFAULT_REFERRAL_HOP_LIMIT} system property is set at
   * the time this class is loaded, then its value will be used.  Otherwise, a
   * default value of 5 will be used.
   */
  private static final int DEFAULT_REFERRAL_HOP_LIMIT =
       getSystemProperty(PROPERTY_DEFAULT_REFERRAL_HOP_LIMIT, 5);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use schema" behavior.  If this property is set at
   * the time that this class is loaded, then its value must be either "true" or
   * "false".  If this property is not set, then a default value of "false" will
   * be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUseSchema".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_SCHEMA =
       PROPERTY_PREFIX + "defaultUseSchema";



  /**
   * The default value for the setting that controls whether to use schema when
   * reading data from the server.  If the {@link #PROPERTY_DEFAULT_USE_SCHEMA}
   * system property is set at the time this class is loaded, then its value
   * will be used.  Otherwise, a default value of {@code false} will be used.
   */
  private static final boolean DEFAULT_USE_SCHEMA =
       getSystemProperty(PROPERTY_DEFAULT_USE_SCHEMA, false);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use pooled schema" behavior.  If this property is
   * set at the time that this class is loaded, then its value must be either
   * "true" or "false".  If this property is not set, then a default value of
   * "false" will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUsePooledSchema".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_POOLED_SCHEMA =
       PROPERTY_PREFIX + "defaultUsePooledSchema";



  /**
   * The default value for the setting that controls whether all connections in
   * a connection pool should use the same cached schema object.  If the
   * {@link #PROPERTY_DEFAULT_USE_POOLED_SCHEMA} system property is set at the
   * time this class is loaded, then its value will be used.  Otherwise, a
   * default of {@code false} will be used.
   */
  private static final boolean DEFAULT_USE_POOLED_SCHEMA =
       getSystemProperty(PROPERTY_DEFAULT_USE_POOLED_SCHEMA, false);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the pooled schema timeout, in milliseconds.  If this
   * property is set at the time that this class is loaded, then its value must
   * be parseable as an integer.  If this property is not set, then a default
   * value of "3600000" (3,600,000 milliseconds, or 1 hour) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultPooledSchemaTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_POOLED_SCHEMA_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultPooledSchemaTimeoutMillis";



  /**
   * The default value for the setting that controls the default pooled schema
   * timeout.  If the {@link #PROPERTY_DEFAULT_POOLED_SCHEMA_TIMEOUT_MILLIS}
   * system property is set at the time this class is loaded, then its value
   * will be used.  Otherwise, a default of 3,600,000 milliseconds (1 hour) will
   * be used.
   */
  private static final long DEFAULT_POOLED_SCHEMA_TIMEOUT_MILLIS = 3_600_000L;



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use keepalive" behavior.  If this property is set at
   * the time that this class is loaded, then its value must be either "true" or
   * "false".  If this property is not set, then a default value of "true" will
   * be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUseKeepalive".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_KEEPALIVE =
       PROPERTY_PREFIX + "defaultUseKeepalive";



  /**
   * The default value for the setting that controls whether to use the
   * {@code SO_KEEPALIVE} socket option.  If the
   * {@link #PROPERTY_DEFAULT_USE_KEEPALIVE} system property is set at the time
   * this class is loaded, then its value will be used.  Otherwise, a default of
   * {@code true} will be used.
   */
  private static final boolean DEFAULT_USE_KEEPALIVE =
       getSystemProperty(PROPERTY_DEFAULT_USE_KEEPALIVE, true);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use linger" behavior.  If this property is set at
   * the time that this class is loaded, then its value must be either "true" or
   * "false".  If this property is not set, then a default value of "true" will
   * be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUseLinger".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_LINGER =
       PROPERTY_PREFIX + "defaultUseLinger";



  /**
   * The default value for the setting that controls whether to use the
   * {@code SO_LINGER} socket option.  If the
   * {@link #PROPERTY_DEFAULT_USE_LINGER} system property is set at the time
   * this class is loaded, then its value will be used.  Otherwise, a default of
   * {@code true} will be used.
   */
  private static final boolean DEFAULT_USE_LINGER =
       getSystemProperty(PROPERTY_DEFAULT_USE_LINGER, true);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the linger timeout, in seconds.  If this property is set
   * at the time that this class is loaded, then its value must be parseable as
   * an integer.  If this property is not set, then a default value of "5" (5
   * seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultLingerTimeoutSeconds".
   */
  @NotNull public static final String PROPERTY_DEFAULT_LINGER_TIMEOUT_SECONDS =
       PROPERTY_PREFIX + "defaultLingerTimeoutSeconds";



  /**
   * The default value for the setting that controls the timeout in seconds that
   * will be used with the {@code SO_LINGER} socket option.  If the
   * {@link #PROPERTY_DEFAULT_LINGER_TIMEOUT_SECONDS} property is set at the
   * time this class is loaded, then its value will be used.  Otherwise, a
   * default linger timeout of 5 seconds will be used.
   */
  private static final int DEFAULT_LINGER_TIMEOUT_SECONDS =
       getSystemProperty(PROPERTY_DEFAULT_LINGER_TIMEOUT_SECONDS, 5);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use reuse address" behavior.  If this property is
   * set at the time that this class is loaded, then its value must be either
   * "true" or "false".  If this property is not set, then a default value of
   * "true" will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUseReuseAddress".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_REUSE_ADDRESS =
       PROPERTY_PREFIX + "defaultUseReuseAddress";



  /**
   * The default value for the setting that controls whether to use the
   * {@code SO_REUSEADDR} socket option.  If the
   * {@link #PROPERTY_DEFAULT_USE_REUSE_ADDRESS} system property is set at the
   * time this class is loaded, then its value will be used.  Otherwise, a
   * default value of {@code true} will be used.
   */
  private static final boolean DEFAULT_USE_REUSE_ADDRESS =
       getSystemProperty(PROPERTY_DEFAULT_USE_REUSE_ADDRESS, true);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use synchronous mode" behavior.  If this property is
   * set at the time that this class is loaded, then its value must be either
   * "true" or "false".  If this property is not set, then a default value of
   * "false" will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUseSynchronousMode".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_SYNCHRONOUS_MODE =
       PROPERTY_PREFIX + "defaultUseSynchronousMode";



  /**
   * The default value for the setting that controls whether to operate in
   * synchronous mode, in which only a single outstanding operation may be in
   * progress on an associated connection at any given time.  If the
   * {@link #PROPERTY_DEFAULT_USE_SYNCHRONOUS_MODE} system property is set at
   * the time this class is loaded, then its value will be used.  Otherwise, a
   * default value of {@code false} will be used.
   */
  private static final boolean DEFAULT_USE_SYNCHRONOUS_MODE =
       getSystemProperty(PROPERTY_DEFAULT_USE_SYNCHRONOUS_MODE, false);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the "use TCP nodelay" behavior.  If this property is set
   * at the time that this class is loaded, then its value must be either "true"
   * or "false".  If this property is not set, then a default value of "true"
   * will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultUseTCPNoDelay".
   */
  @NotNull public static final String PROPERTY_DEFAULT_USE_TCP_NODELAY =
       PROPERTY_PREFIX + "defaultUseTCPNoDelay";



  /**
   * The default value for the setting that controls whether to use the
   * {@code TCP_NODELAY} socket option.  If the
   * {@link #PROPERTY_DEFAULT_USE_TCP_NODELAY} system property is set at the
   * time this class is loaded, then its value will be used.  Otherwise, a
   * default value of {@code true} will be used.
   */
  private static final boolean DEFAULT_USE_TCP_NODELAY =
       getSystemProperty(PROPERTY_DEFAULT_USE_TCP_NODELAY, true);



  /**
   * The name of a system property that can be used to specify the initial
   * default connect timeout, in milliseconds.  If this property is set at the
   * time that this class is loaded, then its value must be parseable as an
   * integer.  If this property is not set then a default value of "10000"
   * (10,000 milliseconds, or ten seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultConnectTimeoutMillis".
   */
  @NotNull public static final String PROPERTY_DEFAULT_CONNECT_TIMEOUT_MILLIS =
       PROPERTY_PREFIX + "defaultConnectTimeoutMillis";



  /**
   * The default value for the setting that controls the timeout in milliseconds
   * when trying to establish a new connection.  If the
   * {@link #PROPERTY_DEFAULT_CONNECT_TIMEOUT_MILLIS} system property is set at
   * the time this class is loaded, then its value will be used.  Otherwise, a
   * default of 10,000 milliseconds (10 seconds) will be used.
   */
  private static final int DEFAULT_CONNECT_TIMEOUT_MILLIS =
       getSystemProperty(PROPERTY_DEFAULT_CONNECT_TIMEOUT_MILLIS, 10_000);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the maximum message size, in bytes.  If this property is
   * set at the time that this class is loaded, then its value must be parseable
   * as an integer.  If this property is not set, then a default value of
   * "20971520" (20 megabytes) will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultMaxMessageSizeBytes".
   */
  @NotNull public static final String PROPERTY_DEFAULT_MAX_MESSAGE_SIZE_BYTES =
       PROPERTY_PREFIX + "defaultMaxMessageSizeBytes";



  /**
   * The default value for the setting that controls the maximum LDAP message
   * size in bytes that will be allowed when reading data from a directory
   * server.  If the {@link #PROPERTY_DEFAULT_MAX_MESSAGE_SIZE_BYTES} system
   * property is set at the time this class is loaded, then its value will be
   * used.  Otherwise, a default value of 20,971,520 bytes (20 megabytes) will
   * be used.
   */
  private static final int DEFAULT_MAX_MESSAGE_SIZE_BYTES =
       getSystemProperty(PROPERTY_DEFAULT_MAX_MESSAGE_SIZE_BYTES, 20_971_520);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the receive buffer size, in bytes.  If this property is
   * set at the time that this class is loaded, then its value must be parseable
   * as an integer.  If this property is not set, then a default value of "0"
   * (indicating that the JVM's default receive buffer size) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultReceiveBufferSizeBytes".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_RECEIVE_BUFFER_SIZE_BYTES =
            PROPERTY_PREFIX + "defaultReceiveBufferSizeBytes";



  /**
   * The default size, in bytes, to use for the receive buffer.  If the
   * {@link #PROPERTY_DEFAULT_RECEIVE_BUFFER_SIZE_BYTES} system property is set
   * at the time this class is loaded, then its value will be used.  Otherwise,
   * a default value of 0 will be used to indicate that the JVM's default
   * receive buffer size should be used.
   */
  private static final int DEFAULT_RECEIVE_BUFFER_SIZE_BYTES =
       getSystemProperty(PROPERTY_DEFAULT_RECEIVE_BUFFER_SIZE_BYTES, 0);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for the send buffer size, in bytes.  If this property is set
   * at the time that this class is loaded, then its value must be parseable as
   * an integer.  If this property is not set, then a default value of "0"
   * (indicating that the JVM's default send buffer size) will be assumed.
   * <BR><BR>
   * The full name for this system property is
   * "com.unboundid.ldap.sdk.LDAPConnectionOptions.defaultSendBufferSizeBytes".
   */
  @NotNull public static final String PROPERTY_DEFAULT_SEND_BUFFER_SIZE_BYTES =
       PROPERTY_PREFIX + "defaultSendBufferSizeBytes";



  /**
   * The default size, in bytes, to use for the send buffer.  If the
   * {@link #PROPERTY_DEFAULT_SEND_BUFFER_SIZE_BYTES} system property is set at
   * the time this class is loaded, then its value will be used.  Otherwise, a
   * default value of 0 will be used to indicate that the JVM's default send
   * buffer size should be used.
   */
  private static final int DEFAULT_SEND_BUFFER_SIZE_BYTES =
       getSystemProperty(PROPERTY_DEFAULT_SEND_BUFFER_SIZE_BYTES, 0);



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for all types of
   * operations.  If this property is set at the time that this class is loaded,
   * then its value must be parseable as an integer, and that value will
   * override the values of any operation-specific properties.  If this property
   * is not set, then a default value of "300000" (300,000 milliseconds, or
   * 5 minutes) will be assumed, but that may be overridden by
   * operation-specific properties.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultResponseTimeoutMillis".
   */
  @NotNull public static final String PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS =
       PROPERTY_PREFIX + "defaultResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for add operations.
   * If this property is set at the time that this class is loaded, then
   * its value must be parseable as an integer.  It will only be used if the
   * {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system property is not
   * set, as that property will override this one.  If neither of those
   * properties is set, then a default value of "30000" (30,000 milliseconds, or
   * 30 seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultAddResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_ADD_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultAddResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for bind operations.
   * If this property is set at the time that this class is loaded, then
   * its value must be parseable as an integer.  It will only be used if the
   * {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system property is not
   * set, as that property will override this one.  If neither of those
   * properties is set, then a default value of "30000" (30,000 milliseconds, or
   * 30 seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultBindResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_BIND_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultBindResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for compare
   * operations.  If this property is set at the time that this class is
   * loaded, then its value must be parseable as an integer.  It will only be
   * used if the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system
   * property is not set, as that property will override this one.  If neither
   * of those properties is set, then a default value of "30000" (30,000
   * milliseconds, or 30 seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultCompareResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_COMPARE_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultCompareResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for delete
   * operations.  If this property is set at the time that this class is
   * loaded, then its value must be parseable as an integer.  It will only be
   * used if the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system
   * property is not set, as that property will override this one.  If neither
   * of those properties is set, then a default value of "30000" (30,000
   * milliseconds, or 30 seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultDeleteResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_DELETE_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultDeleteResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for extended
   * operations.  If this property is set at the time that this class is
   * loaded, then its value must be parseable as an integer.  It will only be
   * used if the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system
   * property is not set, as that property will override this one.  If neither
   * of those properties is set, then a default value of "300000" (300,000
   * milliseconds, or 5 minutes) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultExtendedResponseTimeoutMillis".
   * <BR><BR>
   * Note that different timeouts may be set for specific types using a system
   * property with this name immediately followed by a period and the request
   * OID for the desired extended operation type.  For example, the system
   * property named "com.unboundid.ldap.sdk.LDAPConnectionOptions.
   * defaultExtendedResponseTimeoutMillis.1.3.6.1.4.1.1466.20037" can be used to
   * set a default response timeout for StartTLS extended operations.
   * <BR><BR>
   * If neither the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} nor the
   * {@code PROPERTY_DEFAULT_EXTENDED_RESPONSE_TIMEOUT_MILLIS} property is set,
   * then the following standard extended operation types will have a default
   * timeout of 30,000 milliseconds (30 seconds) instead of 300,000 milliseconds
   * (5 minutes), unless a property is defined to override the timeout for that
   * specific type of extended operation:
   * <BR>
   * <UL>
   *   <LI>Password Modify (1.3.6.1.4.1.4203.1.11.1)</LI>
   *   <LI>StartTLS (1.3.6.1.4.1.1466.20037)</LI>
   *   <LI>Who Am I? (1.3.6.1.4.1.4203.1.11.3)</LI>
   * </UL>
   * <BR>
   * The same will also be true for the following extended operations specific
   * to the UnboundID/Ping Identity Directory Server:
   * <BR>
   * <UL>
   *   <LI>Deregister YubiKey OTP Device (1.3.6.1.4.1.30221.2.6.55)</LI>
   *   <LI>End Administrative Session (1.3.6.1.4.1.30221.2.6.14)</LI>
   *   <LI>Generate TOTP Shared Secret (1.3.6.1.4.1.30221.2.6.56)</LI>
   *   <LI>Get Connection ID (1.3.6.1.4.1.30221.1.6.2)</LI>
   *   <LI>Get Password Quality Requirements (1.3.6.1.4.1.30221.2.6.43)</LI>
   *   <LI>Password Policy State (1.3.6.1.4.1.30221.1.6.1)</LI>
   *   <LI>Register YubiKey OTP Device (1.3.6.1.4.1.30221.2.6.54)</LI>
   *   <LI>Revoke TOTP Shared Secret (1.3.6.1.4.1.30221.2.6.58)</LI>
   *   <LI>Start Administrative Session (1.3.6.1.4.1.30221.2.6.13)</LI>
   *   <LI>Validate TOTP Password (1.3.6.1.4.1.30221.2.6.15)</LI>
   * </UL>
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_EXTENDED_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultExtendedResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for modify
   * operations.  If this property is set at the time that this class is
   * loaded, then its value must be parseable as an integer.  It will only be
   * used if the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system
   * property is not set, as that property will override this one.  If neither
   * of those properties is set, then a default value of "30000" (30,000
   * milliseconds, or 30 seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultModifyResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_MODIFY_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultModifyResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for modify DN
   * operations.  If this property is set at the time that this class is
   * loaded, then its value must be parseable as an integer.  It will only be
   * used if the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system
   * property is not set, as that property will override this one.  If neither
   * of those properties is set, then a default value of "30000" (30,000
   * milliseconds, or 30 seconds) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultModifyDNResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_MODIFY_DN_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultModifyDNResponseTimeoutMillis";



  /**
   * The name of a system property that can be used to specify the initial
   * default value for response timeouts, in milliseconds, for search
   * operations.  If this property is set at the time that this class is
   * loaded, then its value must be parseable as an integer.  It will only be
   * used if the {@link #PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS} system
   * property is not set, as that property will override this one.  If neither
   * of those properties is set, then a default value of "300000" (300,000
   * milliseconds, or 5 minutes) will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultSearchResponseTimeoutMillis".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_SEARCH_RESPONSE_TIMEOUT_MILLIS =
            PROPERTY_PREFIX + "defaultSearchResponseTimeoutMillis";



  /**
   * The default value for the setting that controls the default response
   * timeout, in milliseconds, for all types of operations.
   */
  private static final long DEFAULT_RESPONSE_TIMEOUT_MILLIS;



  /**
   * A map that holds the default values for the settings that control the
   * default response timeouts, in milliseconds, for each type of operation.
   */
  @NotNull private static final Map<OperationType,Long>
       DEFAULT_RESPONSE_TIMEOUT_MILLIS_BY_OPERATION_TYPE;



  /**
   * A map that holds the default values for the settings that control the
   * default response timeouts, in milliseconds, for specific types of extended
   * operations.
   */
  @NotNull private static final Map<String,Long>
       DEFAULT_RESPONSE_TIMEOUT_MILLIS_BY_EXTENDED_OPERATION_TYPE;



  /**
   * The default name resolver that will be used to resolve host names to IP
   * addresses.
   */
  @NotNull public static final NameResolver DEFAULT_NAME_RESOLVER;



  static
  {
    // Get the default response timeout for all types of operations.
    Long allOpsTimeout = null;
    final EnumMap<OperationType,Long> timeoutsByOpType =
         new EnumMap<>(OperationType.class);
    final HashMap<String,Long> timeoutsByExtOpType =
         new HashMap<>(StaticUtils.computeMapCapacity(10));

    final String allOpsPropertyValue = StaticUtils.getSystemProperty(
         PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS);
    if (allOpsPropertyValue != null)
    {
      try
      {
        allOpsTimeout = Math.max(0L, Long.parseLong(allOpsPropertyValue));
        for (final OperationType ot : OperationType.values())
        {
          timeoutsByOpType.put(ot, allOpsTimeout);
        }

        if (Debug.debugEnabled())
        {
          Debug.debug(Level.INFO, DebugType.OTHER,
               "Using value " + allOpsTimeout + " set for system property '" +
                  PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS + "'.  This " +
                    "timeout will be used for all operation types.");
        }
      }
      catch (final Exception e)
      {
        if (Debug.debugEnabled())
        {
          Debug.debugException(e);
          Debug.debug(Level.WARNING, DebugType.OTHER,
               "Invalid value '" + allOpsPropertyValue + "' set for system " +
                    "property '" + PROPERTY_DEFAULT_RESPONSE_TIMEOUT_MILLIS +
                    "'.  The value was expected to be a long.  Ignoring " +
                    "this property and proceeding as if it had not been set.");
        }
      }
    }


    // Get the default response timeout for each type of operation.
    if (allOpsTimeout == null)
    {
      allOpsTimeout = 300_000L;

      // Use hard-coded response timeouts of 10 seconds for abandon and unbind
      // operations.  There is no response for these operations, but the timeout
      // is also used for sending the request.
      timeoutsByOpType.put(OperationType.ABANDON, 10_000L);
      timeoutsByOpType.put(OperationType.UNBIND, 10_000L);

      timeoutsByOpType.put(OperationType.ADD,
           getSystemProperty(PROPERTY_DEFAULT_ADD_RESPONSE_TIMEOUT_MILLIS,
                30_000L));
      timeoutsByOpType.put(OperationType.BIND,
           getSystemProperty(PROPERTY_DEFAULT_BIND_RESPONSE_TIMEOUT_MILLIS,
                30_000L));
      timeoutsByOpType.put(OperationType.COMPARE,
           getSystemProperty(PROPERTY_DEFAULT_COMPARE_RESPONSE_TIMEOUT_MILLIS,
                30_000L));
      timeoutsByOpType.put(OperationType.DELETE,
           getSystemProperty(PROPERTY_DEFAULT_DELETE_RESPONSE_TIMEOUT_MILLIS,
                30_000L));
      timeoutsByOpType.put(OperationType.MODIFY,
           getSystemProperty(PROPERTY_DEFAULT_MODIFY_RESPONSE_TIMEOUT_MILLIS,
                30_000L));
      timeoutsByOpType.put(OperationType.MODIFY_DN,
           getSystemProperty(PROPERTY_DEFAULT_MODIFY_DN_RESPONSE_TIMEOUT_MILLIS,
                30_000L));
      timeoutsByOpType.put(OperationType.SEARCH,
           getSystemProperty(PROPERTY_DEFAULT_SEARCH_RESPONSE_TIMEOUT_MILLIS,
                300_000L));

      final String extendedOperationTypePrefix =
           PROPERTY_DEFAULT_EXTENDED_RESPONSE_TIMEOUT_MILLIS + '.';
      for (final String propertyName :
           StaticUtils.getSystemProperties().stringPropertyNames())
      {
        if (propertyName.startsWith(extendedOperationTypePrefix))
        {
          final Long value = getSystemProperty(propertyName, null);
          if (value != null)
          {
            final String oid = propertyName.substring(
                 extendedOperationTypePrefix.length());
            timeoutsByExtOpType.put(oid, value);
          }
        }
      }


      // Get the default response timeout for different types of extended
      // operations.
      final Long extendedOpTimeout = getSystemProperty(
           PROPERTY_DEFAULT_EXTENDED_RESPONSE_TIMEOUT_MILLIS, null);
      if (extendedOpTimeout == null)
      {
        timeoutsByOpType.put(OperationType.EXTENDED, 300_000L);

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
          if (! timeoutsByExtOpType.containsKey(oid))
          {
            timeoutsByExtOpType.put(oid, 30_000L);
          }
        }
      }
      else
      {
        timeoutsByOpType.put(OperationType.EXTENDED, extendedOpTimeout);
      }
    }


    // Get the default name resolver to use.  If the LDAP SDK is running with
    // access to the Ping Identity Directory Server's codebase, then we'll use
    // the server's default name resolver instead of the LDAP SDK's.
    NameResolver defaultNameResolver = DefaultNameResolver.getInstance();
    try
    {
      if (InternalSDKHelper.getPingIdentityServerRoot() != null)
      {
        final Class<?> nrClass = Class.forName(
             "com.unboundid.directory.server.util.OutageSafeDnsCache");
        final Method getNameResolverMethod =
             nrClass.getMethod("getNameResolver");
        final NameResolver nameResolver =
             (NameResolver) getNameResolverMethod.invoke(null);

        final InetAddress localHostAddress = nameResolver.getLocalHost();
        if (localHostAddress != null)
        {
          if (nameResolver.getByName(localHostAddress.getHostAddress()) != null)
          {
            defaultNameResolver = nameResolver;
          }
        }
      }
    }
    catch (final Throwable t)
    {
      // This is probably fine.  It just means that we're not running with
      // access to the server codebase (or a version of the server codebase that
      // supports the LDAP SDK's name resolver API), or without the appropriate
      // setup in place (e.g., knowledge of the server root).  In this case,
      // we'll just use the LDAP SDK's default resolver.
      //
      // Note that we intentionally catch Throwable in this case rather than
      // just Exception because even if the server code is available, there
      // may be an unexpected Error thrown (e.g., NoClassDefFound or
      // ExceptionInInitializerError) under certain circumstances, like if the
      // server's name resolver code cannot identify the server root.
      Debug.debugException(Level.FINEST, t);
    }


    DEFAULT_RESPONSE_TIMEOUT_MILLIS = allOpsTimeout;
    DEFAULT_RESPONSE_TIMEOUT_MILLIS_BY_OPERATION_TYPE =
         Collections.unmodifiableMap(timeoutsByOpType);
    DEFAULT_RESPONSE_TIMEOUT_MILLIS_BY_EXTENDED_OPERATION_TYPE =
         Collections.unmodifiableMap(timeoutsByExtOpType);
    DEFAULT_NAME_RESOLVER = defaultNameResolver;
  }



  /**
   * The name of a system property that can be used to specify the default value
   * for the "allow concurrent socket factory use" behavior.  If this property
   * is set at the time that this class is loaded, then its value must be
   * either "true" or "false".  If this property is not set, then a default
   * value of "true" will be assumed.
   * <BR><BR>
   * The full name for this system property is "com.unboundid.ldap.sdk.
   * LDAPConnectionOptions.defaultAllowConcurrentSocketFactoryUse".
   */
  @NotNull public static final String
       PROPERTY_DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE =
            PROPERTY_PREFIX + "defaultAllowConcurrentSocketFactoryUse";



  /**
   * The default value for the setting that controls the default behavior with
   * regard to whether to allow concurrent use of a socket factory to create
   * client connections.
   */
  private static final boolean DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE =
       getSystemProperty(PROPERTY_DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE,
            true);



  /**
   * The default {@code SSLSocketVerifier} instance that will be used for
   * performing extra validation for {@code SSLSocket} instances.
   */
  @NotNull private static final SSLSocketVerifier DEFAULT_SSL_SOCKET_VERIFIER =
       TrustAllSSLSocketVerifier.getInstance();



  // Indicates whether to send an abandon request for any operation for which no
  // response is received in the maximum response timeout.
  private boolean abandonOnTimeout;

  // Indicates whether to use synchronization prevent concurrent use of the
  // socket factory instance associated with a connection or set of connections.
  private boolean allowConcurrentSocketFactoryUse;

  // Indicates whether the connection should attempt to automatically reconnect
  // if the connection to the server is lost.
  private boolean autoReconnect;

  // Indicates whether to allow simple binds that contain a DN but no password.
  private boolean bindWithDNRequiresPassword;

  // Indicates whether to capture a thread stack trace whenever an attempt is
  // made to establish a connection;
  private boolean captureConnectStackTrace;

  // Indicates whether to attempt to follow any referrals that are encountered.
  private boolean followReferrals;

  // Indicates whether to use SO_KEEPALIVE for the underlying sockets.
  private boolean useKeepAlive;

  // Indicates whether to use SO_LINGER for the underlying sockets.
  private boolean useLinger;

  // Indicates whether to use SO_REUSEADDR for the underlying sockets.
  private boolean useReuseAddress;

  // Indicates whether all connections in a connection pool should reference
  // the same schema.
  private boolean usePooledSchema;

  // Indicates whether to try to use schema information when reading data from
  // the server.
  private boolean useSchema;

  // Indicates whether to use synchronous mode in which only a single operation
  // may be in progress on associated connections at any given time.
  private boolean useSynchronousMode;

  // Indicates whether to use TCP_NODELAY for the underlying sockets.
  private boolean useTCPNoDelay;

  // The disconnect handler for associated connections.
  @Nullable private DisconnectHandler disconnectHandler;

  // The connect timeout, in milliseconds.
  private int connectTimeoutMillis;

  // The linger timeout to use if SO_LINGER is to be used.
  private int lingerTimeoutSeconds;

  // The maximum message size in bytes that will be allowed when reading data
  // from a directory server.
  private int maxMessageSizeBytes;

  // The socket receive buffer size to request.
  private int receiveBufferSizeBytes;

  // The referral hop limit to use if referral following is enabled.
  private int referralHopLimit;

  // The socket send buffer size to request.
  private int sendBufferSizeBytes;

  // The connection logger that should be used to record information about
  // requests sent and responses received over connections with this set of
  // options.
  @Nullable private LDAPConnectionLogger connectionLogger;

  // The pooled schema timeout, in milliseconds.
  private long pooledSchemaTimeoutMillis;

  // The response timeout, in milliseconds.
  private long responseTimeoutMillis;

  @NotNull private Map<OperationType,Long> responseTimeoutMillisByOperationType;

  @NotNull private Map<String,Long>
       responseTimeoutMillisByExtendedOperationType;

  // The name resolver that will be used to resolve host names to IP addresses.
  @NotNull private NameResolver nameResolver;

  // Tne default referral connector that should be used for associated
  // connections.
  @Nullable private ReferralConnector referralConnector;

  // The SSLSocketVerifier instance to use to perform extra validation on
  // newly-established SSLSocket instances.
  @NotNull private SSLSocketVerifier sslSocketVerifier;

  // The unsolicited notification handler for associated connections.
  @Nullable private UnsolicitedNotificationHandler
       unsolicitedNotificationHandler;



  /**
   * Creates a new set of LDAP connection options with the default settings.
   */
  public LDAPConnectionOptions()
  {
    abandonOnTimeout               = DEFAULT_ABANDON_ON_TIMEOUT;
    autoReconnect                  = DEFAULT_AUTO_RECONNECT;
    bindWithDNRequiresPassword     = DEFAULT_BIND_WITH_DN_REQUIRES_PASSWORD;
    captureConnectStackTrace       = DEFAULT_CAPTURE_CONNECT_STACK_TRACE;
    followReferrals                = DEFAULT_FOLLOW_REFERRALS;
    nameResolver                   = DEFAULT_NAME_RESOLVER;
    useKeepAlive                   = DEFAULT_USE_KEEPALIVE;
    useLinger                      = DEFAULT_USE_LINGER;
    useReuseAddress                = DEFAULT_USE_REUSE_ADDRESS;
    usePooledSchema                = DEFAULT_USE_POOLED_SCHEMA;
    useSchema                      = DEFAULT_USE_SCHEMA;
    useSynchronousMode             = DEFAULT_USE_SYNCHRONOUS_MODE;
    useTCPNoDelay                  = DEFAULT_USE_TCP_NODELAY;
    connectTimeoutMillis           = DEFAULT_CONNECT_TIMEOUT_MILLIS;
    lingerTimeoutSeconds           = DEFAULT_LINGER_TIMEOUT_SECONDS;
    maxMessageSizeBytes            = DEFAULT_MAX_MESSAGE_SIZE_BYTES;
    referralHopLimit               = DEFAULT_REFERRAL_HOP_LIMIT;
    pooledSchemaTimeoutMillis      = DEFAULT_POOLED_SCHEMA_TIMEOUT_MILLIS;
    responseTimeoutMillis          = DEFAULT_RESPONSE_TIMEOUT_MILLIS;
    receiveBufferSizeBytes         = DEFAULT_RECEIVE_BUFFER_SIZE_BYTES;
    sendBufferSizeBytes            = DEFAULT_SEND_BUFFER_SIZE_BYTES;
    connectionLogger               = null;
    disconnectHandler              = null;
    referralConnector              = null;
    sslSocketVerifier              = DEFAULT_SSL_SOCKET_VERIFIER;
    unsolicitedNotificationHandler = null;

    responseTimeoutMillisByOperationType =
         DEFAULT_RESPONSE_TIMEOUT_MILLIS_BY_OPERATION_TYPE;
    responseTimeoutMillisByExtendedOperationType =
         DEFAULT_RESPONSE_TIMEOUT_MILLIS_BY_EXTENDED_OPERATION_TYPE;
    allowConcurrentSocketFactoryUse =
         DEFAULT_ALLOW_CONCURRENT_SOCKET_FACTORY_USE;
  }



  /**
   * Returns a duplicate of this LDAP connection options object that may be
   * modified without impacting this instance.
   *
   * @return  A duplicate of this LDAP connection options object that may be
   *          modified without impacting this instance.
   */
  @NotNull()
  public LDAPConnectionOptions duplicate()
  {
    final LDAPConnectionOptions o = new LDAPConnectionOptions();

    o.abandonOnTimeout                = abandonOnTimeout;
    o.allowConcurrentSocketFactoryUse = allowConcurrentSocketFactoryUse;
    o.autoReconnect                   = autoReconnect;
    o.bindWithDNRequiresPassword      = bindWithDNRequiresPassword;
    o.captureConnectStackTrace        = captureConnectStackTrace;
    o.followReferrals                 = followReferrals;
    o.nameResolver                    = nameResolver;
    o.useKeepAlive                    = useKeepAlive;
    o.useLinger                       = useLinger;
    o.useReuseAddress                 = useReuseAddress;
    o.usePooledSchema                 = usePooledSchema;
    o.useSchema                       = useSchema;
    o.useSynchronousMode              = useSynchronousMode;
    o.useTCPNoDelay                   = useTCPNoDelay;
    o.connectTimeoutMillis            = connectTimeoutMillis;
    o.lingerTimeoutSeconds            = lingerTimeoutSeconds;
    o.maxMessageSizeBytes             = maxMessageSizeBytes;
    o.pooledSchemaTimeoutMillis       = pooledSchemaTimeoutMillis;
    o.responseTimeoutMillis           = responseTimeoutMillis;
    o.referralConnector               = referralConnector;
    o.referralHopLimit                = referralHopLimit;
    o.connectionLogger                = connectionLogger;
    o.disconnectHandler               = disconnectHandler;
    o.unsolicitedNotificationHandler  = unsolicitedNotificationHandler;
    o.receiveBufferSizeBytes          = receiveBufferSizeBytes;
    o.sendBufferSizeBytes             = sendBufferSizeBytes;
    o.sslSocketVerifier               = sslSocketVerifier;

    o.responseTimeoutMillisByOperationType =
         responseTimeoutMillisByOperationType;
    o.responseTimeoutMillisByExtendedOperationType =
         responseTimeoutMillisByExtendedOperationType;

    return o;
  }



  /**
   * Indicates whether associated connections should attempt to automatically
   * reconnect to the target server if the connection is lost.  Note that this
   * option will not have any effect on pooled connections because defunct
   * pooled connections will be replaced by newly-created connections rather
   * than attempting to re-establish the existing connection.
   * <BR><BR>
   * NOTE:  The use of auto-reconnect is strongly discouraged because it is
   * inherently fragile and can only work under very limited circumstances.  It
   * is strongly recommended that a connection pool be used instead of the
   * auto-reconnect option, even in cases where only a single connection is
   * desired.
   *
   * @return  {@code true} if associated connections should attempt to
   *          automatically reconnect to the target server if the connection is
   *          lost, or {@code false} if not.
   *
   * @deprecated  The use of auto-reconnect is strongly discouraged because it
   *              is inherently fragile and can only work under very limited
   *              circumstances.  It is strongly recommended that a connection
   *              pool be used instead of the auto-reconnect option, even in
   *              cases where only a single connection is desired.
   */
  @Deprecated()
  public boolean autoReconnect()
  {
    return autoReconnect;
  }



  /**
   * Specifies whether associated connections should attempt to automatically
   * reconnect to the target server if the connection is lost.  Note that
   * automatic reconnection will only be available for authenticated clients if
   * the authentication mechanism used provides support for re-binding on a new
   * connection.  Also note that this option will not have any effect on pooled
   * connections because defunct pooled connections will be replaced by
   * newly-created connections rather than attempting to re-establish the
   * existing connection.  Further, auto-reconnect should not be used with
   * connections that use StartTLS or some other mechanism to alter the state
   * of the connection beyond authentication.
   * <BR><BR>
   * NOTE:  The use of auto-reconnect is strongly discouraged because it is
   * inherently fragile and can only work under very limited circumstances.  It
   * is strongly recommended that a connection pool be used instead of the
   * auto-reconnect option, even in cases where only a single connection is
   * desired.
   *
   * @param  autoReconnect  Specifies whether associated connections should
   *                        attempt to automatically reconnect to the target
   *                        server if the connection is lost.
   *
   * @deprecated  The use of auto-reconnect is strongly discouraged because it
   *              is inherently fragile and can only work under very limited
   *              circumstances.  It is strongly recommended that a connection
   *              pool be used instead of the auto-reconnect option, even in
   *              cases where only a single connection is desired.
   */
  @Deprecated()
  public void setAutoReconnect(final boolean autoReconnect)
  {
    this.autoReconnect = autoReconnect;
  }



  /**
   * Retrieves the name resolver that should be used to resolve host names to IP
   * addresses.
   *
   * @return  The name resolver that should be used to resolve host names to IP
   *          addresses.
   */
  @NotNull()
  public NameResolver getNameResolver()
  {
    return nameResolver;
  }



  /**
   * Sets the name resolver that should be used to resolve host names to IP
   * addresses.
   *
   * @param  nameResolver  The name resolver that should be used to resolve host
   *                       names to IP addresses.
   */
  public void setNameResolver(@Nullable final NameResolver nameResolver)
  {
    if (nameResolver == null)
    {
      this.nameResolver = DEFAULT_NAME_RESOLVER;
    }
    else
    {
      this.nameResolver = nameResolver;
    }
  }



  /**
   * Indicates whether the SDK should allow simple bind operations that contain
   * a bind DN but no password.  Binds of this type may represent a security
   * vulnerability in client applications because they may cause the client to
   * believe that the user is properly authenticated when the server considers
   * it to be an unauthenticated connection.
   *
   * @return  {@code true} if the SDK should allow simple bind operations that
   *          contain a bind DN but no password, or {@code false} if not.
   */
  public boolean bindWithDNRequiresPassword()
  {
    return bindWithDNRequiresPassword;
  }



  /**
   * Specifies whether the SDK should allow simple bind operations that contain
   * a bind DN but no password.
   *
   * @param  bindWithDNRequiresPassword  Indicates whether the SDK should allow
   *                                     simple bind operations that contain a
   *                                     bind DN but no password.
   */
  public void setBindWithDNRequiresPassword(
                   final boolean bindWithDNRequiresPassword)
  {
    this.bindWithDNRequiresPassword = bindWithDNRequiresPassword;
  }



  /**
   * Indicates whether the LDAP SDK should capture a thread stack trace for each
   * attempt made to establish a connection.  If this is enabled, then the
   * {@link LDAPConnection#getConnectStackTrace()}  method may be used to
   * retrieve the stack trace.
   *
   * @return  {@code true} if a thread stack trace should be captured whenever a
   *          connection is established, or {@code false} if not.
   */
  public boolean captureConnectStackTrace()
  {
    return captureConnectStackTrace;
  }



  /**
   * Specifies whether the LDAP SDK should capture a thread stack trace for each
   * attempt made to establish a connection.
   *
   * @param  captureConnectStackTrace  Indicates whether to capture a thread
   *                                   stack trace for each attempt made to
   *                                   establish a connection.
   */
  public void setCaptureConnectStackTrace(
                   final boolean captureConnectStackTrace)
  {
    this.captureConnectStackTrace = captureConnectStackTrace;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that a connection
   * attempt should be allowed to continue before giving up.
   *
   * @return  The maximum length of time in milliseconds that a connection
   *          attempt should be allowed to continue before giving up, or zero
   *          to indicate that there should be no connect timeout.
   */
  public int getConnectTimeoutMillis()
  {
    return connectTimeoutMillis;
  }



  /**
   * Specifies the maximum length of time in milliseconds that a connection
   * attempt should be allowed to continue before giving up.  A value of zero
   * indicates that there should be no connect timeout.
   *
   * @param  connectTimeoutMillis  The maximum length of time in milliseconds
   *                               that a connection attempt should be allowed
   *                               to continue before giving up.
   */
  public void setConnectTimeoutMillis(final int connectTimeoutMillis)
  {
    this.connectTimeoutMillis = connectTimeoutMillis;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that an operation
   * should be allowed to block while waiting for a response from the server.
   * This may be overridden on a per-operation type basis, so the
   * {@link #getResponseTimeoutMillis(OperationType)} method should be used
   * instead of this one.
   *
   * @return  The maximum length of time in milliseconds that an operation
   *          should be allowed to block while waiting for a response from the
   *          server, or zero if there should not be any default timeout.
   */
  public long getResponseTimeoutMillis()
  {
    return responseTimeoutMillis;
  }



  /**
   * Specifies the maximum length of time in milliseconds that an operation
   * should be allowed to block while waiting for a response from the server.  A
   * value of zero indicates that there should be no timeout.  Note that this
   * will override any per-operation type and per-extended operation type
   * timeouts that had previously been set.
   *
   * @param  responseTimeoutMillis  The maximum length of time in milliseconds
   *                                that an operation should be allowed to block
   *                                while waiting for a response from the
   *                                server.
   */
  public void setResponseTimeoutMillis(final long responseTimeoutMillis)
  {
    this.responseTimeoutMillis = Math.max(0L, responseTimeoutMillis);
    responseTimeoutMillisByExtendedOperationType = Collections.emptyMap();

    final EnumMap<OperationType,Long> newOperationTimeouts =
         new EnumMap<>(OperationType.class);
    for (final OperationType t : OperationType.values())
    {
      newOperationTimeouts.put(t, this.responseTimeoutMillis);
    }
    responseTimeoutMillisByOperationType =
         Collections.unmodifiableMap(newOperationTimeouts);
  }



  /**
   * Retrieves the maximum length of time in milliseconds that an operation
   * of the specified type should be allowed to block while waiting for a
   * response from the server.  Note that for extended operations, the response
   * timeout may be overridden on a per-request OID basis, so the
   * {@link #getExtendedOperationResponseTimeoutMillis(String)} method should be
   * used instead of this one for extended operations.
   *
   * @param  operationType  The operation type for which to make the
   *                        determination.  It must not be {@code null}.
   *
   * @return  The maximum length of time in milliseconds that an operation of
   *          the specified type should be allowed to block while waiting for a
   *          response from the server, or zero if there should not be any
   *          default timeout.
   */
  public long getResponseTimeoutMillis(
                   @NotNull final OperationType operationType)
  {
    return responseTimeoutMillisByOperationType.get(operationType);
  }



  /**
   * Specifies the maximum length of time in milliseconds that an operation of
   * the specified type should be allowed to block while waiting for a response
   * from the server.  A value of zero indicates that there should be no
   * timeout.
   *
   * @param  operationType          The operation type for which to set the
   *                                response timeout.  It must not be
   *                                {@code null}.
   * @param  responseTimeoutMillis  The maximum length of time in milliseconds
   *                                that an operation should be allowed to block
   *                                while waiting for a response from the
   *                                server.
   */
  public void setResponseTimeoutMillis(
                   @NotNull final OperationType operationType,
                   final long responseTimeoutMillis)
  {
    final EnumMap<OperationType,Long> newOperationTimeouts =
         new EnumMap<>(OperationType.class);
    newOperationTimeouts.putAll(responseTimeoutMillisByOperationType);
    newOperationTimeouts.put(operationType,
         Math.max(0L, responseTimeoutMillis));

    responseTimeoutMillisByOperationType = Collections.unmodifiableMap(
         newOperationTimeouts);
  }



  /**
   * Retrieves the maximum length of time in milliseconds that an extended
   * operation with the specified request OID should be allowed to block while
   * waiting for a response from the server.
   *
   * @param  requestOID  The request OID for the extended operation for which to
   *                     make the determination.  It must not be {@code null}.
   *
   * @return  The maximum length of time in milliseconds that the specified type
   *          of extended operation should be allowed to block while waiting for
   *          a response from the server, or zero if there should not be any
   *          default timeout.
   */
  public long getExtendedOperationResponseTimeoutMillis(
                   @NotNull final String requestOID)
  {
    final Long timeout =
         responseTimeoutMillisByExtendedOperationType.get(requestOID);
    if (timeout == null)
    {
      return responseTimeoutMillisByOperationType.get(OperationType.EXTENDED);
    }
    else
    {
      return timeout;
    }
  }



  /**
   * Specifies the maximum length of time in milliseconds that an extended
   * operation with the specified request OID should be allowed to block while
   * waiting for a response from the server.  A value of zero indicates that
   * there should be no timeout.
   *
   * @param  requestOID             The request OID for the extended operation
   *                                type for which to set the response timeout.
   *                                It must not be {@code null}.
   * @param  responseTimeoutMillis  The maximum length of time in milliseconds
   *                                that an operation should be allowed to block
   *                                while waiting for a response from the
   *                                server.
   */
  public void setExtendedOperationResponseTimeoutMillis(
                   @NotNull final String requestOID,
                   final long responseTimeoutMillis)
  {
    final HashMap<String,Long> newExtOpTimeouts =
         new HashMap<>(responseTimeoutMillisByExtendedOperationType);
    newExtOpTimeouts.put(requestOID, responseTimeoutMillis);
    responseTimeoutMillisByExtendedOperationType =
         Collections.unmodifiableMap(newExtOpTimeouts);
  }



  /**
   * Indicates whether the LDAP SDK should attempt to abandon any request for
   * which no response is received in the maximum response timeout period.
   *
   * @return  {@code true} if the LDAP SDK should attempt to abandon any request
   *          for which no response is received in the maximum response timeout
   *          period, or {@code false} if no abandon attempt should be made in
   *          this circumstance.
   */
  public boolean abandonOnTimeout()
  {
    return abandonOnTimeout;
  }



  /**
   * Specifies whether the LDAP SDK should attempt to abandon any request for
   * which no response is received in the maximum response timeout period.
   *
   * @param  abandonOnTimeout  Indicates whether the LDAP SDK should attempt to
   *                           abandon any request for which no response is
   *                           received in the maximum response timeout period.
   */
  public void setAbandonOnTimeout(final boolean abandonOnTimeout)
  {
    this.abandonOnTimeout = abandonOnTimeout;
  }



  /**
   * Indicates whether to use the SO_KEEPALIVE option for the underlying sockets
   * used by associated connections.
   *
   * @return  {@code true} if the SO_KEEPALIVE option should be used for the
   *          underlying sockets, or {@code false} if not.
   */
  public boolean useKeepAlive()
  {
    return useKeepAlive;
  }



  /**
   * Specifies whether to use the SO_KEEPALIVE option for the underlying sockets
   * used by associated connections.  Changes to this setting will take effect
   * only for new sockets, and not for existing sockets.
   *
   * @param  useKeepAlive  Indicates whether to use the SO_KEEPALIVE option for
   *                       the underlying sockets used by associated
   *                       connections.
   */
  public void setUseKeepAlive(final boolean useKeepAlive)
  {
    this.useKeepAlive = useKeepAlive;
  }



  /**
   * Indicates whether to use the SO_LINGER option for the underlying sockets
   * used by associated connections.
   *
   * @return  {@code true} if the SO_LINGER option should be used for the
   *          underlying sockets, or {@code false} if not.
   */
  public boolean useLinger()
  {
    return useLinger;
  }



  /**
   * Retrieves the linger timeout in seconds that will be used if the SO_LINGER
   * socket option is enabled.
   *
   * @return  The linger timeout in seconds that will be used if the SO_LINGER
   *          socket option is enabled.
   */
  public int getLingerTimeoutSeconds()
  {
    return lingerTimeoutSeconds;
  }



  /**
   * Specifies whether to use the SO_LINGER option for the underlying sockets
   * used by associated connections.  Changes to this setting will take effect
   * only for new sockets, and not for existing sockets.
   *
   * @param  useLinger             Indicates whether to use the SO_LINGER option
   *                               for the underlying sockets used by associated
   *                               connections.
   * @param  lingerTimeoutSeconds  The linger timeout in seconds that should be
   *                               used if this capability is enabled.
   */
  public void setUseLinger(final boolean useLinger,
                           final int lingerTimeoutSeconds)
  {
    this.useLinger = useLinger;
    this.lingerTimeoutSeconds = lingerTimeoutSeconds;
  }



  /**
   * Indicates whether to use the SO_REUSEADDR option for the underlying sockets
   * used by associated connections.
   *
   * @return  {@code true} if the SO_REUSEADDR option should be used for the
   *          underlying sockets, or {@code false} if not.
   */
  public boolean useReuseAddress()
  {
    return useReuseAddress;
  }



  /**
   * Specifies whether to use the SO_REUSEADDR option for the underlying sockets
   * used by associated connections.  Changes to this setting will take effect
   * only for new sockets, and not for existing sockets.
   *
   * @param  useReuseAddress  Indicates whether to use the SO_REUSEADDR option
   *                          for the underlying sockets used by associated
   *                          connections.
   */
  public void setUseReuseAddress(final boolean useReuseAddress)
  {
    this.useReuseAddress = useReuseAddress;
  }



  /**
   * Indicates whether to try to use schema information when reading data from
   * the server (e.g., to select the appropriate matching rules for the
   * attributes included in a search result entry).
   * <BR><BR>
   * If the LDAP SDK is configured to make use of schema, then it may be able
   * to more accurately perform client-side matching, including methods like
   * {@link Filter#matchesEntry(Entry)} or {@link Attribute#hasValue(String)}.
   * If both {@code useSchema} and {@code useSPooledSchema} are {@code false},
   * then all client-side matching for attribute values will treat them as
   * directory string values with a caseIgnoreMatch equality matching rule.  If
   * either {@code useSchema} or {@code usePooledSchema} is {@code true}, then
   * the LDAP SDK may be able to use the attribute type definitions from that
   * schema to determine the appropriate syntax and matching rules to use for
   * client-side matching operations involving those attributes.  Any attribute
   * types that are not defined in the schema will still be treated as
   * case-insensitive directory string values.
   *
   * @return  {@code true} if schema should be used when reading data from the
   *          server, or {@code false} if not.
   */
  public boolean useSchema()
  {
    return useSchema;
  }



  /**
   * Specifies whether to try to use schema information when reading data from
   * the server (e.g., to select the appropriate matching rules for the
   * attributes included in a search result entry).
   * <BR><BR>
   * If the LDAP SDK is configured to make use of schema, then it may be able
   * to more accurately perform client-side matching, including methods like
   * {@link Filter#matchesEntry(Entry)} or {@link Attribute#hasValue(String)}.
   * If both {@code useSchema} and {@code useSPooledSchema} are {@code false},
   * then all client-side matching for attribute values will treat them as
   * directory string values with a caseIgnoreMatch equality matching rule.  If
   * either {@code useSchema} or {@code usePooledSchema} is {@code true}, then
   * the LDAP SDK may be able to use the attribute type definitions from that
   * schema to determine the appropriate syntax and matching rules to use for
   * client-side matching operations involving those attributes.  Any attribute
   * types that are not defined in the schema will still be treated as
   * case-insensitive directory string values.
   * <BR><BR>
   * Note that calling this method with a value of {@code true} will also cause
   * the {@code usePooledSchema} setting to be given a value of false, since
   * the two values should not both be {@code true} at the same time.
   *
   * @param  useSchema  Indicates whether to try to use schema information when
   *                    reading data from the server.
   */
  public void setUseSchema(final boolean useSchema)
  {
    this.useSchema = useSchema;
    if (useSchema)
    {
      usePooledSchema = false;
    }
  }



  /**
   * Indicates whether to have connections that are part of a pool try to use
   * shared schema information when reading data from the server (e.g., to
   * select the appropriate matching rules for the attributes included in a
   * search result entry).  If this is {@code true}, then connections in a
   * connection pool will share the same cached schema information in a way that
   * attempts to reduce network bandwidth and connection establishment time (by
   * avoiding the need for each connection to retrieve its own copy of the
   * schema).
   * <BR><BR>
   * If the LDAP SDK is configured to make use of schema, then it may be able
   * to more accurately perform client-side matching, including methods like
   * {@link Filter#matchesEntry(Entry)} or {@link Attribute#hasValue(String)}.
   * If both {@code useSchema} and {@code useSPooledSchema} are {@code false},
   * then all client-side matching for attribute values will treat them as
   * directory string values with a caseIgnoreMatch equality matching rule.  If
   * either {@code useSchema} or {@code usePooledSchema} is {@code true}, then
   * the LDAP SDK may be able to use the attribute type definitions from that
   * schema to determine the appropriate syntax and matching rules to use for
   * client-side matching operations involving those attributes.  Any attribute
   * types that are not defined in the schema will still be treated as
   * case-insensitive directory string values.
   * <BR><BR>
   * If pooled schema is to be used, then it may be configured to expire so that
   * the schema may be periodically re-retrieved for new connections to allow
   * schema updates to be incorporated.  This behavior is controlled by the
   * value returned by the {@link #getPooledSchemaTimeoutMillis} method.
   *
   * @return  {@code true} if all connections in a connection pool should
   *          reference the same schema object, or {@code false} if each
   *          connection should retrieve its own copy of the schema.
   */
  public boolean usePooledSchema()
  {
    return usePooledSchema;
  }



  /**
   * Indicates whether to have connections that are part of a pool try to use
   * shared schema information when reading data from the server (e.g., to
   * select the appropriate matching rules for the attributes included in a
   * search result entry).
   * <BR><BR>
   * If the LDAP SDK is configured to make use of schema, then it may be able
   * to more accurately perform client-side matching, including methods like
   * {@link Filter#matchesEntry(Entry)} or {@link Attribute#hasValue(String)}.
   * If both {@code useSchema} and {@code useSPooledSchema} are {@code false},
   * then all client-side matching for attribute values will treat them as
   * directory string values with a caseIgnoreMatch equality matching rule.  If
   * either {@code useSchema} or {@code usePooledSchema} is {@code true}, then
   * the LDAP SDK may be able to use the attribute type definitions from that
   * schema to determine the appropriate syntax and matching rules to use for
   * client-side matching operations involving those attributes.  Any attribute
   * types that are not defined in the schema will still be treated as
   * case-insensitive directory string values.
   * <BR><BR>
   * Note that calling this method with a value of {@code true} will also cause
   * the {@code useSchema} setting to be given a value of false, since the two
   * values should not both be {@code true} at the same time.
   *
   * @param  usePooledSchema  Indicates whether all connections in a connection
   *                          pool should reference the same schema object
   *                          rather than attempting to retrieve their own copy
   *                          of the schema.
   */
  public void setUsePooledSchema(final boolean usePooledSchema)
  {
    this.usePooledSchema = usePooledSchema;
    if (usePooledSchema)
    {
      useSchema = false;
    }
  }



  /**
   * Retrieves the maximum length of time in milliseconds that a pooled schema
   * object should be considered fresh.  If the schema referenced by a
   * connection pool is at least this old, then the next connection attempt may
   * cause a new version of the schema to be retrieved.
   * <BR><BR>
   * This will only be used if the {@link #usePooledSchema} method returns
   * {@code true}.  A value of zero indicates that the pooled schema will never
   * expire.
   *
   * @return  The maximum length of time, in milliseconds, that a pooled schema
   *          object should be considered fresh, or zero if pooled schema
   *          objects should never expire.
   */
  public long getPooledSchemaTimeoutMillis()
  {
    return pooledSchemaTimeoutMillis;
  }



  /**
   * Specifies the maximum length of time in milliseconds that a pooled schema
   * object should be considered fresh.
   *
   * @param  pooledSchemaTimeoutMillis  The maximum length of time in
   *                                    milliseconds that a pooled schema object
   *                                    should be considered fresh.  A value
   *                                    less than or equal to zero will indicate
   *                                    that pooled schema should never expire.
   */
  public void setPooledSchemaTimeoutMillis(final long pooledSchemaTimeoutMillis)
  {
    this.pooledSchemaTimeoutMillis = Math.max(0L, pooledSchemaTimeoutMillis);
  }



  /**
   * Indicates whether to operate in synchronous mode, in which at most one
   * operation may be in progress at any time on a given connection, which may
   * allow it to operate more efficiently and without requiring a separate
   * reader thread per connection.  The LDAP SDK will not absolutely enforce
   * this restriction, but when operating in this mode correct behavior
   * cannot be guaranteed when multiple attempts are made to use a connection
   * for multiple concurrent operations.
   * <BR><BR>
   * Note that if synchronous mode is to be used, then this connection option
   * must be set on the connection before any attempt is made to establish the
   * connection.  Once the connection has been established, then it will
   * continue to operate in synchronous or asynchronous mode based on the
   * options in place at the time it was connected.
   *
   * @return  {@code true} if associated connections should operate in
   *          synchronous mode, or {@code false} if not.
   */
  public boolean useSynchronousMode()
  {
    return useSynchronousMode;
  }



  /**
   * Specifies whether to operate in synchronous mode, in which at most one
   * operation may be in progress at any time on a given connection.
   * <BR><BR>
   * Note that if synchronous mode is to be used, then this connection option
   * must be set on the connection before any attempt is made to establish the
   * connection.  Once the connection has been established, then it will
   * continue to operate in synchronous or asynchronous mode based on the
   * options in place at the time it was connected.
   *
   * @param  useSynchronousMode  Indicates whether to operate in synchronous
   *                             mode.
   */
  public void setUseSynchronousMode(final boolean useSynchronousMode)
  {
    this.useSynchronousMode = useSynchronousMode;
  }



  /**
   * Indicates whether to use the TCP_NODELAY option for the underlying sockets
   * used by associated connections.
   *
   * @return  {@code true} if the TCP_NODELAY option should be used for the
   *          underlying sockets, or {@code false} if not.
   */
  public boolean useTCPNoDelay()
  {
    return useTCPNoDelay;
  }



  /**
   * Specifies whether to use the TCP_NODELAY option for the underlying sockets
   * used by associated connections.  Changes to this setting will take effect
   * only for new sockets, and not for existing sockets.
   *
   * @param  useTCPNoDelay  Indicates whether to use the TCP_NODELAY option for
   *                        the underlying sockets used by associated
   *                        connections.
   */
  public void setUseTCPNoDelay(final boolean useTCPNoDelay)
  {
    this.useTCPNoDelay = useTCPNoDelay;
  }



  /**
   * Indicates whether associated connections should attempt to follow any
   * referrals that they encounter.
   *
   * @return  {@code true} if associated connections should attempt to follow
   *          any referrals that they encounter, or {@code false} if not.
   */
  public boolean followReferrals()
  {
    return followReferrals;
  }



  /**
   * Specifies whether associated connections should attempt to follow any
   * referrals that they encounter, using the referral connector for the
   * associated connection.
   *
   * @param  followReferrals  Specifies whether associated connections should
   *                          attempt to follow any referrals that they
   *                          encounter.
   */
  public void setFollowReferrals(final boolean followReferrals)
  {
    this.followReferrals = followReferrals;
  }



  /**
   * Retrieves the maximum number of hops that a connection should take when
   * trying to follow a referral.
   *
   * @return  The maximum number of hops that a connection should take when
   *          trying to follow a referral.
   */
  public int getReferralHopLimit()
  {
    return referralHopLimit;
  }



  /**
   * Specifies the maximum number of hops that a connection should take when
   * trying to follow a referral.
   *
   * @param  referralHopLimit  The maximum number of hops that a connection
   *                           should take when trying to follow a referral.  It
   *                           must be greater than zero.
   */
  public void setReferralHopLimit(final int referralHopLimit)
  {
    Validator.ensureTrue(referralHopLimit > 0,
         "LDAPConnectionOptions.referralHopLimit must be greater than 0.");

    this.referralHopLimit = referralHopLimit;
  }



  /**
   * Retrieves the referral connector that will be used to establish and
   * optionally authenticate connections to servers when attempting to follow
   * referrals, if defined.
   *
   * @return  The referral connector that will be used to establish and
   *          optionally authenticate connections to servers when attempting to
   *          follow referrals, or {@code null} if no specific referral
   *          connector has been configured and referral connections should be
   *          created using the same socket factory and bind request as the
   *          connection on which the referral was received.
   */
  @Nullable()
  public ReferralConnector getReferralConnector()
  {
    return referralConnector;
  }



  /**
   * Specifies the referral connector that should be used to establish and
   * optionally authenticate connections to servers when attempting to follow
   * referrals.
   *
   * @param  referralConnector  The referral connector that will be used to
   *                            establish and optionally authenticate
   *                            connections to servers when attempting to follow
   *                            referrals.  It may be {@code null} to indicate
   *                            that the same socket factory and bind request
   *                            as the connection on which the referral was
   *                            received should be used to establish and
   *                            authenticate connections for following
   *                            referrals.
   */
  public void setReferralConnector(
                   @Nullable final ReferralConnector referralConnector)
  {
    this.referralConnector = referralConnector;
  }



  /**
   * Retrieves the maximum size in bytes for an LDAP message that a connection
   * will attempt to read from the directory server.  If it encounters an LDAP
   * message that is larger than this size, then the connection will be
   * terminated.
   *
   * @return  The maximum size in bytes for an LDAP message that a connection
   *          will attempt to read from the directory server, or 0 if no limit
   *          will be enforced.
   */
  public int getMaxMessageSize()
  {
    return maxMessageSizeBytes;
  }



  /**
   * Specifies the maximum size in bytes for an LDAP message that a connection
   * will attempt to read from the directory server.  If it encounters an LDAP
   * message that is larger than this size, then the connection will be
   * terminated.
   *
   * @param  maxMessageSizeBytes  The maximum size in bytes for an LDAP message
   *                              that a connection will attempt to read from
   *                              the directory server.  A value less than or
   *                              equal to zero indicates that no limit should
   *                              be enforced.
   */
  public void setMaxMessageSize(final int maxMessageSizeBytes)
  {
    this.maxMessageSizeBytes = Math.max(0, maxMessageSizeBytes);
  }



  /**
   * Retrieves the logger that should be used to record information about
   * requests sent and responses received over connections with this set of
   * connection options.
   *
   * @return  The logger that should be used to record information about the
   *          requests sent and responses received over connection with this set
   *          of options, or {@code null} if no logging should be performed.
   */
  @Nullable()
  public LDAPConnectionLogger getConnectionLogger()
  {
    return connectionLogger;
  }



  /**
   * Specifies the logger that should be used to record information about
   * requests sent and responses received over connections with this set of
   * connection options.
   *
   * @param  connectionLogger  The logger that should be used to record
   *                           information about the requests sent and
   *                           responses received over connection with this set
   *                           of options.  It may be {@code null} if no logging
   *                           should be performed.
   */
  public void setConnectionLogger(
                   @Nullable final LDAPConnectionLogger connectionLogger)
  {
    this.connectionLogger = connectionLogger;
  }



  /**
   * Retrieves the disconnect handler to use for associated connections.
   *
   * @return  the disconnect handler to use for associated connections, or
   *          {@code null} if none is defined.
   */
  @Nullable()
  public DisconnectHandler getDisconnectHandler()
  {
    return disconnectHandler;
  }



  /**
   * Specifies the disconnect handler to use for associated connections.
   *
   * @param  handler  The disconnect handler to use for associated connections.
   */
  public void setDisconnectHandler(@Nullable final DisconnectHandler handler)
  {
    disconnectHandler = handler;
  }



  /**
   * Retrieves the unsolicited notification handler to use for associated
   * connections.
   *
   * @return  The unsolicited notification handler to use for associated
   *          connections, or {@code null} if none is defined.
   */
  @Nullable()
  public UnsolicitedNotificationHandler getUnsolicitedNotificationHandler()
  {
    return unsolicitedNotificationHandler;
  }



  /**
   * Specifies the unsolicited notification handler to use for associated
   * connections.
   *
   * @param  handler  The unsolicited notification handler to use for associated
   *                  connections.
   */
  public void setUnsolicitedNotificationHandler(
                   @Nullable final UnsolicitedNotificationHandler handler)
  {
    unsolicitedNotificationHandler = handler;
  }



  /**
   * Retrieves the socket receive buffer size, in bytes, that should be
   * requested when establishing a connection.
   *
   * @return  The socket receive buffer size, in bytes, that should be requested
   *          when establishing a connection, or zero if the JVM's default size
   *          should be used.
   */
  public int getReceiveBufferSize()
  {
    return receiveBufferSizeBytes;
  }



  /**
   * Specifies the socket receive buffer size, in bytes, that should be
   * requested when establishing a connection.
   *
   * @param  receiveBufferSizeBytes  The socket receive buffer size, in bytes,
   *                                 that should be requested when establishing
   *                                 a connection, or zero if the JVM's default
   *                                 size should be used.
   */
  public void setReceiveBufferSize(final int receiveBufferSizeBytes)
  {
    this.receiveBufferSizeBytes = Math.max(0, receiveBufferSizeBytes);
  }



  /**
   * Retrieves the socket send buffer size, in bytes, that should be requested
   * when establishing a connection.
   *
   * @return  The socket send buffer size, in bytes, that should be requested
   *          when establishing a connection, or zero if the JVM's default size
   *          should be used.
   */
  public int getSendBufferSize()
  {
    return sendBufferSizeBytes;
  }



  /**
   * Specifies the socket send buffer size, in bytes, that should be requested
   * when establishing a connection.
   *
   * @param  sendBufferSizeBytes  The socket send buffer size, in bytes, that
   *                              should be requested when establishing a
   *                              connection, or zero if the JVM's default size
   *                              should be used.
   */
  public void setSendBufferSize(final int sendBufferSizeBytes)
  {
    this.sendBufferSizeBytes = Math.max(0, sendBufferSizeBytes);
  }



  /**
   * Indicates whether to allow a socket factory instance (which may be shared
   * across multiple connections) to be used create multiple sockets
   * concurrently.  In general, socket factory implementations are threadsafe
   * and can be to create multiple connections simultaneously across separate
   * threads, but this is known to not be the case in some VM implementations
   * (e.g., SSL socket factories in IBM JVMs).  This setting may be used to
   * indicate whether concurrent socket creation attempts should be allowed
   * (which may allow for better and more consistent performance, especially in
   * cases where a connection attempt fails due to a timeout) or prevented
   * (which may be necessary for non-threadsafe socket factory implementations).
   *
   * @return  {@code true} if multiple threads should be able to concurrently
   *          use the same socket factory instance, or {@code false} if Java
   *          synchronization should be used to ensure that no more than one
   *          thread is allowed to use a socket factory at any given time.
   */
  public boolean allowConcurrentSocketFactoryUse()
  {
    return allowConcurrentSocketFactoryUse;
  }



  /**
   * Specifies whether to allow a socket factory instance (which may be shared
   * across multiple connections) to be used create multiple sockets
   * concurrently.  In general, socket factory implementations are threadsafe
   * and can be to create multiple connections simultaneously across separate
   * threads, but this is known to not be the case in some VM implementations
   * (e.g., SSL socket factories in IBM JVMs).  This setting may be used to
   * indicate whether concurrent socket creation attempts should be allowed
   * (which may allow for better and more consistent performance, especially in
   * cases where a connection attempt fails due to a timeout) or prevented
   * (which may be necessary for non-threadsafe socket factory implementations).
   *
   * @param  allowConcurrentSocketFactoryUse  Indicates whether to allow a
   *                                          socket factory instance to be used
   *                                          to create multiple sockets
   *                                          concurrently.
   */
  public void setAllowConcurrentSocketFactoryUse(
                   final boolean allowConcurrentSocketFactoryUse)
  {
    this.allowConcurrentSocketFactoryUse = allowConcurrentSocketFactoryUse;
  }



  /**
   * Retrieves the {@link SSLSocketVerifier} that will be used to perform
   * additional validation for any newly-created {@code SSLSocket} instances.
   *
   * @return  The {@code SSLSocketVerifier} that will be used to perform
   *          additional validation for any newly-created {@code SSLSocket}
   *          instances.
   */
  @NotNull()
  public SSLSocketVerifier getSSLSocketVerifier()
  {
    return sslSocketVerifier;
  }



  /**
   * Specifies the {@link SSLSocketVerifier} that will be used to perform
   * additional validation for any newly-created {@code SSLSocket} instances.
   *
   * @param  sslSocketVerifier  The {@code SSLSocketVerifier} that will be used
   *                            to perform additional validation for any
   *                            newly-created {@code SSLSocket} instances.
   */
  public void setSSLSocketVerifier(
                   @Nullable final SSLSocketVerifier sslSocketVerifier)
  {
    if (sslSocketVerifier == null)
    {
      this.sslSocketVerifier = DEFAULT_SSL_SOCKET_VERIFIER;
    }
    else
    {
      this.sslSocketVerifier = sslSocketVerifier;
    }
  }



  /**
   * Retrieves the value of the specified system property as a boolean.
   *
   * @param  propertyName  The name of the system property whose value should be
   *                       retrieved.
   * @param  defaultValue  The default value that will be returned if the system
   *                       property is not defined or if its value cannot be
   *                       parsed as a boolean.
   *
   * @return  The value of the specified system property as an boolean, or the
   *          default value if the system property is not set with a valid
   *          value.
   */
  static boolean getSystemProperty(@NotNull final String propertyName,
                                   final boolean defaultValue)
  {
    final String propertyValue = StaticUtils.getSystemProperty(propertyName);
    if (propertyValue == null)
    {
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.FINE, DebugType.OTHER,
             "Using the default value of " + defaultValue + " for system " +
                  "property '" + propertyName + "' that is not set.");
      }

      return defaultValue;
    }

    if (propertyValue.equalsIgnoreCase("true"))
    {
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.INFO, DebugType.OTHER,
             "Using value '" + propertyValue + "' set for system property '" +
                  propertyName + "'.");
      }

      return true;
    }
    else if (propertyValue.equalsIgnoreCase("false"))
    {
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.INFO, DebugType.OTHER,
             "Using value '" + propertyValue + "' set for system property '" +
                  propertyName + "'.");
      }

      return false;
    }
    else
    {
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.WARNING, DebugType.OTHER,
             "Invalid value '" + propertyValue + "' set for system property '" +
                  propertyName + "'.  The value was expected to be either " +
                  "'true' or 'false'.  The default value of " + defaultValue +
                  " will be used instead of the configured value.");
      }

      return defaultValue;
    }
  }



  /**
   * Retrieves the value of the specified system property as an integer.
   *
   * @param  propertyName  The name of the system property whose value should be
   *                       retrieved.
   * @param  defaultValue  The default value that will be returned if the system
   *                       property is not defined or if its value cannot be
   *                       parsed as an integer.
   *
   * @return  The value of the specified system property as an integer, or the
   *          default value if the system property is not set with a valid
   *          value.
   */
  static int getSystemProperty(@NotNull final String propertyName,
                               final int defaultValue)
  {
    final String propertyValueString =
         StaticUtils.getSystemProperty(propertyName);
    if (propertyValueString == null)
    {
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.FINE, DebugType.OTHER,
             "Using the default value of " + defaultValue + " for system " +
                  "property '" + propertyName + "' that is not set.");
      }

      return defaultValue;
    }

    try
    {
      final int propertyValueInt = Integer.parseInt(propertyValueString);
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.INFO, DebugType.OTHER,
             "Using value " + propertyValueInt + " set for system property '" +
                  propertyName + "'.");
      }

      return propertyValueInt;
    }
    catch (final Exception e)
    {
      if (Debug.debugEnabled())
      {
        Debug.debugException(e);
        Debug.debug(Level.WARNING, DebugType.OTHER,
             "Invalid value '" + propertyValueString + "' set for system " +
                  "property '" + propertyName + "'.  The value was expected " +
                  "to be an integer.  The default value of " + defaultValue +
                  "will be used instead of the configured value.",
             e);
      }

      return defaultValue;
    }
  }



  /**
   * Retrieves the value of the specified system property as a long.
   *
   * @param  propertyName  The name of the system property whose value should be
   *                       retrieved.
   * @param  defaultValue  The default value that will be returned if the system
   *                       property is not defined or if its value cannot be
   *                       parsed as a long.
   *
   * @return  The value of the specified system property as a long, or the
   *          default value if the system property is not set with a valid
   *          value.
   */
  @Nullable()
  static Long getSystemProperty(@NotNull final String propertyName,
                                @Nullable final Long defaultValue)
  {
    final String propertyValueString =
         StaticUtils.getSystemProperty(propertyName);
    if (propertyValueString == null)
    {
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.FINE, DebugType.OTHER,
             "Using the default value of " + defaultValue + " for system " +
                  "property '" + propertyName + "' that is not set.");
      }

      return defaultValue;
    }

    try
    {
      final long propertyValueLong = Long.parseLong(propertyValueString);
      if (Debug.debugEnabled())
      {
        Debug.debug(Level.INFO, DebugType.OTHER,
             "Using value " + propertyValueLong + " set for system property '" +
                  propertyName + "'.");
      }

      return propertyValueLong;
    }
    catch (final Exception e)
    {
      if (Debug.debugEnabled())
      {
        Debug.debugException(e);
        Debug.debug(Level.WARNING, DebugType.OTHER,
             "Invalid value '" + propertyValueString + "' set for system " +
                  "property '" + propertyName + "'.  The value was expected " +
                  "to be a long.  The default value of " + defaultValue +
                  "will be used instead of the configured value.",
             e);
      }

      return defaultValue;
    }
  }



  /**
   * Retrieves a string representation of this LDAP connection.
   *
   * @return  A string representation of this LDAP connection.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this LDAP connection to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this LDAP connection.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPConnectionOptions(autoReconnect=");
    buffer.append(autoReconnect);
    buffer.append(", nameResolver=");
    nameResolver.toString(buffer);
    buffer.append(", bindWithDNRequiresPassword=");
    buffer.append(bindWithDNRequiresPassword);
    buffer.append(", followReferrals=");
    buffer.append(followReferrals);
    if (followReferrals)
    {
      buffer.append(", referralHopLimit=");
      buffer.append(referralHopLimit);
    }
    if (referralConnector != null)
    {
      buffer.append(", referralConnectorClass=");
      buffer.append(referralConnector.getClass().getName());
    }
    buffer.append(", useKeepAlive=");
    buffer.append(useKeepAlive);
    buffer.append(", useLinger=");
    if (useLinger)
    {
      buffer.append("true, lingerTimeoutSeconds=");
      buffer.append(lingerTimeoutSeconds);
    }
    else
    {
      buffer.append("false");
    }
    buffer.append(", useReuseAddress=");
    buffer.append(useReuseAddress);
    buffer.append(", useSchema=");
    buffer.append(useSchema);
    buffer.append(", usePooledSchema=");
    buffer.append(usePooledSchema);
    buffer.append(", pooledSchemaTimeoutMillis=");
    buffer.append(pooledSchemaTimeoutMillis);
    buffer.append(", useSynchronousMode=");
    buffer.append(useSynchronousMode);
    buffer.append(", useTCPNoDelay=");
    buffer.append(useTCPNoDelay);
    buffer.append(", captureConnectStackTrace=");
    buffer.append(captureConnectStackTrace);
    buffer.append(", connectTimeoutMillis=");
    buffer.append(connectTimeoutMillis);
    buffer.append(", responseTimeoutMillis=");
    buffer.append(responseTimeoutMillis);

    for (final Map.Entry<OperationType,Long> e :
         responseTimeoutMillisByOperationType.entrySet())
    {
      buffer.append(", responseTimeoutMillis.");
      buffer.append(e.getKey().name());
      buffer.append('=');
      buffer.append(e.getValue());
    }

    for (final Map.Entry<String,Long> e :
         responseTimeoutMillisByExtendedOperationType.entrySet())
    {
      buffer.append(", responseTimeoutMillis.EXTENDED.");
      buffer.append(e.getKey());
      buffer.append('=');
      buffer.append(e.getValue());
    }

    buffer.append(", abandonOnTimeout=");
    buffer.append(abandonOnTimeout);
    buffer.append(", maxMessageSizeBytes=");
    buffer.append(maxMessageSizeBytes);
    buffer.append(", receiveBufferSizeBytes=");
    buffer.append(receiveBufferSizeBytes);
    buffer.append(", sendBufferSizeBytes=");
    buffer.append(sendBufferSizeBytes);
    buffer.append(", allowConcurrentSocketFactoryUse=");
    buffer.append(allowConcurrentSocketFactoryUse);

    if (connectionLogger != null)
    {
      buffer.append(", connectionLoggerClass=");
      buffer.append(connectionLogger.getClass().getName());
    }

    if (disconnectHandler != null)
    {
      buffer.append(", disconnectHandlerClass=");
      buffer.append(disconnectHandler.getClass().getName());
    }

    if (unsolicitedNotificationHandler != null)
    {
      buffer.append(", unsolicitedNotificationHandlerClass=");
      buffer.append(unsolicitedNotificationHandler.getClass().getName());
    }

    buffer.append(", sslSocketVerifierClass='");
    buffer.append(sslSocketVerifier.getClass().getName());
    buffer.append('\'');

    buffer.append(')');
  }
}
