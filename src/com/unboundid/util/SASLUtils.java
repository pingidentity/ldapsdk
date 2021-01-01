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
package com.unboundid.util;



import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.unboundid.ldap.sdk.ANONYMOUSBindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequest;
import com.unboundid.ldap.sdk.DIGESTMD5BindRequestProperties;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequest;
import com.unboundid.ldap.sdk.GSSAPIBindRequestProperties;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OAUTHBEARERBindRequest;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLBindRequest;
import com.unboundid.ldap.sdk.SASLQualityOfProtection;
import com.unboundid.ldap.sdk.SCRAMSHA1BindRequest;
import com.unboundid.ldap.sdk.SCRAMSHA256BindRequest;
import com.unboundid.ldap.sdk.SCRAMSHA512BindRequest;
import com.unboundid.ldap.sdk.unboundidds.SingleUseTOTPBindRequest;
import com.unboundid.ldap.sdk.unboundidds.
            UnboundIDCertificatePlusPasswordBindRequest;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDDeliveredOTPBindRequest;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDTOTPBindRequest;
import com.unboundid.ldap.sdk.unboundidds.UnboundIDYubiKeyOTPBindRequest;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a utility that may be used to help process SASL bind
 * operations using the LDAP SDK.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLUtils
{
  /**
   * The name of the SASL option that specifies the access token.  It may be
   * used in conjunction with the OAUTHBEARER mechanism.
   */
  @NotNull public static final String SASL_OPTION_ACCESS_TOKEN = "accessToken";



  /**
   * The name of the SASL option that specifies the authentication ID.  It may
   * be used in conjunction with the CRAM-MD5, DIGEST-MD5, GSSAPI, and PLAIN
   * mechanisms.
   */
  @NotNull public static final String SASL_OPTION_AUTH_ID = "authID";



  /**
   * The name of the SASL option that specifies the authorization ID.  It may
   * be used in conjunction with the DIGEST-MD5, GSSAPI, and PLAIN mechanisms.
   */
  @NotNull public static final String SASL_OPTION_AUTHZ_ID = "authzID";



  /**
   * The name of the SASL option that specifies the path to the JAAS config
   * file.  It may be used in conjunction with the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_CONFIG_FILE = "configFile";



  /**
   * The name of the SASL option that indicates whether debugging should be
   * enabled.  It may be used in conjunction with the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_DEBUG = "debug";



  /**
   * The name of the SASL option that specifies the KDC address.  It may be used
   * in conjunction with the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_KDC_ADDRESS = "kdcAddress";



  /**
   * The name of the SASL option that specifies the desired SASL mechanism to
   * use to authenticate to the server.
   */
  @NotNull public static final String SASL_OPTION_MECHANISM = "mech";



  /**
   * The name of the SASL option that specifies a one-time password.  It may be
   * used in conjunction with the UNBOUNDID-DELIVERED-OTP and
   * UNBOUNDID-YUBIKEY-OTP mechanisms.
   */
  @NotNull public static final String SASL_OPTION_OTP = "otp";



  /**
   * The name of the SASL option that may be used to indicate whether to
   * prompt for a static password.  It may be used in conjunction with the
   * UNBOUNDID-TOTP and UNBOUNDID-YUBIKEY-OTP mechanisms.
   */
  @NotNull public static final String SASL_OPTION_PROMPT_FOR_STATIC_PW =
       "promptForStaticPassword";



  /**
   * The name of the SASL option that specifies the GSSAPI service principal
   * protocol.  It may be used in conjunction with the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_PROTOCOL = "protocol";



  /**
   * The name of the SASL option that specifies the quality of protection that
   * should be used for communication that occurs after the authentication has
   * completed.
   */
  @NotNull public static final String SASL_OPTION_QOP = "qop";



  /**
   * The name of the SASL option that specifies the realm name.  It may be used
   * in conjunction with the DIGEST-MD5 and GSSAPI mechanisms.
   */
  @NotNull public static final String SASL_OPTION_REALM = "realm";



  /**
   * The name of the SASL option that indicates whether to require an existing
   * Kerberos session from the ticket cache.  It may be used in conjunction with
   * the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_REQUIRE_CACHE =
       "requireCache";



  /**
   * The name of the SASL option that indicates whether to attempt to renew the
   * Kerberos TGT for an existing session.  It may be used in conjunction with
   * the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_RENEW_TGT = "renewTGT";



  /**
   * The name of the SASL option that specifies the path to the Kerberos ticket
   * cache to use.  It may be used in conjunction with the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_TICKET_CACHE_PATH =
       "ticketCache";



  /**
   * The name of the SASL option that specifies the TOTP authentication code.
   * It may be used in conjunction with the UNBOUNDID-TOTP mechanism.
   */
  @NotNull public static final String SASL_OPTION_TOTP_PASSWORD =
       "totpPassword";



  /**
   * The name of the SASL option that specifies the trace string.  It may be
   * used in conjunction with the ANONYMOUS mechanism.
   */
  @NotNull public static final String SASL_OPTION_TRACE = "trace";



  /**
   * The name of the SASL option that specifies the username.  It may be
   * used in conjunction with the SCRAM-SHA-1, SCRAM-SHA-256, and SCRAM-SHA-512
   * mechanisms.
   */
  @NotNull public static final String SASL_OPTION_USERNAME = "username";



  /**
   * The name of the SASL option that specifies whether to use a Kerberos ticket
   * cache.  It may be used in conjunction with the GSSAPI mechanism.
   */
  @NotNull public static final String SASL_OPTION_USE_TICKET_CACHE =
       "useTicketCache";



  /**
   * A map with information about all supported SASL mechanisms, mapped from
   * lowercase mechanism name to an object with information about that
   * mechanism.
   */
  @NotNull private static final Map<String,SASLMechanismInfo> SASL_MECHANISMS;



  static
  {
    final TreeMap<String,SASLMechanismInfo> m = new TreeMap<>();

    m.put(
         StaticUtils.toLowerCase(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME),
         new SASLMechanismInfo(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME,
              INFO_SASL_ANONYMOUS_DESCRIPTION.get(), false, false,
              new SASLOption(SASL_OPTION_TRACE,
                   INFO_SASL_ANONYMOUS_OPTION_TRACE.get(), false, false)));

    m.put(StaticUtils.toLowerCase(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME),
         new SASLMechanismInfo(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME,
              INFO_SASL_CRAM_MD5_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_CRAM_MD5_OPTION_AUTH_ID.get(), true, false)));

    m.put(
         StaticUtils.toLowerCase(DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME),
         new SASLMechanismInfo(DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME,
              INFO_SASL_DIGEST_MD5_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_DIGEST_MD5_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_DIGEST_MD5_OPTION_AUTHZ_ID.get(), false, false),
              new SASLOption(SASL_OPTION_REALM,
                   INFO_SASL_DIGEST_MD5_OPTION_REALM.get(), false, false),
              new SASLOption(SASL_OPTION_QOP,
                   INFO_SASL_DIGEST_MD5_OPTION_QOP.get(), false, false)));

    m.put(StaticUtils.toLowerCase(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME),
         new SASLMechanismInfo(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME,
              INFO_SASL_EXTERNAL_DESCRIPTION.get(), false, false));

    m.put(StaticUtils.toLowerCase(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME),
         new SASLMechanismInfo(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME,
              INFO_SASL_GSSAPI_DESCRIPTION.get(), true, false,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_GSSAPI_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_GSSAPI_OPTION_AUTHZ_ID.get(), false, false),
              new SASLOption(SASL_OPTION_CONFIG_FILE,
                   INFO_SASL_GSSAPI_OPTION_CONFIG_FILE.get(), false, false),
              new SASLOption(SASL_OPTION_DEBUG,
                   INFO_SASL_GSSAPI_OPTION_DEBUG.get(), false, false),
              new SASLOption(SASL_OPTION_KDC_ADDRESS,
                   INFO_SASL_GSSAPI_OPTION_KDC_ADDRESS.get(), false, false),
              new SASLOption(SASL_OPTION_PROTOCOL,
                   INFO_SASL_GSSAPI_OPTION_PROTOCOL.get(), false, false),
              new SASLOption(SASL_OPTION_REALM,
                   INFO_SASL_GSSAPI_OPTION_REALM.get(), false, false),
              new SASLOption(SASL_OPTION_QOP,
                   INFO_SASL_GSSAPI_OPTION_QOP.get(), false, false),
              new SASLOption(SASL_OPTION_RENEW_TGT,
                   INFO_SASL_GSSAPI_OPTION_RENEW_TGT.get(), false, false),
              new SASLOption(SASL_OPTION_REQUIRE_CACHE,
                   INFO_SASL_GSSAPI_OPTION_REQUIRE_TICKET_CACHE.get(), false,
                   false),
              new SASLOption(SASL_OPTION_TICKET_CACHE_PATH,
                   INFO_SASL_GSSAPI_OPTION_TICKET_CACHE.get(), false, false),
              new SASLOption(SASL_OPTION_USE_TICKET_CACHE,
                   INFO_SASL_GSSAPI_OPTION_USE_TICKET_CACHE.get(), false,
                   false)));

    m.put(StaticUtils.toLowerCase(
         OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME),
         new SASLMechanismInfo(
              OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME,
              INFO_SASL_PLAIN_DESCRIPTION.get(), false, false,
              new SASLOption(SASL_OPTION_ACCESS_TOKEN,
                   INFO_SASL_OAUTHBEARER_OPTION_ACCESS_TOKEN.get(), false,
                   false)));

    m.put(StaticUtils.toLowerCase(PLAINBindRequest.PLAIN_MECHANISM_NAME),
         new SASLMechanismInfo(PLAINBindRequest.PLAIN_MECHANISM_NAME,
              INFO_SASL_PLAIN_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_PLAIN_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_PLAIN_OPTION_AUTHZ_ID.get(), false, false)));

    m.put(
         StaticUtils.toLowerCase(
              SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME),
         new SASLMechanismInfo(SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME,
              INFO_SASL_SCRAM_SHA_1_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_USERNAME,
                   INFO_SASL_SCRAM_OPTION_USERNAME.get(), true, false)));

    m.put(
         StaticUtils.toLowerCase(
              SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME),
         new SASLMechanismInfo(
              SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME,
              INFO_SASL_SCRAM_SHA_256_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_USERNAME,
                   INFO_SASL_SCRAM_OPTION_USERNAME.get(), true, false)));

    m.put(
         StaticUtils.toLowerCase(
              SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME),
         new SASLMechanismInfo(
              SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME,
              INFO_SASL_SCRAM_SHA_512_DESCRIPTION.get(), true, true,
              new SASLOption(SASL_OPTION_USERNAME,
                   INFO_SASL_SCRAM_OPTION_USERNAME.get(), true, false)));

    m.put(StaticUtils.toLowerCase(
         UnboundIDCertificatePlusPasswordBindRequest.
              UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDCertificatePlusPasswordBindRequest.
                   UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_CERT_PLUS_PASSWORD_DESCRIPTION.get(), true,
              true));

    m.put(
         StaticUtils.toLowerCase(
              UnboundIDDeliveredOTPBindRequest.
                   UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDDeliveredOTPBindRequest.
                   UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_DELIVERED_OTP_DESCRIPTION.get(), false, false,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTHZ_ID.get(), false,
                   false),
              new SASLOption(SASL_OPTION_OTP,
                   INFO_SASL_UNBOUNDID_DELIVERED_OTP_OPTION_OTP.get(), true,
                   false)));

    m.put(
         StaticUtils.toLowerCase(
              UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_TOTP_DESCRIPTION.get(), true, false,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTH_ID.get(), true, false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_AUTHZ_ID.get(), false,
                   false),
              new SASLOption(SASL_OPTION_PROMPT_FOR_STATIC_PW,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_PROMPT_FOR_PW.get(), false,
                   false),
              new SASLOption(SASL_OPTION_TOTP_PASSWORD,
                   INFO_SASL_UNBOUNDID_TOTP_OPTION_TOTP_PASSWORD.get(), true,
                   false)));

    m.put(
         StaticUtils.toLowerCase(
              UnboundIDYubiKeyOTPBindRequest.
                   UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME),
         new SASLMechanismInfo(
              UnboundIDYubiKeyOTPBindRequest.
                   UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME,
              INFO_SASL_UNBOUNDID_YUBIKEY_OTP_DESCRIPTION.get(), true, false,
              new SASLOption(SASL_OPTION_AUTH_ID,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_AUTH_ID.get(), true,
                   false),
              new SASLOption(SASL_OPTION_AUTHZ_ID,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_AUTHZ_ID.get(), false,
                   false),
              new SASLOption(SASL_OPTION_OTP,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_OTP.get(), true,
                   false),
              new SASLOption(SASL_OPTION_PROMPT_FOR_STATIC_PW,
                   INFO_SASL_UNBOUNDID_YUBIKEY_OTP_OPTION_PROMPT_FOR_PW.get(),
                   false, false)));

    SASL_MECHANISMS = Collections.unmodifiableMap(m);
  }



  /**
   * Prevent this utility class from being instantiated.
   */
  private SASLUtils()
  {
    // No implementation required.
  }



  /**
   * Retrieves information about the SASL mechanisms supported for use by this
   * class.
   *
   * @return  Information about the SASL mechanisms supported for use by this
   *          class.
   */
  @NotNull()
  public static List<SASLMechanismInfo> getSupportedSASLMechanisms()
  {
    return Collections.unmodifiableList(
         new ArrayList<>(SASL_MECHANISMS.values()));
  }



  /**
   * Retrieves information about the specified SASL mechanism.
   *
   * @param  mechanism  The name of the SASL mechanism for which to retrieve
   *                    information.  It will be treated in a case-insensitive
   *                    manner.
   *
   * @return  Information about the requested SASL mechanism, or {@code null} if
   *          no information about the specified mechanism is available.
   */
  @Nullable()
  public static SASLMechanismInfo getSASLMechanismInfo(
                                       @NotNull final String mechanism)
  {
    return SASL_MECHANISMS.get(StaticUtils.toLowerCase(mechanism));
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  public static SASLBindRequest createBindRequest(@Nullable final String bindDN,
                                     @Nullable final String password,
                                     @Nullable final String mechanism,
                                     @Nullable final String... options)
         throws LDAPException
  {
    return createBindRequest(bindDN,
         (password == null ? null : StaticUtils.getBytes(password)), mechanism,
         StaticUtils.toList(options));
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   * @param  controls   The set of controls to include in the request.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  public static SASLBindRequest createBindRequest(@Nullable final String bindDN,
                                     @Nullable final String password,
                                     @Nullable final String mechanism,
                                     @Nullable final List<String> options,
                                     @Nullable final Control... controls)
         throws LDAPException
  {
    return createBindRequest(bindDN,
         (password == null
              ? null
              : StaticUtils.getBytes(password)), mechanism, options,
         controls);
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  public static SASLBindRequest createBindRequest(@Nullable final String bindDN,
                                     @Nullable final byte[] password,
                                     @Nullable final String mechanism,
                                     @Nullable final String... options)
         throws LDAPException
  {
    return createBindRequest(bindDN, password, mechanism,
         StaticUtils.toList(options));
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN     The bind DN to use for the SASL bind request.  For most
   *                    SASL mechanisms, this should be {@code null}, since the
   *                    identity of the target user should be specified in some
   *                    other way (e.g., via an "authID" SASL option).
   * @param  password   The password to use for the SASL bind request.  It may
   *                    be {@code null} if no password is required for the
   *                    desired SASL mechanism.
   * @param  mechanism  The name of the SASL mechanism to use.  It may be
   *                    {@code null} if the provided set of options contains a
   *                    "mech" option to specify the desired SASL option.
   * @param  options    The set of SASL options to use when creating the bind
   *                    request, in the form "name=value".  It may be
   *                    {@code null} or empty if no SASL options are needed and
   *                    a value was provided for the {@code mechanism} argument.
   *                    If the set of SASL options includes a "mech" option,
   *                    then the {@code mechanism} argument must be {@code null}
   *                    or have a value that matches the value of the "mech"
   *                    SASL option.
   * @param  controls   The set of controls to include in the request.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  public static SASLBindRequest createBindRequest(@Nullable final String bindDN,
                                     @Nullable final byte[] password,
                                     @Nullable final String mechanism,
                                     @Nullable final List<String> options,
                                     @Nullable final Control... controls)
         throws LDAPException
  {
    return createBindRequest(bindDN, password, false, null, mechanism, options,
         controls);
  }



  /**
   * Creates a new SASL bind request using the provided information.
   *
   * @param  bindDN             The bind DN to use for the SASL bind request.
   *                            For most SASL mechanisms, this should be
   *                            {@code null}, since the identity of the target
   *                            user should be specified in some other way
   *                            (e.g., via an "authID" SASL option).
   * @param  password           The password to use for the SASL bind request.
   *                            It may be {@code null} if no password is
   *                            required for the desired SASL mechanism.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} if
   *                            {@code promptForPassword} is {@code false}.
   * @param  mechanism          The name of the SASL mechanism to use.  It may
   *                            be {@code null} if the provided set of options
   *                            contains a "mech" option to specify the desired
   *                            SASL option.
   * @param  options            The set of SASL options to use when creating the
   *                            bind request, in the form "name=value".  It may
   *                            be {@code null} or empty if no SASL options are
   *                            needed and a value was provided for the
   *                            {@code mechanism} argument.  If the set of SASL
   *                            options includes a "mech" option, then the
   *                            {@code mechanism} argument must be {@code null}
   *                            or have a value that matches the value of the
   *                            "mech" SASL option.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL bind request created using the provided information.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  public static SASLBindRequest createBindRequest(@Nullable final String bindDN,
                                     @Nullable final byte[] password,
                                     final boolean promptForPassword,
                                     @Nullable final CommandLineTool tool,
                                     @Nullable final String mechanism,
                                     @Nullable final List<String> options,
                                     @Nullable final Control... controls)
         throws LDAPException
  {
    if (promptForPassword)
    {
      Validator.ensureNotNull(tool);
    }

    // Parse the provided set of options to ensure that they are properly
    // formatted in name-value form, and extract the SASL mechanism.
    final String mech;
    final Map<String,String> optionsMap = parseOptions(options);
    final String mechOption =
         optionsMap.remove(StaticUtils.toLowerCase(SASL_OPTION_MECHANISM));
    if (mechOption != null)
    {
      mech = mechOption;
      if ((mechanism != null) && (! mech.equalsIgnoreCase(mechanism)))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_CONFLICT.get(mechanism, mech));
      }
    }
    else
    {
      mech = mechanism;
    }

    if (mech == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_NO_MECH.get());
    }

    if (mech.equalsIgnoreCase(ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME))
    {
      return createANONYMOUSBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME))
    {
      return createCRAMMD5BindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
                  DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME))
    {
      return createDIGESTMD5BindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME))
    {
      return createEXTERNALBindRequest(password, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(GSSAPIBindRequest.GSSAPI_MECHANISM_NAME))
    {
      return createGSSAPIBindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
         OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME))
    {
      return createOAUTHBEARERBindRequest(password, promptForPassword,
           tool, optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(PLAINBindRequest.PLAIN_MECHANISM_NAME))
    {
      return createPLAINBindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
         SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME))
    {
      return createSCRAMSHA1BindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
         SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME))
    {
      return createSCRAMSHA256BindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(
         SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME))
    {
      return createSCRAMSHA512BindRequest(password, promptForPassword, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(UnboundIDCertificatePlusPasswordBindRequest.
             UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME))
    {
      return createUnboundIDCertificatePlusPasswordBindRequest(password, tool,
           optionsMap, controls);
    }
    else if (mech.equalsIgnoreCase(UnboundIDDeliveredOTPBindRequest.
             UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME))
    {
      return createUNBOUNDIDDeliveredOTPBindRequest(password, optionsMap,
           controls);
    }
    else if (mech.equalsIgnoreCase(
             UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME))
    {
      return createUNBOUNDIDTOTPBindRequest(password, tool, optionsMap,
           controls);
    }
    else if (mech.equalsIgnoreCase(
         UnboundIDYubiKeyOTPBindRequest.UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME))
    {
      return createUNBOUNDIDYUBIKEYOTPBindRequest(password, tool, optionsMap,
           controls);
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_UNSUPPORTED_MECH.get(mech));
    }
  }



  /**
   * Creates a SASL ANONYMOUS bind request using the provided set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL ANONYMOUS bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static ANONYMOUSBindRequest createANONYMOUSBindRequest(
                      @Nullable final byte[] password,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME));
    }


    // The trace option is optional.
    final String trace =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_TRACE));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         ANONYMOUSBindRequest.ANONYMOUS_MECHANISM_NAME);

    return new ANONYMOUSBindRequest(trace, controls);
  }



  /**
   * Creates a SASL CRAM-MD5 bind request using the provided password and set of
   * options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL CRAM-MD5 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static CRAMMD5BindRequest createCRAMMD5BindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                  CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
      }
    }
    else
    {
      pw = password;
    }


    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME));
    }


    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         CRAMMD5BindRequest.CRAMMD5_MECHANISM_NAME);

    return new CRAMMD5BindRequest(authID, pw, controls);
  }



  /**
   * Creates a SASL DIGEST-MD5 bind request using the provided password and set
   * of options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL DIGEST-MD5 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static DIGESTMD5BindRequest createDIGESTMD5BindRequest(
                      @Nullable() final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                  DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME));
      }
    }
    else
    {
      pw = password;
    }

    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME));
    }

    final DIGESTMD5BindRequestProperties properties =
         new DIGESTMD5BindRequestProperties(authID, pw);

    // The authzID option is optional.
    properties.setAuthorizationID(
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTHZ_ID)));

    // The realm option is optional.
    properties.setRealm(options.remove(
         StaticUtils.toLowerCase(SASL_OPTION_REALM)));

    // The QoP option is optional, and may contain multiple values that need to
    // be parsed.
    final String qopString =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_QOP));
    if (qopString != null)
    {
      properties.setAllowedQoP(
           SASLQualityOfProtection.decodeQoPList(qopString));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         DIGESTMD5BindRequest.DIGESTMD5_MECHANISM_NAME);

    return new DIGESTMD5BindRequest(properties, controls);
  }



  /**
   * Creates a SASL EXTERNAL bind request using the provided set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL EXTERNAL bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static EXTERNALBindRequest createEXTERNALBindRequest(
                      @Nullable final byte[] password,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         EXTERNALBindRequest.EXTERNAL_MECHANISM_NAME);

    return new EXTERNALBindRequest(controls);
  }



  /**
   * Creates a SASL GSSAPI bind request using the provided password and set of
   * options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL GSSAPI bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static GSSAPIBindRequest createGSSAPIBindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                GSSAPIBindRequest.GSSAPI_MECHANISM_NAME));
    }
    final GSSAPIBindRequestProperties gssapiProperties =
         new GSSAPIBindRequestProperties(authID, password);

    // The authzID option is optional.
    gssapiProperties.setAuthorizationID(
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTHZ_ID)));

    // The configFile option is optional.
    gssapiProperties.setConfigFilePath(options.remove(
         StaticUtils.toLowerCase(SASL_OPTION_CONFIG_FILE)));

    // The debug option is optional.
    gssapiProperties.setEnableGSSAPIDebugging(getBooleanValue(options,
         SASL_OPTION_DEBUG, false));

    // The kdcAddress option is optional.
    gssapiProperties.setKDCAddress(options.remove(
         StaticUtils.toLowerCase(SASL_OPTION_KDC_ADDRESS)));

    // The protocol option is optional.
    final String protocol =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_PROTOCOL));
    if (protocol != null)
    {
      gssapiProperties.setServicePrincipalProtocol(protocol);
    }

    // The realm option is optional.
    gssapiProperties.setRealm(options.remove(
         StaticUtils.toLowerCase(SASL_OPTION_REALM)));

    // The QoP option is optional, and may contain multiple values that need to
    // be parsed.
    final String qopString =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_QOP));
    if (qopString != null)
    {
      gssapiProperties.setAllowedQoP(
           SASLQualityOfProtection.decodeQoPList(qopString));
    }

    // The renewTGT option is optional.
    gssapiProperties.setRenewTGT(getBooleanValue(options, SASL_OPTION_RENEW_TGT,
         false));

    // The requireCache option is optional.
    gssapiProperties.setRequireCachedCredentials(getBooleanValue(options,
         SASL_OPTION_REQUIRE_CACHE, false));

    // The ticketCache option is optional.
    gssapiProperties.setTicketCachePath(options.remove(
         StaticUtils.toLowerCase(SASL_OPTION_TICKET_CACHE_PATH)));

    // The useTicketCache option is optional.
    gssapiProperties.setUseTicketCache(getBooleanValue(options,
         SASL_OPTION_USE_TICKET_CACHE, true));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         GSSAPIBindRequest.GSSAPI_MECHANISM_NAME);

    // A password must have been provided unless useTicketCache=true and
    // requireTicketCache=true.
    if (password == null)
    {
      if (! (gssapiProperties.useTicketCache() &&
           gssapiProperties.requireCachedCredentials()))
      {
        if (promptForPassword)
        {
          tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
          gssapiProperties.setPassword(PasswordReader.readPassword());
          tool.getOriginalOut().println();
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SASL_OPTION_GSSAPI_PASSWORD_REQUIRED.get());
        }
      }
    }

    return new GSSAPIBindRequest(gssapiProperties, controls);
  }



  /**
   * Creates a SASL OAUTHBEARER bind request using the provided password and
   * set of options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL OAUTHBEARER bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static OAUTHBEARERBindRequest createOAUTHBEARERBindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    // The accessToken option wasn't declared as required, but we will either
    // require it to have been provided or we will interactively prompt for it.
    String accessToken =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_ACCESS_TOKEN));
    if (accessToken == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(
             INFO_SASL_TOOL_ENTER_OAUTHBEARER_ACCESS_TOKEN.get());
        accessToken = StaticUtils.toUTF8String(PasswordReader.readPassword());
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_ACCESS_TOKEN,
                  OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME));
      }
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         OAUTHBEARERBindRequest.OAUTHBEARER_MECHANISM_NAME);

    return new OAUTHBEARERBindRequest(accessToken, controls);
  }



  /**
   * Creates a SASL PLAIN bind request using the provided password and set of
   * options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL PLAIN bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static PLAINBindRequest createPLAINBindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                  PLAINBindRequest.PLAIN_MECHANISM_NAME));
      }
    }
    else
    {
      pw = password;
    }

    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                PLAINBindRequest.PLAIN_MECHANISM_NAME));
    }

    // The authzID option is optional.
    final String authzID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTHZ_ID));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         PLAINBindRequest.PLAIN_MECHANISM_NAME);

    return new PLAINBindRequest(authID, authzID, pw, controls);
  }



  /**
   * Creates a SASL SCRAM-SHA-1 bind request using the provided password and
   * set of options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL SCRAM-SHA-1 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static SCRAMSHA1BindRequest createSCRAMSHA1BindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                  SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME));
      }
    }
    else
    {
      pw = password;
    }

    // The username option is required.
    final String username =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_USERNAME));
    if (username == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_USERNAME,
                SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         SCRAMSHA1BindRequest.SCRAM_SHA_1_MECHANISM_NAME);

    return new SCRAMSHA1BindRequest(username, pw, controls);
  }



  /**
   * Creates a SASL SCRAM-SHA-256 bind request using the provided password and
   * set of options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL SCRAM-SHA-256 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static SCRAMSHA256BindRequest createSCRAMSHA256BindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                  SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME));
      }
    }
    else
    {
      pw = password;
    }

    // The username option is required.
    final String username =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_USERNAME));
    if (username == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_USERNAME,
                SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         SCRAMSHA256BindRequest.SCRAM_SHA_256_MECHANISM_NAME);

    return new SCRAMSHA256BindRequest(username, pw, controls);
  }



  /**
   * Creates a SASL SCRAM-SHA-512 bind request using the provided password and
   * set of options.
   *
   * @param  password           The password to use for the bind request.
   * @param  promptForPassword  Indicates whether to interactively prompt for
   *                            the password if one is needed but none was
   *                            provided.
   * @param  tool               The command-line tool whose input and output
   *                            streams should be used when prompting for the
   *                            bind password.  It may be {@code null} only if
   *                            {@code promptForPassword} is {@code false}.
   * @param  options            The set of SASL options for the bind request.
   * @param  controls           The set of controls to include in the request.
   *
   * @return  The SASL SCRAM-SHA-512 bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static SCRAMSHA512BindRequest createSCRAMSHA512BindRequest(
                      @Nullable final byte[] password,
                      final boolean promptForPassword,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      if (promptForPassword)
      {
        tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        tool.getOriginalOut().println();
      }
      else
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MECH_REQUIRES_PASSWORD.get(
                  SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME));
      }
    }
    else
    {
      pw = password;
    }

    // The username option is required.
    final String username =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_USERNAME));
    if (username == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_USERNAME,
                SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME));
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         SCRAMSHA512BindRequest.SCRAM_SHA_512_MECHANISM_NAME);

    return new SCRAMSHA512BindRequest(username, pw, controls);
  }



  /**
   * Creates a SASL UNBOUNDID-CERTIFICATE-PLUS-PASSWORD bind request using the
   * provided set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  tool      The command-line tool whose input and output streams
   *                   should be used when prompting for the bind password.  It
   *                   may be {@code null} only if {@code promptForPassword} is
   *                   {@code false}.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-CERTIFICATE-PLUS-PASSWORD bind request that was
   *          created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static UnboundIDCertificatePlusPasswordBindRequest
                      createUnboundIDCertificatePlusPasswordBindRequest(
                           @Nullable final byte[] password,
                           @Nullable final CommandLineTool tool,
                           @NotNull final Map<String,String> options,
                           @Nullable final Control[] controls)
          throws LDAPException
  {
    final byte[] pw;
    if (password == null)
    {
      tool.getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
      pw = PasswordReader.readPassword();
      tool.getOriginalOut().println();
    }
    else
    {
      pw = password;
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         UnboundIDCertificatePlusPasswordBindRequest.
              UNBOUNDID_CERT_PLUS_PW_MECHANISM_NAME);

    return new UnboundIDCertificatePlusPasswordBindRequest(pw, controls);
  }



  /**
   * Creates a SASL UNBOUNDID-DELIVERED-OTP bind request using the provided
   * password and set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-DELIVERED-OTP bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static UnboundIDDeliveredOTPBindRequest
                      createUNBOUNDIDDeliveredOTPBindRequest(
                           @Nullable final byte[] password,
                           @NotNull final Map<String,String> options,
                           @Nullable final Control... controls)
          throws LDAPException
  {
    if (password != null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MECH_DOESNT_ACCEPT_PASSWORD.get(
                UnboundIDDeliveredOTPBindRequest.
                     UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME));
    }

    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                UnboundIDDeliveredOTPBindRequest.
                     UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME));
    }

    // The OTP option is required.
    final String otp = options.remove(StaticUtils.toLowerCase(SASL_OPTION_OTP));
    if (otp == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_OTP,
                UnboundIDDeliveredOTPBindRequest.
                     UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME));
    }

    // The authzID option is optional.
    final String authzID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTHZ_ID));

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         UnboundIDDeliveredOTPBindRequest.
              UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME);

    return new UnboundIDDeliveredOTPBindRequest(authID, authzID, otp, controls);
  }



  /**
   * Creates a SASL UNBOUNDID-TOTP bind request using the provided password and
   * set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  tool      The command-line tool whose input and output streams
   *                   should be used when prompting for the bind password.  It
   *                   may be {@code null} only if {@code promptForPassword} is
   *                   {@code false}.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-TOTP bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static SingleUseTOTPBindRequest createUNBOUNDIDTOTPBindRequest(
                      @Nullable final byte[] password,
                      @Nullable final CommandLineTool tool,
                      @NotNull final Map<String,String> options,
                      @Nullable final Control... controls)
          throws LDAPException
  {
    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME));
    }

    // The TOTP password option is required.
    final String totpPassword =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_TOTP_PASSWORD));
    if (totpPassword == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_TOTP_PASSWORD,
                UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME));
    }

    // The authzID option is optional.
    byte[] pwBytes = password;
    final String authzID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTHZ_ID));

    // The promptForStaticPassword option is optional.
    final String promptStr = options.remove(StaticUtils.toLowerCase(
         SASL_OPTION_PROMPT_FOR_STATIC_PW));
    if (promptStr != null)
    {
      if (promptStr.equalsIgnoreCase("true"))
      {
        if (pwBytes == null)
        {
          tool.getOriginalOut().print(INFO_SASL_ENTER_STATIC_PW.get());
          pwBytes = PasswordReader.readPassword();
          tool.getOriginalOut().println();
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SASL_PROMPT_FOR_PROVIDED_PW.get(
                    SASL_OPTION_PROMPT_FOR_STATIC_PW));
        }
      }
      else if (! promptStr.equalsIgnoreCase("false"))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_PROMPT_FOR_STATIC_PW_BAD_VALUE.get(
                  SASL_OPTION_PROMPT_FOR_STATIC_PW));
      }
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         UnboundIDTOTPBindRequest.UNBOUNDID_TOTP_MECHANISM_NAME);

    return new SingleUseTOTPBindRequest(authID, authzID, totpPassword, pwBytes,
         controls);
  }



  /**
   * Creates a SASL UNBOUNDID-YUBIKEY-OTP bind request using the provided
   * password and set of options.
   *
   * @param  password  The password to use for the bind request.
   * @param  tool      The command-line tool whose input and output streams
   *                   should be used when prompting for the bind password.  It
   *                   may be {@code null} only if {@code promptForPassword} is
   *                   {@code false}.
   * @param  options   The set of SASL options for the bind request.
   * @param  controls  The set of controls to include in the request.
   *
   * @return  The SASL UNBOUNDID-YUBIKEY-OTP bind request that was created.
   *
   * @throws  LDAPException  If a problem is encountered while trying to create
   *                         the SASL bind request.
   */
  @NotNull()
  private static UnboundIDYubiKeyOTPBindRequest
                      createUNBOUNDIDYUBIKEYOTPBindRequest(
                           @Nullable final byte[] password,
                           @Nullable final CommandLineTool tool,
                           @NotNull final Map<String,String> options,
                           @Nullable final Control... controls)
          throws LDAPException
  {
    // The authID option is required.
    final String authID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTH_ID));
    if (authID == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_AUTH_ID,
                UnboundIDYubiKeyOTPBindRequest.
                     UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME));
    }

    // The otp option is required.
    final String otp = options.remove(StaticUtils.toLowerCase(SASL_OPTION_OTP));
    if (otp == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_MISSING_REQUIRED_OPTION.get(SASL_OPTION_OTP,
                UnboundIDYubiKeyOTPBindRequest.
                     UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME));
    }

    // The authzID option is optional.
    final String authzID =
         options.remove(StaticUtils.toLowerCase(SASL_OPTION_AUTHZ_ID));

    // The promptForStaticPassword option is optional.
    byte[] pwBytes = password;
    final String promptStr = options.remove(StaticUtils.toLowerCase(
         SASL_OPTION_PROMPT_FOR_STATIC_PW));
    if (promptStr != null)
    {
      if (promptStr.equalsIgnoreCase("true"))
      {
        if (pwBytes == null)
        {
          tool.getOriginalOut().print(INFO_SASL_ENTER_STATIC_PW.get());
          pwBytes = PasswordReader.readPassword();
          tool.getOriginalOut().println();
        }
        else
        {
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_SASL_PROMPT_FOR_PROVIDED_PW.get(
                    SASL_OPTION_PROMPT_FOR_STATIC_PW));
        }
      }
      else if (! promptStr.equalsIgnoreCase("false"))
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_PROMPT_FOR_STATIC_PW_BAD_VALUE.get(
                  SASL_OPTION_PROMPT_FOR_STATIC_PW));
      }
    }

    // Ensure no unsupported options were provided.
    ensureNoUnsupportedOptions(options,
         UnboundIDYubiKeyOTPBindRequest.UNBOUNDID_YUBIKEY_OTP_MECHANISM_NAME);

    return new UnboundIDYubiKeyOTPBindRequest(authID, authzID, pwBytes, otp,
         controls);
  }



  /**
   * Parses the provided list of SASL options.
   *
   * @param  options  The list of options to be parsed.
   *
   * @return  A map with the parsed set of options.
   *
   * @throws  LDAPException  If a problem is encountered while parsing options.
   */
  @NotNull()
  private static Map<String,String>
                      parseOptions(@Nullable final List<String> options)
          throws LDAPException
  {
    if (options == null)
    {
      return new HashMap<>(0);
    }

    final HashMap<String,String> m =
         new HashMap<>(StaticUtils.computeMapCapacity(options.size()));
    for (final String s : options)
    {
      final int equalPos = s.indexOf('=');
      if (equalPos < 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_MISSING_EQUAL.get(s));
      }
      else if (equalPos == 0)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_STARTS_WITH_EQUAL.get(s));
      }

      final String name = s.substring(0, equalPos);
      final String value = s.substring(equalPos + 1);
      if (m.put(StaticUtils.toLowerCase(name), value) != null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_NOT_MULTI_VALUED.get(name));
      }
    }

    return m;
  }



  /**
   * Ensures that the provided map is empty, and will throw an exception if it
   * isn't.  This method is intended for internal use only.
   *
   * @param  options    The map of options to ensure is empty.
   * @param  mechanism  The associated SASL mechanism.
   *
   * @throws  LDAPException  If the map of SASL options is not empty.
   */
  @InternalUseOnly()
  public static void ensureNoUnsupportedOptions(
                          @NotNull final Map<String,String> options,
                          @NotNull final String mechanism)
          throws LDAPException
  {
    if (! options.isEmpty())
    {
      for (final String s : options.keySet())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SASL_OPTION_UNSUPPORTED_FOR_MECH.get(s,mechanism));
      }
    }
  }



  /**
   * Retrieves the value of the specified option and parses it as a boolean.
   * Values of "true", "t", "yes", "y", "on", and "1" will be treated as
   * {@code true}.  Values of "false", "f", "no", "n", "off", and "0" will be
   * treated as {@code false}.
   *
   * @param  m  The map from which to retrieve the option.  It must not be
   *            {@code null}.
   * @param  o  The name of the option to examine.
   * @param  d  The default value to use if the given option was not provided.
   *
   * @return  The parsed boolean value.
   *
   * @throws  LDAPException  If the option value cannot be parsed as a boolean.
   */
  static boolean getBooleanValue(@NotNull final Map<String,String> m,
                                 @NotNull final String o, final boolean d)
         throws LDAPException
  {
    final String s =
         StaticUtils.toLowerCase(m.remove(StaticUtils.toLowerCase(o)));
    if (s == null)
    {
      return d;
    }
    else if (s.equals("true") ||
             s.equals("t") ||
             s.equals("yes") ||
             s.equals("y") ||
             s.equals("on") ||
             s.equals("1"))
    {
      return true;
    }
    else if (s.equals("false") ||
             s.equals("f") ||
             s.equals("no") ||
             s.equals("n") ||
             s.equals("off") ||
             s.equals("0"))
    {
      return false;
    }
    else
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_SASL_OPTION_MALFORMED_BOOLEAN_VALUE.get(o));
    }
  }



  /**
   * Retrieves a string representation of the SASL usage information.  This will
   * include the supported SASL mechanisms and the properties that may be used
   * with each.
   *
   * @param  maxWidth  The maximum line width to use for the output.  If this is
   *                   less than or equal to zero, then no wrapping will be
   *                   performed.
   *
   * @return  A string representation of the usage information.
   */
  @NotNull()
  public static String getUsageString(final int maxWidth)
  {
    return getUsageString(null, maxWidth);
  }



  /**
   * Retrieves a string representation of the SASL usage information.  This will
   * include the supported SASL mechanisms and the properties that may be used
   * with each.
   *
   * @param  mechanism  The name of the SASL mechanism for which to obtain usage
   *                    information  It may be {@code null} if usage should be
   *                    displayed for all available mechamisms.
   * @param  maxWidth   The maximum line width to use for the output.  If this
   *                    is less than or equal to zero, then no wrapping will be
   *                    performed.
   *
   * @return  A string representation of the usage information.
   */
  @NotNull()
  public static String getUsageString(@Nullable final String mechanism,
                                      final int maxWidth)
  {
    final StringBuilder buffer = new StringBuilder();

    for (final String line : getUsage(mechanism, maxWidth))
    {
      buffer.append(line);
      buffer.append(StaticUtils.EOL);
    }

    return buffer.toString();
  }



  /**
   * Retrieves lines that make up the SASL usage information, optionally
   * wrapping long lines.
   *
   * @param  maxWidth  The maximum line width to use for the output.  If this is
   *                   less than or equal to zero, then no wrapping will be
   *                   performed.
   *
   * @return  The lines that make up the SASL usage information.
   */
  @NotNull()
  public static List<String> getUsage(final int maxWidth)
  {
    return getUsage(null, maxWidth);
  }



  /**
   * Retrieves lines that make up the SASL usage information, optionally
   * wrapping long lines.
   *
   * @param  mechanism  The name of the SASL mechanism for which to obtain usage
   *                    information  It may be {@code null} if usage should be
   *                    displayed for all available mechamisms.
   * @param  maxWidth   The maximum line width to use for the output.  If this
   *                    is less than or equal to zero, then no wrapping will be
   *                    performed.
   *
   * @return  The lines that make up the SASL usage information.
   */
  @NotNull()
  public static List<String> getUsage(@Nullable final String mechanism,
                                      final int maxWidth)
  {
    final ArrayList<String> lines = new ArrayList<>(100);

    boolean first = true;
    for (final SASLMechanismInfo i : getSupportedSASLMechanisms())
    {
      if ((mechanism != null) && (! i.getName().equalsIgnoreCase(mechanism)))
      {
        continue;
      }

      if (first)
      {
        first = false;
      }
      else
      {
        lines.add("");
        lines.add("");
      }

      lines.addAll(
           StaticUtils.wrapLine(INFO_SASL_HELP_MECHANISM.get(i.getName()),
                maxWidth));
      lines.add("");

      for (final String line :
           StaticUtils.wrapLine(i.getDescription(), maxWidth - 4))
      {
        lines.add("  " + line);
      }
      lines.add("");

      for (final String line :
           StaticUtils.wrapLine(INFO_SASL_HELP_MECHANISM_OPTIONS.get(
                i.getName()), maxWidth - 4))
      {
        lines.add("  " + line);
      }

      if (i.acceptsPassword())
      {
        lines.add("");
        if (i.requiresPassword())
        {
          for (final String line :
               StaticUtils.wrapLine(INFO_SASL_HELP_PASSWORD_REQUIRED.get(
                    i.getName()), maxWidth - 4))
          {
            lines.add("  " + line);
          }
        }
        else
        {
          for (final String line :
               StaticUtils.wrapLine(INFO_SASL_HELP_PASSWORD_OPTIONAL.get(
                    i.getName()), maxWidth - 4))
          {
            lines.add("  " + line);
          }
        }
      }

      for (final SASLOption o : i.getOptions())
      {
        lines.add("");
        lines.add("  * " + o.getName());
        for (final String line :
             StaticUtils.wrapLine(o.getDescription(), maxWidth - 14))
        {
          lines.add("       " + line);
        }
      }
    }

    if ((mechanism != null) && lines.isEmpty())
    {
      return getUsage(null, maxWidth);
    }


    return lines;
  }
}
