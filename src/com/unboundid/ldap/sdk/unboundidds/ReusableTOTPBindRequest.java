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
package com.unboundid.ldap.sdk.unboundidds;



import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ToCodeArgHelper;
import com.unboundid.ldap.sdk.ToCodeHelper;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of the UNBOUNDID-TOTP SASL bind request
 * that may be used to repeatedly generate one-time password values.  Because it
 * is configured with the shared secret rather than a point-in-time version of
 * the password, it can be used for cases in which the authentication process
 * may need to be repeated (e.g., for use in a connection pool, following
 * referrals, or if the auto-reconnect feature is enabled).  If the shared
 * secret is not known and the one-time password will be provided from an
 * external source (e.g., entered by a user), then the
 * {@link SingleUseTOTPBindRequest} variant should be used instead.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ReusableTOTPBindRequest
       extends UnboundIDTOTPBindRequest
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8283436883838802510L;



  // The shared secret key to use when generating the TOTP password.
  @NotNull private final byte[] sharedSecret;

  // The duration (in seconds) of the time interval to use when generating the
  // TOTP password.
  private final int totpIntervalDurationSeconds;

  // The number of digits to include in the generated TOTP password.
  private final int totpNumDigits;



  /**
   * Creates a new SASL TOTP bind request with the provided information.
   *
   * @param  authenticationID  The authentication identity for the bind request.
   *                           It must not be {@code null}, and must be in the
   *                           form "u:" followed by a username, or "dn:"
   *                           followed by a DN.
   * @param  authorizationID   The authorization identity for the bind request.
   *                           It may be {@code null} if the authorization
   *                           identity should be the same as the authentication
   *                           identity.  If an authorization identity is
   *                           specified, it must be in the form "u:" followed
   *                           by a username, or "dn:" followed by a DN.  The
   *                           value "dn:" may indicate an authorization
   *                           identity of the anonymous user.
   * @param  sharedSecret      The shared secret key to use when generating the
   *                           TOTP password.
   * @param  staticPassword    The static password for the target user.  It may
   *                           be {@code null} if only the one-time password is
   *                           to be used for authentication (which may or may
   *                           not be allowed by the server).
   * @param  controls          The set of controls to include in the bind
   *                           request.
   */
  public ReusableTOTPBindRequest(@NotNull final String authenticationID,
                                 @Nullable final String authorizationID,
                                 @NotNull final byte[] sharedSecret,
                                 @Nullable final String staticPassword,
                                 @Nullable final Control... controls)
  {
    this(authenticationID, authorizationID, sharedSecret, staticPassword,
         OneTimePassword.DEFAULT_TOTP_INTERVAL_DURATION_SECONDS,
         OneTimePassword.DEFAULT_TOTP_NUM_DIGITS, controls);
  }



  /**
   * Creates a new SASL TOTP bind request with the provided information.
   *
   * @param  authenticationID  The authentication identity for the bind request.
   *                           It must not be {@code null}, and must be in the
   *                           form "u:" followed by a username, or "dn:"
   *                           followed by a DN.
   * @param  authorizationID   The authorization identity for the bind request.
   *                           It may be {@code null} if the authorization
   *                           identity should be the same as the authentication
   *                           identity.  If an authorization identity is
   *                           specified, it must be in the form "u:" followed
   *                           by a username, or "dn:" followed by a DN.  The
   *                           value "dn:" may indicate an authorization
   *                           identity of the anonymous user.
   * @param  sharedSecret      The shared secret key to use when generating the
   *                           TOTP password.
   * @param  staticPassword    The static password for the target user.  It may
   *                           be {@code null} if only the one-time password is
   *                           to be used for authentication (which may or may
   *                           not be allowed by the server).
   * @param  controls          The set of controls to include in the bind
   *                           request.
   */
  public ReusableTOTPBindRequest(@NotNull final String authenticationID,
                                 @Nullable final String authorizationID,
                                 @NotNull final byte[] sharedSecret,
                                 @Nullable final byte[] staticPassword,
                                 @Nullable final Control... controls)
  {
    this(authenticationID, authorizationID, sharedSecret, staticPassword,
         OneTimePassword.DEFAULT_TOTP_INTERVAL_DURATION_SECONDS,
         OneTimePassword.DEFAULT_TOTP_NUM_DIGITS, controls);
  }



  /**
   * Creates a new SASL TOTP bind request with the provided information.
   *
   * @param  authenticationID             The authentication identity for the
   *                                      bind request.  It must not be
   *                                      {@code null}, and must be in the form
   *                                      "u:" followed by a username, or "dn:"
   *                                      followed by a DN.
   * @param  authorizationID              The authorization identity for the
   *                                      bind request.  It may be {@code null}
   *                                      if the authorization identity should
   *                                      be the same as the authentication
   *                                      identity.  If an authorization
   *                                      identity is specified, it must be in
   *                                      the form "u:" followed by a username,
   *                                      or "dn:" followed by a DN.  The value
   *                                      "dn:" may indicate an authorization
   *                                      identity of the anonymous user.
   * @param  sharedSecret                 The shared secret key to use when
   *                                      generating the TOTP password.
   * @param  staticPassword               The static password for the target
   *                                      user.  It may be {@code null} if only
   *                                      the one-time password is to be used
   *                                      for authentication (which may or may
   *                                      not be allowed by the server).
   * @param  totpIntervalDurationSeconds  The duration (in seconds) of the time
   *                                      interval to use for TOTP processing.
   *                                      It must be greater than zero.
   * @param  totpNumDigits                The number of digits to include in the
   *                                      generated TOTP password.  It must be
   *                                      greater than or equal to six and less
   *                                      than or equal to eight.
   * @param  controls                     The set of controls to include in the
   *                                      bind request.
   */
  public ReusableTOTPBindRequest(@NotNull final String authenticationID,
                                 @Nullable final String authorizationID,
                                 @NotNull final byte[] sharedSecret,
                                 @Nullable final String staticPassword,
                                 final int totpIntervalDurationSeconds,
                                 final int totpNumDigits,
                                 @Nullable final Control... controls)
  {
    super(authenticationID, authorizationID, staticPassword, controls);

    Validator.ensureTrue(totpIntervalDurationSeconds > 0);
    Validator.ensureTrue((totpNumDigits >= 6) && (totpNumDigits <= 8));

    this.sharedSecret                = sharedSecret;
    this.totpIntervalDurationSeconds = totpIntervalDurationSeconds;
    this.totpNumDigits               = totpNumDigits;
  }



  /**
   * Creates a new SASL TOTP bind request with the provided information.
   *
   * @param  authenticationID             The authentication identity for the
   *                                      bind request.  It must not be
   *                                      {@code null}, and must be in the form
   *                                      "u:" followed by a username, or "dn:"
   *                                      followed by a DN.
   * @param  authorizationID              The authorization identity for the
   *                                      bind request.  It may be {@code null}
   *                                      if the authorization identity should
   *                                      be the same as the authentication
   *                                      identity.  If an authorization
   *                                      identity is specified, it must be in
   *                                      the form "u:" followed by a username,
   *                                      or "dn:" followed by a DN.  The value
   *                                      "dn:" may indicate an authorization
   *                                      identity of the anonymous user.
   * @param  sharedSecret                 The shared secret key to use when
   *                                      generating the TOTP password.
   * @param  staticPassword               The static password for the target
   *                                      user.  It may be {@code null} if only
   *                                      the one-time password is to be used
   *                                      for authentication (which may or may
   *                                      not be allowed by the server).
   * @param  totpIntervalDurationSeconds  The duration (in seconds) of the time
   *                                      interval to use for TOTP processing.
   *                                      It must be greater than zero.
   * @param  totpNumDigits                The number of digits to include in the
   *                                      generated TOTP password.  It must be
   *                                      greater than or equal to six and less
   *                                      than or equal to eight.
   * @param  controls                     The set of controls to include in the
   *                                      bind request.
   */
  public ReusableTOTPBindRequest(@NotNull final String authenticationID,
                                 @Nullable final String authorizationID,
                                 @NotNull final byte[] sharedSecret,
                                 @Nullable final byte[] staticPassword,
                                 final int totpIntervalDurationSeconds,
                                 final int totpNumDigits,
                                 @Nullable final Control... controls)
  {
    super(authenticationID, authorizationID, staticPassword, controls);

    Validator.ensureTrue(totpIntervalDurationSeconds > 0);
    Validator.ensureTrue((totpNumDigits >= 6) && (totpNumDigits <= 8));

    this.sharedSecret                = sharedSecret;
    this.totpIntervalDurationSeconds = totpIntervalDurationSeconds;
    this.totpNumDigits               = totpNumDigits;
  }



  /**
   * Creates a new SASL TOTP bind request with the provided information.
   *
   * @param  authenticationID             The authentication identity for the
   *                                      bind request.  It must not be
   *                                      {@code null}, and must be in the form
   *                                      "u:" followed by a username, or "dn:"
   *                                      followed by a DN.
   * @param  authorizationID              The authorization identity for the
   *                                      bind request.  It may be {@code null}
   *                                      if the authorization identity should
   *                                      be the same as the authentication
   *                                      identity.  If an authorization
   *                                      identity is specified, it must be in
   *                                      the form "u:" followed by a username,
   *                                      or "dn:" followed by a DN.  The value
   *                                      "dn:" may indicate an authorization
   *                                      identity of the anonymous user.
   * @param  sharedSecret                 The shared secret key to use when
   *                                      generating the TOTP password.
   * @param  staticPassword               The static password for the target
   *                                      user.  It may be {@code null} if only
   *                                      the one-time password is to be used
   *                                      for authentication (which may or may
   *                                      not be allowed by the server).
   * @param  totpIntervalDurationSeconds  The duration (in seconds) of the time
   *                                      interval to use when generating the
   *                                      TOTP password.  It must be greater
   *                                      than zero.
   * @param  totpNumDigits                The number of digits to include in the
   *                                      generated TOTP password.  It must be
   *                                      greater than or equal to six and less
   *                                      than or equal to eight.
   * @param  controls                     The set of controls to include in the
   *                                      bind request.
   */
  private ReusableTOTPBindRequest(@NotNull final String authenticationID,
               @Nullable final String authorizationID,
               @NotNull final byte[] sharedSecret,
               @Nullable final ASN1OctetString staticPassword,
               final int totpIntervalDurationSeconds,
               final int totpNumDigits,
               @Nullable final Control... controls)
  {
    super(authenticationID, authorizationID, staticPassword, controls);

    this.sharedSecret                = sharedSecret;
    this.totpIntervalDurationSeconds = totpIntervalDurationSeconds;
    this.totpNumDigits               = totpNumDigits;
  }



  /**
   * Retrieves the shared secret key to use when generating the TOTP password.
   *
   * @return  The shared secret key to use when generating the TOTP password.
   */
  @NotNull()
  public byte[] getSharedSecret()
  {
    return sharedSecret;
  }



  /**
   * Retrieves the duration (in seconds) of the time interval to use when
   * generating the TOTP password.
   *
   * @return  The duration (in seconds) of the time interval to use when
   *          generating the TOTP password.
   */
  public int getTOTPIntervalDurationSeconds()
  {
    return totpIntervalDurationSeconds;
  }



  /**
   * Retrieves the number of digits to include in the generated TOTP password.
   *
   * @return  The number of digits to include in the generated TOTP password.
   */
  public int getTOTPNumDigits()
  {
    return totpNumDigits;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected ASN1OctetString getSASLCredentials()
            throws LDAPException
  {
    // Generate the TOTP password.
    final String totpPassword = OneTimePassword.totp(sharedSecret,
         System.currentTimeMillis(), totpIntervalDurationSeconds,
         totpNumDigits);

    return encodeCredentials(getAuthenticationID(), getAuthorizationID(),
         totpPassword, getStaticPassword());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReusableTOTPBindRequest getRebindRequest(@NotNull final String host,
                                                  final int port)
  {
    return duplicate();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReusableTOTPBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ReusableTOTPBindRequest duplicate(@Nullable final Control[] controls)
  {
    final ReusableTOTPBindRequest bindRequest =
         new ReusableTOTPBindRequest(getAuthenticationID(),
              getAuthorizationID(), sharedSecret, getStaticPassword(),
              totpIntervalDurationSeconds, totpNumDigits, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(7);
    constructorArgs.add(ToCodeArgHelper.createString(getAuthenticationID(),
         "Authentication ID"));
    constructorArgs.add(ToCodeArgHelper.createString(getAuthorizationID(),
         "Authorization ID"));
    constructorArgs.add(ToCodeArgHelper.createByteArray(
         "---redacted-secret---".getBytes(StandardCharsets.UTF_8), true,
         "Shared Secret"));
    constructorArgs.add(ToCodeArgHelper.createString(
         ((getStaticPassword() == null) ? "null" : "---redacted-password---"),
         "Static Password"));
    constructorArgs.add(ToCodeArgHelper.createInteger(
         totpIntervalDurationSeconds, "Interval Duration (seconds)"));
    constructorArgs.add(ToCodeArgHelper.createInteger(totpNumDigits,
         "Number of TOTP Digits"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "ReusableTOTPBindRequest", requestID + "Request",
         "new ReusableTOTPBindRequest", constructorArgs);


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The bind failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  // Note that the connection is now likely in " +
           "an unauthenticated state.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
