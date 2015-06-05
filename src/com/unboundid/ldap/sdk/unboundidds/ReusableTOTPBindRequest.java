/*
 * Copyright 2012-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides an implementation of the UNBOUNDID-TOTP SASL bind request
 * that may be used to repeatedly generate one-time password values.  Because it
 * is configured with the shared secret rather than a point-in-time version of
 * the password, it can be used for cases in which the authentication process
 * may need to be repeated (e.g., for use in a connection pool, following
 * referrals, or if the auto-reconnect feature is enabled).  If the shared
 * secret is not known and the one-time password will be provided from an
 * external source (e.g., entered by a user), then the
 * {@link SingleUseTOTPBindRequest} variant should be used instead.
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
  private final byte[] sharedSecret;

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
  public ReusableTOTPBindRequest(final String authenticationID,
                                 final String authorizationID,
                                 final byte[] sharedSecret,
                                 final String staticPassword,
                                 final Control... controls)
  {
    this(authenticationID, authorizationID, sharedSecret, staticPassword,
         OneTimePassword.DEFAULT_TOTP_INTERVAL_DURATION_SECONDS,
         OneTimePassword.DEFAULT_TOTP_NUM_DIGITS);
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
  public ReusableTOTPBindRequest(final String authenticationID,
                                 final String authorizationID,
                                 final byte[] sharedSecret,
                                 final byte[] staticPassword,
                                 final Control... controls)
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
  public ReusableTOTPBindRequest(final String authenticationID,
                                 final String authorizationID,
                                 final byte[] sharedSecret,
                                 final String staticPassword,
                                 final int totpIntervalDurationSeconds,
                                 final int totpNumDigits,
                                 final Control... controls)
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
  public ReusableTOTPBindRequest(final String authenticationID,
                                 final String authorizationID,
                                 final byte[] sharedSecret,
                                 final byte[] staticPassword,
                                 final int totpIntervalDurationSeconds,
                                 final int totpNumDigits,
                                 final Control... controls)
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
  private ReusableTOTPBindRequest(final String authenticationID,
                                  final String authorizationID,
                                  final byte[] sharedSecret,
                                  final ASN1OctetString staticPassword,
                                  final int totpIntervalDurationSeconds,
                                  final int totpNumDigits,
                                  final Control... controls)
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
  public ReusableTOTPBindRequest getRebindRequest(final String host,
                                                  final int port)
  {
    return duplicate();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReusableTOTPBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ReusableTOTPBindRequest duplicate(final Control[] controls)
  {
    final ReusableTOTPBindRequest bindRequest =
         new ReusableTOTPBindRequest(getAuthenticationID(),
              getAuthorizationID(), sharedSecret, getStaticPassword(),
              totpIntervalDurationSeconds, totpNumDigits, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }
}
