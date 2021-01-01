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



import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;



/**
 * This enum defines the set of fields that are supported for use with the
 * {@link PasswordPolicyStateJSON} object.
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
public enum PasswordPolicyStateJSONField
{
  /**
   * The field (password-policy-dn) used to hold the DN of the user's password
   * policy.
   */
  PASSWORD_POLICY_DN("password-policy-dn"),



  /**
   * The field (account-is-usable) used to indicate whether the user's account
   * is considered usable.
   */
  ACCOUNT_IS_USABLE("account-is-usable"),



  /**
   * The field (account-usability-errors) used to hold information about any
   * account usability errors.
   */
  ACCOUNT_USABILITY_ERRORS("account-usability-errors"),



  /**
   * The field (account-usability-warnings) used to hold information about any
   * account usability warnings.
   */
  ACCOUNT_USABILITY_WARNINGS("account-usability-warnings"),



  /**
   * The field (account-usability-notices) used to hold information about any
   * account usability notices.
   */
  ACCOUNT_USABILITY_NOTICES("account-usability-notices"),



  /**
   * The field (has-static-password) used to indicate whether the user has a
   * static password.
   */
  HAS_STATIC_PASSWORD("has-static-password"),



  /**
   * The field (password-changed-time) used to hold the time the user's password
   * was last changed.
   */
  PASSWORD_CHANGED_TIME("password-changed-time"),



  /**
   * The field (seconds-since-password-change) used to hold the length of time
   * in seconds since the user's password was last changed.
   */
  SECONDS_SINCE_PASSWORD_CHANGE("seconds-since-password-change"),



  /**
   * The field (account-is-disabled) used to indicate whether the user's account
   * has been administratively disabled.
   */
  ACCOUNT_IS_DISABLED("account-is-disabled"),



  /**
   * The field (account-is-not-yet-active) used to indicate whether the user's
   * account is not yet active.
   */
  ACCOUNT_IS_NOT_YET_ACTIVE(
       "account-is-not-yet-active"),



  /**
   * The field (account-activation-time) used to hold the time that the user's
   * account will become active.
   */
  ACCOUNT_ACTIVATION_TIME("account-activation-time"),



  /**
   * The field (seconds-until-account-activation) used to hold the length of
   * time in seconds until the user's account will become active.
   */
  SECONDS_UNTIL_ACCOUNT_ACTIVATION("seconds-until-account-activation"),



  /**
   * The field (seconds-since-account-activation) used to hold the length of
   * time in seconds since the user's account became active.
   */
  SECONDS_SINCE_ACCOUNT_ACTIVATION("seconds-since-account-activation"),



  /**
   * The field (account-is-expired) used to indicate whether the user's account
   * is expired.
   */
  ACCOUNT_IS_EXPIRED("account-is-expired"),



  /**
   * The field (account-expiration-time) used to hold the time that the user's
   * account will expire.
   */
  ACCOUNT_EXPIRATION_TIME("account-expiration-time"),



  /**
   * The field (seconds-until-account-expiration) used to hold the length of
   * time in seconds until the user's account will expire.
   */
  SECONDS_UNTIL_ACCOUNT_EXPIRATION("seconds-until-account-expiration"),



  /**
   * The field (seconds-since-account-expiration) used to hold the length of
   * time in seconds since the user's account expired.
   */
  SECONDS_SINCE_ACCOUNT_EXPIRATION("seconds-since-account-expiration"),



  /**
   * The field (password-is-expired) used to indicate whether the user's
   * password is expired.
   */
  PASSWORD_IS_EXPIRED("password-is-expired"),



  /**
   * The field (maximum-password-age-seconds) used to hold the maximum length of
   * time in seconds that the user can keep the same password before it expires.
   */
  MAXIMUM_PASSWORD_AGE_SECONDS("maximum-password-age-seconds"),



  /**
   * The field (password-expiration-time) used to hold the time the user's
   * password will (or did) expire.
   */
  PASSWORD_EXPIRATION_TIME("password-expiration-time"),



  /**
   * The field (seconds-until-password-expiration) used to hold the length of
   * time in seconds until the user's password will expire.
   */
  SECONDS_UNTIL_PASSWORD_EXPIRATION("seconds-until-password-expiration"),



  /**
   * The field (seconds-since-password-expiration) used to hold the length of
   * time in seconds since the user's password expired.
   */
  SECONDS_SINCE_PASSWORD_EXPIRATION("seconds-since-password-expiration"),



  /**
   * The field (password-expiration-warning-interval-seconds) used to hold the
   * length of time before the user's password expires that they will be
   * eligible to receive a warning about the upcoming expiration.
   */
  PASSWORD_EXPIRATION_WARNING_INTERVAL_SECONDS(
       "password-expiration-warning-interval-seconds"),



  /**
   * The field (expire-passwords-without-warning) used to indicate whether the
   * server may expire a user's password with issuing at least warning about the
   * upcoming expiration.
   */
  EXPIRE_PASSWORDS_WITHOUT_WARNING("expire-passwords-without-warning"),



  /**
   * The field (password-expiration-warning-issued) used to indicate whether the
   * user has been warned about an upcoming password expiration.
   */
  PASSWORD_EXPIRATION_WARNING_ISSUED("password-expiration-warning-issued"),



  /**
   * The field (password-expiration-warning-time) used to hold the time that the
   * user will be eligible to receive (or first received) a warning about an
   * upcoming password expiration.
   */
  PASSWORD_EXPIRATION_WARNING_TIME("password-expiration-warning-time"),



  /**
   * The field (seconds-until-password-expiration-warning) used to hold the
   * length of time in seconds until the user is eligible to be warned about an
   * upcoming password expiration.
   */
  SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING(
       "seconds-until-password-expiration-warning"),



  /**
   * The field (seconds-since-password-expiration-warning) used to hold the
   * length of time in seconds since the user was first warned about an upcoming
   * password expiration.
   */
  SECONDS_SINCE_PASSWORD_EXPIRATION_WARNING(
       "seconds-since-password-expiration-warning"),



  /**
   * The field (account-is-failure-locked) used to indicate whether the user's
   * account is currently locked as a result of too many failed authentication
   * attempts.
   */
  ACCOUNT_IS_FAILURE_LOCKED("account-is-failure-locked"),



  /**
   * The field (failure-lockout-count) used to hold the number of failed
   * authentication attempts required to lock an account.
   */
  FAILURE_LOCKOUT_COUNT("failure-lockout-count"),



  /**
   * The field (current-authentication-failure-count) used to hold the user's
   * current authentication failure count.
   */
  CURRENT_AUTHENTICATION_FAILURE_COUNT("current-authentication-failure-count"),



  /**
   * The field (remaining-authentication-failure-count) used to hold the
   * remaining number of failed authentication attempts before the user's
   * account will be locked.
   */
  REMAINING_AUTHENTICATION_FAILURE_COUNT(
       "remaining-authentication-failure-count"),



  /**
   * The field (authentication-failure-times) used to hold the times of the
   * outstanding failed authentication attempts.
   */
  AUTHENTICATION_FAILURE_TIMES("authentication-failure-times"),



  /**
   * The field (failure-lockout-time) used to hold the time the user's account
   * was locked as a result of too many failed authentication attempts.
   */
  FAILURE_LOCKOUT_TIME("failure-lockout-time"),



  /**
   * The field (failure-lockout-duration-seconds) used to hold the length of
   * time in seconds that an account will remain locked as a result of too many
   * failed authentication attempts.
   */
  FAILURE_LOCKOUT_DURATION_SECONDS("failure-lockout-duration-seconds"),



  /**
   * The field (failure-lockout-expiration-time) used to hold the time the
   * user's failure-locked account will be automatically unlocked.
   */
  FAILURE_LOCKOUT_EXPIRATION_TIME("failure-lockout-expiration-time"),



  /**
   * The field (seconds-remaining-in-failure-lockout) used to hold the length of
   * time in seconds until the user's failure-locked account will remain locked.
   */
  SECONDS_REMAINING_IN_FAILURE_LOCKOUT("seconds-remaining-in-failure-lockout"),



  /**
   * The field (last-login-time) used to hold the time the user last
   * authenticated to the server.
   */
  LAST_LOGIN_TIME("last-login-time"),



  /**
   * The field (seconds-since-last-login) used to hold the length of time in
   * seconds that has passed since the user last authenticated.
   */
  SECONDS_SINCE_LAST_LOGIN("seconds-since-last-login"),



  /**
   * The field (last-login-ip-address) used to hold the IP address of the client
   * from which the user last authenticated.
   */
  LAST_LOGIN_IP_ADDRESS("last-login-ip-address"),



  /**
   * The field (account-is-idle-locked) used to indicate whether the user's
   * account is currently locked because it has been too long since they
   * authenticated.
   */
  ACCOUNT_IS_IDLE_LOCKED("account-is-idle-locked"),



  /**
   * The field (idle-lockout-interval-seconds) used to hold the maximum length
   * of time in seconds that may pass between successful authentications before
   * the user's account will be locked.
   */
  IDLE_LOCKOUT_INTERVAL_SECONDS("idle-lockout-interval-seconds"),



  /**
   * The field (idle-lockout-time) used to hold the time that the user's account
   * will be (or was) locked for allowing too much time to pass between
   * successful authentications.
   */
  IDLE_LOCKOUT_TIME("idle-lockout-time"),



  /**
   * The field (seconds-until-idle-lockout) used to hold the length of time in
   * seconds until the user's account will be locked for allowing too much time
   * to pass between successful authentications.
   */
  SECONDS_UNTIL_IDLE_LOCKOUT("seconds-until-idle-lockout"),



  /**
   * The field (seconds-since-idle-lockout) used to hold the length of time in
   * seconds since the user's account was locked for allowing too much time to
   * pass between successful authentications.
   */
  SECONDS_SINCE_IDLE_LOCKOUT("seconds-since-idle-lockout"),



  /**
   * The field (must-change-password) used to indicate whether the user must
   * change their password before they will be permitted to request any other
   * operations in the server.
   */
  MUST_CHANGE_PASSWORD("must-change-password"),



  /**
   * The field (account-is-reset-locked) used to indicate whether the user's
   * account is currently locked because they failed to choose a new password in
   * a timely manner after an administrative reset.
   */
  ACCOUNT_IS_RESET_LOCKED("account-is-reset-locked"),



  /**
   * The field (force-change-on-add) used to indicate whether the user's
   * password policy requires them to choose a new password the first time they
   * authenticate after their account is created.
   */
  FORCE_CHANGE_ON_ADD("force-change-on-add"),



  /**
   * The field (force-change-on-reset) used to indicate whether the user's
   * password policy requires them to choose a new password the first time they
   * authenticate after their password is reset by an administrator.
   */
  FORCE_CHANGE_ON_RESET("force-change-on-reset"),



  /**
   * The field (maximum-password-reset-age-seconds) used to hold the maximum
   * length of time in seconds that the user has to choose a new password after
   * their account has been reset by an administrator before it will be locked.
   */
  MAXIMUM_PASSWORD_RESET_AGE_SECONDS("maximum-password-reset-age-seconds"),



  /**
   * The field (reset-lockout-time) used to hold the time at which the user's
   * account will be locked if they do not choose a new password following an
   * administrative reset.
   */
  RESET_LOCKOUT_TIME("reset-lockout-time"),



  /**
   * The field (seconds-until-reset-lockout) used to hold the length of time in
   * seconds until the user's account will be locked if they do not choose a new
   * password following an administrative reset.
   */
  SECONDS_UNTIL_RESET_LOCKOUT("seconds-until-reset-lockout"),



  /**
   * The field (maximum-password-history-count) used to hold the maximum number
   * of passwords that the server will retain in the password history.
   */
  MAXIMUM_PASSWORD_HISTORY_COUNT("maximum-password-history-count"),



  /**
   * The field (maximum-password-history-duration-seconds) used to hold the
   * maximum length of time in seconds that the server will retain passwords in
   * the password history.
   */
  MAXIMUM_PASSWORD_HISTORY_DURATION_SECONDS(
       "maximum-password-history-duration-seconds"),



  /**
   * The field (current-password-history-count) used to hold the number of
   * passwords currently held in the user's password history.
   */
  CURRENT_PASSWORD_HISTORY_COUNT("current-password-history-count"),



  /**
   * The field (is-within-minimum-password-age) used to indicate whether the
   * user is not permitted to change their password because they are within the
   * minimum password age.
   */
  IS_WITHIN_MINIMUM_PASSWORD_AGE("is-within-minimum-password-age"),



  /**
   * The field (minimum-password-age-seconds) used to hold the minimum length of
   * time in seconds that must pass between the time a user changes their
   * password and the time they will be allowed to change it again.
   */
  MINIMUM_PASSWORD_AGE_SECONDS("minimum-password-age-seconds"),



  /**
   * The field (minimum-password-age-expiration-time) used to hold the earliest
   * time that the user will be permitted to change their password following an
   * earlier password change.
   */
  MINIMUM_PASSWORD_AGE_EXPIRATION_TIME("minimum-password-age-expiration-time"),



  /**
   * The field (seconds-remaining-in-minimum-password-age) used to hold the
   * length of time in seconds that must pass before the user will be allowed to
   * change their password following an earlier password change.
   */
  SECONDS_REMAINING_IN_MINIMUM_PASSWORD_AGE(
       "seconds-remaining-in-minimum-password-age"),



  /**
   * The field (maximum-grace-login-count) used to hold the maximum number of
   * grace login attempts that a user may have to change their password after it
   * has expired.
   */
  MAXIMUM_GRACE_LOGIN_COUNT("maximum-grace-login-count"),



  /**
   * The field (used-grace-login-count) used to hold the number of grace logins
   * that the user has currently used.
   */
  USED_GRACE_LOGIN_COUNT("used-grace-login-count"),



  /**
   * The field (remaining-grace-login-count) used to hold the number of
   * remaining grace logins that the user has.
   */
  REMAINING_GRACE_LOGIN_COUNT("remaining-grace-login-count"),



  /**
   * The field (grace-login-use-times) used to hold the times that the user has
   * used a grace login to authenticate.
   */
  GRACE_LOGIN_USE_TIMES("grace-login-use-times"),



  /**
   * The field (has-retired-password) used to indicate whether the user's
   * account currently has a valid retired password.
   */
  HAS_RETIRED_PASSWORD("has-retired-password"),



  /**
   * The field (retired-password-expiration-time) used to hold the time that the
   * user's retired password will expire.
   */
  RETIRED_PASSWORD_EXPIRATION_TIME("retired-password-expiration-time"),



  /**
   * The field (seconds-until-retired-password-expiration) used to hold the
   * length of time in seconds remaining until the user's retired password will
   * expire.
   */
  SECONDS_UNTIL_RETIRED_PASSWORD_EXPIRATION(
       "seconds-until-retired-password-expiration"),



  /**
   * The field (require-secure-authentication) used to indicate whether the user
   * is required to authenticate in a secure manner so that their credentials
   * are not exposed to a third-party observer.
   */
  REQUIRE_SECURE_AUTHENTICATION("require-secure-authentication"),



  /**
   * The field (require-secure-password-changes) used to indicate whether the
   * user is required to change their password in a secure manner that does not
   * expose the credentials to a third-party observer.
   */
  REQUIRE_SECURE_PASSWORD_CHANGES("require-secure-password-changes"),



  /**
   * The field (available-sasl-mechanisms) used to hold the names of the SASL
   * mechanisms that the user can use to authenticate.
   */
  AVAILABLE_SASL_MECHANISMS("available-sasl-mechanisms"),



  /**
   * The field (available-otp-delivery-mechanisms) used to hold the names of the
   * one-time password delivery mechanisms that can be used to deliver one-time
   * passwords, password reset tokens, or single-use tokens to the user.
   */
  AVAILABLE_OTP_DELIVERY_MECHANISMS("available-otp-delivery-mechanisms"),



  /**
   * The field (has-totp-shared-secret) used to indicate whether the user has
   * any TOTP shared secrets registered with the server.
   */
  HAS_TOTP_SHARED_SECRET("has-totp-shared-secret"),



  /**
   * The field (has-registered-yubikey-otp-device) used to indicate whether the
   * user has any YubiKey OTP devices registered with the server.
   */
  HAS_REGISTERED_YUBIKEY_OTP_DEVICE("has-registered-yubikey-otp-device"),



  /**
   * The field (account-is-validation-locked) used to indicate whether the
   * user's account is currently locked because it contains a password that does
   * not satisfy all of the configured password validators.
   */
  ACCOUNT_IS_VALIDATION_LOCKED("account-is-validation-locked"),



  /**
   * The field (last-bind-password-validation-time) used to hold the most recent
   * time that password validation was performed during a bind operation for the
   * user.
   */
  LAST_BIND_PASSWORD_VALIDATION_TIME("last-bind-password-validation-time"),



  /**
   * The field (seconds-since-last-bind-password-validation) used to hold the
   * length of time in seconds since the most recent time that password
   * validation was performed during a bind operation for the user.
   */
  SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION(
       "seconds-since-last-bind-password-validation"),



  /**
   * The field (minimum-bind-password-validation-frequency-seconds) used to hold
   * the minimum length of time that should pass between invoking password
   * validators during a bind operation for the user.
   */
  MINIMUM_BIND_PASSWORD_VALIDATION_FREQUENCY_SECONDS(
       "minimum-bind-password-validation-frequency-seconds"),



  /**
   * The field (bind-password-validation-failure-action) used to indicate the
   * action that the server should take if the bind password does not satisfy
   * all of the configured password validators.
   */
  BIND_PASSWORD_VALIDATION_FAILURE_ACTION(
       "bind-password-validation-failure-action"),



  /**
   * The field (recent-login-history) used to provide an encoded representation
   * of the user's recent login history.
   */
  RECENT_LOGIN_HISTORY("recent-login-history"),



  /**
   * The field (maximum-recent-login-history-successful-authentication-count)
   * used to hold the maximum number of recent successful login attempts the
   * server should maintain for a user.
   */
  MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_COUNT(
       "maximum-recent-login-history-successful-authentication-count"),



  /**
   * The field
   * (maximum-recent-login-history-successful-authentication-duration-seconds)
   * used to hold the maximum age in seconds of recent successful login attempts
   * the server should maintain for a user.
   */
  MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_DURATION_SECONDS(
       "maximum-recent-login-history-successful-authentication-duration-" +
            "seconds"),



  /**
   * The field (maximum-recent-login-history-failed-authentication-count) used
   * to hold the maximum number of recent failed login attempts the server
   * should maintain for a user.
   */
  MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_COUNT(
       "maximum-recent-login-history-failed-authentication-count"),



  /**
   * The field
   * (maximum-recent-login-history-failed-authentication-duration-seconds) used
   * to hold the maximum age in seconds of recent failed login attempts the
   * server should maintain for a user.
   */
  MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_DURATION_SECONDS(
       "maximum-recent-login-history-failed-authentication-duration-seconds"),



  /**
   * The field used to hold information about the requirements that passwords
   * will be required to satisfy.
   */
  PASSWORD_QUALITY_REQUIREMENTS("password-quality-requirements");



  // The name for the JSON field.
  @NotNull private final String fieldName;



  /**
   * Creates a new password policy state JSON field with the specified name.
   *
   * @param  fieldName  The name for the JSON field.
   */
  PasswordPolicyStateJSONField(@NotNull final String fieldName)
  {
    this.fieldName = fieldName;
  }



  /**
   * Retrieves the name for the JSON field.
   *
   * @return  The name for the JSON field.
   */
  @NotNull()
  public String getFieldName()
  {
    return fieldName;
  }



  /**
   * Retrieves the password policy state JSON field value with the specified
   * name.
   *
   * @param  name  The name of the password policy state JSON field value to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The password policy state JSON field value with the specified
   *          name, or {@code null} if there is no value with the specified
   *          name.
   */
  @Nullable()
  public static PasswordPolicyStateJSONField forName(@NotNull final String name)
  {
    try
    {
      final String transformedName =
           StaticUtils.toUpperCase(name).replace('-', '_');
      return valueOf(transformedName);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves a string representation of this password policy state JSON field.
   *
   * @return  A string representation of this password policy state JSON field.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return fieldName;
  }
}
