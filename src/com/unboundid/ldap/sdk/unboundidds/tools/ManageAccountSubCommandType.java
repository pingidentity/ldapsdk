/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateOperation;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This enum provides information about all of the subcommands available for
 * use with the manage-account tool.
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
public enum ManageAccountSubCommandType
{
  /**
   * The subcommand used to get all state information for a user.
   */
  GET_ALL("get-all", INFO_MANAGE_ACCT_SC_DESC_GET_ALL.get(), -1),



  /**
   * The subcommand used to get the DN of a user's password policy.
   */
  GET_PASSWORD_POLICY_DN("get-password-policy-dn",
       INFO_MANAGE_ACCT_SC_DESC_GET_POLICY_DN.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_POLICY_DN),



  /**
   * The subcommand used to determine whether an account is usable.
   */
  GET_ACCOUNT_IS_USABLE("get-account-is-usable",
       INFO_MANAGE_ACCT_SC_DESC_GET_IS_USABLE.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_USABLE),



  /**
   * The subcommand used to retrieve the set of password policy state account
   * usability notice messages for a user.
   */
  GET_ACCOUNT_USABILITY_NOTICES("get-account-usability-notice-messages",
       INFO_MANAGE_ACCT_SC_DESC_GET_USABILITY_NOTICES.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_NOTICES),



  /**
   * The subcommand used to retrieve the set of password policy state account
   * usability warning messages for a user.
   */
  GET_ACCOUNT_USABILITY_WARNINGS("get-account-usability-warning-messages",
       INFO_MANAGE_ACCT_SC_DESC_GET_USABILITY_WARNINGS.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_WARNINGS),



  /**
   * The subcommand used to retrieve the set of password policy state account
   * usability error messages for a user.
   */
  GET_ACCOUNT_USABILITY_ERRORS("get-account-usability-error-messages",
       INFO_MANAGE_ACCT_SC_DESC_GET_USABILITY_ERRORS.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_USABILITY_ERRORS),



  /**
   * The subcommand used to get the password changed time for a user.
   */
  GET_PASSWORD_CHANGED_TIME("get-password-changed-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_CHANGED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_CHANGED_TIME),



  /**
   * The subcommand used to set the password changed time for a user.
   */
  SET_PASSWORD_CHANGED_TIME("set-password-changed-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_PW_CHANGED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_PW_CHANGED_TIME),



  /**
   * The subcommand used to clear the password changed time for a user.
   */
  CLEAR_PASSWORD_CHANGED_TIME("clear-password-changed-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_PW_CHANGED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_PW_CHANGED_TIME),



  /**
   * The subcommand used to determine whether a user account is administratively
   * disabled.
   */
  GET_ACCOUNT_IS_DISABLED("get-account-is-disabled",
       INFO_MANAGE_ACCT_SC_DESC_GET_IS_DISABLED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_DISABLED_STATE),



  /**
   * The subcommand used to specify whether a user account is administratively
   * disabled.
   */
  SET_ACCOUNT_IS_DISABLED("set-account-is-disabled",
       INFO_MANAGE_ACCT_SC_DESC_SET_IS_DISABLED.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_ACCOUNT_DISABLED_STATE),



  /**
   * The subcommand used to clear the account disabled state for a user.
   */
  CLEAR_ACCOUNT_IS_DISABLED("clear-account-is-disabled",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_IS_DISABLED.get(
            SET_ACCOUNT_IS_DISABLED.primaryName, "accountIsDisabled"),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_ACCOUNT_DISABLED_STATE),



  /**
   * The subcommand used to get the account activation time for a user.
   */
  GET_ACCOUNT_ACTIVATION_TIME("get-account-activation-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_ACT_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_ACTIVATION_TIME),



  /**
   * The subcommand used to set the account activation time for a user.
   */
  SET_ACCOUNT_ACTIVATION_TIME("set-account-activation-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_ACCT_ACT_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_ACCOUNT_ACTIVATION_TIME),



  /**
   * The subcommand used to clear the account activation time for a user.
   */
  CLEAR_ACCOUNT_ACTIVATION_TIME("clear-account-activation-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_ACCT_ACT_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_ACCOUNT_ACTIVATION_TIME),



  /**
   * The subcommand used to retrieve the length of time until a user's account
   * becomes active.
   */
  GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION("get-seconds-until-account-activation",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_ACCT_ACT.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION),



  /**
   * The subcommand used to determine whether a user's account is not yet
   * active.
   */
  GET_ACCOUNT_IS_NOT_YET_ACTIVE("get-account-is-not-yet-active",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_NOT_YET_ACTIVE.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_NOT_YET_ACTIVE),



  /**
   * The subcommand used to get the account expiration time for a user.
   */
  GET_ACCOUNT_EXPIRATION_TIME("get-account-expiration-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_EXP_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_EXPIRATION_TIME),



  /**
   * The subcommand used to set the account expiration time for a user.
   */
  SET_ACCOUNT_EXPIRATION_TIME("set-account-expiration-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_ACCT_EXP_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_ACCOUNT_EXPIRATION_TIME),



  /**
   * The subcommand used to clear the account expiration time for a user.
   */
  CLEAR_ACCOUNT_EXPIRATION_TIME("clear-account-expiration-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_ACCT_EXP_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_ACCOUNT_EXPIRATION_TIME),



  /**
   * The subcommand used to retrieve the length of time until a user's account
   * expires.
   */
  GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION("get-seconds-until-account-expiration",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_ACCT_EXP.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION),



  /**
   * The subcommand used to determine whether a user's account is expired.
   */
  GET_ACCOUNT_IS_EXPIRED("get-account-is-expired",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_IS_EXPIRED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_EXPIRED),



  /**
   * The subcommand used to retrieve the time a user received the first warning
   * about an upcoming password expiration.
   *
   */
  GET_PASSWORD_EXPIRATION_WARNED_TIME("get-password-expiration-warned-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_EXP_WARNED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_EXPIRATION_WARNED_TIME),



  /**
   * The subcommand used to specify the time a user received the first warning
   * about an upcoming password expiration.
   */
  SET_PASSWORD_EXPIRATION_WARNED_TIME("set-password-expiration-warned-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_PW_EXP_WARNED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_PW_EXPIRATION_WARNED_TIME),



  /**
   * The subcommand used to clear the password expiration warned time for a
   * user.
   */
  CLEAR_PASSWORD_EXPIRATION_WARNED_TIME("clear-password-expiration-warned-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_PW_EXP_WARNED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_PW_EXPIRATION_WARNED_TIME),



  /**
   * The subcommand used to get the length of time in seconds until a user may
   * start to receive warnings about an upcoming expiration.
   */
  GET_SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING(
       "get-seconds-until-password-expiration-warning",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_PW_EXP_WARNING.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION_WARNING),



  /**
   * The subcommand used to retrieve the password expiration time for a user.
   */
  GET_PASSWORD_EXPIRATION_TIME("get-password-expiration-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_EXP_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_EXPIRATION_TIME),



  /**
   * The subcommand used to get the length of time in seconds until a user's
   * password will expire.
   */
  GET_SECONDS_UNTIL_PASSWORD_EXPIRATION("get-seconds-until-password-expiration",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_PW_EXP.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_SECONDS_UNTIL_PW_EXPIRATION),



  /**
   * The subcommand used to determine whether a user's password is expired.
   */
  GET_PASSWORD_IS_EXPIRED("get-password-is-expired",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_IS_EXPIRED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_IS_EXPIRED),



  /**
   * The subcommand used to determine whether a user account is failure locked.
   */
  GET_ACCOUNT_IS_FAILURE_LOCKED("get-account-is-failure-locked",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_FAILURE_LOCKED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_FAILURE_LOCKED),



  /**
   * The subcommand used to specify whether a user account is failure locked.
   */
  SET_ACCOUNT_IS_FAILURE_LOCKED("set-account-is-failure-locked",
       INFO_MANAGE_ACCT_SC_DESC_SET_ACCT_FAILURE_LOCKED.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_ACCOUNT_IS_FAILURE_LOCKED),



  /**
   * The subcommand used to retrieve the failure lockout time for a user.
   */
  GET_FAILURE_LOCKOUT_TIME("get-failure-lockout-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_FAILURE_LOCKED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_FAILURE_LOCKOUT_TIME,
       "get-failure-locked-time"),



  /**
   * The subcommand used to determine the length of time in seconds until a
   * user's temporary failure lockout will expire.
   */
  GET_SECONDS_UNTIL_AUTHENTICATION_FAILURE_UNLOCK(
       "get-seconds-until-authentication-failure-unlock",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_FAILURE_UNLOCK.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_SECONDS_UNTIL_AUTH_FAILURE_UNLOCK),



  /**
   * The subcommand used to retrieve the times of the failed authentication
   * attempts for a user.
   */
  GET_AUTHENTICATION_FAILURE_TIMES("get-authentication-failure-times",
       INFO_MANAGE_ACCT_SC_DESC_GET_AUTH_FAILURE_TIMES.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_AUTH_FAILURE_TIMES),



  /**
   * The subcommand used to add one or more values to the set of authentication
   * failure times for a user.
   */
  ADD_AUTHENTICATION_FAILURE_TIME("add-authentication-failure-time",
       INFO_MANAGE_ACCT_SC_DESC_ADD_AUTH_FAILURE_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_ADD_AUTH_FAILURE_TIME),



  /**
   * The subcommand used to replace the set of authentication failure times for
   * a user.
   */
  SET_AUTHENTICATION_FAILURE_TIMES("set-authentication-failure-times",
       INFO_MANAGE_ACCT_SC_DESC_SET_AUTH_FAILURE_TIMES.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_AUTH_FAILURE_TIMES),



  /**
   * The subcommand used to clear the set of authentication failure times for a
   * user.
   */
  CLEAR_AUTHENTICATION_FAILURE_TIMES("clear-authentication-failure-times",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_AUTH_FAILURE_TIMES.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_AUTH_FAILURE_TIMES),



  /**
   * The subcommand used to determine the number of remaining failed
   * authentication attempts for a user before the account is locked.
   */
  GET_REMAINING_AUTHENTICATION_FAILURE_COUNT(
       "get-remaining-authentication-failure-count",
       INFO_MANAGE_ACCT_SC_DESC_GET_REMAINING_FAILURE_COUNT.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_REMAINING_AUTH_FAILURE_COUNT),



  /**
   * The subcommand used to determine whether a user account is idle locked.
   */
  GET_ACCOUNT_IS_IDLE_LOCKED("get-account-is-idle-locked",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_IDLE_LOCKED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_IDLE_LOCKED),



  /**
   * The subcommand used to determine the length of time in seconds until a
   * user's account will be idle locked.
   */
  GET_SECONDS_UNTIL_IDLE_LOCKOUT("get-seconds-until-idle-lockout",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_IDLE_LOCKOUT.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_SECONDS_UNTIL_IDLE_LOCKOUT),



  /**
   * The subcommand used to determine the time that a user's account was/will be
   * idle locked.
   */
  GET_IDLE_LOCKOUT_TIME("get-idle-lockout-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_IDLE_LOCKOUT_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_IDLE_LOCKOUT_TIME,
       "get-idle-locked-time"),



  /**
   * The subcommand used to determine whether a user's password has been
   * administratively reset.
   */
  GET_MUST_CHANGE_PASSWORD("get-must-change-password",
       INFO_MANAGE_ACCT_SC_DESC_GET_MUST_CHANGE_PW.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_RESET_STATE,
       "get-password-is-reset"),



  /**
   * The subcommand used to specify whether a user's password has been
   * administratively reset.
   */
  SET_MUST_CHANGE_PASSWORD("set-must-change-password",
       INFO_MANAGE_ACCT_SC_DESC_SET_MUST_CHANGE_PW.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_PW_RESET_STATE,
       "set-password-is-reset"),



  /**
   * The subcommand used to clear whether a user's password has been
   * administratively reset.
   */
  CLEAR_MUST_CHANGE_PASSWORD("clear-must-change-password",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_MUST_CHANGE_PW.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_PW_RESET_STATE,
       "clear-password-is-reset"),



  /**
   * The subcommand used to determine whether a user's account is reset locked.
   */
  GET_ACCOUNT_IS_PASSWORD_RESET_LOCKED("get-account-is-password-reset-locked",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_IS_RESET_LOCKED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_RESET_LOCKED),



  /**
   * The subcommand used to determine the length of time in seconds until a
   * user's account is reset locked.
   */
  GET_SECONDS_UNTIL_PASSWORD_RESET_LOCKOUT(
       "get-seconds-until-password-reset-lockout",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_UNTIL_RESET_LOCKOUT.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_SECONDS_UNTIL_PW_RESET_LOCKOUT),



  /**
   * The subcommand used to determine the time a user's account was/will be
   * reset locked.
   */
  GET_PASSWORD_RESET_LOCKOUT_TIME("get-password-reset-lockout-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_RESET_LOCKOUT_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_RESET_LOCKOUT_TIME,
       "get-password-reset-locked-time"),



  /**
   * The subcommand used to retrieve the last login time for a user.
   */
  GET_LAST_LOGIN_TIME("get-last-login-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_LAST_LOGIN_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_LAST_LOGIN_TIME),



  /**
   * The subcommand used to specify the last login time for a user.
   */
  SET_LAST_LOGIN_TIME("set-last-login-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_LAST_LOGIN_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_LAST_LOGIN_TIME),



  /**
   * The subcommand used to clear the last login time for a user.
   */
  CLEAR_LAST_LOGIN_TIME("clear-last-login-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_LAST_LOGIN_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_LAST_LOGIN_TIME),



  /**
   * The subcommand used to retrieve the last login IP address for a user.
   */
  GET_LAST_LOGIN_IP_ADDRESS("get-last-login-ip-address",
       INFO_MANAGE_ACCT_SC_DESC_GET_LAST_LOGIN_IP.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_LAST_LOGIN_IP_ADDRESS),



  /**
   * The subcommand used to specify the last login IP address for a user.
   */
  SET_LAST_LOGIN_IP_ADDRESS("set-last-login-ip-address",
       INFO_MANAGE_ACCT_SC_DESC_SET_LAST_LOGIN_IP.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_LAST_LOGIN_IP_ADDRESS),



  /**
   * The subcommand used to clear the last login IP address for a user.
   */
  CLEAR_LAST_LOGIN_IP_ADDRESS("clear-last-login-ip-address",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_LAST_LOGIN_IP.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_LAST_LOGIN_IP_ADDRESS),



  /**
   * The subcommand used to retrieve the grace login use times for a user.
   */
  GET_GRACE_LOGIN_USE_TIMES("get-grace-login-use-times",
       INFO_MANAGE_ACCT_SC_DESC_GET_GRACE_LOGIN_TIMES.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_GRACE_LOGIN_USE_TIMES),



  /**
   * The subcommand used to add one or more values to the set of grace login
   * use times for a user.
   */
  ADD_GRACE_LOGIN_USE_TIME("add-grace-login-use-time",
       INFO_MANAGE_ACCT_SC_DESC_ADD_GRACE_LOGIN_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_ADD_GRACE_LOGIN_USE_TIME),



  /**
   * The subcommand used to specify the grace login use times for a user.
   */
  SET_GRACE_LOGIN_USE_TIMES("set-grace-login-use-times",
       INFO_MANAGE_ACCT_SC_DESC_SET_GRACE_LOGIN_TIMES.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_GRACE_LOGIN_USE_TIMES),



  /**
   * The subcommand used to clear the grace login use times for a user.
   */
  CLEAR_GRACE_LOGIN_USE_TIMES("clear-grace-login-use-times",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_GRACE_LOGIN_TIMES.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_GRACE_LOGIN_USE_TIMES),



  /**
   * The subcommand used to retrieve the number of remaining grace logins for a
   * user.
   */
  GET_REMAINING_GRACE_LOGIN_COUNT("get-remaining-grace-login-count",
       INFO_MANAGE_ACCT_SC_DESC_GET_REMAINING_GRACE_LOGIN_COUNT.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_REMAINING_GRACE_LOGIN_COUNT),



  /**
   * The subcommand used to retrieve the most recent required password change
   * time with which a user has complied.
   */
  GET_PASSWORD_CHANGED_BY_REQUIRED_TIME("get-password-changed-by-required-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_CHANGED_BY_REQ_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_CHANGED_BY_REQUIRED_TIME),



  /**
   * The subcommand used to specify the most recent required password change
   * time with which a user has complied.
   */
  SET_PASSWORD_CHANGED_BY_REQUIRED_TIME("set-password-changed-by-required-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_PW_CHANGED_BY_REQ_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_PW_CHANGED_BY_REQUIRED_TIME),



  /**
   * The subcommand used to clear the most recent required password change
   * time with which a user has complied.
   */
  CLEAR_PASSWORD_CHANGED_BY_REQUIRED_TIME(
       "clear-password-changed-by-required-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_PW_CHANGED_BY_REQ_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_PW_CHANGED_BY_REQUIRED_TIME),



  /**
   * The subcommand used to determine the length of seconds until the required
   * password changed time for a user.
   */
  GET_SECONDS_UNTIL_REQUIRED_PASSWORD_CHANGE_TIME(
       "get-seconds-until-required-password-change-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECS_UNTIL_REQ_CHANGE_TIME.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_SECONDS_UNTIL_REQUIRED_CHANGE_TIME,
       "get-seconds-until-required-change-time"),



  /**
   * The subcommand used to retrieve the number of passwords in a user's
   * password history.
   */
  GET_PASSWORD_HISTORY_COUNT("get-password-history-count",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_HISTORY_COUNT.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PW_HISTORY_COUNT,
       "get-password-history"),



  /**
   * The subcommand used to clear a user's password history.
   */
  CLEAR_PASSWORD_HISTORY("clear-password-history",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_PW_HISTORY.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_PW_HISTORY),



  /**
   * The subcommand used to determine whether a user has a retired password.
   */
  GET_HAS_RETIRED_PASSWORD("get-has-retired-password",
       INFO_MANAGE_ACCT_SC_DESC_GET_HAS_RETIRED_PW.get(),
       PasswordPolicyStateOperation.OP_TYPE_HAS_RETIRED_PASSWORD),



  /**
   * The subcommand used to retrieve the time that a user's former password
   * was retired.
   */
  GET_PASSWORD_RETIRED_TIME("get-password-retired-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_PW_RETIRED_TIME.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_PASSWORD_RETIRED_TIME),



  /**
   * The subcommand used to determine the time that a user's retired password
   * will expire.
   */
  GET_RETIRED_PASSWORD_EXPIRATION_TIME("get-retired-password-expiration-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_RETIRED_PW_EXP_TIME.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_RETIRED_PASSWORD_EXPIRATION_TIME),



  /**
   * The subcommand used to purge a user's retired password.
   */
  CLEAR_RETIRED_PASSWORD("clear-retired-password",
       INFO_MANAGE_ACCT_SC_DESC_PURGE_RETIRED_PW.get(),
       PasswordPolicyStateOperation.OP_TYPE_PURGE_RETIRED_PASSWORD,
       "purge-retired-password"),



  /**
   * The subcommand used to obtain a list of the SASL mechanisms that are
   * available for a user.  This will take into account the server
   * configuration, the user credentials, and the user authentication
   * constraints.
   */
  GET_AVAILABLE_SASL_MECHANISMS("get-available-sasl-mechanisms",
       INFO_MANAGE_ACCT_SC_DESC_GET_AVAILABLE_SASL_MECHS.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_AVAILABLE_SASL_MECHANISMS),



  /**
   * The subcommand used to obtain a list of the OTP delivery mechanisms that
   * are available for a user.  If there is a set of preferred delivery
   * mechanisms for the user, they will be listed first.
   */
  GET_AVAILABLE_OTP_DELIVERY_MECHANISMS("get-available-otp-delivery-mechanisms",
       INFO_MANAGE_ACCT_SC_DESC_GET_AVAILABLE_OTP_MECHS.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_AVAILABLE_OTP_DELIVERY_MECHANISMS),



  /**
   * The subcommand used to determine whether a user account has at least one
   * TOTP shared secret.
   */
  GET_HAS_TOTP_SHARED_SECRET("get-has-totp-shared-secret",
       INFO_MANAGE_ACCT_SC_DESC_GET_HAS_TOTP_SHARED_SECRET.get(),
       PasswordPolicyStateOperation.OP_TYPE_HAS_TOTP_SHARED_SECRET),



  /**
   * The subcommand used to add one or more TOTP shared secrets for a user.
   */
  ADD_TOTP_SHARED_SECRET("add-totp-shared-secret",
       INFO_MANAGE_ACCT_SC_DESC_ADD_TOTP_SHARED_SECRET.get(),
       PasswordPolicyStateOperation.OP_TYPE_ADD_TOTP_SHARED_SECRET),



  /**
   * The subcommand used to remove one or more TOTP shared secrets for a user.
   */
  REMOVE_TOTP_SHARED_SECRET("remove-totp-shared-secret",
       INFO_MANAGE_ACCT_SC_DESC_REMOVE_TOTP_SHARED_SECRET.get(),
       PasswordPolicyStateOperation.OP_TYPE_REMOVE_TOTP_SHARED_SECRET),



  /**
   * The subcommand used to replace the TOTP shared secrets for a user.
   */
  SET_TOTP_SHARED_SECRETS("set-totp-shared-secrets",
       INFO_MANAGE_ACCT_SC_DESC_SET_TOTP_SHARED_SECRETS.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_TOTP_SHARED_SECRETS),



  /**
   * The subcommand used to clear the TOTP shared secrets for a user.
   */
  CLEAR_TOTP_SHARED_SECRETS("clear-totp-shared-secrets",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_TOTP_SHARED_SECRETS.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_TOTP_SHARED_SECRETS),



  /**
   * The subcommand used to determine whether a user account has at least one
   * registered YubiKey OTP device public ID.
   */
  GET_HAS_REGISTERED_YUBIKEY_PUBLIC_ID("get-has-registered-yubikey-public-id",
       INFO_MANAGE_ACCT_SC_DESC_GET_HAS_YUBIKEY_ID.get(),
       PasswordPolicyStateOperation.OP_TYPE_HAS_REGISTERED_YUBIKEY_PUBLIC_ID),



  /**
   * The subcommand used to retrieve the set of registered YubiKey OTP device
   * public IDs for a user.
   */
  GET_REGISTERED_YUBIKEY_PUBLIC_IDS("get-registered-yubikey-public-ids",
       INFO_MANAGE_ACCT_SC_DESC_GET_YUBIKEY_IDS.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_REGISTERED_YUBIKEY_PUBLIC_IDS),



  /**
   * The subcommand used to add one or more registered YubiKey OTP device public
   * IDs for a user.
   */
  ADD_REGISTERED_YUBIKEY_PUBLIC_ID("add-registered-yubikey-public-id",
       INFO_MANAGE_ACCT_SC_DESC_ADD_YUBIKEY_ID.get(),
       PasswordPolicyStateOperation.OP_TYPE_ADD_REGISTERED_YUBIKEY_PUBLIC_ID),



  /**
   * The subcommand used to remove one or more registered YubiKey OTP device
   * public IDs for a user.
   */
  REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID("remove-registered-yubikey-public-id",
       INFO_MANAGE_ACCT_SC_DESC_REMOVE_YUBIKEY_ID.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID),



  /**
   * The subcommand used to replace the set of registered YubiKey OTP device
   * public IDs for a user.
   */
  SET_REGISTERED_YUBIKEY_PUBLIC_IDS("set-registered-yubikey-public-ids",
       INFO_MANAGE_ACCT_SC_DESC_SET_YUBIKEY_IDS.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_REGISTERED_YUBIKEY_PUBLIC_IDS),



  /**
   * The subcommand used to clear the set of registered YubiKey OTP device
   * public IDs for a user.
   */
  CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS("clear-registered-yubikey-public-ids",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_YUBIKEY_IDS.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS),



  /**
   * The subcommand used to determine whether a user account has at least one
   * static password.
   */
  GET_HAS_STATIC_PASSWORD("get-has-static-password",
       INFO_MANAGE_ACCT_SC_DESC_GET_HAS_STATIC_PW.get(),
       PasswordPolicyStateOperation.OP_TYPE_HAS_STATIC_PASSWORD),



  /**
   * The subcommand used to retrieve the time that the server last invoked
   * password validators for a bind operation.
   */
  GET_LAST_BIND_PASSWORD_VALIDATION_TIME(
       "get-last-bind-password-validation-time",
       INFO_MANAGE_ACCT_SC_DESC_GET_LAST_BIND_PW_VALIDATION_TIME.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_LAST_BIND_PASSWORD_VALIDATION_TIME),



  /**
   * The subcommand used to retrieve the length of time in seconds since the
   * server last invoked password validators for a bind operation.
   */
  GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION(
       "get-seconds-since-last-bind-password-validation",
       INFO_MANAGE_ACCT_SC_DESC_GET_SECONDS_SINCE_LAST_BIND_PW_VALIDATION.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION),



  /**
   * The subcommand used to specify the time that the server last invoked
   * password validators for a bind operation.
   */
  SET_LAST_BIND_PASSWORD_VALIDATION_TIME(
       "set-last-bind-password-validation-time",
       INFO_MANAGE_ACCT_SC_DESC_SET_LAST_BIND_PW_VALIDATION_TIME.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_SET_LAST_BIND_PASSWORD_VALIDATION_TIME),



  /**
   * The subcommand used to clear the time that the server last invoked password
   * validators for a bind operation.
   */
  CLEAR_LAST_BIND_PASSWORD_VALIDATION_TIME(
       "clear-last-bind-password-validation-time",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_LAST_BIND_PW_VALIDATION_TIME.get(),
       PasswordPolicyStateOperation.
            OP_TYPE_CLEAR_LAST_BIND_PASSWORD_VALIDATION_TIME),



  /**
   * The subcommand used to determine whether a user account is validation
   * locked.
   */
  GET_ACCOUNT_IS_VALIDATION_LOCKED("get-account-is-validation-locked",
       INFO_MANAGE_ACCT_SC_DESC_GET_ACCT_VALIDATION_LOCKED.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_IS_VALIDATION_LOCKED),



  /**
   * The subcommand used to specify whether a user account is validation locked.
   */
  SET_ACCOUNT_IS_VALIDATION_LOCKED("set-account-is-validation-locked",
       INFO_MANAGE_ACCT_SC_DESC_SET_ACCT_VALIDATION_LOCKED.get(),
       PasswordPolicyStateOperation.OP_TYPE_SET_ACCOUNT_IS_VALIDATION_LOCKED),



  /**
   * The subcommand used to retrieve the recent login history for a user.
   */
  GET_RECENT_LOGIN_HISTORY("get-recent-login-history",
       INFO_MANAGE_ACCT_SC_DESC_GET_RECENT_LOGIN_HISTORY.get(),
       PasswordPolicyStateOperation.OP_TYPE_GET_RECENT_LOGIN_HISTORY),



  /**
   * The subcommand used to clear the recent login history for a user.
   */
  CLEAR_RECENT_LOGIN_HISTORY("clear-recent-login-history",
       INFO_MANAGE_ACCT_SC_DESC_CLEAR_RECENT_LOGIN_HISTORY.get(),
       PasswordPolicyStateOperation.OP_TYPE_CLEAR_RECENT_LOGIN_HISTORY);



  /**
   * The map of subcommand types indexed by password policy state operation
   * type.
   */
  @Nullable private static HashMap<Integer,ManageAccountSubCommandType>
       typesByOpType = null;



  /**
   * The map of subcommand types indexed by name.
   */
  @Nullable private static HashMap<String,ManageAccountSubCommandType>
       typesByName = null;



  // The password policy state operation type value that corresponds to this
  // subcommand type.
  private final int operationType;

  // A list containing the primary name and all alternate names for this
  // subcommand.
  @NotNull private final List<String> allNames;

  // A list of alternate names for this subcommand.
  @NotNull private final List<String> alternateNames;

  // The description for this subcommand.
  @NotNull private final String description;

  // The primary name for this subcommand.
  @NotNull private final String primaryName;



  /**
   * Creates a new manage-account subcommand type value with the provided
   * information.
   *
   * @param  primaryName     The primary name for this subcommand.  It must not
   *                         be {@code null}.
   * @param  description     The description for this subcommand.  It must not
   *                         be {@code null}.
   * @param  operationType   The password policy state operation type value that
   *                         corresponds to this subcommand type.
   * @param  alternateNames  The set of alternate names that may be used to
   *                         invoke this subcommand.  It may be empty but not
   *                         {@code null}.
   */
  ManageAccountSubCommandType(@NotNull final String primaryName,
                              @NotNull final String description,
                              final int operationType,
                              @NotNull final String... alternateNames)
  {
    this.primaryName    = primaryName;
    this.description    = description;
    this.operationType  = operationType;

    this.alternateNames =
         Collections.unmodifiableList(Arrays.asList(alternateNames));

    final ArrayList<String> allNamesList =
         new ArrayList<>(alternateNames.length + 1);
    allNamesList.add(primaryName);
    allNamesList.addAll(this.alternateNames);

    allNames = Collections.unmodifiableList(allNamesList);
  }



  /**
   * Retrieves the primary name for the subcommand.
   *
   * @return  The primary name for the subcommand.
   */
  @NotNull()
  public String getPrimaryName()
  {
    return primaryName;
  }



  /**
   * Retrieves the alternate names for this subcommand, if any.
   *
   * @return  The alternate names for this subcommand, or an empty list if
   *          there are no alternate names.
   */
  @NotNull()
  public List<String> getAlternateNames()
  {
    return alternateNames;
  }



  /**
   * Retrieves a list containing all names (primary and alternate) for this
   * subcommand.
   *
   * @return  A list containing all names for ths subcommand.
   */
  @NotNull()
  public List<String> getAllNames()
  {
    return allNames;
  }



  /**
   * Retrieves the description for the subcommand.
   *
   * @return  The description for the subcommand.
   */
  @NotNull()
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the password policy state operation type value that corresponds
   * to this subcommand type.
   *
   * @return  The password policy state operation type value that corresponds
   *          to this subcommand type.
   */
  public int getPasswordPolicyStateOperationType()
  {
    return operationType;
  }



  /**
   * Retrieves the subcommand type with the specified name.
   *
   * @param  name  The name of the subcommand type to retrieve.  It must not be
   *               {@code null}.
   *
   * @return  The subcommand type with the specified name, or {@code null} if
   *          there is no subcommand type for the given name.
   */
  @Nullable()
  public static ManageAccountSubCommandType forName(@NotNull final String name)
  {
    ensureMapsPopulated();

    return typesByName.get(StaticUtils.toLowerCase(name));
  }



  /**
   * Retrieves the subcommand type with the specified password policy state
   * operation type.
   *
   * @param  opType  The password policy state operation type for the subcommand
   *                 type to retrieve.
   *
   * @return  The subcommand type with the specified password policy state
   *          operation type, or {@code null} if there is no subcommand type for
   *          the given operation type.
   */
  @Nullable()
  public static ManageAccountSubCommandType forOperationType(final int opType)
  {
    ensureMapsPopulated();

    return typesByOpType.get(opType);
  }



  /**
   * Ensures that the maps allowing subcommand types to be retrieved by name and
   * by password policy state operation types are populated.  They can't be
   * automatically populated by the constructor because enum constructors can't
   * interact with static
   */
  private static synchronized void ensureMapsPopulated()
  {
    if (typesByName == null)
    {
      final ManageAccountSubCommandType[] values =
           ManageAccountSubCommandType.values();
      typesByName =
           new HashMap<>(StaticUtils.computeMapCapacity(2*values.length));
      typesByOpType =
           new HashMap<>(StaticUtils.computeMapCapacity(values.length));

      for (final ManageAccountSubCommandType t :  values)
      {
        typesByName.put(StaticUtils.toLowerCase(t.primaryName), t);
        for (final String altName : t.alternateNames)
        {
          typesByName.put(StaticUtils.toLowerCase(altName), t);
        }

        if (t.operationType>= 0)
        {
          typesByOpType.put(t.operationType, t);
        }
      }
    }
  }
}
