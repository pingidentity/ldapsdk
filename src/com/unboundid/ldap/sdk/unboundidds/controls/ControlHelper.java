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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a helper class that may be used to ensure that all of the
 * "out-of-the-box" UnboundID-specific response controls supported by this SDK
 * are registered so that they can be properly instantiated when received in a
 * response from the directory server.
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
@InternalUseOnly()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ControlHelper
{
  /**
   * Prevent this class from being instantiated.
   */
  private ControlHelper()
  {
    // No implementation is required.
  }



  /**
   * Registers all "out-of-the-box" response UnboundID-specific controls
   * provided with this SDK so that they may be properly decoded if they are
   * received in an LDAP response.  This method is intended only for internal
   * use only and should not be called by external applications.
   */
  @InternalUseOnly()
  @SuppressWarnings("deprecation")
  public static void registerDefaultResponseControls()
  {
    Control.registerDecodeableControl(
         AccountUsableResponseControl.ACCOUNT_USABLE_RESPONSE_OID,
         new AccountUsableResponseControl());

    Control.registerDecodeableControl(
         AssuredReplicationResponseControl.ASSURED_REPLICATION_RESPONSE_OID,
         new AssuredReplicationResponseControl());

    Control.registerDecodeableControl(
         GeneratePasswordResponseControl.GENERATE_PASSWORD_RESPONSE_OID,
         new GeneratePasswordResponseControl());

    Control.registerDecodeableControl(
         GetAuthorizationEntryResponseControl.
              GET_AUTHORIZATION_ENTRY_RESPONSE_OID,
         new GetAuthorizationEntryResponseControl());

    Control.registerDecodeableControl(
         GetBackendSetIDResponseControl.GET_BACKEND_SET_ID_RESPONSE_OID,
         new GetBackendSetIDResponseControl());

    Control.registerDecodeableControl(
         GetPasswordPolicyStateIssuesResponseControl.
              GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID,
         new GetPasswordPolicyStateIssuesResponseControl());

    Control.registerDecodeableControl(
         GetRecentLoginHistoryResponseControl.
              GET_RECENT_LOGIN_HISTORY_RESPONSE_OID,
         new GetRecentLoginHistoryResponseControl());

    Control.registerDecodeableControl(
         GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID,
         new GetServerIDResponseControl());

    Control.registerDecodeableControl(
         GetUserResourceLimitsResponseControl.
              GET_USER_RESOURCE_LIMITS_RESPONSE_OID,
         new GetUserResourceLimitsResponseControl());

    Control.registerDecodeableControl(
         IntermediateClientResponseControl.INTERMEDIATE_CLIENT_RESPONSE_OID,
         new IntermediateClientResponseControl());

    Control.registerDecodeableControl(
         InteractiveTransactionSpecificationResponseControl.
              INTERACTIVE_TRANSACTION_SPECIFICATION_RESPONSE_OID,
         new InteractiveTransactionSpecificationResponseControl());

    Control.registerDecodeableControl(
         JoinResultControl.JOIN_RESULT_OID,
         new JoinResultControl());

    Control.registerDecodeableControl(
         MatchingEntryCountResponseControl.MATCHING_ENTRY_COUNT_RESPONSE_OID,
         new MatchingEntryCountResponseControl());

    Control.registerDecodeableControl(
         PasswordPolicyResponseControl.PASSWORD_POLICY_RESPONSE_OID,
         new PasswordPolicyResponseControl());

    Control.registerDecodeableControl(
         PasswordValidationDetailsResponseControl.
              PASSWORD_VALIDATION_DETAILS_RESPONSE_OID,
         new PasswordValidationDetailsResponseControl());

    Control.registerDecodeableControl(
         SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID,
         new SoftDeleteResponseControl());

    Control.registerDecodeableControl(
         TransactionSettingsResponseControl.TRANSACTION_SETTINGS_RESPONSE_OID,
         new TransactionSettingsResponseControl());

    Control.registerDecodeableControl(
         UnsolicitedCancelResponseControl.UNSOLICITED_CANCEL_RESPONSE_OID,
         new UnsolicitedCancelResponseControl());

    Control.registerDecodeableControl(
         UniquenessResponseControl.UNIQUENESS_RESPONSE_OID,
         new UniquenessResponseControl());
  }
}
