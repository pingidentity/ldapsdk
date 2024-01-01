/*
 * Copyright 2007-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2024 Ping Identity Corporation
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
 * Copyright (C) 2007-2024 Ping Identity Corporation
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
    final String packageNameDot =
         "com.unboundid.ldap.sdk.unboundidds.controls.";
    Control.registerDecodeableControl("1.3.6.1.4.1.42.2.27.9.5.8",
         packageNameDot + "AccountUsableResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.29",
         packageNameDot + "AssuredReplicationResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.59",
         packageNameDot + "GeneratePasswordResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.68",
         packageNameDot + "GenerateAccessTokenResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.6",
         packageNameDot + "GetAuthorizationEntryResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.34",
         packageNameDot + "GetBackendSetIDResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.47",
         packageNameDot + "GetPasswordPolicyStateIssuesResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.62",
         packageNameDot + "GetRecentLoginHistoryResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.15",
         packageNameDot + "GetServerIDResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.26",
         packageNameDot + "GetUserResourceLimitsResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.4",
         packageNameDot + "InteractiveTransactionSpecificationResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.2",
         packageNameDot + "IntermediateClientResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.9",
         packageNameDot + "JoinResultControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.65",
         packageNameDot + "JSONFormattedResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.37",
         packageNameDot + "MatchingEntryCountResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.42.2.27.8.5.1",
         packageNameDot + "PasswordPolicyResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.41",
         packageNameDot + "PasswordValidationDetailsResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.21",
         packageNameDot + "SoftDeleteResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.39",
         packageNameDot + "TransactionSettingsResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.53",
         packageNameDot + "UniquenessResponseControl");

    Control.registerDecodeableControl("1.3.6.1.4.1.30221.2.5.7",
         packageNameDot + "UnsolicitedCancelResponseControl");
  }
}
