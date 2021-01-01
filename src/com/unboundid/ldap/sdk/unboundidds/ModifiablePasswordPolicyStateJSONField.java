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
 * {@link ModifiablePasswordPolicyStateJSON} object.
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
public enum ModifiablePasswordPolicyStateJSONField
{
  /**
   * The field (password-changed-time) used to hold the time the user's password
   * was last changed.  If present, the value of this field may be a string
   * containing a timestamp in the ISO 8601 format described in RFC 3339, or it
   * may be the JSON null value to indicate that the user does not have a
   * password changed time.  Note that setting this field to {@code null} will
   * cause the server to fall back to using the entry's createTimestamp value
   * (if available) as the last changed time.
   */
  PASSWORD_CHANGED_TIME("password-changed-time"),



  /**
   * The field (account-is-disabled) used to indicate whether the user's account
   * has been administratively disabled.
   */
  ACCOUNT_IS_DISABLED("account-is-disabled"),



  /**
   * The field (account-activation-time) used to hold the user's account
   * activation time.  If present, the value of this field may be a string
   * containing a timestamp in the ISO 8601 format described in RFC 3339, or it
   * may be the JSON null value to indicate that the user does not have an
   * account activation time.
   */
  ACCOUNT_ACTIVATION_TIME("account-activation-time"),



  /**
   * The field (account-expiration-time) used to hold the user's account
   * expiration time.  If present, the value of this field may be a string
   * containing a timestamp in the ISO 8601 format described in RFC 3339, or it
   * may be the JSON null value to indicate that the user does not have an
   * account expiration time.
   */
  ACCOUNT_EXPIRATION_TIME("account-expiration-time"),



  /**
   * The field (account-is-failure-locked) used to indicate whether the user's
   * account is locked as a result of too many failed authentication attempts.
   */
  ACCOUNT_IS_FAILURE_LOCKED("account-is-failure-locked"),



  /**
   * The field (password-expiration-warned-time) used to hold the time that the
   * user was first warned about an upcoming password expiration.  If present,
   * the value of this field may be a string containing a timestamp in the ISO
   * 8601 format described in RFC 3339, or it may be the JSON null value to
   * indicate that the user does not have a password expiration warned time.
   */
  PASSWORD_EXPIRATION_WARNED_TIME("password-expiration-warned-time"),



  /**
   * The field (must-change-password) used to indicate whether the user must
   * change their password before they will be permitted to request any other
   * operations in the server.
   */
  MUST_CHANGE_PASSWORD("must-change-password");



  // The name for the JSON field.
  @NotNull private final String fieldName;



  /**
   * Creates a new password policy state JSON field with the specified name.
   *
   * @param  fieldName  The name for the JSON field.
   */
  ModifiablePasswordPolicyStateJSONField(@NotNull final String fieldName)
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
   * Retrieves the modifiable password policy state JSON field value with the
   * specified name.
   *
   * @param  name  The name of the password policy state JSON field value to
   *               retrieve.  It must not be {@code null}.
   *
   * @return  The modifiable password policy state JSON field value with the
   *          specified name, or {@code null} if there is no value with the
   *          specified name.
   */
  @Nullable()
  public static ModifiablePasswordPolicyStateJSONField forName(
              @NotNull final String name)
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
   * Retrieves a string representation of this modifiable password policy state
   * JSON field.
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
