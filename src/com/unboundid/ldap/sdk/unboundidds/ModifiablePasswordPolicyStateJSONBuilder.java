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



import java.io.Serializable;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.
                   ModifiablePasswordPolicyStateJSONField.*;



/**
 * This class provides support for generating a JSON object that may be included
 * in a REPLACE modification to the ds-pwp-modifiable-state-json operational
 * attribute to manipulate elements in the user's password policy state.
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
 *
 * @see  ModifiablePasswordPolicyStateJSON
 * @see  ModifiablePasswordPolicyStateJSONField
 * @see  PasswordPolicyStateJSON
 * @see  PasswordPolicyStateExtendedRequest
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ModifiablePasswordPolicyStateJSONBuilder
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1059372199527400142L;



  // A flag that indicates whether the user's account is disabled.
  @Nullable private Boolean accountIsDisabled;

  // A flag that indicates whether the user's account is failure-locked.
  @Nullable private Boolean accountIsFailureLocked;

  // A flag that indicates whether the user must change their password.
  @Nullable private Boolean mustChangePassword;

  // A timestamp representing the user's account activation time.
  @Nullable private Long accountActivationTime;

  // A timestamp representing the user's account expiration time.
  @Nullable private Long accountExpirationTime;

  // A timestamp representing the time the user's password was last changed.
  @Nullable private Long passwordChangedTime;

  // A timestamp representing the time the user was first warned about an
  // upcoming password expiration.
  @Nullable private Long passwordExpirationWarnedTime;



  /**
   * Creates a new builder instance with none of the fields set.
   */
  public ModifiablePasswordPolicyStateJSONBuilder()
  {
    accountIsDisabled = null;
    accountIsFailureLocked = null;
    mustChangePassword = null;
    accountActivationTime = null;
    accountExpirationTime = null;
    passwordChangedTime = null;
    passwordExpirationWarnedTime = null;
  }



  /**
   * Creates a new builder instance with values set from the provided modifiable
   * password policy state object.
   *
   * @param  state  The modifiable password policy state object to use to set
   *                the initial values for all of the fields.
   */
  public ModifiablePasswordPolicyStateJSONBuilder(
              @NotNull final ModifiablePasswordPolicyStateJSON state)
  {
    accountIsDisabled = state.getAccountIsDisabled();
    accountIsFailureLocked = state.getAccountIsFailureLocked();
    mustChangePassword = state.getMustChangePassword();
    accountActivationTime = state.getAccountActivationTime();
    accountExpirationTime = state.getAccountExpirationTime();
    passwordChangedTime = state.getPasswordChangedTime();
    passwordExpirationWarnedTime = state.getPasswordExpirationWarnedTime();
  }



  /**
   * Retrieves a timestamp that indicates the time the user's password was last
   * changed.
   *
   * @return  A non-negative value that represents the password changed time in
   *          number of milliseconds since the epoch (the same format used by
   *          {@code System.currentTimeMillis}), a negative value if the field
   *          was present with a JSON null value (indicating that the user
   *          doesn't have a password changed time), or {@code null} if the
   *          field was not included in the JSON object.
   */
  @Nullable()
  public Long getPasswordChangedTime()
  {
    return passwordChangedTime;
  }



  /**
   * Updates this builder with a new password changed time.
   *
   * @param  passwordChangedTime
   *              The new password changed time value to use.  It may be a
   *              positive value representing the number of milliseconds since
   *              the epoch (the same format used by
   *              {@code System.currentTimeMillis}) for the password changed
   *              time, a negative value to indicate that any existing password
   *              changed time value should be cleared, or {@code null} if the
   *              value should not be set in this builder (and therefore omitted
   *              from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setPasswordChangedTime(
              @Nullable final Long passwordChangedTime)
  {
    if ((passwordChangedTime != null) && (passwordChangedTime < 0L))
    {
      this.passwordChangedTime = -1L;
    }
    else
    {
      this.passwordChangedTime = passwordChangedTime;
    }

    return this;
  }



  /**
   * Updates this builder with a new password changed time.
   *
   * @param  passwordChangedTime
   *              The new password changed time value to use.  It may be
   *              {@code null} if any existing password changed time value
   *              should be cleared.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setPasswordChangedTime(
              @Nullable final Date passwordChangedTime)
  {
    if (passwordChangedTime == null)
    {
      this.passwordChangedTime = -1L;
    }
    else
    {
      this.passwordChangedTime = passwordChangedTime.getTime();
    }

    return this;
  }



  /**
   * Updates this builder so that any existing password changed time value will
   * be cleared in the user entry.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder clearPasswordChangedTime()
  {
    passwordChangedTime = -1L;
    return this;
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account has
   * been administratively disabled.
   *
   * @return  {@code Boolean.TRUE} if the account has been administratively
   *          disabled, {@code Boolean.FALSE} if the account has not been
   *          administratively disabled, or {@code null} if this flag was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsDisabled()
  {
    return accountIsDisabled;
  }



  /**
   * Updates this builder with a new value for the flag indicating whether the
   * user's account should be considered disabled.
   *
   * @param  accountIsDisabled
   *              The new account is disabled value to use.  It may be
   *              {@code null} if the value should not be set in this builder
   *              (and therefore omitted from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setAccountIsDisabled(
              @Nullable final Boolean accountIsDisabled)
  {
    this.accountIsDisabled = accountIsDisabled;
    return this;
  }



  /**
   * Retrieves a timestamp that indicates the time the user's account became (or
   * will become) active.
   *
   * @return  A non-negative value that represents the account activation time
   *          in number of milliseconds since the epoch (the same format used by
   *          {@code System.currentTimeMillis}), a negative value if the field
   *          was present with a JSON null value (indicating that the user
   *          doesn't have an account activation time), or {@code null} if the
   *          field was not included in the JSON object.
   */
  @Nullable()
  public Long getAccountActivationTime()
  {
    return accountActivationTime;
  }



  /**
   * Updates this builder with a new account activation time.
   *
   * @param  accountActivationTime
   *              The new account activation time value to use.  It may be a
   *              positive value representing the number of milliseconds since
   *              the epoch (the same format used by
   *              {@code System.currentTimeMillis}) for the account activation
   *              time, a negative value to indicate that any existing account
   *              activation time value should be cleared, or {@code null} if
   *              the value should not be set in this builder (and therefore
   *              omitted from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setAccountActivationTime(
              @Nullable final Long accountActivationTime)
  {
    if ((accountActivationTime != null) && (accountActivationTime < 0L))
    {
      this.accountActivationTime = -1L;
    }
    else
    {
      this.accountActivationTime = accountActivationTime;
    }

    return this;
  }



  /**
   * Updates this builder with a new account activation time.
   *
   * @param  accountActivationTime
   *              The new account activation time value to use.  It may be
   *              {@code null} if any existing account activation time value
   *              should be cleared.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setAccountActivationTime(
              @Nullable final Date accountActivationTime)
  {
    if (accountActivationTime == null)
    {
      this.accountActivationTime = -1L;
    }
    else
    {
      this.accountActivationTime = accountActivationTime.getTime();
    }

    return this;
  }



  /**
   * Updates this builder so that any existing account activation time value
   * will be cleared in the user entry.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder clearAccountActivationTime()
  {
    accountActivationTime = -1L;
    return this;
  }



  /**
   * Retrieves a timestamp that indicates the time the user's account will (or
   * did) expire.
   *
   * @return  A non-negative value that represents the account expiration time
   *          in number of milliseconds since the epoch (the same format used by
   *          {@code System.currentTimeMillis}), a negative value if the field
   *          was present with a JSON null value (indicating that the user
   *          doesn't have an account expiration time), or {@code null} if the
   *          field was not included in the JSON object.
   */
  @Nullable()
  public Long getAccountExpirationTime()
  {
    return accountExpirationTime;
  }



  /**
   * Updates this builder with a new account expiration time.
   *
   * @param  accountExpirationTime
   *              The new account expiration time value to use.  It may be a
   *              positive value representing the number of milliseconds since
   *              the epoch (the same format used by
   *              {@code System.currentTimeMillis}) for the account expiration
   *              time, a negative value to indicate that any existing account
   *              expiration time value should be cleared, or {@code null} if
   *              the value should not be set in this builder (and therefore
   *              omitted from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setAccountExpirationTime(
              @Nullable final Long accountExpirationTime)
  {
    if ((accountExpirationTime != null) && (accountExpirationTime < 0L))
    {
      this.accountExpirationTime = -1L;
    }
    else
    {
      this.accountExpirationTime = accountExpirationTime;
    }

    return this;
  }



  /**
   * Updates this builder with a new account expiration time.
   *
   * @param  accountExpirationTime
   *              The new account expiration time value to use.  It may be
   *              {@code null} if any existing account expiration time value
   *              should be cleared.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setAccountExpirationTime(
              @Nullable final Date accountExpirationTime)
  {
    if (accountExpirationTime == null)
    {
      this.accountExpirationTime = -1L;
    }
    else
    {
      this.accountExpirationTime = accountExpirationTime.getTime();
    }

    return this;
  }



  /**
   * Updates this builder so that any existing account expiration time value
   * will be cleared in the user entry.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder clearAccountExpirationTime()
  {
    accountExpirationTime = -1L;
    return this;
  }



  /**
   * Retrieves the value of a flag that indicates whether the user account is
   * currently locked as a result of too many failed authentication attempts.
   *
   * @return  {@code Boolean.TRUE} if the user account is locked as a result of
   *          too many failed authentication attempts, {@code Boolean.FALSE} if
   *          the user account is not locked because of too many failed
   *          authentication attempts, or {@code null} if this flag was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsFailureLocked()
  {
    return accountIsFailureLocked;
  }



  /**
   * Updates this builder with a new value for the flag indicating whether the
   * user's account should be considered locked as a result of too many failed
   * authentication attempts.  Note that the server may reject an attempt to set
   * the value to {@code Boolean.TRUE} if failure lockout is not enabled in the
   * server.
   *
   * @param  accountIsFailureLocked
   *              The new account is failure-locked value to use.  It may be
   *              {@code null} if the value should not be set in this builder
   *              (and therefore omitted from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setAccountIsFailureLocked(
              @Nullable final Boolean accountIsFailureLocked)
  {
    this.accountIsFailureLocked = accountIsFailureLocked;
    return this;
  }



  /**
   * Retrieves a timestamp that indicates the time the user was first warned
   * about an upcoming password expiration.
   *
   * @return  A non-negative value that represents the password expiration
   *          warned time in number of milliseconds since the epoch (the same
   *          format used by {@code System.currentTimeMillis}), a negative value
   *          if the field was present with a JSON null value (indicating that
   *          the user doesn't have an password expiration warned time), or
   *          {@code null} if the field was not included in the JSON object.
   */
  @Nullable()
  public Long getPasswordExpirationWarnedTime()
  {
    return passwordExpirationWarnedTime;
  }



  /**
   * Updates this builder with a new password expiration warned time.
   *
   * @param  passwordExpirationWarnedTime
   *              The new password expiration warned time value to use.  It may
   *              be a positive value representing the number of milliseconds
   *              since the epoch (the same format used by
   *              {@code System.currentTimeMillis}) for the password expiration
   *              warned time, a negative value to indicate that any existing
   *              password expiration warned time value should be cleared, or
   *              {@code null} if the value should not be set in this builder
   *              (and therefore omitted from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder
              setPasswordExpirationWarnedTime(
                   @Nullable final Long passwordExpirationWarnedTime)
  {
    if ((passwordExpirationWarnedTime != null) &&
         (passwordExpirationWarnedTime < 0L))
    {
      this.passwordExpirationWarnedTime = -1L;
    }
    else
    {
      this.passwordExpirationWarnedTime = passwordExpirationWarnedTime;
    }

    return this;
  }



  /**
   * Updates this builder with a new password expiration warned time.
   *
   * @param  passwordExpirationWarnedTime
   *              The new password expiration warned time value to use.  It may
   *              be {@code null} if any existing password expiration warned
   *              time value should be cleared.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder
              setPasswordExpirationWarnedTime(
                   @Nullable final Date passwordExpirationWarnedTime)
  {
    if (passwordExpirationWarnedTime == null)
    {
      this.passwordExpirationWarnedTime = -1L;
    }
    else
    {
      this.passwordExpirationWarnedTime =
           passwordExpirationWarnedTime.getTime();
    }

    return this;
  }



  /**
   * Updates this builder so that any existing password expiration warned time
   * value will be cleared in the user entry.
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder
              clearPasswordExpirationWarnedTime()
  {
    passwordExpirationWarnedTime = -1L;
    return this;
  }



  /**
   * Retrieves the value of a flag that indicates whether the user must change
   * their password before they will be allowed to perform any other operations
   * in the server.
   *
   * @return  {@code Boolean.TRUE} if the user must change their password before
   *          they will be allowed to perform any other operations in the
   *          server, {@code Boolean.FALSE} if the user is not required to
   *          change their password, or {@code null} if this flag was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getMustChangePassword()
  {
    return mustChangePassword;
  }



  /**
   * Updates this builder with a new value for the flag indicating whether the
   * user must change their password before they will be allowed to perform
   * other operations in the server.
   *
   * @param  mustChangePassword
   *              The new must change password value to use.  It may be
   *              {@code null} if the value should not be set in this builder
   *              (and therefore omitted from any JSON object or
   *              {@link ModifiablePasswordPolicyStateJSON} that is created).
   *
   * @return  This builder object.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSONBuilder setMustChangePassword(
              @Nullable final Boolean mustChangePassword)
  {
    this.mustChangePassword = mustChangePassword;
    return this;
  }



  /**
   * Retrieves a JSON object with an encoded representation of the modifiable
   * password policy state created from this builder.
   *
   * @return  A JSON object with an encoded representation of the modifiable
   *          password policy state created from this builder.
   */
  @NotNull()
  public JSONObject toJSONObject()
  {
    final Map<String,JSONValue> fields =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(7));

    if (passwordChangedTime != null)
    {
      if (passwordChangedTime >= 0L)
      {
        fields.put(PASSWORD_CHANGED_TIME.getFieldName(),
             new JSONString(StaticUtils.encodeRFC3339Time(
                  passwordChangedTime)));
      }
      else
      {
        fields.put(PASSWORD_CHANGED_TIME.getFieldName(), JSONNull.NULL);
      }
    }

    if (accountIsDisabled != null)
    {
      fields.put(ACCOUNT_IS_DISABLED.getFieldName(),
           new JSONBoolean(accountIsDisabled));
    }

    if (accountActivationTime != null)
    {
      if (accountActivationTime >= 0L)
      {
        fields.put(ACCOUNT_ACTIVATION_TIME.getFieldName(),
             new JSONString(StaticUtils.encodeRFC3339Time(
                  accountActivationTime)));
      }
      else
      {
        fields.put(ACCOUNT_ACTIVATION_TIME.getFieldName(), JSONNull.NULL);
      }
    }

    if (accountExpirationTime != null)
    {
      if (accountExpirationTime >= 0L)
      {
        fields.put(ACCOUNT_EXPIRATION_TIME.getFieldName(),
             new JSONString(StaticUtils.encodeRFC3339Time(
                  accountExpirationTime)));
      }
      else
      {
        fields.put(ACCOUNT_EXPIRATION_TIME.getFieldName(), JSONNull.NULL);
      }
    }

    if (accountIsFailureLocked != null)
    {
      fields.put(ACCOUNT_IS_FAILURE_LOCKED.getFieldName(),
           new JSONBoolean(accountIsFailureLocked));
    }

    if (passwordExpirationWarnedTime != null)
    {
      if (passwordExpirationWarnedTime >= 0L)
      {
        fields.put(PASSWORD_EXPIRATION_WARNED_TIME.getFieldName(),
             new JSONString(StaticUtils.encodeRFC3339Time(
                  passwordExpirationWarnedTime)));
      }
      else
      {
        fields.put(PASSWORD_EXPIRATION_WARNED_TIME.getFieldName(),
             JSONNull.NULL);
      }
    }

    if (mustChangePassword != null)
    {
      fields.put(MUST_CHANGE_PASSWORD.getFieldName(),
           new JSONBoolean(mustChangePassword));
    }

    return new JSONObject(fields);
  }



  /**
   * Creates a {@code ModifiablePasswordPolicyStateJSON} object from the
   * contents of this builder.
   *
   * @return  The {@code ModifiablePasswordPolicyStateJSON} object created from
   *          the contents of this builder.
   */
  @NotNull()
  public ModifiablePasswordPolicyStateJSON build()
  {
    return new ModifiablePasswordPolicyStateJSON(toJSONObject());
  }



  /**
   * Creates a modify request that may be used to update the specified user with
   * the appropriate password policy state changes from this builder.
   *
   * @param  userDN  The DN of the user whose password policy state should be
   *                 updated.
   *
   * @return  A modify request that may be used to update the specified user
   *          with the appropriate password policy state changes from this
   *          builder.
   */
  @NotNull()
  public ModifyRequest toModifyRequest(@NotNull final String userDN)
  {
    return new ModifyRequest(userDN,
         new Modification(
              ModificationType.REPLACE,
              ModifiablePasswordPolicyStateJSON.
                   MODIFIABLE_PASSWORD_POLICY_STATE_JSON_ATTRIBUTE,
              toJSONObject().toSingleLineString()));
  }



  /**
   * Retrieves a string representation of the password policy state information.
   *
   * @return  A string representation of the password policy state information.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return toJSONObject().toString();
  }
}
