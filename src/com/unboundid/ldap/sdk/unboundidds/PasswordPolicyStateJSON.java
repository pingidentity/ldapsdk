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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.RecentLoginHistory;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.PasswordPolicyStateJSONField.*;
import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides support for reading and decoding the value of the
 * {@code ds-pwp-state-json} virtual attribute, which holds information about a
 * user's password policy state.
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
 *
 * @see ModifiablePasswordPolicyStateJSON
 * @see PasswordPolicyStateExtendedRequest
 * @see PasswordPolicyStateJSONField
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordPolicyStateJSON
       implements Serializable
{
  /**
   * The name of the operational attribute that holds a JSON representation of a
   * user's password policy state.
   */
  @NotNull public static final String PASSWORD_POLICY_STATE_JSON_ATTRIBUTE =
       "ds-pwp-state-json";



  /**
   * The name of the field that will be used to indicate whether a password
   * quality requirement applies to add operations.
   */
  @NotNull private static final String REQUIREMENT_FIELD_APPLIES_TO_ADD =
       "applies-to-add";



  /**
   * The name of the field that will be used to indicate whether a password
   * quality requirement applies to administrative password resets.
   */
  @NotNull private static final String
       REQUIREMENT_FIELD_APPLIES_TO_ADMIN_RESET =
            "applies-to-administrative-reset";



  /**
   * The name of the field that will be used to indicate whether a password
   * quality requirement applies to bind operations.
   */
  @NotNull private static final String REQUIREMENT_FIELD_APPLIES_TO_BIND =
       "applies-to-bind";



  /**
   * The name of the field that will be used to indicate whether a password
   * quality requirement applies to self password changes.
   */
  @NotNull private static final String
       REQUIREMENT_FIELD_APPLIES_TO_SELF_CHANGE = "applies-to-self-change";



  /**
   * The name of the field that will be used to hold the set of client-side
   * validation properties.
   */
  @NotNull private static final String
       REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES =
       "client-side-validation-properties";



  /**
   * The name of the field that will be used to hold the name of a client-side
   * validation property.
   */
  @NotNull private static final String
       REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_PROPERTY_NAME = "name";



  /**
   * The name of the field that will be used to hold the value of a client-side
   * validation property.
   */
  @NotNull private static final String
       REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_PROPERTY_VALUE = "value";



  /**
   * The name of the field that will be used to hold the name of the client-side
   * validation type for a password quality requirement.
   */
  @NotNull private static final String
       REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_TYPE =
            "client-side-validation-type";



  /**
   * The name of the field that will be used to hold the description component
   * of a password quality requirement.
   */
  @NotNull private static final String REQUIREMENT_FIELD_DESCRIPTION =
       "description";



  /**
   * The name of the field that will be used to hold the message component of an
   * account usability error, warning, or notice.
   */
  @NotNull private static final String USABILITY_FIELD_MESSAGE = "message";



  /**
   * The name of the field that will be used to hold the integer version of
   * the identifier for of an account usability error, warning, or notice.
   */
  @NotNull private static final String USABILITY_FIELD_TYPE_ID = "type-id";



  /**
   * The name of the field that will be used to hold the name of the identifier
   * for of an account usability error, warning, or notice.
   */
  @NotNull private static final String USABILITY_FIELD_TYPE_NAME = "type-name";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3953182526241789456L;




  // The JSON object that contains the password policy state information.
  @NotNull private final JSONObject passwordPolicyStateObject;



  /**
   * Creates a new instance of this object from the provided JSON object.
   *
   * @param  passwordPolicyStateObject  The JSON object containing the encoded
   *                                    password policy state.
   */
  public PasswordPolicyStateJSON(
       @NotNull final JSONObject passwordPolicyStateObject)
  {
    this.passwordPolicyStateObject = passwordPolicyStateObject;
  }



  /**
   * Attempts to retrieve and decode the password policy state information for
   * the specified user.
   *
   * @param  connection  The connection to use to communicate with the server.
   *                     It must not be {@code null}, and it must be established
   *                     and authenticated as an account with permission to
   *                     access the target user's password policy state
   *                     information.
   * @param  userDN      The DN of the user for whom to retrieve the password
   *                     policy state.  It must not be {@code null}.
   *
   * @return  The password policy state information for the specified user, or
   *          {@code null} because no password policy state information is
   *          available for the user.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         retrieve the user's entry or decode the password
   *                         policy state JSON object.
   */
  @Nullable()
  public static PasswordPolicyStateJSON get(
                     @NotNull final LDAPInterface connection,
                     @NotNull final String userDN)
         throws LDAPException
  {
    final SearchResultEntry userEntry = connection.getEntry(userDN,
         PASSWORD_POLICY_STATE_JSON_ATTRIBUTE);
    if (userEntry == null)
    {
      throw new LDAPException(ResultCode.NO_SUCH_OBJECT,
           ERR_PW_POLICY_STATE_JSON_GET_NO_SUCH_USER.get(userDN));
    }

    return get(userEntry);
  }



  /**
   * Attempts to retrieve and decode the password policy state information from
   * the provided user entry.
   *
   * @param  userEntry  The entry for the user for whom to obtain the password
   *                    policy state information.  It must not be {@code null}.
   *
   * @return  The password policy state information from the provided user
   *          entry, or {@code null} if no password policy state information is
   *          available for the user.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the password policy state JSON object.
   */
  @Nullable()
  public static PasswordPolicyStateJSON get(@NotNull final Entry userEntry)
         throws LDAPException
  {
    final String valueString =
         userEntry.getAttributeValue(PASSWORD_POLICY_STATE_JSON_ATTRIBUTE);
    if (valueString == null)
    {
      return null;
    }

    final JSONObject jsonObject;
    try
    {
      jsonObject = new JSONObject(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_POLICY_STATE_JSON_GET_CANNOT_DECODE.get(
                PASSWORD_POLICY_STATE_JSON_ATTRIBUTE, userEntry.getDN()),
           e);
    }

    return new PasswordPolicyStateJSON(jsonObject);
  }



  /**
   * Retrieves the JSON object that contains the encoded password policy state
   * information.
   *
   * @return  The JSON object that contains the encoded password policy state
   *          information.
   */
  @NotNull()
  public JSONObject getPasswordPolicyStateJSONObject()
  {
    return passwordPolicyStateObject;
  }



  /**
   * Retrieves the DN of the entry that defines the password policy that governs
   * the associated user.
   *
   * @return  The DN of the entry that defines hte password policy that governs
   *          the associated user, or {@code null} if this was not included in
   *          the password policy state JSON object.
   */
  @Nullable()
  public String getPasswordPolicyDN()
  {
    return passwordPolicyStateObject.getFieldAsString(
         PASSWORD_POLICY_DN.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account is
   * in a state that the server considers usable.
   *
   * @return  {@code Boolean.TRUE} if the account is in a usable state,
   *          {@code Boolean.FALSE} if the account is not in a usable state, or
   *          {@code null} if this flag was not included in the password policy
   *          state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsUsable()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_USABLE.getFieldName());
  }



  /**
   * Retrieves a list of information about any error conditions that may
   * affect usability of the user's account.
   *
   * @return  A list of information about any error conditions that may affect
   *          the usability of the user's account.  The returned list may be
   *          empty if there are no account usability errors or if this was not
   *          included in the password policy state JSON object.
   */
  @NotNull()
  public List<PasswordPolicyStateAccountUsabilityError>
              getAccountUsabilityErrors()
  {
    final List<PasswordPolicyStateAccountUsabilityError> errors =
         new ArrayList<>();
    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         ACCOUNT_USABILITY_ERRORS.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject o = (JSONObject) v;
          final String typeName = o.getFieldAsString(USABILITY_FIELD_TYPE_NAME);
          final Integer typeID = o.getFieldAsInteger(USABILITY_FIELD_TYPE_ID);
          final String message = o.getFieldAsString(USABILITY_FIELD_MESSAGE);
          if ((typeName != null) && (typeID != null))
          {
            errors.add(new PasswordPolicyStateAccountUsabilityError(typeID,
                 typeName, message));
          }
        }
      }
    }

    return Collections.unmodifiableList(errors);
  }



  /**
   * Retrieves a list of information about any warning conditions that may soon
   * affect usability of the user's account.
   *
   * @return  A list of information about any warning conditions that may soon
   *          affect the usability of the user's account.  The returned list may
   *          be empty if there are no account usability warnings or if this was
   *          not included in the password policy state JSON object.
   */
  @NotNull()
  public List<PasswordPolicyStateAccountUsabilityWarning>
              getAccountUsabilityWarnings()
  {
    final List<PasswordPolicyStateAccountUsabilityWarning> warnings =
         new ArrayList<>();
    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         ACCOUNT_USABILITY_WARNINGS.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject o = (JSONObject) v;
          final String typeName = o.getFieldAsString(USABILITY_FIELD_TYPE_NAME);
          final Integer typeID = o.getFieldAsInteger(USABILITY_FIELD_TYPE_ID);
          final String message = o.getFieldAsString(USABILITY_FIELD_MESSAGE);
          if ((typeName != null) && (typeID != null))
          {
            warnings.add(new PasswordPolicyStateAccountUsabilityWarning(typeID,
                 typeName, message));
          }
        }
      }
    }

    return Collections.unmodifiableList(warnings);
  }



  /**
   * Retrieves a list of information about any notices related to the usability
   * of the user's account.
   *
   * @return  A list of information about any notices related to the usability
   *          of the user's account.  The returned list may be empty if there
   *          are no account usability notices or if this was not included in
   *          the password policy state JSON object.
   */
  @NotNull()
  public List<PasswordPolicyStateAccountUsabilityNotice>
              getAccountUsabilityNotices()
  {
    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         new ArrayList<>();
    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         ACCOUNT_USABILITY_NOTICES.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject o = (JSONObject) v;
          final String typeName = o.getFieldAsString(USABILITY_FIELD_TYPE_NAME);
          final Integer typeID = o.getFieldAsInteger(USABILITY_FIELD_TYPE_ID);
          final String message = o.getFieldAsString(USABILITY_FIELD_MESSAGE);
          if ((typeName != null) && (typeID != null))
          {
            notices.add(new PasswordPolicyStateAccountUsabilityNotice(typeID,
                 typeName, message));
          }
        }
      }
    }

    return Collections.unmodifiableList(notices);
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account
   * contains at least one static password.
   *
   * @return  {@code Boolean.TRUE} if the account has at least one static
   *          password, {@code Boolean.FALSE} if the account does not have any
   *          static password, or {@code null} if this flag was not included in
   *          the password policy state JSON object.
   */
  @Nullable()
  public Boolean getHasStaticPassword()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         HAS_STATIC_PASSWORD.getFieldName());
  }



  /**
   * Retrieves the time that the user's password was last changed.
   *
   * @return  The time that the user's password was last changed, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object.
   */
  @Nullable()
  public Date getPasswordChangedTime()
  {
    return getDate(PASSWORD_CHANGED_TIME);
  }



  /**
   * Retrieves the length of time in seconds that has passed since the user's
   * password was last changed.
   *
   * @return  The length of time in seconds that has passed since the user's
   *          password was last changed, or {@code null} if this was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Integer getSecondsSincePasswordChange()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_PASSWORD_CHANGE.getFieldName());
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
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_DISABLED.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account is
   * not yet active because it has an activation time that is in the future.
   *
   * @return  {@code Boolean.TRUE} if the account is not yet active,
   *          {@code Boolean.FALSE} if the account either does not have an
   *          activation time or if that time has already passed, or
   *          {@code null} if this flag was not included in the password policy
   *          state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsNotYetActive()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_NOT_YET_ACTIVE.getFieldName());
  }



  /**
   * Retrieves the time that the user's account became (or will become) active.
   *
   * @return  The time that the user's account became (or will become) active,
   *          or {@code null} if this was not included in the password policy
   *          state JSON object.
   */
  @Nullable()
  public Date getAccountActivationTime()
  {
    return getDate(ACCOUNT_ACTIVATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds until the user's account will
   * become active.
   *
   * @return  The length of time in seconds until the user's account will become
   *          active, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., because the user does not have an
   *          activation time in the future).
   */
  @Nullable()
  public Integer getSecondsUntilAccountActivation()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_ACCOUNT_ACTIVATION.getFieldName());
  }



  /**
   * Retrieves the length of time in seconds since the user's account became
   * active.
   *
   * @return  The length of time in seconds since the user's account became
   *          active, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., because the user does not have an
   *          activation time in the past).
   */
  @Nullable()
  public Integer getSecondsSinceAccountActivation()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_ACCOUNT_ACTIVATION.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account is
   * expired.
   *
   * @return  {@code Boolean.TRUE} if the account is expired,
   *          {@code Boolean.FALSE} if the account is not expired, or
   *          {@code null} if this flag was not included in the password policy
   *          state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsExpired()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_EXPIRED.getFieldName());
  }



  /**
   * Retrieves the time that the user's account will (or did) expire.
   *
   * @return  The time that the user's account will (or did) expire, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object.
   */
  @Nullable()
  public Date getAccountExpirationTime()
  {
    return getDate(ACCOUNT_EXPIRATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds until the user's account will
   * expire.
   *
   * @return  The length of time in seconds until the user's account will
   *          expire, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., because the user does not have an
   *          expiration time in the future).
   */
  @Nullable()
  public Integer getSecondsUntilAccountExpiration()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_ACCOUNT_EXPIRATION.getFieldName());
  }



  /**
   * Retrieves the length of time in seconds since the user's account expired.
   *
   * @return  The length of time in seconds since the user's account expired,
   *          or {@code null} if this was not included in the password policy
   *          state JSON object (e.g., because the user does not have an
   *          expiration time in the past).
   */
  @Nullable()
  public Integer getSecondsSinceAccountExpiration()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_ACCOUNT_EXPIRATION.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's password is
   * expired.
   *
   * @return  {@code Boolean.TRUE} if the password is expired,
   *          {@code Boolean.FALSE} if the password is not expired, or
   *          {@code null} if this flag was not included in the password policy
   *          state JSON object.
   */
  @Nullable()
  public Boolean getPasswordIsExpired()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         PASSWORD_IS_EXPIRED.getFieldName());
  }



  /**
   * Retrieves the maximum length of time in seconds after a password change
   * that the user is allowed to keep using that password.
   *
   * @return  The maximum length of time in seconds after a password change that
   *          the user is allowed to keep using that password, or {@code null}
   *          if this flag was not included in the password policy state JSON
   *          object (e.g., because password expiration is not configured in the
   *          password policy that governs the user).
   */
  @Nullable()
  public Integer getMaximumPasswordAgeSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_PASSWORD_AGE_SECONDS.getFieldName());
  }



  /**
   * Retrieves the time that the user's password will (or did) expire.
   *
   * @return  The time that the user's password will (or did) expire, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object (e.g., because password expiration is not configured
   *          in the password policy that governs the user).
   */
  @Nullable()
  public Date getPasswordExpirationTime()
  {
    return getDate(PASSWORD_EXPIRATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds until the user's password will
   * expire.
   *
   * @return  The length of time in seconds until the user's password will
   *          expire, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., because password expiration is not
   *          configured in the password policy that governs the user, or
   *          because the user's password is already expired).
   */
  @Nullable()
  public Integer getSecondsUntilPasswordExpiration()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_PASSWORD_EXPIRATION.getFieldName());
  }



  /**
   * Retrieves the length of time in seconds since the user's password expired.
   *
   * @return  The length of time in seconds since the user's password expired,
   *          or {@code null} if this was not included in the password policy
   *          state JSON object (e.g., because password expiration is not
   *          configured in the password policy that governs the user, or
   *          because the user's password is not expired).
   */
  @Nullable()
  public Integer getSecondsSincePasswordExpiration()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_PASSWORD_EXPIRATION.getFieldName());
  }



  /**
   * Retrieves the length of time in seconds before an upcoming password
   * expiration that the user will be eligible to start receving warnings about
   * that expiration.
   *
   * @return  The length of time in seconds before an upcoming password
   *          expiration that the user will be eligible to start receiving
   *          messages about that expiration, or {@code null} if this was not
   *          included in the password policy state JSON object (e.g., because
   *          password expiration is not configured in the password policy that
   *          governs the user).
   */
  @Nullable()
  public Integer getPasswordExpirationWarningIntervalSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         PASSWORD_EXPIRATION_WARNING_INTERVAL_SECONDS.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the server will allow
   * a user's password to expire even if they have not yet received any warnings
   * about an upcoming expiration.
   *
   * @return  {@code Boolean.TRUE} if the server will allow a user's password to
   *          expire even if they have not been warned about an upcoming
   *          expiration, {@code Boolean.FALSE} if the server will ensure that
   *          the user receives at least one warning before expiring the
   *          password, or {@code null} if this flag was not included in the
   *          password policy state JSON object (e.g., because password
   *          expiration is not configured in the password policy that governs
   *          the user).
   */
  @Nullable()
  public Boolean getExpirePasswordsWithoutWarning()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         EXPIRE_PASSWORDS_WITHOUT_WARNING.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user has
   * received at least one warning about an upcoming password expiration.
   *
   * @return  {@code Boolean.TRUE} if the user has received at least one warning
   *          about an upcoming password expiration, {@code Boolean.FALSE} if
   *          the user has not been warned about an upcoming password
   *          expiration, or {@code null} if this flag was not included in the
   *          password policy state JSON object (e.g., because password
   *          expiration is not configured in the password policy that governs
   *          the user).
   */
  @Nullable()
  public Boolean getPasswordExpirationWarningIssued()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         PASSWORD_EXPIRATION_WARNING_ISSUED.getFieldName());
  }



  /**
   * Retrieves the time that the user will be eligible to receive (or the time
   * that the user first received) a warning about an upcoming password
   * expiration.
   *
   * @return  The time that the user will be eligible to receive (or the time
   *          that the user first received) a warning about an upcoming password
   *          expiration, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because password
   *          expiration is not configured in the password policy that governs
   *          the user).
   */
  @Nullable()
  public Date getPasswordExpirationWarningTime()
  {
    return getDate(PASSWORD_EXPIRATION_WARNING_TIME);
  }



  /**
   * Retrieves the length of time in seconds until the user will be eligible to
   * receive a warning about an upcoming password expiration.
   *
   * @return  The length of time in seconds until the user will be eligible to
   *          receive a warning about an upcoming password expiration, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object (e.g., because password expiration is not configured
   *          in the password policy that governs the user, or because the user
   *          has already been warned about an upcoming expiration).
   */
  @Nullable()
  public Integer getSecondsUntilPasswordExpirationWarning()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING.getFieldName());
  }



  /**
   * Retrieves the length of time in seconds since the user received the first
   * warning about an upcoming password expiration.
   *
   * @return  The length of time in seconds since the user received the first
   *          warning about an upcoming password expiration, or {@code null} if
   *          this was not included in the password policy state JSON object
   *          (e.g., because password expiration is not configured in the
   *          password policy that governs the user, or because the user has
   *          not yet been warned about an upcoming expiration).
   */
  @Nullable()
  public Integer getSecondsSincePasswordExpirationWarning()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_PASSWORD_EXPIRATION_WARNING.getFieldName());
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
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_FAILURE_LOCKED.getFieldName());
  }



  /**
   * Retrieves the number of consecutive failed authentication attempts that are
   * required to lock the user's account.
   *
   * @return  The number of consecutive failed authentication attempts that are
   *          required to lock the user's account, or {@code null} if this was
   *          not included in the password policy state JSON object (e.g.,
   *          because account lockout is not configured in the password policy
   *          that governs the user).
   */
  @Nullable()
  public Integer getFailureLockoutCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         FAILURE_LOCKOUT_COUNT.getFieldName());
  }



  /**
   * Retrieves the current number of failed authentication attempts for the
   * user account.
   *
   * @return  The current number of failed authentication attempts for the user
   *          account, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., because account lockout is not
   *          configured in the password policy that governs the user).
   */
  @Nullable()
  public Integer getCurrentAuthenticationFailureCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         CURRENT_AUTHENTICATION_FAILURE_COUNT.getFieldName());
  }



  /**
   * Retrieves the remaining number of failed authentication attempts required
   * to lock the user account.
   *
   * @return  The remaining number of failed authentication attempts required to
   *          lock the user account, or {@code null} if this was not included in
   *          the password policy state JSON object (e.g., because account
   *          lockout is not configured in the password policy that governs the
   *          user).
   */
  @Nullable()
  public Integer getRemainingAuthenticationFailureCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         REMAINING_AUTHENTICATION_FAILURE_COUNT.getFieldName());
  }



  /**
   * Retrieves a list of the outstanding authentication failure times for the
   * user account.
   *
   * @return  A list of the outstanding authentication failure times for the
   *          user account, or an empty list if there are no outstanding
   *          authentication failures or if this was not included in the
   *          password policy state JSON object (e.g., because account lockout
   *          is not configured in the password policy that governs the user).
   */
  @NotNull()
  public List<Date> getAuthenticationFailureTimes()
  {
    final List<Date> authFailureTimes = new ArrayList<>();

    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         AUTHENTICATION_FAILURE_TIMES.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        try
        {
          final String valueString = ((JSONString) v).stringValue();
          authFailureTimes.add(StaticUtils.decodeRFC3339Time(valueString));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    return Collections.unmodifiableList(authFailureTimes);
  }



  /**
   * Retrieves the time that the user's account was locked as a result of too
   * many failed authentication attempts.
   *
   * @return  The time that the user's account was locked as a result of too
   *          many failed authentication attempts, or {@code null} if this was
   *          not included in the password policy state JSON object (e.g.,
   *          because the user's account is not failure locked).
   */
  @Nullable()
  public Date getFailureLockoutTime()
  {
    return getDate(FAILURE_LOCKOUT_TIME);
  }



  /**
   * Retrieves the length of time in seconds that a user's account will be
   * locked after too many failed authentication attempts.
   *
   * @return  The length of time in seconds that a user's account will be
   *          locked after too many failed authentication attempts, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object (e.g., because account lockout is not configured in
   *          the password policy that governs the user, or because account
   *          lockout is not temporary).
   */
  @Nullable()
  public Integer getFailureLockoutDurationSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         FAILURE_LOCKOUT_DURATION_SECONDS.getFieldName());

  }



  /**
   * Retrieves the time that the user's failure-locked account will be
   * automatically unlocked.
   *
   * @return  The time that the user's failure-locked account will be
   *          automatically unlocked, or {@code null} if this was not included
   *          in the password policy state JSON object (e.g., because the user's
   *          account is not failure locked, or because the lockout is not
   *          temporary).
   */
  @Nullable()
  public Date getFailureLockoutExpirationTime()
  {
    return getDate(FAILURE_LOCKOUT_EXPIRATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds remaining until the user's
   * failure-locked account will be automatically unlocked.
   *
   * @return  The length of time in seconds remaining until the user's
   *          failure-locked account will be automatically unlocked, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object (e.g., because the user's account is not failure
   *          locked, or because the lockout is not temporary).
   */
  @Nullable()
  public Integer getSecondsRemainingInFailureLockout()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_REMAINING_IN_FAILURE_LOCKOUT.getFieldName());
  }



  /**
   * Retrieves the time that the user last successfully authenticated to the
   * server.
   *
   * @return  The time that the user last successfully authenticated to the
   *          server, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., because last login time tracking
   *          is not configured in the password policy that governs the user).
   */
  @Nullable()
  public Date getLastLoginTime()
  {
    return getDate(LAST_LOGIN_TIME);
  }



  /**
   * Retrieves the length of time in seconds since the user last successfully
   * authenticated to the server.
   *
   * @return  The length of time in seconds since the user last successfully
   *          authenticated to the server, or {@code null} if this was not
   *          included in the password policy state JSON object (e.g., because
   *          last login time tracking is not configured in the password policy
   *          that governs the user).
   */
  @Nullable()
  public Integer getSecondsSinceLastLogin()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_LAST_LOGIN.getFieldName());
  }



  /**
   * Retrieves the IP address of the client from which the user last
   * successfully authenticated.
   *
   * @return  The IP address of the client from which the user last successfully
   *          authenticated, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because last login IP
   *          address tracking is not configured in the password policy that
   *          governs the user).
   */
  @Nullable()
  public String getLastLoginIPAddress()
  {
    return passwordPolicyStateObject.getFieldAsString(
         LAST_LOGIN_IP_ADDRESS.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account is
   * currently locked because it has been too long since they last authenticated
   * to the server.
   *
   * @return  {@code Boolean.TRUE} if the user's account is currently
   *          idle-locked, {@code Boolean.FALSE} if the user's account is not
   *          currently idle-locked, or {@code null} if this flag was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsIdleLocked()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_IDLE_LOCKED.getFieldName());
  }



  /**
   * Retrieves the maximum length of time in seconds that can elapse between
   * successful authentications before the user's account is locked.
   *
   * @return  The maximum length of time in seconds that can elapse between
   *          successful authentications before the user's account is locked, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object (e.g., because idle lockout is not configured in the
   *          password policy that governs the user).
   */
  @Nullable()
  public Integer getIdleLockoutIntervalSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         IDLE_LOCKOUT_INTERVAL_SECONDS.getFieldName());
  }



  /**
   * Retrieves the time that the user's account will be (or was) locked for
   * allowing too much time to elapse between successful authentications.
   *
   * @return  The time that the user's account will be (or was) locked for
   *          allowing too much time to elapse between successful
   *          authentications, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because idle lockout is
   *          not configured in the password policy that governs the user).
   */
  @Nullable()
  public Date getIdleLockoutTime()
  {
    return getDate(IDLE_LOCKOUT_TIME);
  }



  /**
   * Retrieves the length of time in seconds until the user's account will be
   * locked for allowing too much time to elapse between successful
   * authentications.
   *
   * @return  The length of time in seconds until the user's account will be
   *          locked for allowing too much time to elapse between successful
   *          authentication, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because idle lockout is
   *          not configured in the password policy that governs the user, or
   *          because the user's account is already idle-locked).
   */
  @Nullable()
  public Integer getSecondsUntilIdleLockout()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_IDLE_LOCKOUT.getFieldName());
  }



  /**
   * Retrieves the length of time in seconds since the user's account was
   * locked for allowing too much time to elapse between successful
   * authentications.
   *
   * @return  The length of time in seconds since the user's account was locked
   *          for allowing too much time to elapse between successful
   *          authentication, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because idle lockout is
   *          not configured in the password policy that governs the user, or
   *          because the user's account is not idle-locked).
   */
  @Nullable()
  public Integer getSecondsSinceIdleLockout()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_IDLE_LOCKOUT.getFieldName());
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
    return passwordPolicyStateObject.getFieldAsBoolean(
         MUST_CHANGE_PASSWORD.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user's account is
   * locked because they failed to choose a new password in a timely manner
   * after an administrative reset.
   *
   * @return  {@code Boolean.TRUE} if the user's account is currently
   *          reset-locked, {@code Boolean.FALSE} if the user's account is not
   *          reset-locked, or {@code null} if this flag was not included in the
   *          password policy state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsResetLocked()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_RESET_LOCKED.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the password policy
   * that governs the user is configured to require users to choose a new
   * password the first time they authenticate after their account is created.
   *
   * @return  {@code Boolean.TRUE} if users are required to choose a new
   *          password the first time they authenticate after their account is
   *          created, {@code Boolean.FALSE} if users are not required to choose
   *          a new password after their account is created, or {@code null} if
   *          this flag was not included in the password policy state JSON
   *          object.
   */
  @Nullable()
  public Boolean getForceChangeOnAdd()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         FORCE_CHANGE_ON_ADD.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the password policy
   * that governs the user is configured to require users to choose a new
   * password the first time they authenticate after their password has been
   * reset by an administrator.
   *
   * @return  {@code Boolean.TRUE} if users are required to choose a new
   *          password the first time they authenticate after their password is
   *          reset, {@code Boolean.FALSE} if users are not required to choose
   *          a new password after their password is reset, or {@code null} if
   *          this flag was not included in the password policy state JSON
   *          object.
   */
  @Nullable()
  public Boolean getForceChangeOnReset()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         FORCE_CHANGE_ON_RESET.getFieldName());
  }



  /**
   * Retrieves the maximum length of time in seconds that a user has to change
   * their password after an administrative reset before their account will be
   * locked.
   *
   * @return  The maximum length of time in seconds that a user has to change
   *          their password after an administrative reset before their account
   *          will be locked, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because reset lockout is
   *          not configured in the password policy that governs the user).
   */
  @Nullable()
  public Integer getMaximumPasswordResetAgeSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_PASSWORD_RESET_AGE_SECONDS.getFieldName());
  }



  /**
   * Retrieves the time that the user's account will be (or was) locked after
   * failing to choose a new password in a timely manner after an administrative
   * reset.
   *
   * @return  The time that the user's account will be (or wa) locked after
   *          failing to choose a new password in a timely manner after an
   *          administrative reset, or {@code null} if this was not included in
   *          the password policy state JSON object (e.g., because reset lockout
   *          is not configured in the password policy that governs the user,
   *          or because the user's password has not been reset).
   */
  @Nullable()
  public Date getResetLockoutTime()
  {
    return getDate(RESET_LOCKOUT_TIME);
  }



  /**
   * Retrieves the length of time in seconds until the user's account will be
   * locked for failing to choose a new password after an administrative
   * reset.
   *
   * @return  The length of time in seconds until the user's account will be
   *          locked for failing to choose a new password after an
   *          administrative reset, or {@code null} if this was not included in
   *          the password policy state JSON object (e.g., because reset lockout
   *          is not configured in the password policy that governs the user,
   *          because the user's password has not been reset, or because the
   *          user's account is already reset-locked).
   */
  @Nullable()
  public Integer getSecondsUntilResetLockout()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_RESET_LOCKOUT.getFieldName());
  }



  /**
   * Retrieves the maximum number of passwords that the server will maintain in
   * the user's password history.
   *
   * @return  The maximum number of passwords that the server will maintain in
   *          the user's password history, or {@code null} if this was not
   *          included in the password policy state JSON object (e.g., because
   *          the password policy that governs the user is not configured to
   *          maintain a password history, or because it maintains a password
   *          history based on a duration rather than a count).
   */
  @Nullable()
  public Integer getMaximumPasswordHistoryCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_PASSWORD_HISTORY_COUNT.getFieldName());
  }



  /**
   * Retrieves the maximum length of time in seconds that the server will
   * maintain passwords in the user's password history.
   *
   * @return  The maximum length of time in seconds that the server will
   *           maintain passwords in the user's password history, or
   *           {@code null} if this was not included in the password policy
   *           state JSON object (e.g., because the password policy that governs
   *           the user is not configured to maintain a password history, or
   *           because it maintains a password history based on a count rather
   *           than a duration).
   */
  @Nullable()
  public Integer getMaximumPasswordHistoryDurationSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_PASSWORD_HISTORY_DURATION_SECONDS.getFieldName());
  }



  /**
   * Retrieves the number of passwords currently held in the user's password
   * history.
   *
   * @return  The number of passwords currently held in the user's password
   *          history, or {@code null} if this was not incldued in the password
   *          policy state JSON object (e.g., because the password policy that
   *          governs the user is not configured to maintain a password
   *          history).
   */
  @Nullable()
  public Integer getCurrentPasswordHistoryCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         CURRENT_PASSWORD_HISTORY_COUNT.getFieldName());
  }



  /**
   * Indicates whether the user is currently prohibited from changing their
   * password because not enough time has elapsed since they last changed their
   * password.
   *
   * @return  {@code Boolean.TRUE} if the user is currently prohibited from
   *          changing their password because not enough time has elapsed since
   *          they last changed their password, {@code Boolean.FALSE} if the
   *          user is not prohibited from changing their password because of the
   *          minimum password age, or {@code null} if this flag was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getIsWithinMinimumPasswordAge()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         IS_WITHIN_MINIMUM_PASSWORD_AGE.getFieldName());
  }



  /**
   * Retrieves the minimum length of time in seconds that must elapse after a
   * user changes their password before they will be permitted to change it
   * again.
   *
   * @return  The minimum length of time in seconds that must elapse after a
   *          user changes their password before they will be permitted to
   *          change it again, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because no minimum
   *          password age is configured in the password policy that governs the
   *          user).
   */
  @Nullable()
  public Integer getMinimumPasswordAgeSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MINIMUM_PASSWORD_AGE_SECONDS.getFieldName());
  }



  /**
   * Retrieves the earliest time that the user will be permitted to change their
   * password as a result of the minimum password age.
   *
   * @return  The earliest time that the user will be permitted to change their
   *          password as a result of the minimum password age, or {@code null}
   *          if this was not included in the password policy state JSON
   *          object (e.g., because no minimum password age is configured in the
   *          password policy that governs the user, or because it has been
   *          longer than the minimum age since they last changed their
   *          password).
   */
  @Nullable()
  public Date getMinimumPasswordAgeExpirationTime()
  {
    return getDate(MINIMUM_PASSWORD_AGE_EXPIRATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds remaining until the user will be
   * permitted to change their password as a result of the minimum password age.
   *
   * @return  The length of time in seconds remaining until the user will be
   *          permitted to change their password as a result of the minimum
   *          password age, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because no minimum
   *          password age is configured in the password policy that governs the
   *          user, or because it has been longer than the minimum age since
   *          they last changed their password).
   */
  @Nullable()
  public Integer getSecondsRemainingInMinimumPasswordAge()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_REMAINING_IN_MINIMUM_PASSWORD_AGE.getFieldName());
  }



  /**
   * Retrieves the maximum number of grace login attempts that the user will
   * have to allow them to change an expired password.
   *
   * @return  The maximum number of grace login attempts that the user will have
   *          to allow them to change an expired password, or {@code null} if
   *          this was not included in the password policy state JSON object
   *          (e.g., if grace logins are not configured in the password policy
   *          that governs the user).
   */
  @Nullable()
  public Integer getMaximumGraceLoginCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_GRACE_LOGIN_COUNT.getFieldName());
  }



  /**
   * Retrieves the number of grace logins that the user has currently used.
   *
   * @return  The number of grace login attempts that the user has currently
   *          used, or {@code null} if this was not included in the password
   *          policy state JSON object (e.g., if grace logins are not configured
   *          in the password policy that governs the user).
   */
  @Nullable()
  public Integer getUsedGraceLoginCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         USED_GRACE_LOGIN_COUNT.getFieldName());
  }



  /**
   * Retrieves the remaining number of grace logins for the user.
   *
   * @return  The remaining number of grace logins for the user, or {@code null}
   *          if this was not included in the password policy state JSON object
   *          (e.g., if grace logins are not configured in the password policy
   *          that governs the user).
   */
  @Nullable()
  public Integer getRemainingGraceLoginCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         REMAINING_GRACE_LOGIN_COUNT.getFieldName());
  }



  /**
   * Retrieves a list of the times that the user has used a grace login to
   * authenticate.
   *
   * @return  A list of the times that the user has used a grace login to
   *          authenticate, or an empty list if the user has not used any grace
   *          logins, or if this was not included in the password policy state
   *          JSON object (e.g., if grace logins are not configured in the
   *          password policy that governs the user).
   */
  @NotNull()
  public List<Date> getGraceLoginUseTimes()
  {
    final List<Date> graceLoginTimes = new ArrayList<>();

    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         GRACE_LOGIN_USE_TIMES.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        try
        {
          final String valueString = ((JSONString) v).stringValue();
          graceLoginTimes.add(StaticUtils.decodeRFC3339Time(valueString));
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    return Collections.unmodifiableList(graceLoginTimes);
  }



  /**
   * Retrieves the value of a flag that indicates whether the user account has a
   * retired former password that may still be used to authenticate.
   *
   * @return  {@code Boolean.TRUE} if the user account currently has a valid
   *          retired password, {@code Boolean.FALSE} if the user account does
   *          not have a valid retired password, or {@code null} if this flag
   *          was not included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getHasRetiredPassword()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         HAS_RETIRED_PASSWORD.getFieldName());
  }



  /**
   * Retrieves the time that the user's retired password will expire and can no
   * longer be used to authenticate.
   *
   * @return  The time that the user's retired password will expire, or
   *          {@code null} if this was not included in the password policy state
   *          JSON object (e.g., because the user does not have a retired
   *          password).
   */
  @Nullable()
  public Date getRetiredPasswordExpirationTime()
  {
    return getDate(RETIRED_PASSWORD_EXPIRATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds remaining until the user's retired
   * password expires and can no longer be used to authenticate.
   *
   * @return  The length of time in seconds remaining until the user's retired
   *          password expires, or {@code null} if this was not included in the
   *          password policy state JSON object (e.g., because the user does not
   *          have a retired password).
   */
  @Nullable()
  public Integer getSecondsUntilRetiredPasswordExpiration()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_UNTIL_RETIRED_PASSWORD_EXPIRATION.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user will be
   * required to authenticate in a secure manner that does not reveal their
   * credentials to an observer.
   *
   * @return  {@code Boolean.TRUE} if the user will be required to authenticate
   *          in a secure manner, {@code Boolean.FALSE} if the user will not be
   *          required to authenticate in a secure manner, or {@code null} if
   *          this flag was not included in the password policy state JSON
   *          object.
   */
  @Nullable()
  public Boolean getRequireSecureAuthentication()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         REQUIRE_SECURE_AUTHENTICATION.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user will be
   * required to change their password in a secure manner that does not reveal
   * their credentials to an observer.
   *
   * @return  {@code Boolean.TRUE} if the user will be required to change their
   *          password in a secure manner, {@code Boolean.FALSE} if the user
   *          will not be required to change their password in a secure manner,
   *          or {@code null} if this flag was not included in the password
   *          policy state JSON object.
   */
  @Nullable()
  public Boolean getRequireSecurePasswordChanges()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         REQUIRE_SECURE_PASSWORD_CHANGES.getFieldName());
  }



  /**
   * Retrieves a list of the names of the SASL mechanisms that the user can use
   * to authenticate.
   *
   * @return  A list of the names of the SASL mechanisms that the user can use
   *          to authenticate, or an empty list if no SASL mechanisms are
   *          available to the user or if this was not included in the password
   *          policy state JSON object.
   */
  @NotNull()
  public List<String> getAvailableSASLMechanisms()
  {
    final List<String> saslMechanismNames = new ArrayList<>();

    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         AVAILABLE_SASL_MECHANISMS.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        try
        {
          saslMechanismNames.add(((JSONString) v).stringValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    return Collections.unmodifiableList(saslMechanismNames);
  }



  /**
   * Retrieves a list of the names of the OTP delivery mechanisms that the user
   * can use to receive one-time passwords, password reset tokens, and
   * single-use tokens.
   *
   * @return  A list of the names of the OTP delivery mechanisms that the user
   *          can use, or an empty list if no OTP delivery mechanisms are
   *          available to the user or if this was not included in the password
   *          policy state JSON object.
   */
  @NotNull()
  public List<String> getAvailableOTPDeliveryMechanisms()
  {
    final List<String> deliveryMechanismNames = new ArrayList<>();

    final List<JSONValue> values = passwordPolicyStateObject.getFieldAsArray(
         AVAILABLE_OTP_DELIVERY_MECHANISMS.getFieldName());
    if (values != null)
    {
      for (final JSONValue v : values)
      {
        try
        {
          deliveryMechanismNames.add(((JSONString) v).stringValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    return Collections.unmodifiableList(deliveryMechanismNames);
  }



  /**
   * Retrieves the value of a flag that indicates whether the user account has
   * at least one TOTP shared secret that can be used to authenticate with
   * time-based one-time passwords via the UNBOUNDID-TOTP SASL mechanism.
   *
   * @return  {@code Boolean.TRUE} if the user account has at least one TOTP
   *          shared secret, {@code Boolean.FALSE} if the user account does not
   *          have any TOTP shared secrets, or {@code null} if this flag was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getHasTOTPSharedSecret()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         HAS_TOTP_SHARED_SECRET.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user account has
   * at least one registered YubiKey OTP device that can be used to authenticate
   * via the UNBOUNDID-YUBIKEY-OTP SASL mechanism.
   *
   * @return  {@code Boolean.TRUE} if the user account has at least one
   *          registered YubiKey OTP device, {@code Boolean.FALSE} if the user
   *          account does not have any registered YubiKey OTP devices, or
   *          {@code null} if this flag was not included in the password policy
   *          state JSON object.
   */
  @Nullable()
  public Boolean getHasRegisteredYubiKeyOTPDevice()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         HAS_REGISTERED_YUBIKEY_OTP_DEVICE.getFieldName());
  }



  /**
   * Retrieves the value of a flag that indicates whether the user account is
   * currently locked because it contains a password that does not satisfy all
   * of the configured password validators.
   *
   * @return  {@code Boolean.TRUE} if the user account is locked because it
   *          contains a password that does not satisfy all of the configured
   *          password validators, {@code Boolean.FALSE} if the account is not
   *          validation-locked, or {@code null} if this flag was not included
   *          in the password policy state JSON object.
   */
  @Nullable()
  public Boolean getAccountIsValidationLocked()
  {
    return passwordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_VALIDATION_LOCKED.getFieldName());
  }



  /**
   * Retrieves the time that the server last invoked password validators during
   * a bind operation for the user.
   *
   * @return  The time that the server last invoked password validators during a
   *          bind operation for the user, or {@code null} if this was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Date getLastBindPasswordValidationTime()
  {
    return getDate(LAST_BIND_PASSWORD_VALIDATION_TIME);
  }



  /**
   * Retrieves the length of time in seconds that has passed since the server
   * last invoked password validators during a bind operation for the user.
   *
   * @return  The length of time in seconds that has passed since the server
   *          last invoked password validators during a bind operation for the
   *          user, or {@code null} if this was not included in the password
   *          policy state JSON object.
   */
  @Nullable()
  public Integer getSecondsSinceLastBindPasswordValidation()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION.getFieldName());
  }



  /**
   * Retrieves the minimum length of time in seconds that should pass between
   * invocations of password validators during a bind operation for the user.
   *
   * @return  The minimum length of time in seconds that should pass between
   *          invocations of password validators during a bind operation for
   *          each user, or {@code null} if this was not included in the
   *          password policy state JSON object.
   */
  @Nullable()
  public Integer getMinimumBindPasswordValidationFrequencySeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MINIMUM_BIND_PASSWORD_VALIDATION_FREQUENCY_SECONDS.getFieldName());
  }



  /**
   * Retrieves the name of the action that the server should take if the
   * password provided during a bind operation fails to satisfy one or more
   * password validators.
   *
   * @return  The name of the action that the server should take if the password
   *          provided during a bind operation fails to satisfy one or more
   *          password validators, or {@code null} if this was not included in
   *          the password policy state JSON object.
   */
  @Nullable()
  public String getBindPasswordValidationFailureAction()
  {
    return passwordPolicyStateObject.getFieldAsString(
         BIND_PASSWORD_VALIDATION_FAILURE_ACTION.getFieldName());
  }



  /**
   * Retrieves the recent login history for the user.
   *
   * @return  The recent login history for the user, or {@code null} if this was
   *          not included in the password policy state JSON object.
   *
   * @throws  LDAPException  If a problem occurs while trying to parse the
   *                         recent login history for the user.
   */
  @Nullable()
  public RecentLoginHistory getRecentLoginHistory()
         throws LDAPException
  {
    final JSONObject o = passwordPolicyStateObject.getFieldAsObject(
         RECENT_LOGIN_HISTORY.getFieldName());
    if (o == null)
    {
      return null;
    }
    else
    {
      return new RecentLoginHistory(o);
    }
  }



  /**
   * Retrieves the maximum number of recent successful login attempts the server
   * should maintain for a user.
   *
   * @return  The maximum number of recent successful login attempts the server
   *          should maintain for a user, or {@code null}if this was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Integer getMaximumRecentLoginHistorySuccessfulAuthenticationCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_COUNT.
              getFieldName());
  }



  /**
   * Retrieves the maximum age in seconds of recent successful login attempts
   * the server should maintain for a user.
   *
   * @return  The maximum age in seconds of recent successful login attempts the
   *          server should maintain for a user, or {@code null}if this was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Integer
       getMaximumRecentLoginHistorySuccessfulAuthenticationDurationSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_RECENT_LOGIN_HISTORY_SUCCESSFUL_AUTHENTICATION_DURATION_SECONDS
              .getFieldName());
  }



  /**
   * Retrieves the maximum number of recent failed login attempts the server
   * should maintain for a user.
   *
   * @return  The maximum number of recent failed login attempts the server
   *          should maintain for a user, or {@code null}if this was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Integer getMaximumRecentLoginHistoryFailedAuthenticationCount()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_COUNT.
              getFieldName());
  }



  /**
   * Retrieves the maximum age in seconds of recent failed login attempts
   * the server should maintain for a user.
   *
   * @return  The maximum age in seconds of recent failed login attempts the
   *          server should maintain for a user, or {@code null}if this was not
   *          included in the password policy state JSON object.
   */
  @Nullable()
  public Integer
       getMaximumRecentLoginHistoryFailedAuthenticationDurationSeconds()
  {
    return passwordPolicyStateObject.getFieldAsInteger(
         MAXIMUM_RECENT_LOGIN_HISTORY_FAILED_AUTHENTICATION_DURATION_SECONDS.
              getFieldName());
  }



  /**
   * Retrieves the list of quality requirements that must be satisfied for
   * passwords included in new entries that are added using the same password
   * policy as the associated entry.
   *
   * @return  The list of password quality requirements that will be enforced
   *          for adds using the same password policy as the associated entry,
   *          or an empty list if no requirements will be imposed.
   */
  @NotNull()
  public List<PasswordQualityRequirement> getAddPasswordQualityRequirements()
  {
    return getPasswordQualityRequirements(REQUIREMENT_FIELD_APPLIES_TO_ADD);
  }



  /**
   * Retrieves the list of quality requirements that must be satisfied when the
   * associated user attempts to change their own password.
   *
   * @return  The list of password quality requirements that will be enforced
   *          for self password changes, or an empty list if no requirements
   *          will be imposed.
   */
    @NotNull()
  public List<PasswordQualityRequirement>
            getSelfChangePasswordQualityRequirements()
  {
    return getPasswordQualityRequirements(
         REQUIREMENT_FIELD_APPLIES_TO_SELF_CHANGE);
  }



  /**
   * Retrieves the list of quality requirements that must be satisfied when an
   * administrator attempts to change the user's password.
   *
   * @return  The list of password quality requirements that will be enforced
   *          for administrative password resets, or an empty list if no
   *          requirements will be imposed.
   */
  @NotNull()
  public List<PasswordQualityRequirement>
            getAdministrativeResetPasswordQualityRequirements()
  {
    return getPasswordQualityRequirements(
         REQUIREMENT_FIELD_APPLIES_TO_ADMIN_RESET);
  }



  /**
   * Retrieves the list of quality requirements that must be satisfied when the
   * associated user authenticates in a manner that makes the clear-text
   * password available to the server.
   *
   * @return  The list of password quality requirements that will be enforced
   *          for binds, or an empty list if no requirements will be imposed.
   */
  @NotNull()
  public List<PasswordQualityRequirement> getBindPasswordQualityRequirements()
  {
    return getPasswordQualityRequirements(REQUIREMENT_FIELD_APPLIES_TO_BIND);
  }



  /**
   * Retrieves a list of the password quality requirements that are contained in
   * the JSON object in which the indicated Boolean field is present and set to
   * {@code true}.
   *
   * @param  booleanFieldName  The name of the field that is expected to be
   *                           present with a Boolean value of true for each
   *                           requirement to be included in the list that is
   *                           returned.
   *
   * @return  The appropriate list of password quality requirements, or an empty
   *          list if no requirements will be imposed.
   */
  @NotNull()
  private List<PasswordQualityRequirement> getPasswordQualityRequirements(
       @NotNull final String booleanFieldName)
  {
    final List<JSONValue> requirementObjectLst =
         passwordPolicyStateObject.getFieldAsArray(
              PASSWORD_QUALITY_REQUIREMENTS.getFieldName());
    if ((requirementObjectLst == null) || requirementObjectLst.isEmpty())
    {
      return Collections.emptyList();
    }

    final List<PasswordQualityRequirement> requirements =
         new ArrayList<>(requirementObjectLst.size());
    for (final JSONValue requirementObjectValue : requirementObjectLst)
    {
      if (! (requirementObjectValue instanceof JSONObject))
      {
        continue;
      }

      final JSONObject requirementObject = (JSONObject) requirementObjectValue;
      final Boolean include = requirementObject.getFieldAsBoolean(
           booleanFieldName);
      if ((include == null) || (! include.booleanValue()))
      {
        continue;
      }

      final String description =
           requirementObject.getFieldAsString(REQUIREMENT_FIELD_DESCRIPTION);
      if (description == null)
      {
        continue;
      }

      final String clientSideValidationType =
           requirementObject.getFieldAsString(
                REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_TYPE);

      final Map<String,String> clientSideValidationProperties =
           new LinkedHashMap<>();
      final List<JSONValue> propertyValues = requirementObject.getFieldAsArray(
           REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_PROPERTIES);
      if (propertyValues != null)
      {
        for (final JSONValue propertyValue : propertyValues)
        {
          if (! (propertyValue instanceof JSONObject))
          {
            continue;
          }

          final JSONObject propertyObject = (JSONObject) propertyValue;
          final String name = propertyObject.getFieldAsString(
               REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_PROPERTY_NAME);
          final String value = propertyObject.getFieldAsString(
               REQUIREMENT_FIELD_CLIENT_SIDE_VALIDATION_PROPERTY_VALUE);
          if ((name != null) && (value != null))
          {
            clientSideValidationProperties.put(name, value);
          }
        }
      }

      requirements.add(new PasswordQualityRequirement(description,
           clientSideValidationType, clientSideValidationProperties));
    }

    return requirements;
  }



  /**
   * Retrieves the value of the specified field as a {@code Date}.
   *
   * @param  field  The field whose value is to be retrieved and parsed as a
   *                {@code Date}.
   *
   * @return  The value of the specified field as a {@code Date}, or
   *          {@code null} if the field is not contained in the JSON object or
   *          if its value cannot be parsed as a {@code Date}.
   */
  @Nullable()
  private Date getDate(@NotNull final PasswordPolicyStateJSONField field)
  {
    final String stringValue =
         passwordPolicyStateObject.getFieldAsString(field.getFieldName());
    if (stringValue == null)
    {
      return null;
    }

    try
    {
      return StaticUtils.decodeRFC3339Time(stringValue);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
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
    return passwordPolicyStateObject.toSingleLineString();
  }
}
