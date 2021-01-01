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

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONNull;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.
                   ModifiablePasswordPolicyStateJSONField.*;
import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides support for reading and decoding the value of the
 * {@code ds-pwp-modifiable-state-json} virtual attribute, which may be used to
 * manipulate elements of a user's password policy state.  The value of this
 * attribute is a JSON object, and using an LDAP modify operation to replace the
 * value with a new JSON object will cause the associated state elements to be
 * updated in the user entry.  The
 * {@link ModifiablePasswordPolicyStateJSONBuilder} class can be used to
 * construct values to more easily manipulate that state.  Note that the
 * {@link PasswordPolicyStateExtendedRequest} class provides a mechanism for
 * manipulating an even broader range of password policy state elements.
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
 * @see  ModifiablePasswordPolicyStateJSONBuilder
 * @see  ModifiablePasswordPolicyStateJSONField
 * @see  PasswordPolicyStateJSON
 * @see  PasswordPolicyStateExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModifiablePasswordPolicyStateJSON
       implements Serializable
{
  /**
   * The name of the operational attribute that holds a JSON representation of
   * the modifiable elements in a user's password policy state.
   */
  @NotNull public static final String
       MODIFIABLE_PASSWORD_POLICY_STATE_JSON_ATTRIBUTE =
            "ds-pwp-modifiable-state-json";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5181314292507625116L;




  // The JSON object that contains the modifiable password policy state
  // information.
  @NotNull private final JSONObject modifiablePasswordPolicyStateObject;



  /**
   * Creates a new instance of this object from the provided JSON object.
   *
   * @param  modifiablePasswordPolicyStateObject
   *              The JSON object containing the encoded modifiable password
   *              policy state.
   */
  public ModifiablePasswordPolicyStateJSON(
       @NotNull final JSONObject modifiablePasswordPolicyStateObject)
  {
    this.modifiablePasswordPolicyStateObject =
         modifiablePasswordPolicyStateObject;
  }



  /**
   * Attempts to retrieve and decode the modifiable password policy state
   * information for the specified user.
   *
   * @param  connection  The connection to use to communicate with the server.
   *                     It must not be {@code null}, and it must be established
   *                     and authenticated as an account with permission to
   *                     access the target user's password policy state
   *                     information.
   * @param  userDN      The DN of the user for whom to retrieve the password
   *                     policy state.  It must not be {@code null}.
   *
   * @return  The modifiable password policy state information for the specified
   *          user, or {@code null} because no modifiable password policy state
   *          information is available for the user.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         retrieve the user's entry or decode the modifiable
   *                         password policy state JSON object.
   */
  @Nullable()
  public static ModifiablePasswordPolicyStateJSON get(
                     @NotNull final LDAPInterface connection,
                     @NotNull final String userDN)
         throws LDAPException
  {
    final SearchResultEntry userEntry = connection.getEntry(userDN,
         MODIFIABLE_PASSWORD_POLICY_STATE_JSON_ATTRIBUTE);
    if (userEntry == null)
    {
      throw new LDAPException(ResultCode.NO_SUCH_OBJECT,
           ERR_MODIFIABLE_PW_POLICY_STATE_JSON_GET_NO_SUCH_USER.get(userDN));
    }

    return get(userEntry);
  }



  /**
   * Attempts to retrieve and decode the modifiable password policy state
   * information from the provided user entry.
   *
   * @param  userEntry  The entry for the user for whom to obtain the modifiable
   *                    password policy state information.  It must not be
   *                    {@code null}.
   *
   * @return  The modifiable password policy state information from the provided
   *          user entry, or {@code null} if no modifiable password policy state
   *          information is available for the user.
   *
   * @throws  LDAPException  If a problem is encountered while trying to decode
   *                         the modifiable password policy state JSON object.
   */
  @Nullable()
  public static ModifiablePasswordPolicyStateJSON get(
              @NotNull final Entry userEntry)
         throws LDAPException
  {
    final String valueString = userEntry.getAttributeValue(
         MODIFIABLE_PASSWORD_POLICY_STATE_JSON_ATTRIBUTE);
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
           ERR_MODIFIABLE_PW_POLICY_STATE_JSON_GET_CANNOT_DECODE.get(
                MODIFIABLE_PASSWORD_POLICY_STATE_JSON_ATTRIBUTE,
                userEntry.getDN()),
           e);
    }

    return new ModifiablePasswordPolicyStateJSON(jsonObject);
  }



  /**
   * Retrieves the JSON object that contains the encoded modifiable password
   * policy state information.
   *
   * @return  The JSON object that contains the encoded modifiable password
   *          policy state information.
   */
  @NotNull()
  public JSONObject getModifiablePasswordPolicyStateJSONObject()
  {
    return modifiablePasswordPolicyStateObject;
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
    return getTimestamp(PASSWORD_CHANGED_TIME);
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
    return modifiablePasswordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_DISABLED.getFieldName());
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
    return getTimestamp(ACCOUNT_ACTIVATION_TIME);
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
    return getTimestamp(ACCOUNT_EXPIRATION_TIME);
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
    return modifiablePasswordPolicyStateObject.getFieldAsBoolean(
         ACCOUNT_IS_FAILURE_LOCKED.getFieldName());
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
    return getTimestamp(PASSWORD_EXPIRATION_WARNED_TIME);
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
    return modifiablePasswordPolicyStateObject.getFieldAsBoolean(
         MUST_CHANGE_PASSWORD.getFieldName());
  }



  /**
   * Decodes the value of the specified field as a timestamp.  The field may
   * have a value that is either a string containing an ISO 8601 timestamp in
   * the format described in RFC 3339, or it may be a JSON null value to
   * indicate that the user does not have the requested timestamp.
   *
   * @param  field  The field whose value is to be retrieved and parsed as a
   *                timestamp.
   *
   * @return  A non-negative value providing the value of the timestamp (in the
   *          number of milliseconds since the epoch, which is the same format
   *          used by the {@code System.currentTimeMillis} method), a negative
   *          value to indicate that the field was present with a value of
   *          {@code null} (and therefore the user did not have that timestamp
   *          in their state), or {@code null} if the field was not present in
   *          the JSON object or if its string value could not be parsed as a
   *          valid timestamp.
   */
  @Nullable()
  private Long getTimestamp(
       @NotNull final ModifiablePasswordPolicyStateJSONField field)
  {
    final JSONValue fieldValue =
         modifiablePasswordPolicyStateObject.getField(field.getFieldName());
    if (fieldValue == null)
    {
      return null;
    }

    if (fieldValue instanceof JSONNull)
    {
      return -1L;
    }
    else  if (fieldValue instanceof JSONString)
    {
      try
      {
        return StaticUtils.decodeRFC3339Time(
             ((JSONString) fieldValue).stringValue()).getTime();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return null;
      }
    }
    else
    {
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
    return modifiablePasswordPolicyStateObject.toSingleLineString();
  }
}
