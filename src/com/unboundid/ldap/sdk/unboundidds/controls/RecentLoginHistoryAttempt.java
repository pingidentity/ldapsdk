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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a data structure with information about a recent login
 * attempt for a user.
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
 * @see  GetRecentLoginHistoryRequestControl
 * @see  GetRecentLoginHistoryResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RecentLoginHistoryAttempt
       implements Serializable, Comparable<RecentLoginHistoryAttempt>
{
  /**
   * The name of the JSON field used to hold the additional attempt count.
   */
  @NotNull private static final String JSON_FIELD_ADDITIONAL_ATTEMPT_COUNT =
       "additional-attempt-count";



  /**
   * The name of the JSON field used to hold the authentication method.
   */
  @NotNull private static final String JSON_FIELD_AUTHENTICATION_METHOD =
       "authentication-method";



  /**
   * The name of the JSON field used to hold the client IP address.
   */
  @NotNull private static final String JSON_FIELD_CLIENT_IP_ADDRESS =
       "client-ip-address";



  /**
   * The name of the JSON field used to provide a general reason that the
   * attempt was not successful.
   */
  @NotNull private static final String JSON_FIELD_FAILURE_REASON =
       "failure-reason";



  /**
   * The name of the JSON field used to indicate whether the attempt was
   * successful.
   */
  @NotNull private static final String JSON_FIELD_SUCCESSFUL = "successful";



  /**
   * The name of the JSON field used to hold the timestamp.
   */
  @NotNull private static final String JSON_FIELD_TIMESTAMP = "timestamp";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6060214815221896077L;



  // Indicates whether the authentication attempt was successful.
  private final boolean successful;

  // The JSON object providing an encoded representation of this attempt.
  @NotNull private final JSONObject jsonObject;

  // The number of additional authentication attempts on the same date (in the
  // UTC time zone) as this attempt with the same values for the successful,
  // authentication method, client IP address, and failure reason fields.
  @Nullable private final Long additionalAttemptCount;

  // The time that the authentication attempt occurred.
  private final long timestamp;

  // The name of the authentication method attempted by the client.
  @NotNull  private final String authenticationMethod;

  // The IP address of the client, if available.
  @Nullable private final String clientIPAddress;

  // A general reason that the authentication attempt failed, if available.
  @Nullable private final String failureReason;



  /**
   * Creates a new recent login history attempt object with the provided
   * information.
   *
   * @param  successful              Indicates whether the attempt was
   *                                 successful.
   * @param  timestamp               The time of the authentication attempt.
   * @param  authenticationMethod    The name of the authentication method
   *                                 used for the attempt.  This must not be
   *                                 {@code null} or empty.
   * @param  clientIPAddress         The IP address of the client that made the
   *                                 authentication attempt.  This may be
   *                                 {@code null} if no client IP address is
   *                                 available.
   * @param  failureReason           A general reason that the authentication
   *                                 attempt failed.  It must be {@code null} if
   *                                 the attempt succeeded and must not be
   *                                 {@code null} if the attempt failed.  If
   *                                 provided, the value should be one of the
   *                                 {@code FAILURE_NAME_}* constants in the
   *                                 {@link AuthenticationFailureReason} class.
   * @param  additionalAttemptCount  The number of additional authentication
   *                                 attempts that occurred on the same date (in
   *                                 the UTC time zone) as the provided
   *                                 timestamp with the same values for the
   *                                 successful, authentication method, client
   *                                 IP address, and failure reason fields.  It
   *                                 may be {@code null} if this should not be
   *                                 included (e.g., if information about
   *                                 similar attempts should not be collapsed).
   */
  public RecentLoginHistoryAttempt(final boolean successful,
              final long timestamp,
              @NotNull final String authenticationMethod,
              @Nullable final String clientIPAddress,
              @Nullable final String failureReason,
              @Nullable final Long additionalAttemptCount)
  {
    Validator.ensureNotNullOrEmpty(authenticationMethod,
         "RecentLoginHistoryAttempt.<init>.authenticationMethod must not be " +
              "null or empty.");

    if (successful)
    {
      Validator.ensureTrue((failureReason == null),
           "RecentLoginHistoryAttempt.<init>.failureReason must be null for " +
                "successful authentication attempts.");
    }
    else
    {
      Validator.ensureNotNullOrEmpty(failureReason,
           "RecentLoginHistoryAttempt.<init>.failureReason must not be null " +
                "or empty for failed authentication attempts.");
    }

    this.successful = successful;
    this.timestamp = timestamp;
    this.authenticationMethod = authenticationMethod;
    this.clientIPAddress = clientIPAddress;
    this.failureReason = failureReason;
    this.additionalAttemptCount = additionalAttemptCount;

    jsonObject = encodeToJSON(successful, timestamp, authenticationMethod,
         clientIPAddress, failureReason, additionalAttemptCount);
  }



  /**
   * Creates a new recent login history attempt object that is decoded from the
   * provided JSON object.
   *
   * @param  jsonObject  A JSON object containing an encoded representation of
   *                     the attempt.  It must not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided JSON object as a recent login history
   *                         attempt.
   */
  public RecentLoginHistoryAttempt(@NotNull final JSONObject jsonObject)
         throws LDAPException
  {
    Validator.ensureNotNull(jsonObject,
         "RecentLoginHistoryAttempt.<init>.jsonObject must not be null.");

    this.jsonObject = jsonObject;

    final Boolean successfulBoolean =
         jsonObject.getFieldAsBoolean(JSON_FIELD_SUCCESSFUL);
    if (successfulBoolean == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RECENT_LOGIN_HISTORY_ATTEMPT_MISSING_FIELD.get(
                jsonObject.toSingleLineString(), JSON_FIELD_SUCCESSFUL));
    }
    else
    {
      successful = successfulBoolean;
    }

    final String timestampValue =
         jsonObject.getFieldAsString(JSON_FIELD_TIMESTAMP);
    if (timestampValue == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RECENT_LOGIN_HISTORY_ATTEMPT_MISSING_FIELD.get(
                jsonObject.toSingleLineString(), JSON_FIELD_TIMESTAMP));
    }

    try
    {
      timestamp = StaticUtils.decodeRFC3339Time(timestampValue).getTime();
    }
    catch (final ParseException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RECENT_LOGIN_HISTORY_ATTEMPT_MALFORMED_TIMESTAMP.get(
                jsonObject.toSingleLineString(), timestampValue,
                e.getMessage()),
           e);
    }

    authenticationMethod =
         jsonObject.getFieldAsString(JSON_FIELD_AUTHENTICATION_METHOD);
    if (authenticationMethod == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RECENT_LOGIN_HISTORY_ATTEMPT_MISSING_FIELD.get(
                jsonObject.toSingleLineString(),
                JSON_FIELD_AUTHENTICATION_METHOD));
    }

    clientIPAddress = jsonObject.getFieldAsString(JSON_FIELD_CLIENT_IP_ADDRESS);

    failureReason = jsonObject.getFieldAsString(JSON_FIELD_FAILURE_REASON);
    if (successful)
    {
      if (failureReason != null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_RECENT_LOGIN_HISTORY_ATTEMPT_UNEXPECTED_FAILURE_REASON.get(
                  jsonObject.toSingleLineString()));
      }
    }
    else if (failureReason == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_RECENT_LOGIN_HISTORY_ATTEMPT_MISSING_FAILURE_REASON.get(
                jsonObject.toSingleLineString(), JSON_FIELD_FAILURE_REASON));
    }

    additionalAttemptCount =
         jsonObject.getFieldAsLong(JSON_FIELD_ADDITIONAL_ATTEMPT_COUNT);
  }



  /**
   * Encodes the provided information about a successful authentication attempt
   * to a JSON object.
   *
   * @param  successful              Indicates whether the attempt was
   *                                 successful.
   * @param  timestamp               The time of the authentication attempt.
   * @param  authenticationMethod    The name of the authentication method
   *                                 used for the attempt.  This must not be
   *                                 {@code null} or empty.
   * @param  clientIPAddress         The IP address of the client that made the
   *                                 authentication attempt.  This may be
   *                                 {@code null} if no client IP address is
   *                                 available.
   * @param  failureReason           A general reason that the authentication
   *                                 attempt failed.  It must be {@code null} if
   *                                 the attempt succeeded and must not be
   *                                 {@code null} if the attempt failed.  If
   *                                 provided, the value should be one of the
   *                                 {@code FAILURE_NAME_}* constants in the
   *                                 {@link AuthenticationFailureReason} class.
   * @param  additionalAttemptCount  The number of additional authentication
   *                                 attempts that occurred on the same date (in
   *                                 the UTC time zone) as the provided
   *                                 timestamp with the same values for the
   *                                 successful, authentication method, client
   *                                 IP address, and failure reason fields.  It
   *                                 may be {@code null} if this should not be
   *                                 included (e.g., if information about
   *                                 similar attempts should not be collapsed).
   *
   * @return  A JSON object containing the provided information.
   */
  @NotNull()
  private static JSONObject encodeToJSON(final boolean successful,
               final long timestamp,
               @NotNull final String authenticationMethod,
               @Nullable final String clientIPAddress,
               @Nullable final String failureReason,
               @Nullable final Long additionalAttemptCount)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(6));

    fields.put(JSON_FIELD_SUCCESSFUL, new JSONBoolean(successful));
    fields.put(JSON_FIELD_TIMESTAMP,
         new JSONString(StaticUtils.encodeRFC3339Time(timestamp)));
    fields.put(JSON_FIELD_AUTHENTICATION_METHOD,
         new JSONString(authenticationMethod));

    if (clientIPAddress != null)
    {
      fields.put(JSON_FIELD_CLIENT_IP_ADDRESS, new JSONString(clientIPAddress));
    }

    if (failureReason != null)
    {
      fields.put(JSON_FIELD_FAILURE_REASON, new JSONString(failureReason));
    }

    if (additionalAttemptCount != null)
    {
      fields.put(JSON_FIELD_ADDITIONAL_ATTEMPT_COUNT,
           new JSONNumber(additionalAttemptCount));
    }

    return new JSONObject(fields);
  }



  /**
   * Indicates whether this recent login history attempt is for a successful
   * login.
   *
   * @return  {@code true} if this recent login history attempt is for a
   *          successful login, or {@code false} if it is for a failed login.
   */
  public boolean isSuccessful()
  {
    return successful;
  }



  /**
   * Retrieves the time that the authentication attempt occurred.
   *
   * @return  The time that the authentication attempt occurred.
   */
  @NotNull()
  public Date getTimestamp()
  {
    return new Date(timestamp);
  }



  /**
   * Retrieves the name of the authentication method that the client used.  The
   * value should generally be one of "simple" (for LDAP simple authentication),
   * "internal" (if the authentication occurred internally within the server),
   * or "SASL {mechanism}" (if the client authenticated via some SASL
   * mechanism).
   *
   * @return  The name of the authentication method that the client used.
   */
  @NotNull()
  public String getAuthenticationMethod()
  {
    return authenticationMethod;
  }



  /**
   * Retrieves the IP address of the client that made the authentication
   * attempt, if available.
   *
   * @return  The IP address of the client that made the authentication attempt,
   *          or {@code null} if no client IP address is available (e.g.,
   *          because the client authenticated through some internal mechanism).
   */
  @Nullable()
  public String getClientIPAddress()
  {
    return clientIPAddress;
  }



  /**
   * Retrieves a general reason that the authentication attempt failed, if
   * appropriate.
   *
   * @return  A general reason that the authentication attempt failed, or
   *          {@code null} if the attempt was successful.
   */
  @Nullable()
  public String getFailureReason()
  {
    return failureReason;
  }



  /**
   * Retrieves the number of additional authentication attempts that occurred on
   * the same date (in the UTC time zone) as the timestamp for this attempt and
   * had the same values for the successful, authentication method, client IP
   * address, and failure reason fields.
   *
   * @return  The number of additional similar authentication attempts that
   *          occurred on the same date as this attempt, or {@code null} if this
   *          is not available (e.g., because the server is not configured to
   *          collapse information about multiple similar attempts into a
   *          single record).
   */
  @Nullable()
  public Long getAdditionalAttemptCount()
  {
    return additionalAttemptCount;
  }



  /**
   * Retrieves a JSON object with an encoded representation of this recent
   * login history attempt.
   *
   * @return  A JSON object with an encoded representation of this recent long
   *          history attempt.
   */
  @NotNull()
  public JSONObject asJSONObject()
  {
    return jsonObject;
  }



  /**
   * Indicates whether the provided object is logically equivalent to this
   * recent login history attempt object.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is logically equivalent to
   *          this recent login history attempt object, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof RecentLoginHistoryAttempt))
    {
      return false;
    }

    final RecentLoginHistoryAttempt a = (RecentLoginHistoryAttempt) o;
    if (successful != a.successful)
    {
      return false;
    }

    if (timestamp != a.timestamp)
    {
      return false;
    }

    if (! authenticationMethod.equalsIgnoreCase(a.authenticationMethod))
    {
      return false;
    }

    if (! Objects.equals(clientIPAddress, a.clientIPAddress))
    {
      return false;
    }

    if (! Objects.equals(failureReason, a.failureReason))
    {
      return false;
    }

    if (! Objects.equals(additionalAttemptCount, a.additionalAttemptCount))
    {
      return false;
    }

    return true;
  }



  /**
   * Retrieves a hash code for this recent login history attempt.
   *
   * @return  A hash code for this recent login history attempt.
   */
  @Override()
  public int hashCode()
  {
    int hashCode = (successful ? 1 : 0);
    hashCode += (int) timestamp;
    hashCode += StaticUtils.toLowerCase(authenticationMethod).hashCode();

    if (clientIPAddress != null)
    {
      hashCode += StaticUtils.toLowerCase(clientIPAddress).hashCode();
    }

    if (failureReason != null)
    {
      hashCode += StaticUtils.toLowerCase(failureReason).hashCode();
    }

    if (additionalAttemptCount != null)
    {
      hashCode += additionalAttemptCount.hashCode();
    }

    return hashCode;
  }



  /**
   * Retrieves an integer value that indicates the order of the provided recent
   * login history attempt relative to this attempt in a sorted list.
   *
   * @param  a  The recent login history attempt to compare to this attempt.  It
   *            must not be {@code null}.
   *
   * @return  A negative value integer if this attempt should be ordered before
   *          the provided attempt in a sorted list, a positive integer if this
   *          attempt should be ordered after the provided attempt, or zero if
   *          they are logically equivalent.
   */
  @Override()
  public int compareTo(@NotNull final RecentLoginHistoryAttempt a)
  {
    // Order first by timestamp, with newer timestamps coming before older.
    if (timestamp > a.timestamp)
    {
      return -1;
    }
    else if (timestamp < a.timestamp)
    {
      return 1;
    }

    // Order successful attempts ahead of failed attempts.
    if (successful != a.successful)
    {
      if (successful)
      {
        return -1;
      }
      else
      {
        return 1;
      }
    }

    // Order based on the authentication method.
    if (! authenticationMethod.equalsIgnoreCase(a.authenticationMethod))
    {
      return StaticUtils.toLowerCase(authenticationMethod).compareTo(
           StaticUtils.toLowerCase(a.authenticationMethod));
    }

    // Order based on the additional attempt count, with a higher count coming
    // before a lower/nonexistent count.
    if (additionalAttemptCount == null)
    {
      if (a.additionalAttemptCount != null)
      {
        return 1;
      }
    }
    else if (a.additionalAttemptCount == null)
    {
      return -1;
    }
    else if (additionalAttemptCount > a.additionalAttemptCount)
    {
      return -1;
    }
    else if (additionalAttemptCount < a.additionalAttemptCount)
    {
      return 1;
    }

    // Order based on the client IP address.  A null address will be ordered
    // after a non-null address.
    if (clientIPAddress == null)
    {
      if (a.clientIPAddress != null)
      {
        return 1;
      }
    }
    else if (a.clientIPAddress == null)
    {
      return -1;
    }
    else if (! clientIPAddress.equalsIgnoreCase(a.clientIPAddress))
    {
      return StaticUtils.toLowerCase(clientIPAddress).compareTo(
           StaticUtils.toLowerCase(a.clientIPAddress));
    }

    // Order based on the failure reason.  A null reason will be ordered after
    // a non-null reason.
    if ((failureReason != null) &&
         (! failureReason.equalsIgnoreCase(a.failureReason)))
    {
      return StaticUtils.toLowerCase(failureReason).compareTo(
           StaticUtils.toLowerCase(a.failureReason));
    }

    // If we've gotten here, then the records must be considered logically
    // equivalent.
    return 0;
  }



  /**
   * Retrieves a string representation of this recent login history attempt.
   *
   * @return  A string representation of this recent login history attempt.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return jsonObject.toSingleLineString();
  }
}
