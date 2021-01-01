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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

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
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a data structure with information about recent successful
 * and failed login attempts for a user.
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
public final class RecentLoginHistory
       implements Serializable
{
  /**
   * The name of the JSON field used to hold the set of failed attempts.
   */
  @NotNull private static final String JSON_FIELD_FAILED_ATTEMPTS =
       "failed-attempts";



  /**
   * The name of the JSON field used to hold the set of successful attempts.
   */
  @NotNull private static final String JSON_FIELD_SUCCESSFUL_ATTEMPTS =
       "successful-attempts";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5692706886656940486L;



  // The JSON object providing an encoded representation of the recent login
  // history.
  @NotNull private final JSONObject jsonObject;

  // A set of the recent failed authentication attempts.
  @NotNull private final SortedSet<RecentLoginHistoryAttempt> failedAttempts;

  // A set of the recent successful authentication attempts.
  @NotNull private final SortedSet<RecentLoginHistoryAttempt>
       successfulAttempts;



  /**
   * Creates a new recent login history with the provided sets of successful and
   * failed attempts.
   *
   * @param  successfulAttempts  A list of recent successful authentication
   *                             attempts.  It may be {@code null} or empty if
   *                             there were no recent successful attempts.
   * @param  failedAttempts      A list of recent failed authentication
   *                             attempts.  It may be {@code null} or empty if
   *                             there were no recent failed attempts.
   */
  public RecentLoginHistory(
       @Nullable final Collection<RecentLoginHistoryAttempt> successfulAttempts,
       @Nullable final Collection<RecentLoginHistoryAttempt> failedAttempts)
  {
    final List<JSONValue> successValues = new ArrayList<>();
    final SortedSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    if (successfulAttempts != null)
    {
      for (final RecentLoginHistoryAttempt a : successfulAttempts)
      {
        successes.add(a);
        successValues.add(a.asJSONObject());
      }
    }
    this.successfulAttempts = Collections.unmodifiableSortedSet(successes);


    final List<JSONValue> failureValues = new ArrayList<>();
    final SortedSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    if (failedAttempts != null)
    {
      for (final RecentLoginHistoryAttempt a : failedAttempts)
      {
        failures.add(a);
        failureValues.add(a.asJSONObject());
      }
    }
    this.failedAttempts = Collections.unmodifiableSortedSet(failures);


    jsonObject = new JSONObject(
         new JSONField(JSON_FIELD_SUCCESSFUL_ATTEMPTS,
              new JSONArray(successValues)),
         new JSONField(JSON_FIELD_FAILED_ATTEMPTS,
              new JSONArray(failureValues)));
  }



  /**
   * Creates a new recent login history that is decoded from the provided JSON
   * object.
   *
   * @param  jsonObject  A JSON object containing an encoded representation of
   *                     the recent login history.  It must not be
   * {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided JSON object as a recent login history.
   */
  public RecentLoginHistory(@NotNull final JSONObject jsonObject)
         throws LDAPException
  {
    Validator.ensureNotNull(jsonObject,
         "RecentLoginHistory.<init>.jsonObject must not be null.");

    this.jsonObject = jsonObject;

    final SortedSet<RecentLoginHistoryAttempt> successes = new TreeSet<>();
    final List<JSONValue> successValues =
         jsonObject.getFieldAsArray(JSON_FIELD_SUCCESSFUL_ATTEMPTS);
    if (successValues != null)
    {
      for (final JSONValue v : successValues)
      {
        try
        {
          successes.add(new RecentLoginHistoryAttempt((JSONObject) v));
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_RECENT_LOGIN_HISTORY_CANNOT_PARSE_SUCCESS.get(
                    jsonObject.toSingleLineString(), e.getMessage()),
               e);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_RECENT_LOGIN_HISTORY_CANNOT_PARSE_SUCCESS.get(
                    jsonObject.toSingleLineString(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }

    final SortedSet<RecentLoginHistoryAttempt> failures = new TreeSet<>();
    final List<JSONValue> failureValues =
         jsonObject.getFieldAsArray(JSON_FIELD_FAILED_ATTEMPTS);
    if (failureValues != null)
    {
      for (final JSONValue v : failureValues)
      {
        try
        {
          failures.add(new RecentLoginHistoryAttempt((JSONObject) v));
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_RECENT_LOGIN_HISTORY_CANNOT_PARSE_FAILURE.get(
                    jsonObject.toSingleLineString(), e.getMessage()),
               e);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_RECENT_LOGIN_HISTORY_CANNOT_PARSE_FAILURE.get(
                    jsonObject.toSingleLineString(),
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }

    successfulAttempts = Collections.unmodifiableSortedSet(successes);
    failedAttempts = Collections.unmodifiableSortedSet(failures);
  }



  /**
   * Retrieves the set of recent successful login attempts.
   *
   * @return  The set of recent successful login attempts.
   */
  @NotNull()
  public SortedSet<RecentLoginHistoryAttempt> getSuccessfulAttempts()
  {
    return successfulAttempts;
  }



  /**
   * Retrieves the set of recent failed login attempts.
   *
   * @return  The set of recent failed login attempts.
   */
  @NotNull()
  public SortedSet<RecentLoginHistoryAttempt> getFailedAttempts()
  {
    return failedAttempts;
  }



  /**
   * Retrieves a JSON object with an encoded representation of this recent
   * login history.
   *
   * @return  A JSON object with an encoded representation of this recent long
   *          history.
   */
  @NotNull()
  public JSONObject asJSONObject()
  {
    return jsonObject;
  }



  /**
   * Retrieves a string representation of this recent login history.
   *
   * @return  A string representation of this recent login history.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return jsonObject.toSingleLineString();
  }
}
