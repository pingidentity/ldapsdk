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
package com.unboundid.ldap.sdk;



import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.StringTokenizer;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a bind result that can provide access to the details of
 * a failed OAUTHBEARER SASL bind attempt.
 *
 * @see  OAUTHBEARERBindRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class OAUTHBEARERBindResult
       extends BindResult
{
  /**
   * The name of the failure details field that holds the authorization error
   * code.
   */
  @NotNull private static final String FAILURE_DETAILS_FIELD_AUTHZ_ERROR_CODE =
       "status";



  /**
   * The name of the failure details field that holds the OpenID configuration
   * URL.
   */
  @NotNull private static final String FAILURE_DETAILS_FIELD_OPENID_CONFIG_URL =
       "openid-configuration";



  /**
   * The name of the failure details field that holds the space-delimited set of
   * scopes.
   */
  @NotNull private static final String FAILURE_DETAILS_FIELD_SCOPE = "scope";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6513765034667496311L;



  // The final bind result received during bind processing.
  @Nullable private final BindResult finalBindResult;

  // The initial bind result received during bind processing.
  @NotNull private final BindResult initialBindResult;

  // A JSON object with additional details about a failed authentication
  // attempt.
  @Nullable private final JSONObject failureDetailsObject;

  // The set of scopes included in the failure details object.
  @NotNull private final Set<String> scopes;

  // The authorization error code included in the failure details object.
  @Nullable private final String authorizationErrorCode;

  // The OpenID configuration URL included in the failure details object.
  @Nullable private final String openIDConfigurationURL;



  /**
   * Creates a new OAUTHBEARER bind result from the provided single bind
   * result.  The provided result is not expected to contain server SASL
   * credentials, but it will attempt to decode any credentials included in the
   * provided result.
   *
   * @param  bindResult  The bind result to use to create this OAUTHBEARER bind
   *                     result.  It must not be {@code null}.
   */
  public OAUTHBEARERBindResult(@NotNull final BindResult bindResult)
  {
    this(bindResult, null);
  }



  /**
   * Creates a new OAUTHBEARER bind result from the provided pair of results,
   * which correspond to the initial and final (if any) phases of bind
   * processing.
   *
   * @param  initialBindResult  The result obtained in response to the initial
   *                            OAUTHBEARER bind request.  It must not be
   *                            {@code null}.
   * @param  finalBindResult    The result obtained in response to the final
   *                            OAUTHBEARER bind request, if any.  It may be
   *                            {@code null} if the bind consisted of only a
   *                            single request.
   */
  public OAUTHBEARERBindResult(@NotNull final BindResult initialBindResult,
                               @Nullable final BindResult finalBindResult)
  {
    super(mergeBindResults(initialBindResult, finalBindResult));

    this.initialBindResult = initialBindResult;
    this.finalBindResult = finalBindResult;

    final ASN1OctetString serverSASLCredentials =
         initialBindResult.getServerSASLCredentials();
    if (serverSASLCredentials == null)
    {
      failureDetailsObject = null;
      authorizationErrorCode = null;
      scopes = Collections.emptySet();
      openIDConfigurationURL = null;
      return;
    }

    final JSONObject credentialsObject;
    try
    {
      credentialsObject = new JSONObject(serverSASLCredentials.stringValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      failureDetailsObject = null;
      authorizationErrorCode = null;
      scopes = Collections.emptySet();
      openIDConfigurationURL = null;
      return;
    }

    failureDetailsObject = credentialsObject;
    authorizationErrorCode = credentialsObject.getFieldAsString(
         FAILURE_DETAILS_FIELD_AUTHZ_ERROR_CODE);
    openIDConfigurationURL = credentialsObject.getFieldAsString(
         FAILURE_DETAILS_FIELD_OPENID_CONFIG_URL);

    final String scopeStr =
         credentialsObject.getFieldAsString(FAILURE_DETAILS_FIELD_SCOPE);
    if (scopeStr == null)
    {
      scopes = Collections.emptySet();
      return;
    }

    final Set<String> scopeSet = new LinkedHashSet<>();
    final StringTokenizer tokenizer = new StringTokenizer(scopeStr, " ");
    while (tokenizer.hasMoreTokens())
    {
      scopeSet.add(tokenizer.nextToken());
    }
    scopes = Collections.unmodifiableSet(scopeSet);
  }



  /**
   * Creates a bind result that is merged from the provided results.  If the
   * provided final result is {@code null}, then this will simply return the
   * initial result.  If both are non-{@code null}, then it will use all details
   * from the final result except the server SASL credentials, which will come
   * from the initial result.
   *
   * @param  initialBindResult  The result obtained in response to the initial
   *                            OAUTHBEARER bind request.  It must not be
   *                            {@code null}.
   * @param  finalBindResult    The result obtained in response to the final
   *                            OAUTHBEARER bind request, if any.  It may be
   *                            {@code null} if the bind consisted of only a
   *                            single request.
   *
   * @return  The merged bind results.
   */
  @NotNull()
  private static BindResult mergeBindResults(
               @NotNull final BindResult initialBindResult,
               @Nullable final BindResult finalBindResult)
  {
    if (finalBindResult == null)
    {
      return initialBindResult;
    }

    return new BindResult(finalBindResult.getMessageID(),
         finalBindResult.getResultCode(),
         finalBindResult.getDiagnosticMessage(),
         finalBindResult.getMatchedDN(),
         finalBindResult.getReferralURLs(),
         finalBindResult.getResponseControls(),
         initialBindResult.getServerSASLCredentials());
  }



  /**
   * Retrieves the result obtained from the initial bind attempt in the
   * OAUTHBEARER authentication process.  For a successful authentication, there
   * should only be a single bind.  For a failed authentication attempt, there
   * may be either one or two binds, based on whether credentials were included
   * in the initial bind result.
   *
   * @return  The result obtained from the initial bind attempt in the
   *          OAUTHBEARER authentication process.
   */
  @NotNull()
  public BindResult getInitialBindResult()
  {
    return initialBindResult;
  }



  /**
   * Retrieves the result obtained from the final bind attempt in the
   * OAUTHBEARER authentication process, if any.  This should always be
   * {@code null} for a successful bind, and it may or may not be {@code null}
   * for a failed attempt, based on whether credentials were included in the
   * initial bind result.
   *
   * @return  The result obtained for the final bind attempt in the
   *          OAUTHBEARER authentication process, or {@code null} if the
   *          authentication process only included a single bind.
   */
  @Nullable()
  public BindResult getFinalBindResult()
  {
    return finalBindResult;
  }



  /**
   * Retrieves a JSON object with additional information about a failed
   * authentication attempt, if any.
   *
   * @return  A JSON object with additional information about a failed
   *          authentication attempt, or {@code null} this is not available.
   */
  @Nullable()
  public JSONObject getFailureDetailsObject()
  {
    return failureDetailsObject;
  }



  /**
   * Retrieves the authorization error code obtained from the failure details
   * object, if available.
   *
   * @return  The authorization error code obtained from the failure details
   *          object, or {@code null} if no failure details object was provided
   *          or if it did not include an authorization error code.
   */
  @Nullable()
  public String getAuthorizationErrorCode()
  {
    return authorizationErrorCode;
  }



  /**
   * Retrieves the set of scopes included in the failure details object, if
   * available.
   *
   * @return  The set of scopes included in teh failure details object, or an
   *          empty set if no failure details object was provided or if it did
   *          not include any scopes.
   */
  @NotNull()
  public Set<String> getScopes()
  {
    return scopes;
  }



  /**
   * Retrieves the OpenID configuration URL obtained from the failure details
   * object, if available.
   *
   * @return  The OpenID configuration URL obtained from the failure details
   *          object, or {@code null} if no failure details object was provided
   *          or if it did not include an OpenID configuration URL.
   */
  @Nullable()
  public String getOpenIDConfigurationURL()
  {
    return openIDConfigurationURL;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("OAUTHBEARERBindResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    buffer.append(", hasServerSASLCredentials=");
    buffer.append(getServerSASLCredentials() != null);

    if (finalBindResult != null)
    {
      buffer.append(", initialBindResult=");
      initialBindResult.toString(buffer);

      buffer.append(", finalBindResult=");
      finalBindResult.toString(buffer);
    }

    if (failureDetailsObject != null)
    {
      buffer.append(", failureDetailsObject=");
      failureDetailsObject.toSingleLineString(buffer);
    }

    if (authorizationErrorCode != null)
    {
      buffer.append(", authorizationErrorCode='");
      buffer.append(authorizationErrorCode);
      buffer.append('\'');
    }

    if (! scopes.isEmpty())
    {
      buffer.append(", scopes={");

      final Iterator<String> iterator = scopes.iterator();
      while (iterator.hasNext())
      {
        buffer.append(' ');
        buffer.append(iterator.next());

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append(" }");
    }

    if (openIDConfigurationURL != null)
    {
      buffer.append(", openIDConfigURL='");
      buffer.append(openIDConfigurationURL);
      buffer.append('\'');
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
