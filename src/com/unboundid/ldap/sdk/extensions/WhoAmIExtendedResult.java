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
package com.unboundid.ldap.sdk.extensions;


import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class implements a data structure for storing the information from an
 * extended result for the "Who Am I?" extended request as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4532.txt">RFC 4532</A>.  It is able to
 * decode a generic extended result to extract the returned authorization
 * identify from it.
 * <BR><BR>
 * See the documentation for the {@link WhoAmIExtendedRequest} class for an
 * example that demonstrates using the "Who Am I?" extended operation.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class WhoAmIExtendedResult
       extends ExtendedResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7466531316632846077L;



  // The authorization identity string returned by the server.
  @Nullable private final String authorizationID;



  /**
   * Creates a new "Who Am I?" extended result from the provided extended
   * result.
   *
   * @param  extendedResult  The extended result to be decoded as a "Who Am I?"
   *                         extended result.
   */
  public WhoAmIExtendedResult(@NotNull final ExtendedResult extendedResult)
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      authorizationID = null;
    }
    else
    {
      authorizationID = value.stringValue();
    }
  }



  /**
   * Creates a new "Who Am I?" extended result with the provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  authorizationID    The authorization ID for this response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public WhoAmIExtendedResult(final int messageID,
                              @NotNull final ResultCode resultCode,
                              @Nullable final String diagnosticMessage,
                              @Nullable final String matchedDN,
                              @Nullable final String[] referralURLs,
                              @Nullable final String authorizationID,
                              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(authorizationID), responseControls);

    this.authorizationID = authorizationID;
  }



  /**
   * Encodes the value for this extended result using the provided information.
   *
   * @param  authorizationID  The authorization ID for this response.
   *
   * @return  An ASN.1 octet string containing the encoded value, or
   *          {@code null} if there should not be an encoded value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
                                      @Nullable final String authorizationID)
  {
    if (authorizationID == null)
    {
      return null;
    }
    else
    {
      return new ASN1OctetString(authorizationID);
    }
  }



  /**
   * Retrieves the authorization ID for this "Who Am I?" extended result, if
   * available.
   *
   * @return  The authorization ID for this "Who Am I?" extended result, or
   *          {@code null} if none was provided.
   */
  @Nullable()
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_WHO_AM_I.get();
  }



  /**
   * Appends a string representation of this extended result to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which a string representation of this
   *                 extended result will be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("WhoAmIExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (authorizationID != null)
    {
      buffer.append(", authorizationID='");
      buffer.append(authorizationID);
      buffer.append('\'');
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
