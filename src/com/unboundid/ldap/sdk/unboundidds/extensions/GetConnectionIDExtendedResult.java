/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class implements a data structure for storing the information from an
 * extended result for the get connection ID extended request.  It is able to
 * decode a generic extended result to obtain the associated connection ID.
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
 * <BR>
 * This extended result does not have an OID.  If the request was processed
 * successfully by the server, then the response should have a value that is the
 * BER-encoded integer representation of the connection ID.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetConnectionIDExtendedResult
       extends ExtendedResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3161975076326146250L;



  // The connection ID for the associated client connection.
  private final long connectionID;



  /**
   * Creates a new get connection ID extended result from the provided generic
   * extended result.
   *
   * @param  extendedResult  The generic extended result to be decoded.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended result as a get connection ID
   *                         result.
   */
  public GetConnectionIDExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      connectionID = -1;
      return;
    }

    try
    {
      final ASN1Element e = ASN1Element.decode(value.getValue());
      connectionID = ASN1Long.decodeAsLong(e).longValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_GET_CONN_ID_RESPONSE_VALUE_NOT_INT.get(), e);
    }
  }



  /**
   * Creates a get connection ID extended result with the provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  connectionID       The connection ID for the response.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public GetConnectionIDExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Long connectionID,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(connectionID), responseControls);

    if (connectionID == null)
    {
      this.connectionID = -1;
    }
    else
    {
      this.connectionID = connectionID;
    }
  }



  /**
   * Encodes the value for this extended result using the provided information.
   *
   * @param  connectionID  The connection ID for the response.
   *
   * @return  An ASN.1 octet string containing the properly-encoded value, or
   *          {@code null} if there should be no value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(@Nullable final Long connectionID)
  {
    if ((connectionID == null) || (connectionID < 0))
    {
      return null;
    }
    else
    {
      return new ASN1OctetString(new ASN1Long(connectionID).encode());
    }
  }



  /**
   * Retrieves the connection ID from this response.
   *
   * @return  The connection ID from this response, or -1 if the connection ID
   *          is not available for some reason (e.g., because this is an error
   *          response).
   */
  public long getConnectionID()
  {
    return connectionID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_GET_CONNECTION_ID.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetConnectionIDExtendedResult(connectionID=");
    buffer.append(connectionID);

    buffer.append(", resultCode=");
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
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      buffer.append(", referralURLs={ '");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }
        buffer.append(referralURLs[i]);
      }

      buffer.append("' }");
    }

    final Control[] controls = getResponseControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
