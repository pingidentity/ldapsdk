/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the aborted transaction extended
 * result as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc5805.txt">RFC 5805</A>, which is used as
 * an unsolicited notification to indicate that the server has aborted an LDAP
 * transaction without the client's explicit request.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AbortedTransactionExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.1.21.4) for the aborted transaction extended result.
   */
  @NotNull public static final String ABORTED_TRANSACTION_RESULT_OID =
       "1.3.6.1.1.21.4";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7521522597566232465L;



  // The transaction ID for the transaction that has been aborted.
  @NotNull private final ASN1OctetString transactionID;



  /**
   * Creates a new instance of this aborted transaction extended result with the
   * provided information.
   *
   * @param  transactionID      The transaction ID of the transaction that has
   *                            been aborted.  It must not be {@code null}.
   * @param  resultCode         The result code for this aborted transaction
   *                            result.  It must not be {@code null}.
   * @param  diagnosticMessage  The diagnostic message for this aborted
   *                            transaction result.  It may be {@code null} if
   *                            there is no diagnostic message.
   * @param  matchedDN          The matched DN for this aborted transaction
   *                            result.  It may be {@code null} if there is no
   *                            matched DN.
   * @param  referralURLs       The referral URLs for this aborted transaction
   *                            result.  It may be {@code null} or empty if
   *                            there are no referral URLs.
   * @param  controls           The controls for this aborted transaction
   *                            result.  It may be {@code null} or empty if
   *                            there are no controls.
   */
  public AbortedTransactionExtendedResult(
              @NotNull final ASN1OctetString transactionID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Control[] controls)
  {
    super(0, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ABORTED_TRANSACTION_RESULT_OID, transactionID, controls);

    Validator.ensureNotNull(transactionID, resultCode);

    this.transactionID = transactionID;
  }



  /**
   * Creates a new instance of this aborted transaction extended result from the
   * provided generic extended result.
   *
   * @param  extendedResult  The extended result to use to create this aborted
   *                         transaction extended result.
   *
   * @throws  LDAPException  If the provided extended result cannot be decoded
   *                         as an aborted transaction extended result.
   */
  public AbortedTransactionExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    transactionID = extendedResult.getValue();
    if (transactionID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ABORTED_TXN_NO_VALUE.get());
    }
  }



  /**
   * Retrieves the transaction ID of the transaction that has been aborted.
   *
   * @return  The transaction ID of the transaction that has been aborted.
   */
  @NotNull()
  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_ABORTED_TXN.get();
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
    buffer.append("AbortedTransactionExtendedResult(transactionID='");
    buffer.append(transactionID.stringValue());
    buffer.append("', resultCode=");
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

    buffer.append(", oid=");
    buffer.append(ABORTED_TRANSACTION_RESULT_OID);

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
