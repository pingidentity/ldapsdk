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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  The use of interactive transactions is strongly discouraged
 *   because it can create conditions which are prone to deadlocks between
 *   operations that may significantly affect performance and will result in the
 *   cancellation of one or both operations.  It is strongly recommended that
 *   standard LDAP transactions (which may be started using a
 *   {@link com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest})
 *   or a {@link MultiUpdateExtendedRequest} be used instead.  Although they
 *   cannot include arbitrary read operations, LDAP transactions and
 *   multi-update operations may be used in conjunction with the
 *   {@link com.unboundid.ldap.sdk.controls.AssertionRequestControl},
 *   {@link com.unboundid.ldap.sdk.controls.PreReadRequestControl}, and
 *   {@link com.unboundid.ldap.sdk.controls.PostReadRequestControl} to
 *   incorporate some read capability into a transaction, and in conjunction
 *   with the {@link com.unboundid.ldap.sdk.ModificationType#INCREMENT}
 *   modification type to increment integer values without the need to know the
 *   precise value before or after the operation (although the pre-read and/or
 *   post-read controls may be used to determine that).
 * </BLOCKQUOTE>
 * This class provides an implementation of the interactive transaction aborted
 * extended result, which is used as an unsolicited notification to indicate
 * that the server has aborted an interactive transaction without the client's
 * explicit request.
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
 * @deprecated  The use of interactive transactions is strongly discouraged
 *              because it can create conditions which are prone to deadlocks
 *              between operations that may significantly affect performance and
 *              will result in the cancellation of one or both operations.
 */
@Deprecated()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class InteractiveTransactionAbortedExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.5) for the interactive transaction aborted
   * extended result.
   */
  @NotNull public static final String
       INTERACTIVE_TRANSACTION_ABORTED_RESULT_OID =
            "1.3.6.1.4.1.30221.2.6.5";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 296814913448182605L;



  /**
   * Creates a new instance of this interactive transaction aborted extended
   * result from the provided generic extended result.
   *
   * @param  extendedResult  The extended result to use to create this
   *                         interactive transaction aborted extended result.
   */
  public InteractiveTransactionAbortedExtendedResult(
              @NotNull final ExtendedResult extendedResult)
  {
    super(extendedResult);
  }



  /**
   * Creates a new instance of this interactive transaction aborted extended
   * result from the provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public InteractiveTransactionAbortedExtendedResult(
              final int messageID, @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          INTERACTIVE_TRANSACTION_ABORTED_RESULT_OID, null, responseControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_INTERACTIVE_TXN_ABORTED.get();
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
    buffer.append("InteractiveTransactionAbortedExtendedResult(resultCode=");
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
    buffer.append(INTERACTIVE_TRANSACTION_ABORTED_RESULT_OID);

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
