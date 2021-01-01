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
package com.unboundid.ldap.sdk.extensions;



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the notice of disconnection extended
 * result as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc4511.txt">RFC 4511</A>.  It may be used
 * as an unsolicited notification to indicate that the directory server is
 * closing the client connection.
 * <BR><BR>
 * See the {@link com.unboundid.ldap.sdk.UnsolicitedNotificationHandler}
 * interface for a mechanism that can be used to receive and handle unsolicited
 * notifications.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class NoticeOfDisconnectionExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.1466.20036) for the notice of disconnection extended
   * result.
   */
  @NotNull public static final String NOTICE_OF_DISCONNECTION_RESULT_OID =
       "1.3.6.1.4.1.1466.20036";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4706102471360689558L;



  /**
   * Creates a new instance of this notice of disconnection extended result from
   * the provided generic extended result.
   *
   * @param  resultCode         The result code for the notice of disconnection.
   * @param  diagnosticMessage  The diagnostic message to include in the
   *                            notice of disconnection.  It may be {@code null}
   *                            if no diagnostic message should be included.
   * @param  responseControls   The set of controls to include in the notice of
   *                            disconnection.  It may be {@code null} or empty
   *                            if no response controls are needed.
   */
  public NoticeOfDisconnectionExtendedResult(
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final Control... responseControls)
  {
    this(0, resultCode, diagnosticMessage, null, null, responseControls);
  }



  /**
   * Creates a new instance of this notice of disconnection extended result from
   * the provided generic extended result.
   *
   * @param  extendedResult  The extended result to use to create this notice of
   *                         disconnection extended result.
   */
  public NoticeOfDisconnectionExtendedResult(
              @NotNull final ExtendedResult extendedResult)
  {
    super(extendedResult);
  }



  /**
   * Creates a new instance of this notice of disconnection extended result from
   * the provided LDAP exception.
   *
   * @param  ldapException  The LDAP exception to use to create this notice of
   *                        disconnection extended result.
   */
  public NoticeOfDisconnectionExtendedResult(
              @NotNull final LDAPException ldapException)
  {
    this(0, ldapException.getResultCode(), ldapException.getDiagnosticMessage(),
         ldapException.getMatchedDN(), ldapException.getReferralURLs(),
         ldapException.getResponseControls());
  }



  /**
   * Creates a new instance of this notice of disconnection extended result from
   * the provided information.
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
  public NoticeOfDisconnectionExtendedResult(
              final int messageID, @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          NOTICE_OF_DISCONNECTION_RESULT_OID, null, responseControls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_NOTICE_OF_DISCONNECT.get();
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
    buffer.append("NoticeOfDisconnectionExtendedResult(resultCode=");
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
    buffer.append(NOTICE_OF_DISCONNECTION_RESULT_OID);

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
