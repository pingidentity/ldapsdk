/*
 * Copyright 2021-2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021-2022 Ping Identity Corporation
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
 * Copyright (C) 2021-2022 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class implements an extended result that may be returned in response to
 * a {@link ReplaceListenerCertificateExtendedRequest}.  See the
 * {@link ReplaceCertificateExtendedResult} class for a description of the
 * content for the result.
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
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplaceListenerCertificateExtendedResult
       extends ReplaceCertificateExtendedResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8514170861819417947L;



  /**
   * Creates a new replace listener certificate extended result that is decoded
   * from the provided extended result.
   *
   * @param  extendedResult  The generic extended result to decode as a replace
   *                         listener certificate extended result.  It must not
   *                         be {@code null}.
   *
   * @throws  LDAPException  If the provided extended result cannot be decoded
   *                         as a replace listener certificate extended result.
   */
  public ReplaceListenerCertificateExtendedResult(
                 @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);
  }



  /**
   * Creates a new replace listener certificate extended result with the
   * provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  toolOutput         The output (a combined representation of both
   *                            standard output and standard error) obtained
   *                            from running the {@code replace-certificate}
   *                            tool.  It may be {@code null} if request
   *                            processing failed before running the tool.
   * @param  responseControls   The set of controls to include in the extended
   *                            result.  It may be {@code null} or empty if no
   *                            response controls should be included.
   */
  public ReplaceListenerCertificateExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final String toolOutput,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ReplaceListenerCertificateExtendedRequest.
              REPLACE_LISTENER_CERT_REQUEST_OID,
         toolOutput, responseControls);
  }
}
