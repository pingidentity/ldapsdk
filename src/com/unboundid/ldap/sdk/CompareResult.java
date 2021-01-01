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
package com.unboundid.ldap.sdk;



import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for holding information about the result
 * of processing a compare operation.  It provides generic response elements as
 * described in the {@link LDAPResult} class, and also includes a
 * {@link CompareResult#compareMatched} method for determining whether the
 * compare operation matched the target entry.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CompareResult
       extends LDAPResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6061844770039020617L;



  /**
   * Creates a new compare result based on the provided LDAP result.
   *
   * @param  ldapResult  The LDAP result object to use to create this compare
   *                     response.
   */
  public CompareResult(@NotNull final LDAPResult ldapResult)
  {
    super(ldapResult);
  }



  /**
   * Creates a new compare result from the provided {@code LDAPException}.
   *
   * @param  exception  The {@code LDAPException} to use to create this compare
   *                    result.
   */
  public CompareResult(@NotNull final LDAPException exception)
  {
    super(exception.toLDAPResult());
  }



  /**
   * Creates a new compare result with the provided information.
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
  public CompareResult(final int messageID,
                       @NotNull final ResultCode resultCode,
                       @Nullable final String diagnosticMessage,
                       @Nullable final String matchedDN,
                       @Nullable final String[] referralURLs,
                       @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          responseControls);
  }



  /**
   * Creates a new compare result object with the provided message ID and with
   * the protocol op and controls read from the given ASN.1 stream reader.
   *
   * @param  messageID        The LDAP message ID for the LDAP message that is
   *                          associated with this LDAP result.
   * @param  messageSequence  The ASN.1 stream reader sequence used in the
   *                          course of reading the LDAP message elements.
   * @param  reader           The ASN.1 stream reader from which to read the
   *                          protocol op and controls.
   *
   * @return  The decoded compare result.
   *
   * @throws  LDAPException  If a problem occurs while reading or decoding data
   *                         from the ASN.1 stream reader.
   */
  @NotNull()
  static CompareResult readCompareResultFrom(final int messageID,
              @NotNull final ASN1StreamReaderSequence messageSequence,
              @NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    return new CompareResult(LDAPResult.readLDAPResultFrom(messageID,
                    messageSequence, reader));
  }



  /**
   * Indicates whether the compare operation matched the target entry.
   *
   * @return  {@code true} if the compare operation matched the target entry,
   *          or {@code false} if not.
   */
  public boolean compareMatched()
  {
    return (getResultCode().equals(ResultCode.COMPARE_TRUE));
  }
}
