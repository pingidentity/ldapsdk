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



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  The use of interactive transactions is discouraged because it
 *   can create conditions which are prone to deadlocks between operations that
 *   may result in the cancellation of one or both operations.  It is strongly
 *   recommended that standard LDAP transactions (which may be started using a
 *   {@link com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest})
 *   or a multi-update extended operation be used instead.  Although they cannot
 *   include arbitrary read operations, LDAP transactions and multi-update
 *   operations may be used in conjunction with the
 *   {@link com.unboundid.ldap.sdk.controls.AssertionRequestControl},
 *   {@link com.unboundid.ldap.sdk.controls.PreReadRequestControl}, and
 *   {@link com.unboundid.ldap.sdk.controls.PostReadRequestControl} to
 *   incorporate some read capability into a transaction, and in conjunction
 *   with the {@link com.unboundid.ldap.sdk.ModificationType#INCREMENT}
 *   modification type to increment integer values without the need to know the
 *   precise value before or after the operation (although the pre-read and/or
 *   post-read controls may be used to determine that).
 * </BLOCKQUOTE>
 * This class implements a data structure for storing the information from an
 * extended result for the start interactive transaction extended request.  It
 * is able to decode a generic extended result to extract the transaction ID and
 * base DNs that it may contain, if the operation was successful.
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
 * See the documentation for the
 * {@link StartInteractiveTransactionExtendedRequest} class for an example that
 * demonstrates the use of interactive transactions.
 *
 * @deprecated  The use of interactive transactions is strongly discouraged
 *              because it can create conditions which are prone to deadlocks
 *              between operations that may significantly affect performance and
 *              will result in the cancellation of one or both operations.
 */
@Deprecated()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StartInteractiveTransactionExtendedResult
       extends ExtendedResult
{
  /**
   * The BER type for the {@code txnID} element of the response.
   */
  private static final byte TYPE_TXN_ID = (byte) 0x80;



  /**
   * The BER type for the {@code baseDNs} element of the response.
   */
  private static final byte TYPE_BASE_DNS = (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4010094216900393866L;



  // The transaction ID returned by the server.
  @Nullable private final ASN1OctetString transactionID;

  // The list of base DNs returned by the server, if any.
  @Nullable private final List<String> baseDNs;



  /**
   * Creates a new start interactive transaction extended result from the
   * provided extended result.
   *
   * @param  extendedResult  The extended result to be decoded as a start
   *                         interactive transaction extended result.  It must
   *                         not be {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended result as a start interactive
   *                         transaction extended result.
   */
  public StartInteractiveTransactionExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    if (! extendedResult.hasValue())
    {
      transactionID = null;
      baseDNs       = null;
      return;
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement =
           ASN1Element.decode(extendedResult.getValue().getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_START_INT_TXN_RESULT_VALUE_NOT_SEQUENCE.get(e.getMessage()), e);
    }

    ASN1OctetString txnID      = null;
    List<String>    baseDNList = null;
    for (final ASN1Element element : valueSequence.elements())
    {
      switch (element.getType())
      {
        case TYPE_TXN_ID:
          txnID = ASN1OctetString.decodeAsOctetString(element);
          break;
        case TYPE_BASE_DNS:
          try
          {
            final ASN1Sequence baseDNsSequence =
                 ASN1Sequence.decodeAsSequence(element);
            final ArrayList<String> dnList =
                 new ArrayList<>(baseDNsSequence.elements().length);
            for (final ASN1Element e : baseDNsSequence.elements())
            {
              dnList.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            baseDNList = Collections.unmodifiableList(dnList);
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_START_INT_TXN_RESULT_BASE_DNS_NOT_SEQUENCE.get(
                      e.getMessage()), e);
          }
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_START_INT_TXN_RESULT_INVALID_ELEMENT.get(
                    StaticUtils.toHex(element.getType())));
      }
    }

    transactionID = txnID;
    baseDNs       =  baseDNList;

    if (transactionID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_START_INT_TXN_RESULT_NO_TXN_ID.get());
    }
  }



  /**
   * Creates a new start interactive transaction extended result with the
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
   * @param  transactionID      The transaction ID for this response, if
   *                            available.
   * @param  baseDNs            The list of base DNs for this response, if
   *                            available.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public StartInteractiveTransactionExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final ASN1OctetString transactionID,
              @Nullable final List<String> baseDNs,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(transactionID, baseDNs), responseControls);

    this.transactionID = transactionID;

    if (baseDNs == null)
    {
      this.baseDNs = null;
    }
    else
    {
      this.baseDNs =
           Collections.unmodifiableList(new ArrayList<>(baseDNs));
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended result.
   *
   * @param  transactionID  The transaction ID for this response, if available.
   * @param  baseDNs        The list of base DNs for this response, if
   *                        available.
   *
   * @return  The ASN.1 octet string containing the encoded value, or
   *          {@code null} if no value should be used.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
                      @Nullable final ASN1OctetString transactionID,
                      @Nullable final List<String> baseDNs)
  {
    if ((transactionID == null) && (baseDNs == null))
    {
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(2);
    if (transactionID != null)
    {
      elements.add(new ASN1OctetString(TYPE_TXN_ID, transactionID.getValue()));
    }

    if ((baseDNs != null) && (! baseDNs.isEmpty()))
    {
      final ArrayList<ASN1Element> baseDNElements =
           new ArrayList<>(baseDNs.size());
      for (final String s : baseDNs)
      {
        baseDNElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_BASE_DNS, baseDNElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the transaction ID for this start interactive transaction
   * extended result, if available.
   *
   * @return  The transaction ID for this start interactive transaction extended
   *          result, or {@code null} if none was provided.
   */
  @Nullable()
  public ASN1OctetString getTransactionID()
  {
    return transactionID;
  }



  /**
   * Retrieves the list of base DNs for this start interactive transaction
   * extended result, if available.
   *
   * @return  The list of base DNs for this start interactive transaction
   *          extended result, or {@code null} if no base DN list was provided.
   */
  @Nullable()
  public List<String> getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_START_INTERACTIVE_TXN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("StartInteractiveTransactionExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (transactionID != null)
    {
      buffer.append(", transactionID='");
      buffer.append(transactionID.stringValue());
      buffer.append('\'');
    }

    if (baseDNs != null)
    {
      buffer.append(", baseDNs={");
      for (int i=0; i < baseDNs.size(); i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(baseDNs.get(i));
        buffer.append('\'');
      }
      buffer.append('}');
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
