/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that can be used
 * to provide information about the processing for a
 * {@link MultiUpdateExtendedRequest}.  The OID for this result is
 * 1.3.6.1.4.1.30221.2.6.18, and the value (if present) should have the
 * following encoding:
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
 * <PRE>
 *   MultiUpdateResultValue ::= SEQUENCE {
 *        changesApplied     ENUMERATED {
 *             none        (0),
 *             all         (1),
 *             partial     (2),
 *             ... },
 *        responses     SEQUENCE OF SEQUENCE {
 *             responseOp     CHOICE {
 *                  modifyResponse     ModifyResponse,
 *                  addResponse        AddResponse,
 *                  delResponse        DelResponse,
 *                  modDNResponse      ModifyDNResponse,
 *                  extendedResp       ExtendedResponse,
 *                  ... },
 *             controls       [0] Controls OPTIONAL,
 *             ... },
 *        ... }
 * </PRE>
 *
 * @see MultiUpdateChangesApplied
 * @see MultiUpdateExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MultiUpdateExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.18) for the multi-update extended result.
   */
  @NotNull public static final String MULTI_UPDATE_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.18";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2529988892013489969L;



  // The set of results for the operations that were processed.
  @NotNull private final List<ObjectPair<OperationType,LDAPResult>> results;

  // The changes applied value for this result.
  @Nullable private final MultiUpdateChangesApplied changesApplied;



  /**
   * Creates a new multi-update extended result from the provided extended
   * result.
   *
   * @param  extendedResult  The extended result to be decoded as a multi-update
   *                         result.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided extended result as a
   *                         multi-update result.
   */
  public MultiUpdateExtendedResult(@NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      changesApplied = MultiUpdateChangesApplied.NONE;
      results        = Collections.emptyList();
      return;
    }

    try
    {
      final ASN1Element[] outerSequenceElements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      final int cav = ASN1Enumerated.decodeAsEnumerated(
           outerSequenceElements[0]).intValue();
      changesApplied = MultiUpdateChangesApplied.valueOf(cav);
      if (changesApplied == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MULTI_UPDATE_RESULT_INVALID_CHANGES_APPLIED.get(cav));
      }

      final ASN1Element[] responseSetElements =
           ASN1Sequence.decodeAsSequence(outerSequenceElements[1]).elements();
      final ArrayList<ObjectPair<OperationType,LDAPResult>> rl =
           new ArrayList<>(responseSetElements.length);
      for (final ASN1Element rse : responseSetElements)
      {
        final ASN1Element[] elements =
             ASN1Sequence.decodeAsSequence(rse).elements();
        final Control[] controls;
        if (elements.length == 2)
        {
          controls = Control.decodeControls(
               ASN1Sequence.decodeAsSequence(elements[1]));
        }
        else
        {
          controls = null;
        }

        switch (elements[0].getType())
        {
          case LDAPMessage.PROTOCOL_OP_TYPE_ADD_RESPONSE:
            rl.add(new ObjectPair<>(OperationType.ADD,
                 AddResponseProtocolOp.decodeProtocolOp(elements[0]).
                      toLDAPResult(controls)));
            break;
          case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_RESPONSE:
            rl.add(new ObjectPair<>(OperationType.DELETE,
                 DeleteResponseProtocolOp.decodeProtocolOp(elements[0]).
                      toLDAPResult(controls)));
            break;
          case LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_RESPONSE:
            rl.add(new ObjectPair<OperationType,LDAPResult>(
                 OperationType.EXTENDED,
                 ExtendedResponseProtocolOp.decodeProtocolOp(elements[0]).
                      toExtendedResult(controls)));
            break;
          case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_RESPONSE:
            rl.add(new ObjectPair<>(OperationType.MODIFY,
                 ModifyResponseProtocolOp.decodeProtocolOp(elements[0]).
                      toLDAPResult(controls)));
            break;
          case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_RESPONSE:
            rl.add(new ObjectPair<>(OperationType.MODIFY_DN,
                 ModifyDNResponseProtocolOp.decodeProtocolOp(elements[0]).
                      toLDAPResult(controls)));
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_MULTI_UPDATE_RESULT_DECODE_INVALID_OP_TYPE.get(
                      StaticUtils.toHex(elements[0].getType())));
        }
      }

      results = Collections.unmodifiableList(rl);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MULTI_UPDATE_RESULT_CANNOT_DECODE_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new multi-update extended request with the provided information.
   *
   * @param  messageID          The message ID for this extended result.
   * @param  resultCode         The result code for this result.  It must not be
   *                            {@code null}.
   * @param  diagnosticMessage  The diagnostic message to include in the result.
   *                            It may be {@code null} if no diagnostic message
   *                            should be included.
   * @param  matchedDN          The matched DN to include in the result.  It may
   *                            be {@code null} if no matched DN should be
   *                            included.
   * @param  referralURLs       The set of referral URLs to include in the
   *                            result.  It may be {@code null} or empty if no
   *                            referral URLs should be included.
   * @param  changesApplied     The value which indicates whether any or all of
   *                            the changes from the request were successfully
   *                            applied.
   * @param  results            The set of operation results to be included in
   *                            the extended result value.  It may be
   *                            {@code null} or empty if no operation results
   *                            should be included.
   * @param  controls           The set of controls to include in the
   *                            multi-update result.  It may be {@code null} or
   *                            empty if no controls should be included.
   *
   * @throws  LDAPException  If any of the results are for an inappropriate
   *                         operation type.
   */
  public MultiUpdateExtendedResult(final int messageID,
       @NotNull final ResultCode resultCode,
       @Nullable final String diagnosticMessage,
       @Nullable final String matchedDN,
       @Nullable final String[] referralURLs,
       @Nullable final MultiUpdateChangesApplied changesApplied,
       @Nullable final List<ObjectPair<OperationType,LDAPResult>> results,
       @Nullable final Control... controls)
       throws LDAPException
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         MULTI_UPDATE_RESULT_OID, encodeValue(changesApplied, results),
         controls);

    this.changesApplied = changesApplied;

    if (results == null)
    {
      this.results = Collections.emptyList();
    }
    else
    {
      this.results = Collections.unmodifiableList(results);
    }
  }



  /**
   * Encodes the information from the provided set of results into a form
   * suitable for use as the value of a multi-update extended result.
   *
   * @param  changesApplied  The value which indicates whether any or all of the
   *                         changes from the request were successfully applied.
   * @param  results         The set of operation results to be included in the
   *                         extended result value.  It may be {@code null} or
   *                         empty if no operation results should be included.
   *
   * @return  An ASN.1 element suitable for use as the value of a multi-update
   *          extended result.
   *
   * @throws  LDAPException  If any of the results are for an inappropriate
   *                         operation type.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
       @Nullable final MultiUpdateChangesApplied changesApplied,
       @Nullable final List<ObjectPair<OperationType,LDAPResult>> results)
       throws LDAPException
  {
    if ((results == null) || results.isEmpty())
    {
      return null;
    }

    final ArrayList<ASN1Element> opElements = new ArrayList<>(results.size());
    for (final ObjectPair<OperationType,LDAPResult> p : results)
    {
      final OperationType t = p.getFirst();
      final LDAPResult    r = p.getSecond();

      final ASN1Element protocolOpElement;
      switch (t)
      {
        case ADD:
          protocolOpElement = new AddResponseProtocolOp(r).encodeProtocolOp();
          break;
        case DELETE:
          protocolOpElement =
               new DeleteResponseProtocolOp(r).encodeProtocolOp();
          break;
        case EXTENDED:
          protocolOpElement =
               new ExtendedResponseProtocolOp(r).encodeProtocolOp();
          break;
        case MODIFY:
          protocolOpElement =
               new ModifyResponseProtocolOp(r).encodeProtocolOp();
          break;
        case MODIFY_DN:
          protocolOpElement =
               new ModifyDNResponseProtocolOp(r).encodeProtocolOp();
          break;
        default:
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MULTI_UPDATE_RESULT_INVALID_OP_TYPE.get(t.name()));
      }

      final Control[] controls = r.getResponseControls();
      if ((controls == null) || (controls.length == 0))
      {
        opElements.add(new ASN1Sequence(protocolOpElement));
      }
      else
      {
        opElements.add(new ASN1Sequence(
             protocolOpElement,
             Control.encodeControls(controls)));

      }
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(changesApplied.intValue()),
         new ASN1Sequence(opElements));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the value that indicates whether any or all changes from the
   * multi-update request were successfully applied.
   *
   * @return  The value that indicates whether any or all changes from the
   *          multi-update request were successfully applied.
   */
  @Nullable()
  public MultiUpdateChangesApplied getChangesApplied()
  {
    return changesApplied;
  }



  /**
   * Retrieves a list of the results for operations processed as part of the
   * multi-update operation, with each result paired with its corresponding
   * operation type.
   *
   * @return  A list of the results for operations processed as part of the
   *          multi-update operation.  The returned list may be empty if no
   *          operation results were available.
   */
  @NotNull()
  public List<ObjectPair<OperationType,LDAPResult>> getResults()
  {
    return results;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_MULTI_UPDATE.get();
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
    buffer.append("MultiUpdateExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append(", changesApplied=");
    buffer.append(changesApplied.name());
    buffer.append(", results={");

    final Iterator<ObjectPair<OperationType,LDAPResult>> resultIterator =
         results.iterator();
    while (resultIterator.hasNext())
    {
      resultIterator.next().getSecond().toString(buffer);
      if (resultIterator.hasNext())
      {
        buffer.append(", ");
      }
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
