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
package com.unboundid.ldap.sdk.unboundidds.extensions;


import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1Integer;
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
 * This class provides an implementation of the end batched transaction extended
 * result.  It is able to decode a generic extended result to extract the
 * appropriate response information.
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
 * The end batched transaction result may include two elements:
 * <UL>
 *   <LI>{@code failedOpMessageID} -- The message ID associated with the LDAP
 *       request that caused the transaction to fail.  It will be "{@code -1}"
 *       if the transaction was committed successfully.</LI>
 *   <LI>{@code opResponseControls} -- A map containing the response controls
 *       associated with each of the operations processed as part of the
 *       transaction, mapped from the message ID of the associated request to
 *       the array of response controls for that operation.  If there are no
 *       response controls for a given request, then it will not be included in
 *       the map.</LI>
 * </UL>
 * Note that both of these elements reference the LDAP message ID for the
 * associated request.  Normally, this is not something that developers using
 * the UnboundID LDAP SDK for Java need to access since it is handled behind the
 * scenes, but the LDAP message ID for an operation is available through the
 * {@link com.unboundid.ldap.sdk.LDAPResult#getMessageID} method in the response
 * for that operation.  When processing operations that are part of a batched,
 * transaction it may be desirable to keep references to the associated requests
 * mapped by message ID so that they can be available if necessary for the
 * {@code failedOpMessageID} and/or {@code opResponseControls} elements.
 * <BR><BR>
 * See the documentation for the {@link StartBatchedTransactionExtendedRequest}
 * for an example of performing a batched transaction.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class EndBatchedTransactionExtendedResult
       extends ExtendedResult
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1514265185948328221L;



  // The message ID for the operation that failed, if applicable.
  private final int failedOpMessageID;

  // A mapping of the response controls for the operations performed as part of
  // the transaction.
  @NotNull private final TreeMap<Integer,Control[]> opResponseControls;



  /**
   * Creates a new end batched transaction extended result from the provided
   * extended result.
   *
   * @param  extendedResult  The extended result to be decoded as an end batched
   *                         transaction extended result.  It must not be
   *                         {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended result as an end batched
   *                         transaction extended result.
   */
  public EndBatchedTransactionExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    opResponseControls = new TreeMap<>();

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      failedOpMessageID = -1;
      return;
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_RESPONSE_VALUE_NOT_SEQUENCE.get(ae.getMessage()), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length == 0)
    {
      failedOpMessageID = -1;
      return;
    }
    else if (valueElements.length > 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_RESPONSE_INVALID_ELEMENT_COUNT.get(
                valueElements.length));
    }

    int msgID = -1;
    for (final ASN1Element e : valueElements)
    {
      if (e.getType() == ASN1Constants.UNIVERSAL_INTEGER_TYPE)
      {
        try
        {
          msgID = ASN1Integer.decodeAsInteger(e).intValue();
        }
        catch (final ASN1Exception ae)
        {
          Debug.debugException(ae);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_END_TXN_RESPONSE_CANNOT_DECODE_MSGID.get(ae), ae);
        }
      }
      else if (e.getType() == ASN1Constants.UNIVERSAL_SEQUENCE_TYPE)
      {
        decodeOpControls(e, opResponseControls);
      }
      else
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_INVALID_TYPE.get(
                  StaticUtils.toHex(e.getType())));
      }
    }

    failedOpMessageID = msgID;
  }



  /**
   * Creates a new end batched transaction extended result with the provided
   * information.
   *
   * @param  messageID           The message ID for the LDAP message that is
   *                             associated with this LDAP result.
   * @param  resultCode          The result code from the response.
   * @param  diagnosticMessage   The diagnostic message from the response, if
   *                             available.
   * @param  matchedDN           The matched DN from the response, if available.
   * @param  referralURLs        The set of referral URLs from the response, if
   *                             available.
   * @param  failedOpMessageID   The message ID for the operation that failed,
   *                             or {@code null} if there was no failure.
   * @param  opResponseControls  A map containing the response controls for each
   *                             operation, indexed by message ID.  It may be
   *                             {@code null} if there were no response
   *                             controls.
   * @param  responseControls    The set of controls from the response, if
   *                             available.
   */
  public EndBatchedTransactionExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final Integer failedOpMessageID,
              @Nullable final Map<Integer,Control[]> opResponseControls,
              @Nullable final Control[] responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(failedOpMessageID, opResponseControls),
                            responseControls);

    if ((failedOpMessageID == null) || (failedOpMessageID <= 0))
    {
      this.failedOpMessageID = -1;
    }
    else
    {
      this.failedOpMessageID = failedOpMessageID;
    }

    if (opResponseControls == null)
    {
      this.opResponseControls = new TreeMap<>();
    }
    else
    {
      this.opResponseControls = new TreeMap<>(opResponseControls);
    }
  }



  /**
   * Decodes the provided ASN.1 element as an update controls sequence.  Each
   * element of the sequence should itself be a sequence containing the message
   * ID associated with the operation in which the control was returned and a
   * sequence of the controls included in the response for that operation.
   *
   * @param  element     The ASN.1 element to be decoded.
   * @param  controlMap  The map into which to place the decoded controls.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         contents of the provided ASN.1 element.
   */
  private static void decodeOpControls(@NotNull final ASN1Element element,
                           @NotNull final Map<Integer,Control[]> controlMap)
          throws LDAPException
  {
    final ASN1Sequence ctlsSequence;
    try
    {
      ctlsSequence = ASN1Sequence.decodeAsSequence(element);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_END_TXN_RESPONSE_CONTROLS_NOT_SEQUENCE.get(ae), ae);
    }

    for (final ASN1Element e : ctlsSequence.elements())
    {
      final ASN1Sequence ctlSequence;
      try
      {
        ctlSequence = ASN1Sequence.decodeAsSequence(e);
      }
      catch (final ASN1Exception ae)
      {
        Debug.debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_CONTROL_NOT_SEQUENCE.get(ae), ae);
      }

      final ASN1Element[] ctlSequenceElements = ctlSequence.elements();
      if (ctlSequenceElements.length != 2)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_CONTROL_INVALID_ELEMENT_COUNT.get(
                  ctlSequenceElements.length));
      }

      final int msgID;
      try
      {
        msgID = ASN1Integer.decodeAsInteger(ctlSequenceElements[0]).intValue();
      }
      catch (final ASN1Exception ae)
      {
        Debug.debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_CONTROL_MSGID_NOT_INT.get(ae), ae);
      }

      final ASN1Sequence controlsSequence;
      try
      {
        controlsSequence =
             ASN1Sequence.decodeAsSequence(ctlSequenceElements[1]);
      }
      catch (final ASN1Exception ae)
      {
        Debug.debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_END_TXN_RESPONSE_CONTROLS_ELEMENT_NOT_SEQUENCE.get(ae), ae);
      }

      final Control[] controls = Control.decodeControls(controlsSequence);
      if (controls.length == 0)
      {
        continue;
      }

      controlMap.put(msgID, controls);
    }
  }



  /**
   * Encodes the provided information into an appropriate value for this
   * control.
   *
   * @param  failedOpMessageID   The message ID for the operation that failed,
   *                             or {@code null} if there was no failure.
   * @param  opResponseControls  A map containing the response controls for each
   *                             operation, indexed by message ID.  It may be
   *                             {@code null} if there were no response
   *                             controls.
   *
   * @return  An ASN.1 octet string containing the encoded value for this
   *          control, or {@code null} if there should not be a value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
               @Nullable final Integer failedOpMessageID,
               @Nullable final Map<Integer,Control[]> opResponseControls)
  {
    if ((failedOpMessageID == null) && (opResponseControls == null))
    {
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(2);
    if (failedOpMessageID != null)
    {
      elements.add(new ASN1Integer(failedOpMessageID));
    }

    if ((opResponseControls != null) && (! opResponseControls.isEmpty()))
    {
      final ArrayList<ASN1Element> controlElements = new ArrayList<>(10);
      for (final Map.Entry<Integer,Control[]> e : opResponseControls.entrySet())
      {
        final ASN1Element[] ctlElements =
        {
          new ASN1Integer(e.getKey()),
          Control.encodeControls(e.getValue())
        };
        controlElements.add(new ASN1Sequence(ctlElements));
      }

      elements.add(new ASN1Sequence(controlElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the message ID of the operation that caused the transaction
   * processing to fail, if applicable.
   *
   * @return  The message ID of the operation that caused the transaction
   *          processing to fail, or -1 if no message ID was included in the
   *          end transaction response.
   */
  public int getFailedOpMessageID()
  {
    return failedOpMessageID;
  }



  /**
   * Retrieves the set of response controls returned by the operations
   * processed as part of the transaction.  The value returned will contain a
   * mapping between the message ID of the associated request message and a list
   * of the response controls for that operation.
   *
   * @return  The set of response controls returned by the operations processed
   *          as part of the transaction.  It may be an empty map if none of the
   *          operations had any response controls.
   */
  @NotNull()
  public Map<Integer,Control[]> getOperationResponseControls()
  {
    return opResponseControls;
  }



  /**
   * Retrieves the set of response controls returned by the specified operation
   * processed as part of the transaction.
   *
   * @param  messageID  The message ID of the operation for which to retrieve
   *                    the response controls.
   *
   * @return  The response controls for the specified operation, or
   *          {@code null} if there were no controls returned for the specified
   *          operation.
   */
  @Nullable()
  public Control[] getOperationResponseControls(final int messageID)
  {
    return opResponseControls.get(messageID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_END_BATCHED_TXN.get();
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
    buffer.append("EndBatchedTransactionExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (failedOpMessageID > 0)
    {
      buffer.append(", failedOpMessageID=");
      buffer.append(failedOpMessageID);
    }

    if (! opResponseControls.isEmpty())
    {
      buffer.append(", opResponseControls={");

      for (final int msgID : opResponseControls.keySet())
      {
        buffer.append("opMsgID=");
        buffer.append(msgID);
        buffer.append(", opControls={");

        boolean first = true;
        for (final Control c : opResponseControls.get(msgID))
        {
          if (first)
          {
            first = false;
          }
          else
          {
            buffer.append(", ");
          }

          buffer.append(c);
        }
        buffer.append('}');
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
