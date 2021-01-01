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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.AsyncRequestID;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the LDAP cancel extended request as
 * defined in <A HREF="http://www.ietf.org/rfc/rfc3909.txt">RFC 3909</A>.  It
 * may be used to request that the server interrupt processing on another
 * operation in progress on the same connection.  It behaves much like the
 * abandon operation, with the exception that both the cancel request and the
 * operation that is canceled will receive responses, whereas an abandon request
 * never returns a response, and the operation that is abandoned will also not
 * receive a response if the abandon is successful.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example initiates an asynchronous modify operation and then
 * attempts to cancel it:
 * <PRE>
 * Modification mod = new Modification(ModificationType.REPLACE,
 *      "description", "This is the new description.");
 * ModifyRequest modifyRequest =
 *      new ModifyRequest("dc=example,dc=com", mod);
 *
 * AsyncRequestID asyncRequestID =
 *      connection.asyncModify(modifyRequest, myAsyncResultListener);
 *
 * // Assume that we've waited a reasonable amount of time but the modify
 * // hasn't completed yet so we'll try to cancel it.
 *
 * ExtendedResult cancelResult;
 * try
 * {
 *   cancelResult = connection.processExtendedOperation(
 *        new CancelExtendedRequest(asyncRequestID));
 *   // This doesn't necessarily mean that the operation was successful, since
 *   // some kinds of extended operations (like cancel) return non-success
 *   // results under normal conditions.
 * }
 * catch (LDAPException le)
 * {
 *   // For an extended operation, this generally means that a problem was
 *   // encountered while trying to send the request or read the result.
 *   cancelResult = new ExtendedResult(le);
 * }
 *
 * switch (cancelResult.getResultCode().intValue())
 * {
 *   case ResultCode.CANCELED_INT_VALUE:
 *     // The modify operation was successfully canceled.
 *     break;
 *   case ResultCode.CANNOT_CANCEL_INT_VALUE:
 *     // This indicates that the server isn't capable of canceling that
 *     // type of operation.  This probably won't happen for  this kind of
 *     // modify operation, but it could happen for other kinds of operations.
 *     break;
 *   case ResultCode.TOO_LATE_INT_VALUE:
 *     // This indicates that the cancel request was received too late and the
 *     // server is intending to process the operation.
 *     break;
 *   case ResultCode.NO_SUCH_OPERATION_INT_VALUE:
 *     // This indicates that the server doesn't know anything about the
 *     // operation, most likely because it has already completed.
 *     break;
 *   default:
 *     // This suggests that the operation failed for some other reason.
 *     break;
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CancelExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.1.8) for the cancel extended request.
   */
  @NotNull public static final String CANCEL_REQUEST_OID = "1.3.6.1.1.8";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7170687636394194183L;



  // The message ID of the request to cancel.
  private final int targetMessageID;



  /**
   * Creates a new cancel extended request that will cancel the request with the
   * specified async request ID.
   *
   * @param  requestID  The async request ID of the request to cancel.  It must
   *                    not be {@code null}.
   */
  public CancelExtendedRequest(@NotNull final AsyncRequestID requestID)
  {
    this(requestID.getMessageID(), null);
  }



  /**
   * Creates a new cancel extended request that will cancel the request with the
   * specified message ID.
   *
   * @param  targetMessageID  The message ID of the request to cancel.
   */
  public CancelExtendedRequest(final int targetMessageID)
  {
    this(targetMessageID, null);
  }



  /**
   * Creates a new cancel extended request that will cancel the request with the
   * specified request ID.
   *
   * @param  requestID  The async request ID of the request to cancel.  It must
   *                    not be {@code null}.
   * @param  controls   The set of controls to include in the request.
   */
  public CancelExtendedRequest(@NotNull final AsyncRequestID requestID,
                               @Nullable final Control[] controls)
  {
    this(requestID.getMessageID(), controls);
  }



  /**
   * Creates a new cancel extended request that will cancel the request with the
   * specified message ID.
   *
   * @param  targetMessageID  The message ID of the request to cancel.
   * @param  controls         The set of controls to include in the request.
   */
  public CancelExtendedRequest(final int targetMessageID,
                               @Nullable final Control[] controls)
  {
    super(CANCEL_REQUEST_OID, encodeValue(targetMessageID), controls);

    this.targetMessageID = targetMessageID;
  }



  /**
   * Creates a new cancel extended request from the provided generic extended
   * request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          cancel extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public CancelExtendedRequest(@NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CANCEL_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(valueElement).elements();
      targetMessageID = ASN1Integer.decodeAsInteger(elements[0]).intValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CANCEL_REQUEST_CANNOT_DECODE.get(e), e);
    }
  }



  /**
   * Generates a properly-encoded request value for this cancel extended
   * request.
   *
   * @param  targetMessageID  The message ID of the request to cancel.
   *
   * @return  An ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int targetMessageID)
  {
    final ASN1Element[] sequenceValues =
    {
      new ASN1Integer(targetMessageID)
    };

    return new ASN1OctetString(new ASN1Sequence(sequenceValues).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected ExtendedResult process(@NotNull final LDAPConnection connection,
                                   final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      throw new LDAPException(ResultCode.NOT_SUPPORTED,
           ERR_CANCEL_NOT_SUPPORTED_IN_SYNCHRONOUS_MODE.get());
    }

    return super.process(connection, depth);
  }



  /**
   * Retrieves the message ID of the request to cancel.
   *
   * @return  The message ID of the request to cancel.
   */
  public int getTargetMessageID()
  {
    return targetMessageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CancelExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public CancelExtendedRequest duplicate(@Nullable final Control[] controls)
  {
    final CancelExtendedRequest cancelRequest =
         new CancelExtendedRequest(targetMessageID, controls);
    cancelRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return cancelRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_CANCEL.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("CancelExtendedRequest(targetMessageID=");
    buffer.append(targetMessageID);

    final Control[] controls = getControls();
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
