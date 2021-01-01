/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.extensions.AbortedTransactionExtendedResult;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.EndTransactionExtendedResult;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTransactionExtendedResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an extended operation handler for
 * the start transaction and end transaction extended operations as defined in
 * <A HREF="http://www.ietf.org/rfc/rfc5805.txt">RFC 5805</A>.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TransactionExtendedOperationHandler
       extends InMemoryExtendedOperationHandler
{
  /**
   * The counter that will be used to generate transaction IDs.
   */
  @NotNull private static final AtomicLong TXN_ID_COUNTER = new AtomicLong(1L);



  /**
   * The name of the connection state variable that will be used to hold the
   * transaction ID for the active transaction on the associated connection.
   */
  @NotNull static final String STATE_VARIABLE_TXN_INFO = "TXN-INFO";



  /**
   * Creates a new instance of this extended operation handler.
   */
  public TransactionExtendedOperationHandler()
  {
    // No initialization is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedOperationHandlerName()
  {
    return "LDAP Transactions";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getSupportedExtendedRequestOIDs()
  {
    return Arrays.asList(
         StartTransactionExtendedRequest.START_TRANSACTION_REQUEST_OID,
         EndTransactionExtendedRequest.END_TRANSACTION_REQUEST_OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ExtendedResult processExtendedOperation(
                             @NotNull final InMemoryRequestHandler handler,
                             final int messageID,
                             @NotNull final ExtendedRequest request)
  {
    // This extended operation handler does not support any controls.  If the
    // request has any critical controls, then reject it.
    for (final Control c : request.getControls())
    {
      if (c.isCritical())
      {
        // See if there is a transaction already in progress.  If so, then abort
        // it.
        final ObjectPair<?,?> existingTxnInfo = (ObjectPair<?,?>)
             handler.getConnectionState().remove(STATE_VARIABLE_TXN_INFO);
        if (existingTxnInfo != null)
        {
          final ASN1OctetString txnID =
               (ASN1OctetString) existingTxnInfo.getFirst();
          try
          {
            handler.getClientConnection().sendUnsolicitedNotification(
                 new AbortedTransactionExtendedResult(txnID,
                      ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
                      ERR_TXN_EXTOP_ABORTED_BY_UNSUPPORTED_CONTROL.get(
                           txnID.stringValue(), c.getOID()),
                      null, null, null));
          }
          catch (final LDAPException le)
          {
            Debug.debugException(le);
            return new ExtendedResult(le);
          }
        }

        return new ExtendedResult(messageID,
             ResultCode.UNAVAILABLE_CRITICAL_EXTENSION,
             ERR_TXN_EXTOP_UNSUPPORTED_CONTROL.get(c.getOID()), null, null,
             null, null, null);
      }
    }


    // Figure out whether the request represents a start or end transaction
    // request and handle it appropriately.
    final String oid = request.getOID();
    if (oid.equals(
             StartTransactionExtendedRequest.START_TRANSACTION_REQUEST_OID))
    {
      return handleStartTransaction(handler, messageID, request);
    }
    else
    {
      return handleEndTransaction(handler, messageID, request);
    }
  }



  /**
   * Performs the appropriate processing for a start transaction extended
   * request.
   *
   * @param  handler    The in-memory request handler that received the request.
   * @param  messageID  The message ID for the associated request.
   * @param  request    The extended request that was received.
   *
   * @return  The result for the extended operation processing.
   */
  @NotNull()
  private static StartTransactionExtendedResult handleStartTransaction(
                      @NotNull final InMemoryRequestHandler handler,
                      final int messageID,
                      @NotNull final ExtendedRequest request)
  {
    // If there is already an active transaction on the associated connection,
    // then make sure it gets aborted.
    final Map<String,Object> connectionState = handler.getConnectionState();
    final ObjectPair<?,?> existingTxnInfo =
         (ObjectPair<?,?>) connectionState.remove(STATE_VARIABLE_TXN_INFO);
    if (existingTxnInfo != null)
    {
      final ASN1OctetString txnID =
           (ASN1OctetString) existingTxnInfo.getFirst();

      try
      {
        handler.getClientConnection().sendUnsolicitedNotification(
             new AbortedTransactionExtendedResult(txnID,
                  ResultCode.CONSTRAINT_VIOLATION,
                  ERR_TXN_EXTOP_TXN_ABORTED_BY_NEW_START_TXN.get(
                       txnID.stringValue()),
                  null, null, null));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new StartTransactionExtendedResult(
             new ExtendedResult(le));
      }
    }


    // Make sure that we can decode the provided request as a start transaction
    // request.
    try
    {
      new StartTransactionExtendedRequest(request);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new StartTransactionExtendedResult(messageID,
           ResultCode.PROTOCOL_ERROR, le.getMessage(), null, null, null,
           null);
    }


    // Create a new object with information to use for the transaction.  It will
    // include the transaction ID and a list of LDAP messages that are part of
    // the transaction.  Store it in the connection state.
    final ASN1OctetString txnID =
         new ASN1OctetString(String.valueOf(TXN_ID_COUNTER.getAndIncrement()));
    final List<LDAPMessage> requestList = new ArrayList<>(10);
    final ObjectPair<ASN1OctetString,List<LDAPMessage>> txnInfo =
         new ObjectPair<>(txnID, requestList);
    connectionState.put(STATE_VARIABLE_TXN_INFO, txnInfo);


    // Return the response to the client.
    return new StartTransactionExtendedResult(messageID, ResultCode.SUCCESS,
         INFO_TXN_EXTOP_CREATED_TXN.get(txnID.stringValue()), null, null, txnID,
         null);
  }



  /**
   * Performs the appropriate processing for an end transaction extended
   * request.
   *
   * @param  handler    The in-memory request handler that received the request.
   * @param  messageID  The message ID for the associated request.
   * @param  request    The extended request that was received.
   *
   * @return  The result for the extended operation processing.
   */
  @NotNull()
  private static EndTransactionExtendedResult handleEndTransaction(
                      @NotNull final InMemoryRequestHandler handler,
                      final int messageID,
                      @NotNull final ExtendedRequest request)
  {
    // Get information about any transaction currently in progress on the
    // connection.  If there isn't one, then fail.
    final Map<String,Object> connectionState = handler.getConnectionState();
    final ObjectPair<?,?> txnInfo =
         (ObjectPair<?,?>) connectionState.remove(STATE_VARIABLE_TXN_INFO);
    if (txnInfo == null)
    {
      return new EndTransactionExtendedResult(messageID,
           ResultCode.CONSTRAINT_VIOLATION,
           ERR_TXN_EXTOP_END_NO_ACTIVE_TXN.get(), null, null, null, null,
           null);
    }


    // Make sure that we can decode the end transaction request.
    final ASN1OctetString existingTxnID = (ASN1OctetString) txnInfo.getFirst();
    final EndTransactionExtendedRequest endTxnRequest;
    try
    {
      endTxnRequest = new EndTransactionExtendedRequest(request);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      try
      {
        handler.getClientConnection().sendUnsolicitedNotification(
             new AbortedTransactionExtendedResult(existingTxnID,
                  ResultCode.PROTOCOL_ERROR,
                  ERR_TXN_EXTOP_ABORTED_BY_MALFORMED_END_TXN.get(
                       existingTxnID.stringValue()),
                  null, null, null));
      }
      catch (final LDAPException le2)
      {
        Debug.debugException(le2);
      }

      return new EndTransactionExtendedResult(messageID,
           ResultCode.PROTOCOL_ERROR, le.getMessage(), null, null, null, null,
           null);
    }


    // Make sure that the transaction ID of the existing transaction matches the
    // transaction ID from the end transaction request.
    final ASN1OctetString targetTxnID = endTxnRequest.getTransactionID();
    if (! existingTxnID.stringValue().equals(targetTxnID.stringValue()))
    {
      // Send an unsolicited notification indicating that the existing
      // transaction has been aborted.
      try
      {
        handler.getClientConnection().sendUnsolicitedNotification(
             new AbortedTransactionExtendedResult(existingTxnID,
                  ResultCode.CONSTRAINT_VIOLATION,
                  ERR_TXN_EXTOP_ABORTED_BY_WRONG_END_TXN.get(
                       existingTxnID.stringValue(), targetTxnID.stringValue()),
                  null, null, null));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        return new EndTransactionExtendedResult(messageID,
             le.getResultCode(), le.getMessage(), le.getMatchedDN(),
             le.getReferralURLs(), null, null, le.getResponseControls());
      }

      return new EndTransactionExtendedResult(messageID,
           ResultCode.CONSTRAINT_VIOLATION,
           ERR_TXN_EXTOP_END_WRONG_TXN.get(targetTxnID.stringValue(),
                existingTxnID.stringValue()),
           null, null, null, null, null);
    }


    // If the transaction should be aborted, then we can just send the response.
    if (! endTxnRequest.commit())
    {
      return new EndTransactionExtendedResult(messageID, ResultCode.SUCCESS,
           INFO_TXN_EXTOP_END_TXN_ABORTED.get(existingTxnID.stringValue()),
           null, null, null, null, null);
    }


    // If we've gotten here, then we'll try to commit the transaction.  First,
    // get a snapshot of the current state so that we can roll back to it if
    // necessary.
    final InMemoryDirectoryServerSnapshot snapshot = handler.createSnapshot();
    boolean rollBack = true;

    try
    {
      // Create a map to hold information about response controls from
      // operations processed as part of the transaction.
      final List<?> requestMessages = (List<?>) txnInfo.getSecond();
      final Map<Integer,Control[]> opResponseControls = new LinkedHashMap<>(
           StaticUtils.computeMapCapacity(requestMessages.size()));

      // Iterate through the requests that have been submitted as part of the
      // transaction and attempt to process them.
      ResultCode resultCode        = ResultCode.SUCCESS;
      String     diagnosticMessage = null;
      String     failedOpType      = null;
      Integer    failedOpMessageID = null;
txnOpLoop:
      for (final Object o : requestMessages)
      {
        final LDAPMessage m = (LDAPMessage) o;
        switch (m.getProtocolOpType())
        {
          case LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST:
            final LDAPMessage addResponseMessage = handler.processAddRequest(
                 m.getMessageID(), m.getAddRequestProtocolOp(),
                 m.getControls());
            final AddResponseProtocolOp addResponseOp =
                 addResponseMessage.getAddResponseProtocolOp();
            final List<Control> addControls = addResponseMessage.getControls();
            if ((addControls != null) && (! addControls.isEmpty()))
            {
              final Control[] controls = new Control[addControls.size()];
              addControls.toArray(controls);
              opResponseControls.put(m.getMessageID(), controls);
            }
            if (addResponseOp.getResultCode() != ResultCode.SUCCESS_INT_VALUE)
            {
              resultCode = ResultCode.valueOf(addResponseOp.getResultCode());
              diagnosticMessage = addResponseOp.getDiagnosticMessage();
              failedOpType = INFO_TXN_EXTOP_OP_TYPE_ADD.get();
              failedOpMessageID = m.getMessageID();
              break txnOpLoop;
            }
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST:
            final LDAPMessage deleteResponseMessage =
                 handler.processDeleteRequest(m.getMessageID(),
                      m.getDeleteRequestProtocolOp(), m.getControls());
            final DeleteResponseProtocolOp deleteResponseOp =
                 deleteResponseMessage.getDeleteResponseProtocolOp();
            final List<Control> deleteControls =
                 deleteResponseMessage.getControls();
            if ((deleteControls != null) && (! deleteControls.isEmpty()))
            {
              final Control[] controls = new Control[deleteControls.size()];
              deleteControls.toArray(controls);
              opResponseControls.put(m.getMessageID(), controls);
            }
            if (deleteResponseOp.getResultCode() !=
                     ResultCode.SUCCESS_INT_VALUE)
            {
              resultCode = ResultCode.valueOf(deleteResponseOp.getResultCode());
              diagnosticMessage = deleteResponseOp.getDiagnosticMessage();
              failedOpType = INFO_TXN_EXTOP_OP_TYPE_DELETE.get();
              failedOpMessageID = m.getMessageID();
              break txnOpLoop;
            }
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST:
            final LDAPMessage modifyResponseMessage =
                 handler.processModifyRequest(m.getMessageID(),
                      m.getModifyRequestProtocolOp(), m.getControls());
            final ModifyResponseProtocolOp modifyResponseOp =
                 modifyResponseMessage.getModifyResponseProtocolOp();
            final List<Control> modifyControls =
                 modifyResponseMessage.getControls();
            if ((modifyControls != null) && (! modifyControls.isEmpty()))
            {
              final Control[] controls = new Control[modifyControls.size()];
              modifyControls.toArray(controls);
              opResponseControls.put(m.getMessageID(), controls);
            }
            if (modifyResponseOp.getResultCode() !=
                     ResultCode.SUCCESS_INT_VALUE)
            {
              resultCode = ResultCode.valueOf(modifyResponseOp.getResultCode());
              diagnosticMessage = modifyResponseOp.getDiagnosticMessage();
              failedOpType = INFO_TXN_EXTOP_OP_TYPE_MODIFY.get();
              failedOpMessageID = m.getMessageID();
              break txnOpLoop;
            }
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
            final LDAPMessage modifyDNResponseMessage =
                 handler.processModifyDNRequest(m.getMessageID(),
                      m.getModifyDNRequestProtocolOp(), m.getControls());
            final ModifyDNResponseProtocolOp modifyDNResponseOp =
                 modifyDNResponseMessage.getModifyDNResponseProtocolOp();
            final List<Control> modifyDNControls =
                 modifyDNResponseMessage.getControls();
            if ((modifyDNControls != null) && (! modifyDNControls.isEmpty()))
            {
              final Control[] controls = new Control[modifyDNControls.size()];
              modifyDNControls.toArray(controls);
              opResponseControls.put(m.getMessageID(), controls);
            }
            if (modifyDNResponseOp.getResultCode() !=
                     ResultCode.SUCCESS_INT_VALUE)
            {
              resultCode =
                   ResultCode.valueOf(modifyDNResponseOp.getResultCode());
              diagnosticMessage = modifyDNResponseOp.getDiagnosticMessage();
              failedOpType = INFO_TXN_EXTOP_OP_TYPE_MODIFY_DN.get();
              failedOpMessageID = m.getMessageID();
              break txnOpLoop;
            }
            break;
        }
      }

      if (resultCode == ResultCode.SUCCESS)
      {
        diagnosticMessage =
             INFO_TXN_EXTOP_COMMITTED.get(existingTxnID.stringValue());
        rollBack = false;
      }
      else
      {
        diagnosticMessage = ERR_TXN_EXTOP_COMMIT_FAILED.get(
             existingTxnID.stringValue(), failedOpType, failedOpMessageID,
             diagnosticMessage);
      }

      return new EndTransactionExtendedResult(messageID, resultCode,
           diagnosticMessage, null, null, failedOpMessageID, opResponseControls,
           null);
    }
    finally
    {
      if (rollBack)
      {
        handler.restoreSnapshot(snapshot);
      }
    }
  }
}
