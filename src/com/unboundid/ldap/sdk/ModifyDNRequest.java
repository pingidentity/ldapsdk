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



import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.util.Debug;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 modify DN
 * operation, which can be used to rename and/or move an entry or subtree in the
 * directory.  A modify DN request contains the DN of the target entry, the new
 * RDN to use for that entry, and a flag which indicates whether to remove the
 * current RDN attribute value(s) from the entry.  It may optionally contain a
 * new superior DN, which will cause the entry to be moved below that new parent
 * entry.
 * <BR><BR>
 * Note that some directory servers may not support all possible uses of the
 * modify DN operation.  In particular, some servers may not support the use of
 * a new superior DN, especially if it may cause the entry to be moved to a
 * different database or another server.  Also, some servers may not support
 * renaming or moving non-leaf entries (i.e., entries that have one or more
 * subordinates).
 * <BR><BR>
 * {@code ModifyDNRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code ModifyDNRequest}
 * objects are not threadsafe and therefore a single {@code ModifyDNRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for performing a modify DN
 * operation.  In this case, it will rename "ou=People,dc=example,dc=com" to
 * "ou=Users,dc=example,dc=com".  It will not move the entry below a new parent.
 * <PRE>
 * ModifyDNRequest modifyDNRequest =
 *      new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", true);
 * LDAPResult modifyDNResult;
 *
 * try
 * {
 *   modifyDNResult = connection.modifyDN(modifyDNRequest);
 *   // If we get here, the delete was successful.
 * }
 * catch (LDAPException le)
 * {
 *   // The modify DN operation failed.
 *   modifyDNResult = le.toLDAPResult();
 *   ResultCode resultCode = le.getResultCode();
 *   String errorMessageFromServer = le.getDiagnosticMessage();
 * }
 * </PRE>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ModifyDNRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyModifyDNRequest, ResponseAcceptor, ProtocolOp
{
  /**
   * The BER type for the new superior element.
   */
  private static final byte NEW_SUPERIOR_TYPE = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2325552729975091008L;



  // The queue that will be used to receive response messages from the server.
  @NotNull private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<>();

  // Indicates whether to delete the current RDN value from the entry.
  private boolean deleteOldRDN;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The current DN of the entry to rename.
  @NotNull private String dn;

  // The new RDN to use for the entry.
  @NotNull private String newRDN;

  // The new superior DN for the entry.
  @Nullable private String newSuperiorDN;



  /**
   * Creates a new modify DN request that will rename the entry but will not
   * move it below a new entry.
   *
   * @param  dn            The current DN for the entry to rename.  It must not
   *                       be {@code null}.
   * @param  newRDN        The new RDN for the target entry.  It must not be
   *                       {@code null}.
   * @param  deleteOldRDN  Indicates whether to delete the current RDN value
   *                       from the target entry.
   */
  public ModifyDNRequest(@NotNull final String dn, @NotNull final String newRDN,
                         final boolean deleteOldRDN)
  {
    super(null);

    Validator.ensureNotNull(dn, newRDN);

    this.dn           = dn;
    this.newRDN       = newRDN;
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }



  /**
   * Creates a new modify DN request that will rename the entry but will not
   * move it below a new entry.
   *
   * @param  dn            The current DN for the entry to rename.  It must not
   *                       be {@code null}.
   * @param  newRDN        The new RDN for the target entry.  It must not be
   *                       {@code null}.
   * @param  deleteOldRDN  Indicates whether to delete the current RDN value
   *                       from the target entry.
   */
  public ModifyDNRequest(@NotNull final DN dn, @NotNull final RDN newRDN,
                         final boolean deleteOldRDN)
  {
    super(null);

    Validator.ensureNotNull(dn, newRDN);

    this.dn           = dn.toString();
    this.newRDN       = newRDN.toString();
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }



  /**
   * Creates a new modify DN request that will rename the entry and will
   * optionally move it below a new entry.
   *
   * @param  dn             The current DN for the entry to rename.  It must not
   *                        be {@code null}.
   * @param  newRDN         The new RDN for the target entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the current RDN value
   *                        from the target entry.
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be moved below a
   *                        new parent.
   */
  public ModifyDNRequest(@NotNull final String dn, @NotNull final String newRDN,
                         final boolean deleteOldRDN,
                         @Nullable final String newSuperiorDN)
  {
    super(null);

    Validator.ensureNotNull(dn, newRDN);

    this.dn            = dn;
    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }



  /**
   * Creates a new modify DN request that will rename the entry and will
   * optionally move it below a new entry.
   *
   * @param  dn             The current DN for the entry to rename.  It must not
   *                        be {@code null}.
   * @param  newRDN         The new RDN for the target entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the current RDN value
   *                        from the target entry.
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be moved below a
   *                        new parent.
   */
  public ModifyDNRequest(@NotNull final DN dn, @NotNull final RDN newRDN,
                         final boolean deleteOldRDN,
                         @Nullable final DN newSuperiorDN)
  {
    super(null);

    Validator.ensureNotNull(dn, newRDN);

    this.dn            = dn.toString();
    this.newRDN        = newRDN.toString();
    this.deleteOldRDN  = deleteOldRDN;

    if (newSuperiorDN == null)
    {
      this.newSuperiorDN = null;
    }
    else
    {
      this.newSuperiorDN = newSuperiorDN.toString();
    }
  }



  /**
   * Creates a new modify DN request that will rename the entry but will not
   * move it below a new entry.
   *
   * @param  dn            The current DN for the entry to rename.  It must not
   *                       be {@code null}.
   * @param  newRDN        The new RDN for the target entry.  It must not be
   *                       {@code null}.
   * @param  deleteOldRDN  Indicates whether to delete the current RDN value
   *                       from the target entry.
   * @param  controls      The set of controls to include in the request.
   */
  public ModifyDNRequest(@NotNull final String dn, @NotNull final String newRDN,
                         final boolean deleteOldRDN,
                         @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, newRDN);

    this.dn           = dn;
    this.newRDN       = newRDN;
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }



  /**
   * Creates a new modify DN request that will rename the entry but will not
   * move it below a new entry.
   *
   * @param  dn            The current DN for the entry to rename.  It must not
   *                       be {@code null}.
   * @param  newRDN        The new RDN for the target entry.  It must not be
   *                       {@code null}.
   * @param  deleteOldRDN  Indicates whether to delete the current RDN value
   *                       from the target entry.
   * @param  controls      The set of controls to include in the request.
   */
  public ModifyDNRequest(@NotNull final DN dn, @NotNull final RDN newRDN,
                         final boolean deleteOldRDN,
                         @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, newRDN);

    this.dn           = dn.toString();
    this.newRDN       = newRDN.toString();
    this.deleteOldRDN = deleteOldRDN;

    newSuperiorDN = null;
  }



  /**
   * Creates a new modify DN request that will rename the entry and will
   * optionally move it below a new entry.
   *
   * @param  dn             The current DN for the entry to rename.  It must not
   *                        be {@code null}.
   * @param  newRDN         The new RDN for the target entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the current RDN value
   *                        from the target entry.
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be moved below a
   *                        new parent.
   * @param  controls      The set of controls to include in the request.
   */
  public ModifyDNRequest(@NotNull final String dn, @NotNull final String newRDN,
                         final boolean deleteOldRDN,
                         @Nullable final String newSuperiorDN,
                         @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, newRDN);

    this.dn            = dn;
    this.newRDN        = newRDN;
    this.deleteOldRDN  = deleteOldRDN;
    this.newSuperiorDN = newSuperiorDN;
  }



  /**
   * Creates a new modify DN request that will rename the entry and will
   * optionally move it below a new entry.
   *
   * @param  dn             The current DN for the entry to rename.  It must not
   *                        be {@code null}.
   * @param  newRDN         The new RDN for the target entry.  It must not be
   *                        {@code null}.
   * @param  deleteOldRDN   Indicates whether to delete the current RDN value
   *                        from the target entry.
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be moved below a
   *                        new parent.
   * @param  controls      The set of controls to include in the request.
   */
  public ModifyDNRequest(@NotNull final DN dn, @NotNull final RDN newRDN,
                         final boolean deleteOldRDN,
                         @Nullable final DN newSuperiorDN,
                         @Nullable final Control[] controls)
  {
    super(controls);

    Validator.ensureNotNull(dn, newRDN);

    this.dn            = dn.toString();
    this.newRDN        = newRDN.toString();
    this.deleteOldRDN  = deleteOldRDN;

    if (newSuperiorDN == null)
    {
      this.newSuperiorDN = null;
    }
    else
    {
      this.newSuperiorDN = newSuperiorDN.toString();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Specifies the current DN of the entry to move/rename.
   *
   * @param  dn  The current DN of the entry to move/rename.  It must not be
   *             {@code null}.
   */
  public void setDN(@NotNull final String dn)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn;
  }



  /**
   * Specifies the current DN of the entry to move/rename.
   *
   * @param  dn  The current DN of the entry to move/rename.  It must not be
   *             {@code null}.
   */
  public void setDN(@NotNull final DN dn)
  {
    Validator.ensureNotNull(dn);

    this.dn = dn.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getNewRDN()
  {
    return newRDN;
  }



  /**
   * Specifies the new RDN for the entry.
   *
   * @param  newRDN  The new RDN for the entry.  It must not be {@code null}.
   */
  public void setNewRDN(@NotNull final String newRDN)
  {
    Validator.ensureNotNull(newRDN);

    this.newRDN = newRDN;
  }



  /**
   * Specifies the new RDN for the entry.
   *
   * @param  newRDN  The new RDN for the entry.  It must not be {@code null}.
   */
  public void setNewRDN(@NotNull final RDN newRDN)
  {
    Validator.ensureNotNull(newRDN);

    this.newRDN = newRDN.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }



  /**
   * Specifies whether the current RDN value should be removed from the entry.
   *
   * @param  deleteOldRDN  Specifies whether the current RDN value should be
   *                       removed from the entry.
   */
  public void setDeleteOldRDN(final boolean deleteOldRDN)
  {
    this.deleteOldRDN = deleteOldRDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getNewSuperiorDN()
  {
    return newSuperiorDN;
  }



  /**
   * Specifies the new superior DN for the entry.
   *
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be removed below
   *                        a new parent.
   */
  public void setNewSuperiorDN(@Nullable final String newSuperiorDN)
  {
    this.newSuperiorDN = newSuperiorDN;
  }



  /**
   * Specifies the new superior DN for the entry.
   *
   * @param  newSuperiorDN  The new superior DN for the entry.  It may be
   *                        {@code null} if the entry is not to be removed below
   *                        a new parent.
   */
  public void setNewSuperiorDN(@Nullable final DN newSuperiorDN)
  {
    if (newSuperiorDN == null)
    {
      this.newSuperiorDN = null;
    }
    else
    {
      this.newSuperiorDN = newSuperiorDN.toString();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(@NotNull final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST);
    writer.addOctetString(dn);
    writer.addOctetString(newRDN);
    writer.addBoolean(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      writer.addOctetString(NEW_SUPERIOR_TYPE, newSuperiorDN);
    }
    requestSequence.end();
  }



  /**
   * Encodes the modify DN request protocol op to an ASN.1 element.
   *
   * @return  The ASN.1 element with the encoded modify DN request protocol op.
   */
  @Override()
  @NotNull()
  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element[] protocolOpElements;
    if (newSuperiorDN == null)
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(dn),
        new ASN1OctetString(newRDN),
        new ASN1Boolean(deleteOldRDN)
      };
    }
    else
    {
      protocolOpElements = new ASN1Element[]
      {
        new ASN1OctetString(dn),
        new ASN1OctetString(newRDN),
        new ASN1Boolean(deleteOldRDN),
        new ASN1OctetString(NEW_SUPERIOR_TYPE, newSuperiorDN)
      };
    }

    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST,
                            protocolOpElements);
  }



  /**
   * Sends this modify DN request to the directory server over the provided
   * connection and returns the associated response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the modify DN processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  @NotNull()
  protected LDAPResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    if (connection.synchronousMode())
    {
      @SuppressWarnings("deprecation")
      final boolean autoReconnect =
           connection.getConnectionOptions().autoReconnect();
      return processSync(connection, depth, autoReconnect);
    }

    final long requestTime = System.nanoTime();
    processAsync(connection, null);

    try
    {
      // Wait for and process the response.
      final LDAPResponse response;
      try
      {
        final long responseTimeout = getResponseTimeoutMillis(connection);
        if (responseTimeout > 0)
        {
          response = responseQueue.poll(responseTimeout, TimeUnit.MILLISECONDS);
        }
        else
        {
          response = responseQueue.take();
        }
      }
      catch (final InterruptedException ie)
      {
        Debug.debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MODDN_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime, depth, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Sends this modify DN request to the directory server over the provided
   * connection and returns the message ID for the request.
   *
   * @param  connection      The connection to use to communicate with the
   *                         directory server.
   * @param  resultListener  The async result listener that is to be notified
   *                         when the response is received.  It may be
   *                         {@code null} only if the result is to be processed
   *                         by this class.
   *
   * @return  The async request ID created for the operation, or {@code null} if
   *          the provided {@code resultListener} is {@code null} and the
   *          operation will not actually be processed asynchronously.
   *
   * @throws  LDAPException  If a problem occurs while sending the request.
   */
  @Nullable()
  AsyncRequestID processAsync(@NotNull final LDAPConnection connection,
                      @Nullable final AsyncResultListener resultListener)
                 throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message = new LDAPMessage(messageID, this, getControls());


    // If the provided async result listener is {@code null}, then we'll use
    // this class as the message acceptor.  Otherwise, create an async helper
    // and use it as the message acceptor.
    final AsyncRequestID asyncRequestID;
    final long timeout = getResponseTimeoutMillis(connection);
    if (resultListener == null)
    {
      asyncRequestID = null;
      connection.registerResponseAcceptor(messageID, this);
    }
    else
    {
      final AsyncHelper helper = new AsyncHelper(connection,
           OperationType.MODIFY_DN, messageID, resultListener,
           getIntermediateResponseListener());
      connection.registerResponseAcceptor(messageID, helper);
      asyncRequestID = helper.getAsyncRequestID();

      if (timeout > 0L)
      {
        final Timer timer = connection.getTimer();
        final AsyncTimeoutTimerTask timerTask =
             new AsyncTimeoutTimerTask(helper);
        timer.schedule(timerTask, timeout);
        asyncRequestID.setTimerTask(timerTask);
      }
    }


    // Send the request to the server.
    try
    {
      Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

      final LDAPConnectionLogger logger =
           connection.getConnectionOptions().getConnectionLogger();
      if (logger != null)
      {
        logger.logModifyDNRequest(connection, messageID, this);
      }

      connection.getConnectionStatistics().incrementNumModifyDNRequests();
      connection.sendMessage(message, timeout);
      return asyncRequestID;
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      connection.deregisterResponseAcceptor(messageID);
      throw le;
    }
  }



  /**
   * Processes this modify DN operation in synchronous mode, in which the same
   * thread will send the request and read the response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   * @param  allowRetry  Indicates whether the request may be re-tried on a
   *                     re-established connection if the initial attempt fails
   *                     in a way that indicates the connection is no longer
   *                     valid and autoReconnect is true.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the modify DN processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @NotNull()
  private LDAPResult processSync(@NotNull final LDAPConnection connection,
                                 final int depth,
                                 final boolean allowRetry)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    Debug.debugLDAPRequest(Level.INFO, this, messageID, connection);

    final LDAPConnectionLogger logger =
         connection.getConnectionOptions().getConnectionLogger();
    if (logger != null)
    {
      logger.logModifyDNRequest(connection, messageID, this);
    }

    connection.getConnectionStatistics().incrementNumModifyDNRequests();
    try
    {
      connection.sendMessage(message, getResponseTimeoutMillis(connection));
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);

      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             le.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      throw le;
    }

    while (true)
    {
      final LDAPResponse response;
      try
      {
        response = connection.readResponse(messageID);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        if ((le.getResultCode() == ResultCode.TIMEOUT) &&
            connection.getConnectionOptions().abandonOnTimeout())
        {
          connection.abandon(messageID);
        }

        if (allowRetry)
        {
          final LDAPResult retryResult = reconnectAndRetry(connection, depth,
               le.getResultCode());
          if (retryResult != null)
          {
            return retryResult;
          }
        }

        throw le;
      }

      if (response instanceof IntermediateResponse)
      {
        final IntermediateResponseListener listener =
             getIntermediateResponseListener();
        if (listener != null)
        {
          listener.intermediateResponseReturned(
               (IntermediateResponse) response);
        }
      }
      else
      {
        return handleResponse(connection, response, requestTime, depth,
             allowRetry);
      }
    }
  }



  /**
   * Performs the necessary processing for handling a response.
   *
   * @param  connection   The connection used to read the response.
   * @param  response     The response to be processed.
   * @param  requestTime  The time the request was sent to the server.
   * @param  depth        The current referral depth for this request.  It
   *                      should always be one for the initial request, and
   *                      should only be incremented when following referrals.
   * @param  allowRetry   Indicates whether the request may be re-tried on a
   *                      re-established connection if the initial attempt fails
   *                      in a way that indicates the connection is no longer
   *                      valid and autoReconnect is true.
   *
   * @return  The modify DN result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  @NotNull()
  private LDAPResult handleResponse(@NotNull final LDAPConnection connection,
                                    @Nullable final LDAPResponse response,
                                    final long requestTime, final int depth,
                                    final boolean allowRetry)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime =
           StaticUtils.nanosToMillis(System.nanoTime() - requestTime);
      if (connection.getConnectionOptions().abandonOnTimeout())
      {
        connection.abandon(messageID);
      }

      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_MODIFY_DN_CLIENT_TIMEOUT.get(waitTime, messageID, dn,
                connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumModifyDNResponses(
         System.nanoTime() - requestTime);
    if (response instanceof ConnectionClosedResponse)
    {
      // The connection was closed while waiting for the response.
      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             ResultCode.SERVER_DOWN);
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      final ConnectionClosedResponse ccr = (ConnectionClosedResponse) response;
      final String message = ccr.getMessage();
      if (message == null)
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_DN_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_DN_RESPONSE_WITH_MESSAGE.get(
                  connection.getHostPort(), toString(), message));
      }
    }

    final LDAPResult result = (LDAPResult) response;
    if ((result.getResultCode().equals(ResultCode.REFERRAL)) &&
        followReferrals(connection))
    {
      if (depth >= connection.getConnectionOptions().getReferralHopLimit())
      {
        return new LDAPResult(messageID, ResultCode.REFERRAL_LIMIT_EXCEEDED,
                              ERR_TOO_MANY_REFERRALS.get(),
                              result.getMatchedDN(), result.getReferralURLs(),
                              result.getResponseControls());
      }

      return followReferral(result, connection, depth);
    }
    else
    {
      if (allowRetry)
      {
        final LDAPResult retryResult = reconnectAndRetry(connection, depth,
             result.getResultCode());
        if (retryResult != null)
        {
          return retryResult;
        }
      }

      return result;
    }
  }



  /**
   * Attempts to re-establish the connection and retry processing this request
   * on it.
   *
   * @param  connection  The connection to be re-established.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   * @param  resultCode  The result code for the previous operation attempt.
   *
   * @return  The result from re-trying the add, or {@code null} if it could not
   *          be re-tried.
   */
  @Nullable()
  private LDAPResult reconnectAndRetry(@NotNull final LDAPConnection connection,
                                       final int depth,
                                       @NotNull final ResultCode resultCode)
  {
    try
    {
      // We will only want to retry for certain result codes that indicate a
      // connection problem.
      switch (resultCode.intValue())
      {
        case ResultCode.SERVER_DOWN_INT_VALUE:
        case ResultCode.DECODING_ERROR_INT_VALUE:
        case ResultCode.CONNECT_ERROR_INT_VALUE:
          connection.reconnect();
          return processSync(connection, depth, false);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    return null;
  }



  /**
   * Attempts to follow a referral to perform a modify DN operation in the
   * target server.
   *
   * @param  referralResult  The LDAP result object containing information about
   *                         the referral to follow.
   * @param  connection      The connection on which the referral was received.
   * @param  depth           The number of referrals followed in the course of
   *                         processing this request.
   *
   * @return  The result of attempting to process the modify DN operation by
   *          following the referral.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the referral connection, sending the request, or
   *                         reading the result.
   */
  @NotNull()
  private LDAPResult followReferral(@NotNull final LDAPResult referralResult,
                                    @NotNull final LDAPConnection connection,
                                    final int depth)
          throws LDAPException
  {
    for (final String urlString : referralResult.getReferralURLs())
    {
      try
      {
        final LDAPURL referralURL = new LDAPURL(urlString);
        final String host = referralURL.getHost();

        if (host == null)
        {
          // We can't handle a referral in which there is no host.
          continue;
        }

        final ModifyDNRequest modifyDNRequest;
        if (referralURL.baseDNProvided())
        {
          modifyDNRequest =
               new ModifyDNRequest(referralURL.getBaseDN().toString(),
                                   newRDN, deleteOldRDN, newSuperiorDN,
                                   getControls());
        }
        else
        {
          modifyDNRequest = this;
        }

        final LDAPConnection referralConn = getReferralConnector(connection).
             getReferralConnection(referralURL, connection);
        try
        {
          return modifyDNRequest.process(referralConn, depth+1);
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
      }
    }

    // If we've gotten here, then we could not follow any of the referral URLs,
    // so we'll just return the original referral result.
    return referralResult;
  }



  /**
   * {@inheritDoc}
   */
  @InternalUseOnly()
  @Override()
  public void responseReceived(@NotNull final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(
                StaticUtils.getExceptionMessage(e)), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public OperationType getOperationType()
  {
    return OperationType.MODIFY_DN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ModifyDNRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ModifyDNRequest duplicate(@NotNull final Control[] controls)
  {
    final ModifyDNRequest r = new ModifyDNRequest(dn, newRDN, deleteOldRDN,
         newSuperiorDN, controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    if (getReferralConnectorInternal() != null)
    {
      r.setReferralConnector(getReferralConnectorInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFModifyDNChangeRecord toLDIFChangeRecord()
  {
    return new LDIFModifyDNChangeRecord(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String[] toLDIF()
  {
    return toLDIFChangeRecord().toLDIF();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String toLDIFString()
  {
    return toLDIFChangeRecord().toLDIFString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ModifyDNRequest(dn='");
    buffer.append(dn);
    buffer.append("', newRDN='");
    buffer.append(newRDN);
    buffer.append("', deleteOldRDN=");
    buffer.append(deleteOldRDN);

    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN='");
      buffer.append(newSuperiorDN);
      buffer.append('\'');
    }

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



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(4);
    constructorArgs.add(ToCodeArgHelper.createString(dn, "Current DN"));
    constructorArgs.add(ToCodeArgHelper.createString(newRDN, "New RDN"));
    constructorArgs.add(ToCodeArgHelper.createBoolean(deleteOldRDN,
         "Delete Old RDN Value(s)"));

    if (newSuperiorDN != null)
    {
      constructorArgs.add(ToCodeArgHelper.createString(newSuperiorDN,
           "New Superior Entry DN"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "ModifyDNRequest",
         requestID + "Request", "new ModifyDNRequest", constructorArgs);


    // If there are any controls, then add them to the request.
    for (final Control c : getControls())
    {
      ToCodeHelper.generateMethodCall(lineList, indentSpaces, null, null,
           requestID + "Request.addControl",
           ToCodeArgHelper.createControl(c, null));
    }


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  LDAPResult " + requestID +
           "Result = connection.modifyDN(" + requestID + "Request);");
      lineList.add(indent + "  // The modify DN was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The modify DN failed.  Maybe the following " +
           "will help explain why.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
