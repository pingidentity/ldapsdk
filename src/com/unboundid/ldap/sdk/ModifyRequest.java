/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.LDAPResponse;
import com.unboundid.ldap.protocol.ProtocolOp;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.InternalUseOnly;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class implements the processing necessary to perform an LDAPv3 modify
 * operation, which can be used to update an entry in the directory server.  A
 * modify request contains the DN of the entry to modify, as well as one or more
 * changes to apply to that entry.  See the {@link Modification} class for more
 * information about the types of modifications that may be processed.
 * <BR><BR>
 * A modify request can be created with a DN and set of modifications, but it
 * can also be as a list of the lines that comprise the LDIF representation of
 * the modification as described in
 * <A HREF="http://www.ietf.org/rfc/rfc2849.txt">RFC 2849</A>.  For example, the
 * following code demonstrates creating a modify request from the LDIF
 * representation of the modification:
 * <PRE>
 *   ModifyRequest modifyRequest = new ModifyRequest(
 *     "dn: dc=example,dc=com",
 *     "changetype: modify",
 *     "replace: description",
 *     "description: This is the new description.");
 * </PRE>
 * <BR><BR>
 * {@code ModifyRequest} objects are mutable and therefore can be altered and
 * re-used for multiple requests.  Note, however, that {@code ModifyRequest}
 * objects are not threadsafe and therefore a single {@code ModifyRequest}
 * object instance should not be used to process multiple requests at the same
 * time.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ModifyRequest
       extends UpdatableLDAPRequest
       implements ReadOnlyModifyRequest, ResponseAcceptor, ProtocolOp
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4747622844001634758L;



  // The queue that will be used to receive response messages from the server.
  private final LinkedBlockingQueue<LDAPResponse> responseQueue =
       new LinkedBlockingQueue<LDAPResponse>();

  // The set of modifications to perform.
  private final ArrayList<Modification> modifications;

  // The message ID from the last LDAP message sent from this request.
  private int messageID = -1;

  // The DN of the entry to modify.
  private String dn;



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn   The DN of the entry to modify.  It must not be {@code null}.
   * @param  mod  The modification to apply to the entry.  It must not be
   *              {@code null}.
   */
  public ModifyRequest(final String dn, final Modification mod)
  {
    super(null);

    ensureNotNull(dn, mod);

    this.dn = dn;

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the entry.  It must not
   *               be {@code null} or empty.
   */
  public ModifyRequest(final String dn, final Modification... mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
         "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the entry.  It must not
   *               be {@code null} or empty.
   */
  public ModifyRequest(final String dn, final List<Modification> mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn   The DN of the entry to modify.  It must not be {@code null}.
   * @param  mod  The modification to apply to the entry.  It must not be
   *              {@code null}.
   */
  public ModifyRequest(final DN dn, final Modification mod)
  {
    super(null);

    ensureNotNull(dn, mod);

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the entry.  It must not
   *               be {@code null} or empty.
   */
  public ModifyRequest(final DN dn, final Modification... mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
         "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn    The DN of the entry to modify.  It must not be {@code null}.
   * @param  mods  The set of modifications to apply to the entry.  It must not
   *               be {@code null} or empty.
   */
  public ModifyRequest(final DN dn, final List<Modification> mods)
  {
    super(null);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn        The DN of the entry to modify.  It must not be
   *                   {@code null}.
   * @param  mod       The modification to apply to the entry.  It must not be
   *                   {@code null}.
   * @param  controls  The set of controls to include in the request.
   */
  public ModifyRequest(final String dn, final Modification mod,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mod);

    this.dn = dn;

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn        The DN of the entry to modify.  It must not be
   *                   {@code null}.
   * @param  mods      The set of modifications to apply to the entry.  It must
   *                   not be {@code null} or empty.
   * @param  controls  The set of controls to include in the request.
   */
  public ModifyRequest(final String dn, final Modification[] mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
         "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn        The DN of the entry to modify.  It must not be
   *                   {@code null}.
   * @param  mods      The set of modifications to apply to the entry.  It must
   *                   not be {@code null} or empty.
   * @param  controls  The set of controls to include in the request.
   */
  public ModifyRequest(final String dn, final List<Modification> mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn;

    modifications = new ArrayList<Modification>(mods);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn        The DN of the entry to modify.  It must not be
   *                   {@code null}.
   * @param  mod       The modification to apply to the entry.  It must not be
   *                   {@code null}.
   * @param  controls  The set of controls to include in the request.
   */
  public ModifyRequest(final DN dn, final Modification mod,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mod);

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(1);
    modifications.add(mod);
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn        The DN of the entry to modify.  It must not be
   *                   {@code null}.
   * @param  mods      The set of modifications to apply to the entry.  It must
   *                   not be {@code null} or empty.
   * @param  controls  The set of controls to include in the request.
   */
  public ModifyRequest(final DN dn, final Modification[] mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.length == 0,
         "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods.length);
    modifications.addAll(Arrays.asList(mods));
  }



  /**
   * Creates a new modify request with the provided information.
   *
   * @param  dn        The DN of the entry to modify.  It must not be
   *                   {@code null}.
   * @param  mods      The set of modifications to apply to the entry.  It must
   *                   not be {@code null} or empty.
   * @param  controls  The set of controls to include in the request.
   */
  public ModifyRequest(final DN dn, final List<Modification> mods,
                       final Control[] controls)
  {
    super(controls);

    ensureNotNull(dn, mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.mods must not be empty.");

    this.dn = dn.toString();

    modifications = new ArrayList<Modification>(mods);
  }



  /**
   * Creates a new modify request from the provided LDIF representation of the
   * changes.
   *
   * @param  ldifModificationLines  The lines that comprise an LDIF
   *                                representation of a modify change record.
   *                                It must not be {@code null} or empty.
   *
   * @throws  LDIFException  If the provided set of lines cannot be parsed as an
   *                         LDIF modify change record.
   */
  public ModifyRequest(final String... ldifModificationLines)
         throws LDIFException
  {
    super(null);

    final LDIFChangeRecord changeRecord =
         LDIFReader.decodeChangeRecord(ldifModificationLines);
    if (! (changeRecord instanceof LDIFModifyChangeRecord))
    {
      throw new LDIFException(ERR_MODIFY_INVALID_LDIF.get(), 0, false,
                              ldifModificationLines, null);
    }

    final LDIFModifyChangeRecord modifyRecord =
         (LDIFModifyChangeRecord) changeRecord;
    final ModifyRequest r = modifyRecord.toModifyRequest();

    dn            = r.dn;
    modifications = r.modifications;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getDN()
  {
    return dn;
  }



  /**
   * Specifies the DN of the entry to modify.
   *
   * @param  dn  The DN of the entry to modify.  It must not be {@code null}.
   */
  public void setDN(final String dn)
  {
    ensureNotNull(dn);

    this.dn = dn;
  }



  /**
   * Specifies the DN of the entry to modify.
   *
   * @param  dn  The DN of the entry to modify.  It must not be {@code null}.
   */
  public void setDN(final DN dn)
  {
    ensureNotNull(dn);

    this.dn = dn.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<Modification> getModifications()
  {
    return Collections.unmodifiableList(modifications);
  }



  /**
   * Adds the provided modification to the set of modifications for this modify
   * request.
   *
   * @param  mod  The modification to be added.  It must not be {@code null}.
   */
  public void addModification(final Modification mod)
  {
    ensureNotNull(mod);

    modifications.add(mod);
  }



  /**
   * Removes the provided modification from the set of modifications for this
   * modify request.
   *
   * @param  mod  The modification to be removed.  It must not be {@code null}.
   *
   * @return  {@code true} if the specified modification was found and removed,
   *          or {@code false} if not.
   */
  public boolean removeModification(final Modification mod)
  {
    ensureNotNull(mod);

    return modifications.remove(mod);
  }



  /**
   * Replaces the existing set of modifications for this modify request with the
   * provided modification.
   *
   * @param  mod  The modification to use for this modify request.  It must not
   *              be {@code null}.
   */
  public void setModifications(final Modification mod)
  {
    ensureNotNull(mod);

    modifications.clear();
    modifications.add(mod);
  }



  /**
   * Replaces the existing set of modifications for this modify request with the
   * provided modifications.
   *
   * @param  mods  The set of modification to use for this modify request.  It
   *               must not be {@code null} or empty.
   */
  public void setModifications(final Modification[] mods)
  {
    ensureNotNull(mods);
    ensureFalse(mods.length == 0,
         "ModifyRequest.setModifications.mods must not be empty.");

    modifications.clear();
    modifications.addAll(Arrays.asList(mods));
  }



  /**
   * Replaces the existing set of modifications for this modify request with the
   * provided modifications.
   *
   * @param  mods  The set of modification to use for this modify request.  It
   *               must not be {@code null} or empty.
   */
  public void setModifications(final List<Modification> mods)
  {
    ensureNotNull(mods);
    ensureFalse(mods.isEmpty(),
                "ModifyRequest.setModifications.mods must not be empty.");

    modifications.clear();
    modifications.addAll(mods);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte getProtocolOpType()
  {
    return LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeTo(final ASN1Buffer writer)
  {
    final ASN1BufferSequence requestSequence =
         writer.beginSequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST);
    writer.addOctetString(dn);

    final ASN1BufferSequence modSequence = writer.beginSequence();
    for (final Modification m : modifications)
    {
      m.writeTo(writer);
    }
    modSequence.end();
    requestSequence.end();
  }



  /**
   * Encodes the modify request protocol op to an ASN.1 element.
   *
   * @return  The ASN.1 element with the encoded modify request protocol op.
   */
  @Override()
  public ASN1Element encodeProtocolOp()
  {
    final ASN1Element[] modElements = new ASN1Element[modifications.size()];
    for (int i=0; i < modElements.length; i++)
    {
      modElements[i] = modifications.get(i).encode();
    }

    final ASN1Element[] protocolOpElements =
    {
      new ASN1OctetString(dn),
      new ASN1Sequence(modElements)
    };



    return new ASN1Sequence(LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST,
                            protocolOpElements);
  }



  /**
   * Sends this modify request to the directory server over the provided
   * connection and returns the associated response.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  depth       The current referral depth for this request.  It should
   *                     always be one for the initial request, and should only
   *                     be incremented when following referrals.
   *
   * @return  An LDAP result object that provides information about the result
   *          of the modify processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  @Override()
  protected LDAPResult process(final LDAPConnection connection, final int depth)
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
        debugException(ie);
        Thread.currentThread().interrupt();
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MODIFY_INTERRUPTED.get(connection.getHostPort()), ie);
      }

      return handleResponse(connection, response, requestTime, depth, false);
    }
    finally
    {
      connection.deregisterResponseAcceptor(messageID);
    }
  }



  /**
   * Sends this modify request to the directory server over the provided
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
  AsyncRequestID processAsync(final LDAPConnection connection,
                              final AsyncResultListener resultListener)
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
           OperationType.MODIFY, messageID, resultListener,
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
      debugLDAPRequest(Level.INFO, this, messageID, connection);
      connection.getConnectionStatistics().incrementNumModifyRequests();
      connection.sendMessage(message, timeout);
      return asyncRequestID;
    }
    catch (final LDAPException le)
    {
      debugException(le);

      connection.deregisterResponseAcceptor(messageID);
      throw le;
    }
  }



  /**
   * Processes this modify operation in synchronous mode, in which the same
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
   *          of the modify processing.
   *
   * @throws  LDAPException  If a problem occurs while sending the request or
   *                         reading the response.
   */
  private LDAPResult processSync(final LDAPConnection connection,
                                 final int depth, final boolean allowRetry)
          throws LDAPException
  {
    // Create the LDAP message.
    messageID = connection.nextMessageID();
    final LDAPMessage message =
         new LDAPMessage(messageID,  this, getControls());


    // Send the request to the server.
    final long requestTime = System.nanoTime();
    debugLDAPRequest(Level.INFO, this, messageID, connection);
    connection.getConnectionStatistics().incrementNumModifyRequests();
    try
    {
      connection.sendMessage(message, getResponseTimeoutMillis(connection));
    }
    catch (final LDAPException le)
    {
      debugException(le);

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
        debugException(le);

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
   * @return  The modify result.
   *
   * @throws  LDAPException  If a problem occurs.
   */
  private LDAPResult handleResponse(final LDAPConnection connection,
                                    final LDAPResponse response,
                                    final long requestTime, final int depth,
                                    final boolean allowRetry)
          throws LDAPException
  {
    if (response == null)
    {
      final long waitTime = nanosToMillis(System.nanoTime() - requestTime);
      if (connection.getConnectionOptions().abandonOnTimeout())
      {
        connection.abandon(messageID);
      }

      throw new LDAPException(ResultCode.TIMEOUT,
           ERR_MODIFY_CLIENT_TIMEOUT.get(waitTime, messageID, dn,
                connection.getHostPort()));
    }

    connection.getConnectionStatistics().incrementNumModifyResponses(
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
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_RESPONSE.get(
                  connection.getHostPort(), toString()));
      }
      else
      {
        throw new LDAPException(ccr.getResultCode(),
             ERR_CONN_CLOSED_WAITING_FOR_MODIFY_RESPONSE_WITH_MESSAGE.get(
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
  private LDAPResult reconnectAndRetry(final LDAPConnection connection,
                                       final int depth,
                                       final ResultCode resultCode)
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
      debugException(e);
    }

    return null;
  }



  /**
   * Attempts to follow a referral to perform a modify operation in the target
   * server.
   *
   * @param  referralResult  The LDAP result object containing information about
   *                         the referral to follow.
   * @param  connection      The connection on which the referral was received.
   * @param  depth           The number of referrals followed in the course of
   *                         processing this request.
   *
   * @return  The result of attempting to process the modify operation by
   *          following the referral.
   *
   * @throws  LDAPException  If a problem occurs while attempting to establish
   *                         the referral connection, sending the request, or
   *                         reading the result.
   */
  private LDAPResult followReferral(final LDAPResult referralResult,
                                    final LDAPConnection connection,
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

        final ModifyRequest modifyRequest;
        if (referralURL.baseDNProvided())
        {
          modifyRequest = new ModifyRequest(referralURL.getBaseDN(),
                                            modifications, getControls());
        }
        else
        {
          modifyRequest = this;
        }

        final LDAPConnection referralConn = connection.getReferralConnector().
             getReferralConnection(referralURL, connection);
        try
        {
          return modifyRequest.process(referralConn, depth+1);
        }
        finally
        {
          referralConn.setDisconnectInfo(DisconnectType.REFERRAL, null, null);
          referralConn.close();
        }
      }
      catch (final LDAPException le)
      {
        debugException(le);
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
  public void responseReceived(final LDAPResponse response)
         throws LDAPException
  {
    try
    {
      responseQueue.put(response);
    }
    catch (final Exception e)
    {
      debugException(e);

      if (e instanceof InterruptedException)
      {
        Thread.currentThread().interrupt();
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_EXCEPTION_HANDLING_RESPONSE.get(getExceptionMessage(e)), e);
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
  public OperationType getOperationType()
  {
    return OperationType.MODIFY;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ModifyRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ModifyRequest duplicate(final Control[] controls)
  {
    final ModifyRequest r = new ModifyRequest(dn,
         new ArrayList<Modification>(modifications), controls);

    if (followReferralsInternal() != null)
    {
      r.setFollowReferrals(followReferralsInternal());
    }

    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));

    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFModifyChangeRecord toLDIFChangeRecord()
  {
    return new LDIFModifyChangeRecord(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String[] toLDIF()
  {
    return toLDIFChangeRecord().toLDIF();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String toLDIFString()
  {
    return toLDIFChangeRecord().toLDIFString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ModifyRequest(dn='");
    buffer.append(dn);
    buffer.append("', mods={");
    for (int i=0; i < modifications.size(); i++)
    {
      final Modification m = modifications.get(i);

      if (i > 0)
      {
        buffer.append(", ");
      }

      switch (m.getModificationType().intValue())
      {
        case 0:
          buffer.append("ADD ");
          break;

        case 1:
          buffer.append("DELETE ");
          break;

        case 2:
          buffer.append("REPLACE ");
          break;

        case 3:
          buffer.append("INCREMENT ");
          break;
      }

      buffer.append(m.getAttributeName());
    }
    buffer.append('}');

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
  public void toCode(final List<String> lineList, final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs =
         new ArrayList<ToCodeArgHelper>(modifications.size() + 1);
    constructorArgs.add(ToCodeArgHelper.createString(dn, "Entry DN"));

    boolean firstMod = true;
    for (final Modification m : modifications)
    {
      final String comment;
      if (firstMod)
      {
        firstMod = false;
        comment = "Modifications";
      }
      else
      {
        comment = null;
      }

      constructorArgs.add(ToCodeArgHelper.createModification(m, comment));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces, "ModifyRequest",
         requestID + "Request", "new ModifyRequest", constructorArgs);


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
           "Result = connection.modify(" + requestID + "Request);");
      lineList.add(indent + "  // The modify was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The modify failed.  Maybe the following " +
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
