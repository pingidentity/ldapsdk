/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.AddResponseProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.BindResponseProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareResponseProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteResponseProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedResponseProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyResponseProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNResponseProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchResultDoneProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of an LDAP listener request handler
 * that can be used to limit the number of requests that may be processed
 * concurrently.  It uses one or more {@link Semaphore} instances to limit the
 * number of requests that may be processed at any time, and provides the
 * ability to impose limiting on a per-operation-type basis.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ConcurrentRequestLimiterRequestHandler
       extends LDAPListenerRequestHandler
{
  // The downstream request handler that will be used to process the requests
  // after any appropriate concurrent request limiting has been performed.
  @NotNull private final LDAPListenerRequestHandler downstreamRequestHandler;

  // A timeout value (expressed in milliseconds) that will cause the operation
  // to be rejected rather than processed if the associated semaphore cannot be
  // acquired in this length of time.
  private final long rejectTimeoutMillis;

  // The semaphores that will be used for each type of operation.
  @Nullable private final          Semaphore abandonSemaphore;
  @Nullable private final Semaphore addSemaphore;
  @Nullable private final Semaphore bindSemaphore;
  @Nullable private final Semaphore compareSemaphore;
  @Nullable private final Semaphore deleteSemaphore;
  @Nullable private final Semaphore extendedSemaphore;
  @Nullable private final Semaphore modifySemaphore;
  @Nullable private final Semaphore modifyDNSemaphore;
  @Nullable private final Semaphore searchSemaphore;



  /**
   * Creates a new concurrent request limiter request handler that will impose
   * the specified limit on the number of operations that may be in progress at
   * any time.  The limit will be enforced for all types of operations except
   * abandon and unbind operations, which will not be limited.
   *
   * @param  downstreamRequestHandler  The downstream request handler that will
   *                                   be used to actually process the requests
   *                                   after any appropriate limiting has been
   *                                   performed.
   * @param  maxConcurrentRequests     The maximum number of requests that may
   *                                   be processed at any given time.  This
   *                                   limit will be enforced for all operation
   *                                   types except abandon and unbind, which
   *                                   will not be limited.
   * @param  rejectTimeoutMillis       A timeout value (expressed in
   *                                   milliseconds) that will cause a requested
   *                                   operation to be rejected rather than
   *                                   processed if the associate semaphore
   *                                   cannot be acquired in this length of
   *                                   time.  A value of zero indicates that the
   *                                   operation should be rejected immediately
   *                                   if the maximum number of concurrent
   *                                   requests are already in progress.  A
   *                                   value that is less than zero indicates
   *                                   that no timeout should be imposed and
   *                                   that requests should be forced to wait as
   *                                   long as necessary until they can be
   *                                   processed.
   */
  public ConcurrentRequestLimiterRequestHandler(
       @NotNull final LDAPListenerRequestHandler downstreamRequestHandler,
       final int maxConcurrentRequests, final long rejectTimeoutMillis)
  {
    this(downstreamRequestHandler, new Semaphore(maxConcurrentRequests),
         rejectTimeoutMillis);
  }



  /**
   * Creates a new concurrent request limiter request handler that will use the
   * provided semaphore to limit on the number of operations that may be in
   * progress at any time.  The limit will be enforced for all types of
   * operations except abandon and unbind operations, which will not be limited.
   *
   * @param  downstreamRequestHandler  The downstream request handler that will
   *                                   be used to actually process the requests
   *                                   after any appropriate limiting has been
   *                                   performed.
   * @param  semaphore                 The semaphore that will be used to limit
   *                                   the number of concurrent operations in
   *                                   progress, for all operation types except
   *                                   abandon and unbind.
   * @param  rejectTimeoutMillis       A timeout value (expressed in
   *                                   milliseconds) that will cause a requested
   *                                   operation to be rejected rather than
   *                                   processed if the associate semaphore
   *                                   cannot be acquired in this length of
   *                                   time.  A value of zero indicates that the
   *                                   operation should be rejected immediately
   *                                   if the maximum number of concurrent
   *                                   requests are already in progress.  A
   *                                   value that is less than zero indicates
   *                                   that no timeout should be imposed and
   *                                   that requests should be forced to wait as
   *                                   long as necessary until they can be
   *                                   processed.
   */
  public ConcurrentRequestLimiterRequestHandler(
       @NotNull final LDAPListenerRequestHandler downstreamRequestHandler,
       @NotNull final Semaphore semaphore, final long rejectTimeoutMillis)
  {
    this(downstreamRequestHandler, null, semaphore, semaphore, semaphore,
         semaphore, semaphore, semaphore, semaphore, semaphore,
         rejectTimeoutMillis);
  }



  /**
   * Creates a new concurrent request limiter request handler that can use the
   * provided semaphore instances to limit the number of operations in progress
   * concurrently for each type of operation.  The same semaphore instance can
   * be provided for multiple operation types if performance for those
   * operations should be limited in aggregate rather than individually (e.g.,
   * if you don't want the total combined number of search and modify operations
   * in progress at any time to exceed a given threshold, then you could provide
   * the same semaphore instance for the {@code modifySemaphore} and
   * {@code searchSemaphore} arguments).
   *
   * @param  downstreamRequestHandler  The downstream request handler that will
   *                                   be used to actually process the requests
   *                                   after any appropriate rate limiting has
   *                                   been performed.  It must not be
   *                                   {@code null}.
   * @param  abandonSemaphore          The semaphore to use when processing
   *                                   abandon operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for abandon
   *                                   operations.
   * @param  addSemaphore              The semaphore to use when processing add
   *                                   operations.  It may be {@code null} if no
   *                                   concurrent request limiting should be
   *                                   performed for add operations.
   * @param  bindSemaphore             The semaphore to use when processing
   *                                   bind operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for bind
   *                                   operations.
   * @param  compareSemaphore          The semaphore to use when processing
   *                                   compare operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for compare
   *                                   operations.
   * @param  deleteSemaphore           The semaphore to use when processing
   *                                   delete operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for delete
   *                                   operations.
   * @param  extendedSemaphore         The semaphore to use when processing
   *                                   extended operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for extended
   *                                   operations.
   * @param  modifySemaphore           The semaphore to use when processing
   *                                   modify operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for modify
   *                                   operations.
   * @param  modifyDNSemaphore         The semaphore to use when processing
   *                                   modify DN operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for modify
   *                                   DN operations.
   * @param  searchSemaphore           The semaphore to use when processing
   *                                   search operations.  It may be
   *                                   {@code null} if no concurrent request
   *                                   limiting should be performed for search
   *                                   operations.
   * @param  rejectTimeoutMillis       A timeout value (expressed in
   *                                   milliseconds) that will cause a requested
   *                                   operation to be rejected rather than
   *                                   processed if the associate semaphore
   *                                   cannot be acquired in this length of
   *                                   time.  A value of zero indicates that the
   *                                   operation should be rejected immediately
   *                                   if the maximum number of concurrent
   *                                   requests are already in progress.  A
   *                                   value that is less than zero indicates
   *                                   that no timeout should be imposed and
   *                                   that requests should be forced to wait as
   *                                   long as necessary until they can be
   *                                   processed.
   */
  public ConcurrentRequestLimiterRequestHandler(
       @NotNull final LDAPListenerRequestHandler downstreamRequestHandler,
       @Nullable final Semaphore abandonSemaphore,
       @Nullable final Semaphore addSemaphore,
       @Nullable final Semaphore bindSemaphore,
       @Nullable final Semaphore compareSemaphore,
       @Nullable final Semaphore deleteSemaphore,
       @Nullable final Semaphore extendedSemaphore,
       @Nullable final Semaphore modifySemaphore,
       @Nullable final Semaphore modifyDNSemaphore,
       @Nullable final Semaphore searchSemaphore,
       final long rejectTimeoutMillis)
  {
    Validator.ensureNotNull(downstreamRequestHandler);

    this.downstreamRequestHandler = downstreamRequestHandler;
    this.abandonSemaphore         = abandonSemaphore;
    this.addSemaphore             = addSemaphore;
    this.bindSemaphore            = bindSemaphore;
    this.compareSemaphore         = compareSemaphore;
    this.deleteSemaphore          = deleteSemaphore;
    this.extendedSemaphore        = extendedSemaphore;
    this.modifySemaphore          = modifySemaphore;
    this.modifyDNSemaphore        = modifyDNSemaphore;
    this.searchSemaphore          = searchSemaphore;

    if (rejectTimeoutMillis >= 0L)
    {
      this.rejectTimeoutMillis = rejectTimeoutMillis;
    }
    else
    {
      this.rejectTimeoutMillis = (long) Integer.MAX_VALUE;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ConcurrentRequestLimiterRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new ConcurrentRequestLimiterRequestHandler(
         downstreamRequestHandler.newInstance(connection), abandonSemaphore,
         addSemaphore, bindSemaphore, compareSemaphore, deleteSemaphore,
         extendedSemaphore, modifySemaphore, modifyDNSemaphore,
         searchSemaphore, rejectTimeoutMillis);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                   @NotNull final AbandonRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(abandonSemaphore, OperationType.ABANDON);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return;
    }

    try
    {
      downstreamRequestHandler.processAbandonRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(abandonSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processAddRequest(final int messageID,
                          @NotNull final AddRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(addSemaphore, OperationType.ADD);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new AddResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processAddRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(addSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processBindRequest(final int messageID,
                          @NotNull final BindRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(bindSemaphore, OperationType.BIND);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new BindResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processBindRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(bindSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processCompareRequest(final int messageID,
                          @NotNull final CompareRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(compareSemaphore, OperationType.COMPARE);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new CompareResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processCompareRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(compareSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processDeleteRequest(final int messageID,
                          @NotNull final DeleteRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(deleteSemaphore, OperationType.DELETE);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new DeleteResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processDeleteRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(deleteSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processExtendedRequest(final int messageID,
                          @NotNull final ExtendedRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(extendedSemaphore, OperationType.EXTENDED);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new ExtendedResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processExtendedRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(extendedSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyRequest(final int messageID,
                          @NotNull final ModifyRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(modifySemaphore, OperationType.MODIFY);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new ModifyResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processModifyRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(modifySemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processModifyDNRequest(final int messageID,
                          @NotNull final ModifyDNRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(modifyDNSemaphore, OperationType.MODIFY_DN);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new ModifyDNResponseProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processModifyDNRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(modifyDNSemaphore);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPMessage processSearchRequest(final int messageID,
                          @NotNull final SearchRequestProtocolOp request,
                          @NotNull final List<Control> controls)
  {
    try
    {
      acquirePermit(searchSemaphore, OperationType.SEARCH);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      return new LDAPMessage(messageID,
           new SearchResultDoneProtocolOp(le.toLDAPResult()));
    }

    try
    {
      return downstreamRequestHandler.processSearchRequest(messageID, request,
           controls);
    }
    finally
    {
      releasePermit(searchSemaphore);
    }
  }



  /**
   * Acquires a permit from the provided semaphore.
   *
   * @param  semaphore      The semaphore from which to acquire a permit.  It
   *                        may be {@code null} if no semaphore is needed for
   *                        the associated operation type.
   * @param  operationType  The type of operation
   *
   * @throws  LDAPException  If it was not possible to acquire a permit from the
   *                         provided semaphore.
   */
  private void acquirePermit(@NotNull final Semaphore semaphore,
                             @NotNull final OperationType operationType)
          throws LDAPException
  {
    if (semaphore == null)
    {
      return;
    }

    try
    {
      if (rejectTimeoutMillis == 0L)
      {
        if (! semaphore.tryAcquire())
        {
          throw new LDAPException(ResultCode.BUSY,
               ERR_CONCURRENT_LIMITER_REQUEST_HANDLER_NO_TIMEOUT.get(
                    operationType.name()));
        }
      }
      else
      {
        if (! semaphore.tryAcquire(rejectTimeoutMillis, TimeUnit.MILLISECONDS))
        {
          throw new LDAPException(ResultCode.BUSY,
               ERR_CONCURRENT_LIMITER_REQUEST_HANDLER_TIMEOUT.get(
                    operationType.name(), rejectTimeoutMillis));
        }
      }
    }
    catch (final LDAPException le)
    {
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.OTHER,
           ERR_CONCURRENT_LIMITER_REQUEST_HANDLER_SEMAPHORE_EXCEPTION.get(
                operationType.name(), StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Releases a permit back to the provided semaphore.
   *
   * @param  semaphore  The semaphore to which the permit should be released.
   *                    It may be {@code null} if no semaphore is needed for the
   *                    associated operation type.
   */
  private static void releasePermit(@NotNull final Semaphore semaphore)
  {
    if (semaphore != null)
    {
      semaphore.release();
    }
  }
}
