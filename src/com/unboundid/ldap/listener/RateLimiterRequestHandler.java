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

import com.unboundid.ldap.protocol.AbandonRequestProtocolOp;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.protocol.CompareRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.SearchRequestProtocolOp;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides an implementation of an LDAP listener request handler
 * that can be used to apply rate limiting to client requests.  It uses one or
 * more {@link FixedRateBarrier} instances to enforce the rate limiting, and
 * provides the ability to control rate limiting on a per-operation-type basis.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RateLimiterRequestHandler
       extends LDAPListenerRequestHandler
{
  // The rate limiters that will be used for each type of operation.
  @Nullable private final FixedRateBarrier abandonRateLimiter;
  @Nullable private final FixedRateBarrier addRateLimiter;
  @Nullable private final FixedRateBarrier bindRateLimiter;
  @Nullable private final FixedRateBarrier compareRateLimiter;
  @Nullable private final FixedRateBarrier deleteRateLimiter;
  @Nullable private final FixedRateBarrier extendedRateLimiter;
  @Nullable private final FixedRateBarrier modifyRateLimiter;
  @Nullable private final FixedRateBarrier modifyDNRateLimiter;
  @Nullable private final FixedRateBarrier searchRateLimiter;

  // The downstream request handler that will be used to process the requests
  // after any appropriate rate limiting has been performed.
  @NotNull private final LDAPListenerRequestHandler downstreamRequestHandler;



  /**
   * Creates a new rate limiter request handler that will limit the rate of
   * operations to the specified maximum number per second.  The rate limiting
   * will be enforced for all types of operations except abandon and unbind.
   * No rate limiting will be enforced for abandon or unbind operations.
   *
   * @param  downstreamRequestHandler  The downstream request handler that will
   *                                   be used to actually process the requests
   *                                   after any appropriate rate limiting has
   *                                   been performed.  It must not be
   *                                   {@code null}.
   * @param  maxPerSecond              The maximum number of operations that
   *                                   will be allowed per second, across all
   *                                   types of operations except abandon and
   *                                   unbind.  It must be greater than zero.
   */
  public RateLimiterRequestHandler(
       @NotNull final LDAPListenerRequestHandler downstreamRequestHandler,
       final int maxPerSecond)
  {
    Validator.ensureNotNull(downstreamRequestHandler);
    Validator.ensureTrue(maxPerSecond > 0);

    this.downstreamRequestHandler = downstreamRequestHandler;

    final FixedRateBarrier rateLimiter =
         new FixedRateBarrier(1000L, maxPerSecond);

    abandonRateLimiter  = null;
    addRateLimiter      = rateLimiter;
    bindRateLimiter     = rateLimiter;
    compareRateLimiter  = rateLimiter;
    deleteRateLimiter   = rateLimiter;
    extendedRateLimiter = rateLimiter;
    modifyRateLimiter   = rateLimiter;
    modifyDNRateLimiter = rateLimiter;
    searchRateLimiter   = rateLimiter;
  }



  /**
   * Creates a new rate limiter request handler that will use the provided
   * {@link FixedRateBarrier} to perform rate limiting for all types of
   * operations except abandon and unbind.  No rate limiting will be enforced
   * for abandon or unbind operations.
   *
   * @param  downstreamRequestHandler  The downstream request handler that will
   *                                   be used to actually process the requests
   *                                   after any appropriate rate limiting has
   *                                   been performed.  It must not be
   *                                   {@code null}.
   * @param  rateLimiter               The fixed-rate barrier that will be used
   *                                   to achieve the rate limiting for all
   *                                   types of operations except abandon and
   *                                   unbind.  It may be {@code null} if no
   *                                   rate limiting should be performed for any
   *                                   operation types.
   */
  public RateLimiterRequestHandler(
       @NotNull final LDAPListenerRequestHandler downstreamRequestHandler,
       @Nullable final FixedRateBarrier rateLimiter)
  {
    this(downstreamRequestHandler, null, rateLimiter, rateLimiter, rateLimiter,
         rateLimiter, rateLimiter, rateLimiter, rateLimiter, rateLimiter);
  }



  /**
   * Creates a new rate limiter request handler that can use the provided
   * {@link FixedRateBarrier} instances to perform rate limiting for different
   * types of operations.  The same barrier instance can be provided for
   * multiple operation types if performance for those operations should be
   * limited in aggregate rather than individually (e.g., if you don't want the
   * total combined rate of search and modify operations to exceed a given
   * threshold, then you could provide the same barrier instance for the
   * {@code modifyRateLimiter} and {@code searchRateLimiter} arguments).
   *
   * @param  downstreamRequestHandler  The downstream request handler that will
   *                                   be used to actually process the requests
   *                                   after any appropriate rate limiting has
   *                                   been performed.  It must not be
   *                                   {@code null}.
   * @param  abandonRateLimiter        The fixed-rate barrier to use when
   *                                   processing abandon operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for abandon operations.
   * @param  addRateLimiter            The fixed-rate barrier to use when
   *                                   processing add operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for add operations.
   * @param  bindRateLimiter           The fixed-rate barrier to use when
   *                                   processing bind operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for bind operations.
   * @param  compareRateLimiter        The fixed-rate barrier to use when
   *                                   processing compare operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for compare operations.
   * @param  deleteRateLimiter         The fixed-rate barrier to use when
   *                                   processing delete operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for delete operations.
   * @param  extendedRateLimiter       The fixed-rate barrier to use when
   *                                   processing extended operations.  It may
   *                                   be {@code null} if no rate limiting
   *                                   should be enforced for extended
   *                                   operations.
   * @param  modifyRateLimiter         The fixed-rate barrier to use when
   *                                   processing modify operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for modify operations.
   * @param  modifyDNRateLimiter       The fixed-rate barrier to use when
   *                                   processing modify DN operations.  It may
   *                                   be {@code null} if no rate limiting
   *                                   should be enforced for modify DN
   *                                   operations.
   * @param  searchRateLimiter         The fixed-rate barrier to use when
   *                                   processing search operations.  It may be
   *                                   {@code null} if no rate limiting should
   *                                   be enforced for search operations.
   */
  public RateLimiterRequestHandler(
       @Nullable final LDAPListenerRequestHandler downstreamRequestHandler,
       @Nullable final FixedRateBarrier abandonRateLimiter,
       @Nullable final FixedRateBarrier addRateLimiter,
       @Nullable final FixedRateBarrier bindRateLimiter,
       @Nullable final FixedRateBarrier compareRateLimiter,
       @Nullable final FixedRateBarrier deleteRateLimiter,
       @Nullable final FixedRateBarrier extendedRateLimiter,
       @Nullable final FixedRateBarrier modifyRateLimiter,
       @Nullable final FixedRateBarrier modifyDNRateLimiter,
       @Nullable final FixedRateBarrier searchRateLimiter)
  {
    Validator.ensureNotNull(downstreamRequestHandler);

    this.downstreamRequestHandler = downstreamRequestHandler;
    this.abandonRateLimiter       = abandonRateLimiter;
    this.addRateLimiter           = addRateLimiter;
    this.bindRateLimiter          = bindRateLimiter;
    this.compareRateLimiter       = compareRateLimiter;
    this.deleteRateLimiter        = deleteRateLimiter;
    this.extendedRateLimiter      = extendedRateLimiter;
    this.modifyRateLimiter        = modifyRateLimiter;
    this.modifyDNRateLimiter      = modifyDNRateLimiter;
    this.searchRateLimiter        = searchRateLimiter;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull
  public RateLimiterRequestHandler newInstance(
              @NotNull final LDAPListenerClientConnection connection)
         throws LDAPException
  {
    return new RateLimiterRequestHandler(
         downstreamRequestHandler.newInstance(connection), abandonRateLimiter,
         addRateLimiter, bindRateLimiter, compareRateLimiter, deleteRateLimiter,
         extendedRateLimiter, modifyRateLimiter, modifyDNRateLimiter,
         searchRateLimiter);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAbandonRequest(final int messageID,
                   @NotNull final AbandonRequestProtocolOp request,
                   @NotNull final List<Control> controls)
  {
    if (abandonRateLimiter != null)
    {
      abandonRateLimiter.await();
    }

    downstreamRequestHandler.processAbandonRequest(messageID, request,
         controls);
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
    if (addRateLimiter != null)
    {
      addRateLimiter.await();
    }

    return downstreamRequestHandler.processAddRequest(messageID, request,
         controls);
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
    if (bindRateLimiter != null)
    {
      bindRateLimiter.await();
    }

    return downstreamRequestHandler.processBindRequest(messageID, request,
         controls);
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
    if (compareRateLimiter != null)
    {
      compareRateLimiter.await();
    }

    return downstreamRequestHandler.processCompareRequest(messageID, request,
         controls);
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
    if (deleteRateLimiter != null)
    {
      deleteRateLimiter.await();
    }

    return downstreamRequestHandler.processDeleteRequest(messageID, request,
         controls);
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
    if (extendedRateLimiter != null)
    {
      extendedRateLimiter.await();
    }

    return downstreamRequestHandler.processExtendedRequest(messageID, request,
         controls);
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
    if (modifyRateLimiter != null)
    {
      modifyRateLimiter.await();
    }

    return downstreamRequestHandler.processModifyRequest(messageID, request,
         controls);
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
    if (modifyDNRateLimiter != null)
    {
      modifyDNRateLimiter.await();
    }

    return downstreamRequestHandler.processModifyDNRequest(messageID, request,
         controls);
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
    if (searchRateLimiter != null)
    {
      searchRateLimiter.await();
    }

    return downstreamRequestHandler.processSearchRequest(messageID, request,
         controls);
  }
}
