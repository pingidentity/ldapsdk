/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be used to request that the
 * Directory Proxy Server forward the associated operation to a specific backend
 * set associated with an entry-balancing request processor.  It may be either
 * an absolute routing request, indicating that the target backend set(s) are
 * the only ones that may be used to process the operation, or it may be used to
 * provide a routing hint in lieu of accessing the global index.
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
 * This control may be used for a number of different kinds of requests, as
 * follows:
 * <UL>
 *   <LI>For an add request that uses absolute routing, exactly one target
 *       backend set ID must be specified, and the request will be sent only to
 *       that backend set.
 *       <BR>
 *       <B>WARNING</B>:  The use of absolute routing for an add
 *       operation bypasses the check to ensure that no entry already exists
 *       with the same DN as the new entry, so it is possible that an add
 *       performed immediately below the balancing point could result in
 *       creating an entry in one backend set with the same DN as another entry
 *       in a different backend set.  Similarly, if the entry-balancing request
 *       processor is configured to broadcast add operations outside the
 *       balancing point rather than relying on those adds to be replicated,
 *       then it is strongly recommended that absolute routing not be used for
 *       add operations outside the balancing point because that will cause the
 *       entry to be added to only one backend set rather than to all backend
 *       sets.</LI>
 *   <LI>For an add request that uses a routing hint, exactly one target backend
 *       set ID must be specified for the first guess, although any number of
 *       fallback set IDs may be specified.  For entries immediately below the
 *       balancing point, the routing hint will be used instead of a placement
 *       algorithm in order to select which backend set should hold the entry
 *       (and the fallback sets will not be used).  For entries more than one
 *       level below the balancing point, the routing hint will be used in lieu
 *       of the global index as an attempt to determine where the parent entry
 *       exists, and the fallback sets may be used if the parent entry doesn't
 *       exist in the first guess set.  For entries outside the balancing point,
 *       if the entry-balancing request processor is configured to add entries
 *       to one set and allow them to be replicated to other sets, then the
 *       first guess hint will be used to select the set to which the entry will
 *       be added (and the fallback sets will not be used).  An add operation
 *       with a routing hint cannot be used to create multiple entries with the
 *       same DN in different backend sets, nor can it cause an entry outside
 *       the balancing point to exist in only one backend set.</LI>
 *   <LI>For a simple bind request that uses absolute routing, exactly one
 *       target backend set ID must be specified, and the request will be sent
 *       only to that backend set.  If the bind fails in that set, even if the
 *       failure is because the target entry does not exist in that backend set,
 *       then the failure will be returned to the client rather than attempting
 *       the operation in a different backend set.</LI>
 *   <LI>For a simple bind request that uses a routing hint, exactly one target
 *       backend set ID must be specified for the first guess, although any
 *       number of fallback set IDs may be specified.  If the bind fails in the
 *       first guess set, it may be re-attempted in the fallback sets.</LI>
 *   <LI>For a compare request that uses absolute routing, exactly one target
 *       backend set ID must be specified, and the request will be sent only to
 *       that backend set.  If the compare fails in that set, even if the
 *       failure is because the target entry does not exist in that set, then
 *       the failure will be returned to the client rather than attempting the
 *       operation in a different backend set.</LI>
 *   <LI>For a compare request that uses a routing hint, exactly one target
 *       backend set ID must be specified for the first guess, although any
 *       number of fallback set IDs may be specified.  If the compare operation
 *       fails in the first guess set in a way that suggests the target entry
 *       does not exist in that backend set, then it will be re-attempted in the
 *       fallback sets.</LI>
 *   <LI>For a delete request that uses absolute routing, exactly one target
 *       backend set ID must be specified, and the request will be sent only to
 *       that backend set.  If the delete fails in that set, even if the failure
 *       is because the target entry does not exist in that set, then the
 *       failure will be returned to the client rather than attempting the
 *       operation in a different backend set.
 *       <BR>
 *       <B>WARNING</B>:  If the entry-balancing request processor is configured
 *       to broadcast delete operations outside the balancing point rather than
 *       relying on those deletes to be replicated, then it is strongly
 *       recommended that absolute routing not be used for delete operations
 *       outside the balancing point because that will cause the entry to be
 *       deleted in only one backend set and will remain in all other backend
 *       sets.</LI>
 *   <LI>For a delete request that uses a routing hint, exactly one target
 *       backend set ID must be specified for the first guess, although any
 *       number of fallback set IDs may be specified.  For entries below the
 *       balancing point, the routing hint will be used in lieu of the global
 *       index in order to determine which backend set contains the target
 *       entry.  If the delete fails in the first guess set in a way that
 *       suggests that the target entry does not exist in that backend set, then
 *       it will be re-attempted in the fallback sets.
 *       <BR>
 *       For entries outside the balancing point, if the entry-balancing request
 *       processor is configured to delete entries from only one backend set
 *       and allow that delete to be replicated to all other sets, then the
 *       routing hint may be used to select the set from which that entry will
 *       be deleted.  A delete operation with a routing hint cannot be used to
 *       cause an entry outside the balancing point to be removed from only one
 *       backend set while leaving it in the remaining sets.</LI>
 *   <LI>For an atomic multi-update extended request, only absolute routing is
 *       supported, and the route to backend set request control must be
 *       attached to the extended operation itself and not to any of the
 *       requests contained inside the multi-update.  Exactly one backend set ID
 *       must be specified, and the multi-update request will be sent only to
 *       that backend set.</LI>
 *   <LI>For a non-atomic multi-update extended request, the extended operation
 *       must not include a route to backend set request control.  However, any
 *       or all of the requests inside the multi-update request may include a
 *       route to backend set request control, and in that case it will be
 *       treated in the same way as for a request of the same type not
 *       included in multi-update request (e.g., if a multi-update extended
 *       operation includes an add request with a route to backend set request
 *       control, then that route control will have the same effect as for the
 *       same add request with the same control processed outside a multi-update
 *       operation).</LI>
 *   <LI>For an extended request that will be processed by a proxied extended
 *       operation handler, the request may include a route to backend set
 *       request control and that control will be used to select the target
 *       backend sets instead of the proxied extended operation handler's
 *       {@code selectBackendSets} method.</LI>
 *   <LI>For a modify request that uses absolute routing, exactly one target
 *       backend set ID must be specified, and the request will be sent only to
 *       that backend set.  If the modify fails in that set, even if the failure
 *       is because the target entry does not exist in that set, then the
 *       failure will be returned to the client rather than attempting the
 *       operation in a different backend set.
 *       <BR>
 *       <B>WARNING</B>:  When processing a modify operation against the
 *       balancing point entry itself, the Directory Proxy Server will typically
 *       send that modify request to all backend sets to ensure that it is
 *       properly applied everywhere.  However, with an absolute routing
 *       request, the modify operation will be sent only to one backend set,
 *       which will cause the entry in that set to be out of sync with the entry
 *       in all other sets.  It is therefore strongly recommended that absolute
 *       routing not be used for modify operations that target the balancing
 *       point entry.  Similarly, if the entry-balancing request processor is
 *       configured to broadcast modify operations targeting entries outside the
 *       balancing point to all backend sets rather than having those modify
 *       operations replicated to the other backend sets, it is strongly
 *       recommended that absolute routing not be used for those operations
 *       because the request will be sent to only one set, causing the entry in
 *       that set to be out of sync with the corresponding entry in other
 *       backend sets.</LI>
 *   <LI>For a modify request that uses a routing hint, exactly one target
 *       backend set ID must be specified for the first guess, although any
 *       number of fallback set IDs may be specified.  For entries below the
 *       balancing point, the routing hint will be used in lieu of the global
 *       index in order to determine which backend set contains the target
 *       entry.  If the modify attempt fails in the first guess set in a way
 *       that suggests the target entry does not exist in that backend set, then
 *       it will be re-attempted in the fallback sets.
 *       <BR>
 *       For modify operations that target the balancing point entry itself, the
 *       entry-balancing request processor will send the request to all backend
 *       sets, and the routing hint will not be used.  Similarly, for entries
 *       outside the balancing point, if the entry-balancing request processor
 *       is configured to modify entries in only one backend set and allow that
 *       modify operation to be replicated to all other sets, then the routing
 *       hint may be used to select the set in which that entry will be
 *       modified.  A modify operation with a routing hint cannot be used to
 *       cause an entry at or outside the balancing point to be updated in only
 *       one backend set, leaving it out of sync with the corresponding entry in
 *       the remaining sets.</LI>
 *   <LI>For a modify DN request that uses absolute routing, exactly one target
 *       backend set ID must be specified, and the request wil be sent only to
 *       that backend set.  If the modify DN operation fails in that set, even
 *       if the failure is because the target entry does not exist in that set,
 *       then the failure will be returned to the client rather than attempting
 *       the operation in a different backend set.
 *       <BR>
 *       <B>WARNING</B>:  Processing a modify DN operation with absolute routing
 *       bypasses the check to ensure that the new DN for the target entry does
 *       not conflict with the DN for an entry that exists in any other backend
 *       set.  As a result, you are strongly discouraged from using absolute
 *       routing for any modify DN operation that would cause the new DN for the
 *       entry to be exactly one level below the balancing point.  Further, for
 *       entries that exist outside the balancing point, if the entry-balancing
 *       request processor is configured to broadcast modify DN operations
 *       rather than expecting them to be replicated to the other backend sets,
 *       a modify DN operation with absolute routing would cause the change to
 *       be applied only in one backend set, leaving it out of sync with the
 *       other sets.</LI>
 *   <LI>For a modify DN request that uses a routing hint, exactly one target
 *       backend set ID must be specified for the first guess, although any
 *       number of fallback set IDs may be specified.  For entries below the
 *       balancing point, the routing hint will be used in lieu of the global
 *       index in order to determine which backend set contains the target
 *       entry.  If the modify attempt fails in the first guess set in a way
 *       that suggests the target entry does not exist in that backend set, then
 *       it will be re-attempted in the fallback sets.
 *       <BR>
 *       For entries outside the balancing point, if the entry-balancing request
 *       processor is configured to process modify DN operations in one backend
 *       set and allow them to be replicated to other backend sets, then the
 *       routing hint will be used to select which backend set should receive
 *       the modify DN request.  A modify DN operation with a routing hint
 *       cannot be used to create a conflict in which the same DN exists in
 *       multiple backend sets, or a case in which a modify DN operation outside
 *       the balancing point leaves one backend set out of sync with the other
 *       sets.</LI>
 *   <LI>For a search request that uses absolute routing, there may be multiple
 *       target backend set IDs only if the scope of the search may include
 *       data from multiple backend sets (i.e., the base DN is at or above the
 *       balancing point, and the scope include entries at least one level below
 *       the balancing point entry).  If the base and scope of the search allow
 *       it to match only entries at or above the balancing point or only
 *       entries within one backend set, then the absolute routing request must
 *       target exactly one backend set.</LI>
 *   <LI>For a search request that uses a routing hint, exactly one target
 *       backend set ID must be specified for the first guess, although any
 *       number of fallback set IDs may be specified.  The routing hint will
 *       only be used for cases in which the entire scope of the search is
 *       contained entirely within a backend set (i.e., the entire scope is
 *       at or above the balancing point, or the entire scope is at least one
 *       level below the balancing point).</LI>
 * </UL>
 * <BR><BR>
 * The OID for a route to backend set request control is
 * "1.3.6.1.4.1.30221.2.5.35", and the criticality may be either {@code true} or
 * {@code false}.  It must have a value with the following encoding:
 * <PRE>
 *   RouteToBackendSetRequest ::= SEQUENCE {
 *        entryBalancingRequestProcessorID     OCTET STRING,
 *        backendSets                          CHOICE {
 *             absoluteRoutingRequest     [0] SET OF OCTET STRING,
 *             routingHint                [1] SEQUENCE {
 *                  firstGuessSetIDs     SET OF OCTET STRING,
 *                  fallbackSetIDs       SET OF OCTET STRING OPTIONAL }
 *             ... }
 *        ... }
 * </PRE>
 * The use of the route to backend set request control will also cause the
 * server to behave as if the get backend set ID request control had been
 * included, so that the get backend set ID response control may be included in
 * operation result and search result entry messages as appropriate.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RouteToBackendSetRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.35) for the route to server request control.
   */
  @NotNull public static final String ROUTE_TO_BACKEND_SET_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.35";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2486448910813783450L;



  // The routing type for the request.
  @NotNull private final RouteToBackendSetRoutingType routingType;

  // The backend set IDs for an absolute routing request.
  @Nullable private final Set<String> absoluteBackendSetIDs;

  // The backend set IDs for the fallback sets of a routing hint.
  @Nullable private final Set<String> routingHintFallbackSetIDs;

  // The backend set IDs for the first guess of a routing hint.
  @Nullable private final Set<String> routingHintFirstGuessSetIDs;

  // The identifier for the entry-balancing request processor with which the
  // backend set IDs are associated.
  @NotNull private final String entryBalancingRequestProcessorID;



  /**
   * Creates a new route to backend set request control with the provided
   * information.
   *
   * @param  isCritical                        Indicates whether this control
   *                                           should be critical.
   * @param  encodedValue                      The encoded value for this
   *                                           control.  It must not be
   *                                           {@code null}.
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  routingType                       The routing type for this
   *                                           request.  It must not be
   *                                           {@code null}.
   * @param  absoluteBackendSetIDs             The collection of backend sets to
   *                                           which the request should be sent
   *                                           for an absolute routing request.
   *                                           It must be non-{@code null} and
   *                                           non-empty for an absolute routing
   *                                           request, and must be {@code null}
   *                                           for a routing hint.
   * @param  routingHintFirstGuessSetIDs       The collection of backend sets
   *                                           that should be used as the first
   *                                           guess for a routing hint request.
   *                                           It must be {@code null} for an
   *                                           absolute routing request, and
   *                                           must be non-{@code null} and
   *                                           non-empty for a routing hint.
   * @param  routingHintFallbackSetIDs         The collection of fallback
   *                                           backend sets that should be used
   *                                           for a routing hint request if the
   *                                           first guess was unsuccessful.  It
   *                                           must be {@code null} for an
   *                                           absolute routing request, and may
   *                                           be {@code null} for a routing
   *                                           hint if the fallback sets should
   *                                           be all backend sets for the
   *                                           entry-balancing request processor
   *                                           that were not included in the
   *                                           first guess.  If it is
   *                                           non-{@code null}, then it must
   *                                           also be non-empty.
   */
  private RouteToBackendSetRequestControl(final boolean isCritical,
               @NotNull final ASN1OctetString encodedValue,
               @NotNull final String entryBalancingRequestProcessorID,
               @NotNull final RouteToBackendSetRoutingType routingType,
               @Nullable final Collection<String> absoluteBackendSetIDs,
               @Nullable final Collection<String> routingHintFirstGuessSetIDs,
               @Nullable final Collection<String> routingHintFallbackSetIDs)
  {
    super(ROUTE_TO_BACKEND_SET_REQUEST_OID, isCritical, encodedValue);

    this.entryBalancingRequestProcessorID = entryBalancingRequestProcessorID;
    this.routingType = routingType;

    if (absoluteBackendSetIDs == null)
    {
      this.absoluteBackendSetIDs = null;
    }
    else
    {
      this.absoluteBackendSetIDs = Collections.unmodifiableSet(
           new LinkedHashSet<>(absoluteBackendSetIDs));
    }

    if (routingHintFirstGuessSetIDs == null)
    {
      this.routingHintFirstGuessSetIDs = null;
    }
    else
    {
      this.routingHintFirstGuessSetIDs = Collections.unmodifiableSet(
           new LinkedHashSet<>(routingHintFirstGuessSetIDs));
    }

    if (routingHintFallbackSetIDs == null)
    {
      this.routingHintFallbackSetIDs = null;
    }
    else
    {
      this.routingHintFallbackSetIDs = Collections.unmodifiableSet(
           new LinkedHashSet<>(routingHintFallbackSetIDs));
    }
  }



  /**
   * Creates a new route to backend set request control that is decoded from the
   * provided generic control.
   *
   * @param  control  The control to decode as a route to backend set request
   *                  control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         route to backend set request control.
   */
  public RouteToBackendSetRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ROUTE_TO_BACKEND_SET_REQUEST_MISSING_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      entryBalancingRequestProcessorID =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      routingType = RouteToBackendSetRoutingType.valueOf(elements[1].getType());
      if (routingType == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_ROUTE_TO_BACKEND_SET_REQUEST_UNKNOWN_ROUTING_TYPE.get(
                  StaticUtils.toHex(elements[1].getType())));
      }

      if (routingType == RouteToBackendSetRoutingType.ABSOLUTE_ROUTING)
      {
        final ASN1Element[] arElements =
             ASN1Set.decodeAsSet(elements[1]).elements();
        final LinkedHashSet<String> arSet = new LinkedHashSet<>(
             StaticUtils.computeMapCapacity(arElements.length));
        for (final ASN1Element e : arElements)
        {
          arSet.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
        }
        absoluteBackendSetIDs = Collections.unmodifiableSet(arSet);
        if (absoluteBackendSetIDs.isEmpty())
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_ROUTE_TO_BACKEND_SET_REQUEST_ABSOLUTE_SET_EMPTY.get());
        }

        routingHintFirstGuessSetIDs = null;
        routingHintFallbackSetIDs = null;
      }
      else
      {
        final ASN1Element[] hintElements =
             ASN1Sequence.decodeAsSequence(elements[1]).elements();

        final ASN1Element[] firstGuessElements =
             ASN1Set.decodeAsSet(hintElements[0]).elements();
        final LinkedHashSet<String> firstGuessSet = new LinkedHashSet<>(
             StaticUtils.computeMapCapacity(firstGuessElements.length));
        for (final ASN1Element e : firstGuessElements)
        {
          firstGuessSet.add(
               ASN1OctetString.decodeAsOctetString(e).stringValue());
        }
        routingHintFirstGuessSetIDs =
             Collections.unmodifiableSet(firstGuessSet);
        if (routingHintFirstGuessSetIDs.isEmpty())
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_ROUTE_TO_BACKEND_SET_REQUEST_HINT_FIRST_SET_EMPTY.get());
        }

        if (hintElements.length == 1)
        {
          routingHintFallbackSetIDs = null;
        }
        else
        {
          final ASN1Element[] fallbackElements =
               ASN1Set.decodeAsSet(hintElements[1]).elements();
          final LinkedHashSet<String> fallbackSet = new LinkedHashSet<>(
               StaticUtils.computeMapCapacity(fallbackElements.length));
          for (final ASN1Element e : fallbackElements)
          {
            fallbackSet.add(
                 ASN1OctetString.decodeAsOctetString(e).stringValue());
          }
          routingHintFallbackSetIDs = Collections.unmodifiableSet(fallbackSet);
          if (routingHintFallbackSetIDs.isEmpty())
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ROUTE_TO_BACKEND_SET_REQUEST_HINT_FALLBACK_SET_EMPTY.
                      get());
          }
        }

        absoluteBackendSetIDs = null;
      }
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
           ERR_ROUTE_TO_BACKEND_SET_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new route to backend set request control that may be used for
   * absolute routing to the specified backend set.
   *
   * @param  isCritical                        Indicates whether the control
   *                                           should be marked critical.
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set ID
   *                                           is associated.  It must not be
   *                                           {@code null}.
   * @param  backendSetID                      The backend set ID for the
   *                                           backend set to which the request
   *                                           should be forwarded.  It must not
   *                                           be {@code null}.
   *
   * @return  The route to backend set request control created from the
   *          provided information.
   */
  @NotNull()
  public static RouteToBackendSetRequestControl createAbsoluteRoutingRequest(
                     final boolean isCritical,
                     @NotNull final String entryBalancingRequestProcessorID,
                     @NotNull final String backendSetID)
  {
    return createAbsoluteRoutingRequest(isCritical,
         entryBalancingRequestProcessorID,
         Collections.singletonList(backendSetID));
  }



  /**
   * Creates a new route to backend set request control that may be used for
   * absolute routing to the specified collection of backend sets.
   *
   * @param  isCritical                        Indicates whether the control
   *                                           should be marked critical.
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  backendSetIDs                     The backend set IDs for the
   *                                           backend sets to which the request
   *                                           should be forwarded.  It must not
   *                                           be {@code null} or empty.
   *
   * @return  The route to backend set request control created from the
   *          provided information.
   */
  @NotNull()
  public static RouteToBackendSetRequestControl createAbsoluteRoutingRequest(
                     final boolean isCritical,
                     @NotNull final String entryBalancingRequestProcessorID,
                     @NotNull final Collection<String> backendSetIDs)
  {
    Validator.ensureNotNull(backendSetIDs);
    Validator.ensureFalse(backendSetIDs.isEmpty());

    final ArrayList<ASN1Element> backendSetIDElements =
         new ArrayList<>(backendSetIDs.size());
    for (final String s : backendSetIDs)
    {
      backendSetIDElements.add(new ASN1OctetString(s));
    }

    final RouteToBackendSetRoutingType routingType =
         RouteToBackendSetRoutingType.ABSOLUTE_ROUTING;
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(entryBalancingRequestProcessorID),
         new ASN1Set(routingType.getBERType(), backendSetIDElements));

    return new RouteToBackendSetRequestControl(isCritical,
         new ASN1OctetString(valueSequence.encode()),
         entryBalancingRequestProcessorID, routingType, backendSetIDs, null,
         null);
  }



  /**
   * Creates a new route to backend set request control that may be used to
   * provide a hint as to the backend set to which the operation should be
   * forwarded, and an optional specification of fallback sets.
   *
   * @param  isCritical                        Indicates whether the control
   *                                           should be marked critical.
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  firstGuessSetID                   The backend set ID for the
   *                                           backend set to try first.  It
   *                                           must not be {@code null}.
   * @param  fallbackSetIDs                    The backend set ID(s) for the
   *                                           backend set(s) to use if none of
   *                                           the servers in the first guess
   *                                           set returns a success result.
   *                                           If this is {@code null}, then the
   *                                           server will use a default
   *                                           fallback set of all backend sets
   *                                           except for the first guess set.
   *                                           If this is not {@code null}, then
   *                                           it must also be non-empty.
   *
   * @return  The route to backend set request control created from the
   *          provided information.
   */
  @NotNull()
  public static RouteToBackendSetRequestControl createRoutingHintRequest(
                     final boolean isCritical,
                     @NotNull final String entryBalancingRequestProcessorID,
                     @NotNull final String firstGuessSetID,
                     @Nullable final Collection<String> fallbackSetIDs)
  {
    return createRoutingHintRequest(isCritical,
         entryBalancingRequestProcessorID,
         Collections.singletonList(firstGuessSetID),
         fallbackSetIDs);
  }



  /**
   * Creates a new route to backend set request control that may be used to
   * provide a hint as to the backend set(s) to which the operation should be
   * forwarded, and an optional specification of fallback sets.
   *
   * @param  isCritical                        Indicates whether the control
   *                                           should be marked critical.
   * @param  entryBalancingRequestProcessorID  The identifier for the
   *                                           entry-balancing request processor
   *                                           with which the backend set IDs
   *                                           are associated.  It must not be
   *                                           {@code null}.
   * @param  firstGuessSetIDs                  The backend set ID(s) for the
   *                                           backend set(s) to try first.  It
   *                                           must not be {@code null} or
   *                                           empty.
   * @param  fallbackSetIDs                    The backend set ID(s) for the
   *                                           backend set(s) to use if none of
   *                                           the servers in the first guess
   *                                           set returns a success result.
   *                                           If this is {@code null}, then the
   *                                           server will use a default
   *                                           fallback set of all backend sets
   *                                           not included in the first guess.
   *                                           If this is not {@code null}, then
   *                                           it must also be non-empty.
   *
   * @return  The route to backend set request control created from the
   *          provided information.
   */
  @NotNull()
  public static RouteToBackendSetRequestControl createRoutingHintRequest(
                     final boolean isCritical,
                     @NotNull final String entryBalancingRequestProcessorID,
                     @NotNull final Collection<String> firstGuessSetIDs,
                     @Nullable final Collection<String> fallbackSetIDs)
  {
    Validator.ensureNotNull(firstGuessSetIDs);
    Validator.ensureFalse(firstGuessSetIDs.isEmpty());

    if (fallbackSetIDs != null)
    {
      Validator.ensureFalse(fallbackSetIDs.isEmpty());
    }

    final ArrayList<ASN1Element> backendSetsElements = new ArrayList<>(2);
    final ArrayList<ASN1Element> firstGuessElements =
         new ArrayList<>(firstGuessSetIDs.size());
    for (final String s : firstGuessSetIDs)
    {
      firstGuessElements.add(new ASN1OctetString(s));
    }
    backendSetsElements.add(new ASN1Set(firstGuessElements));

    if (fallbackSetIDs != null)
    {
      final ArrayList<ASN1Element> fallbackElements =
           new ArrayList<>(fallbackSetIDs.size());
      for (final String s : fallbackSetIDs)
      {
        fallbackElements.add(new ASN1OctetString(s));
      }
      backendSetsElements.add(new ASN1Set(fallbackElements));
    }

    final RouteToBackendSetRoutingType routingType =
         RouteToBackendSetRoutingType.ROUTING_HINT;
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(entryBalancingRequestProcessorID),
         new ASN1Sequence(routingType.getBERType(), backendSetsElements));

    return new RouteToBackendSetRequestControl(isCritical,
         new ASN1OctetString(valueSequence.encode()),
         entryBalancingRequestProcessorID, routingType, null, firstGuessSetIDs,
         fallbackSetIDs);
  }



  /**
   * Retrieves the identifier for the entry-balancing request processor with
   * which the backend set IDs are associated.
   *
   * @return  The identifier for the entry-balancing request processor with
   *          which the backend set IDs are associated.
   */
  @NotNull()
  public String getEntryBalancingRequestProcessorID()
  {
    return entryBalancingRequestProcessorID;
  }



  /**
   * Retrieves the type of routing requested by this control.
   *
   * @return  The type of routing requested by this control.
   */
  @NotNull()
  public RouteToBackendSetRoutingType getRoutingType()
  {
    return routingType;
  }



  /**
   * Retrieves the collection of backend set IDs for the backend sets to which
   * the request should be forwarded if the control uses absolute routing.
   *
   * @return  The collection of backend set IDs for the backend sets to which
   *          the request should be forwarded if the control uses absolute
   *          routing, or {@code null} if the control uses a routing hint.
   */
  @Nullable()
  public Set<String> getAbsoluteBackendSetIDs()
  {
    return absoluteBackendSetIDs;
  }



  /**
   * Retrieves the collection of backend set IDs for the first guess of backend
   * sets to which the request should be forwarded if the control uses a routing
   * hint.
   *
   * @return  The collection of backend set IDs for the first guess of backend
   *          sets to which the request should be forwarded if the control uses
   *          a routing hint, or {@code null} if the control uses absolute
   *          routing.
   */
  @Nullable()
  public Set<String> getRoutingHintFirstGuessSetIDs()
  {
    return routingHintFirstGuessSetIDs;
  }



  /**
   * Retrieves the collection of backend set IDs to which the request should be
   * forwarded if the control uses a routing hint and an explicit group of
   * fallback sets was specified.
   *
   * @return  The collection of backend set IDs to which the request should be
   *          forwarded if the control uses a routing hint and an explicit
   *          group of fallback sets was specified, or {@code null} if the
   *          control uses absolute routing or if a default group of fallback
   *          sets (all sets not included in the first guess) should be used.
   */
  @Nullable()
  public Set<String> getRoutingHintFallbackSetIDs()
  {
    return routingHintFallbackSetIDs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ROUTE_TO_BACKEND_SET_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RouteToBackendSetRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", entryBalancingRequestProcessorID='");
    buffer.append(entryBalancingRequestProcessorID);
    buffer.append("', routingType='");

    Iterator<String> iterator = null;
    switch (routingType)
    {
      case ABSOLUTE_ROUTING:
        buffer.append("absolute', backendSetIDs={");
        iterator = absoluteBackendSetIDs.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(iterator.next());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }
        buffer.append('}');
        break;

      case ROUTING_HINT:
        buffer.append("hint', firstGuessSetIDs={");
        iterator = routingHintFirstGuessSetIDs.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(iterator.next());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }
        buffer.append('}');

        if (routingHintFallbackSetIDs != null)
        {
          buffer.append(", fallbackSetIDs={");
          iterator = routingHintFallbackSetIDs.iterator();
          while (iterator.hasNext())
          {
            buffer.append('\'');
            buffer.append(iterator.next());
            buffer.append('\'');

            if (iterator.hasNext())
            {
              buffer.append(", ");
            }
          }
          buffer.append('}');
        }
        break;
    }
    buffer.append(')');
  }
}
