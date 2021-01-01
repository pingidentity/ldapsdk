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



import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be used to request that the
 * Directory Proxy Server return the backend set IDs for the entry-balancing
 * backend set(s) in which an operation was processed successfully.  It may be
 * used in conjunction with the route to backend set request control in order
 * to specify which backend set(s) should be used to process an operation.
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
 * This control may be used for a number of different kinds of requests,
 * including:
 * <UL>
 *   <LI>If an add request includes a get backend set ID request control, the
 *       add response will include a get backend set ID response control if the
 *       entry was successfully added to an entry-balanced data set.</LI>
 *   <LI>If a simple bind request includes a get backend set ID request control,
 *       the bind response will include a get backend set ID response control if
 *       the authentication was successful and the entry for the authenticated
 *       user exists in an entry-balanced data set.  This control is currently
 *       not supported for use with SASL bind operations.</LI>
 *   <LI>If a compare request includes a get backend set ID request control, the
 *       compare response will include a get backend set ID response control if
 *       the result code is either COMPARE_TRUE or COMPARE_FALSE and the target
 *       entry exists in an entry-balanced data set.</LI>
 *   <LI>If a delete request includes a get backend set ID request control, the
 *       delete response will include a get backend set ID response control if
 *       the entry was successfully removed from an entry-balanced data
 *       set.</LI>
 *   <LI>If an atomic multi-update extended request includes a get backend set
 *       ID request control and the request is successfully processed through an
 *       entry-balancing request processor, then the extended response will
 *       include a get backend set ID response control.  A non-atomic
 *       multi-update extended request should not include the get backend set ID
 *       request control in the extended operation itself, but may be attached
 *       to any or all of the requests inside the multi-update operation, in
 *       which case the server will return a multi-update response control
 *       attached to the corresponding successful responses.</LI>
 *   <LI>If an extended request includes a get backend set ID request control
 *       and that request is successfully processed by a proxied extended
 *       operation handler, then the extended response will include a get
 *       backend set ID response control indicating the backend set(s) that
 *       returned a success result during internal processing.  Note that if the
 *       same extended request was processed by multiple entry-balancing
 *       request processors (i.e., if the deployment includes multiple
 *       entry-balanced subtrees), then the extended response may include a
 *       separate get backend set ID response control for each entry-balancing
 *       request processor used to process the request.</LI>
 *   <LI>If a modify request includes a get backend set ID request control, the
 *       modify response will include a get backend set ID response control if
 *       the entry was successfully modified in an entry-balanced data set.</LI>
 *   <LI>If a modify DN request includes a get backend set ID request control,
 *       the modify DN response will include a get backend set ID response
 *       control if the entry was successfully moved and/or renamed in an
 *       entry-balanced data set.</LI>
 *   <LI>If a modify DN request includes a get backend set ID request control,
 *       the modify DN response will include a get backend set ID response
 *       control if the entry was successfully moved and/or renamed in an
 *       entry-balanced data set.</LI>
 *   <LI>If a search request includes a get backend set ID request control, any
 *       search result entries retrieved from an entry-balanced data set will
 *       include a get backend set ID response control.  The search result done
 *       message will not include a get backend set ID response control.</LI>
 * </UL>
 *
 * Note the response for any operation involving an entry that exists outside of
 * an entry-balanced dat set will not include a get backend set ID response
 * control.  Similarly, the response for any non-successful operation may not
 * include a get backend set ID response control even if it involved processing
 * in one or more backend sets.  Also note that even if an entry exists in
 * multiple backend sets (i.e., because it is at or above the balancing point),
 * the get backend set ID response control may only include one backend set ID
 * if only one backend set was accessed during the course of processing the
 * operation.
 * <BR><BR>
 * The get backend set ID request control has an OID of
 * "1.3.6.1.4.1.30221.2.5.33" and no value.  It is recommended that the control
 * be non-critical so that the associated operation may still be processed even
 * if the target server does not support this control (and note that even if
 * the server supports the control, the server may not return a response control
 * if the operation was not successful or did not access entry-balanced data).
 *
 * @see GetBackendSetIDResponseControl
 * @see RouteToBackendSetRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetBackendSetIDRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.33) for the get backend set ID request
   * control.
   */
  @NotNull public static final  String GET_BACKEND_SET_ID_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.33";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7874405591825684773L;



  /**
   * Creates a new get backend set ID request control.  It will not be marked
   * critical.
   */
  public GetBackendSetIDRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new get backend set ID request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public GetBackendSetIDRequestControl(final boolean isCritical)
  {
    super(GET_BACKEND_SET_ID_REQUEST_OID, isCritical, null);
  }



  /**
   * Creates a new get backend set ID request control which is decoded from the
   * provided generic control.
   *
   * @param  control  The generic control to be decoded as a get backend set ID
   *                  request control.
   *
   * @throws LDAPException  If the provided control cannot be decoded as a get
   *                         backend set ID request control.
   */
  public GetBackendSetIDRequestControl(@NotNull final Control control)
       throws LDAPException
  {
    super(control);

    if (control.hasValue())
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_BACKEND_SET_ID_REQUEST_HAS_VALUE.get());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_BACKEND_SET_ID_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetBackendSetIDRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
