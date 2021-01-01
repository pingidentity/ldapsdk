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



import java.io.Serializable;
import java.util.List;

import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a set of methods that may be safely called in an LDAP
 * request without altering its contents.  This interface must not be
 * implemented by any class outside of the LDAP SDK.
 * <BR><BR>
 * This interface does not inherently provide the assurance of thread safety for
 * the methods that it exposes, because it is still possible for a thread
 * referencing the object which implements this interface to alter the request
 * using methods not included in this interface.  However, if it can be
 * guaranteed that no thread will alter the underlying object, then the methods
 * exposed by this interface can be safely invoked concurrently by any number of
 * threads.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface ReadOnlyLDAPRequest
       extends Serializable
{
  /**
   * Retrieves the set of controls for this request.  The caller must not alter
   * this set of controls.
   *
   * @return  The set of controls for this request.
   */
  @NotNull()
  Control[] getControls();



  /**
   * Retrieves a list containing the set of controls for this request.
   *
   * @return  A list containing the set of controls for this request.
   */
  @NotNull()
  List<Control> getControlList();



  /**
   * Indicates whether this request contains at least one control.
   *
   * @return  {@code true} if this request contains at least one control, or
   *          {@code false} if not.
   */
  boolean hasControl();



  /**
   * Indicates whether this request contains at least one control with the
   * specified OID.
   *
   * @param  oid  The object identifier for which to make the determination.  It
   *              must not be {@code null}.
   *
   * @return  {@code true} if this request contains at least one control with
   *          the specified OID, or {@code false} if not.
   */
  boolean hasControl(@NotNull String oid);



  /**
   * Retrieves the control with the specified OID from this request.  If this
   * request has multiple controls with the specified OID, then the first will
   * be returned.
   *
   * @param  oid  The object identifier for which to retrieve the corresponding
   *              control.  It must not be {@code null}.
   *
   * @return  The first control found with the specified OID, or {@code null} if
   *          no control with that OID is included in this request.
   */
  @Nullable()
  Control getControl(@NotNull String oid);



  /**
   * Retrieves the maximum length of time in milliseconds that processing on
   * this operation should be allowed to block while waiting for a response from
   * the server.
   *
   * @param  connection  The connection to use in order to retrieve the default
   *                     value, if appropriate.  It may be {@code null} to
   *                     retrieve the request-specific timeout (which may be
   *                     negative if no response-specific timeout has been set).
   *
   * @return  The maximum length of time in milliseconds that processing on this
   *          operation should be allowed to block while waiting for a response
   *          from the server, or zero if no timeout should be enforced.
   */
  long getResponseTimeoutMillis(@Nullable LDAPConnection connection);



  /**
   * Indicates whether to automatically follow any referrals encountered while
   * processing this request.  If a value has been set for this request, then it
   * will be returned.  Otherwise, the default from the connection options for
   * the provided connection will be used.
   *
   * @param  connection  The connection whose connection options may be used in
   *                     the course of making the determination.  It must not
   *                     be {@code null}.
   *
   * @return  {@code true} if any referrals encountered during processing should
   *          be automatically followed, or {@code false} if not.
   */
  boolean followReferrals(@NotNull LDAPConnection connection);



  /**
   * Retrieves the referral connector that should be used when establishing a
   * connection for the purpose of automatically following a referral.
   *
   * @param  connection  The connection that may be used in the course of
   *                     obtaining the appropriate referral connector.  It must
   *                     not be {@code null}.
   *
   * @return  The referral connector that should be used for the purpose of
   *          automatically following a referral.  It will not be {@code null}.
   */
  @NotNull()
  ReferralConnector getReferralConnector(@NotNull LDAPConnection connection);



  /**
   * Creates a new instance of this LDAP request that may be modified without
   * impacting this request.
   *
   * @return  A new instance of this LDAP request that may be modified without
   *          impacting this request.
   */
  @NotNull()
  LDAPRequest duplicate();



  /**
   * Creates a new instance of this LDAP request that may be modified without
   * impacting this request.  The provided controls will be used for the new
   * request instead of duplicating the controls from this request.
   *
   * @param  controls  The set of controls to include in the duplicate request.
   *
   * @return  A new instance of this LDAP request that may be modified without
   *          impacting this request.
   */
  @NotNull()
  LDAPRequest duplicate(@Nullable Control[] controls);



  /**
   * Retrieves a string representation of this request.
   *
   * @return  A string representation of this request.
   */
  @Override()
  @NotNull()
  String toString();



  /**
   * Appends a string representation of this request to the provided buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this request.
   */
  void toString(@NotNull StringBuilder buffer);



  /**
   * Appends a number of lines comprising the Java source code that can be used
   * to recreate this request to the given list.
   *
   * @param  lineList           The list to which the source code lines should
   *                            be added.
   * @param  requestID          The name that should be used as an identifier
   *                            for the request.  If this is {@code null} or
   *                            empty, then a generic ID will be used.
   * @param  indentSpaces       The number of spaces that should be used to
   *                            indent the generated code.  It must not be
   *                            negative.
   * @param  includeProcessing  Indicates whether the generated code should
   *                            include code required to actually process the
   *                            request and handle the result (if {@code true}),
   *                            or just to generate the request (if
   *                            {@code false}).
   */
  void toCode(@NotNull List<String> lineList, @NotNull String requestID,
              int indentSpaces, boolean includeProcessing);
}
