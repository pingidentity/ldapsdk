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



import java.io.Serializable;
import java.util.List;

import com.unboundid.util.NotExtensible;
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
   * Retrieves a list containing the set of controls for this request.
   *
   * @return  A list containing the set of controls for this request.
   */
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
  boolean hasControl(String oid);



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
  Control getControl(String oid);



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
  long getResponseTimeoutMillis(LDAPConnection connection);



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
  boolean followReferrals(LDAPConnection connection);



  /**
   * Creates a new instance of this LDAP request that may be modified without
   * impacting this request.
   *
   * @return  A new instance of this LDAP request that may be modified without
   *          impacting this request.
   */
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
  LDAPRequest duplicate(Control[] controls);



  /**
   * Retrieves a string representation of this request.
   *
   * @return  A string representation of this request.
   */
  @Override()
  String toString();



  /**
   * Appends a string representation of this request to the provided buffer.
   *
   * @param  buffer  The buffer to which to append a string representation of
   *                 this request.
   */
  void toString(StringBuilder buffer);



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
  void toCode(List<String> lineList, String requestID,
              int indentSpaces, boolean includeProcessing);
}
