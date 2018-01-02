/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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

import com.unboundid.util.Extensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This interface defines a method that may be used to process intermediate
 * response messages that are returned to the client while processing an
 * operation.  If an operation may return intermediate response messages, then
 * an intermediate response listener must be registered with the associated
 * request (via the {@link LDAPRequest#setIntermediateResponseListener} method)
 * in order to be able to access the intermediate response messages.
 *
 * @see  IntermediateResponse
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface IntermediateResponseListener
       extends Serializable
{
  /**
   * Indicates that the provided intermediate response has been returned by the
   * server and may be processed by this intermediate response listener.
   *
   * @param  intermediateResponse  The intermediate response that has been
   *                               returned by the server.
   */
  void intermediateResponseReturned(IntermediateResponse intermediateResponse);
}
