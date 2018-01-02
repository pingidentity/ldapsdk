/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.ReadOnlyAddRequest;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an API that can be used in the course of processing an
 * add request via the {@link InMemoryOperationInterceptor} API.
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public interface InMemoryInterceptedAddRequest
       extends InMemoryInterceptedRequest
{
  /**
   * Retrieves the add request to be processed.
   *
   * @return  The add request to be processed.
   */
  ReadOnlyAddRequest getRequest();



  /**
   * Replaces the add request to be processed.
   *
   * @param  addRequest  The add request that should be processed instead of the
   *                     one that was originally received from the client.  It
   *                     must not be {@code null}.
   */
  void setRequest(AddRequest addRequest);
}
