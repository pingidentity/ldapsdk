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
package com.unboundid.ldap.sdk;



import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of an async result listener that may be
 * used for add, compare, delete, modify, and modify DN operations.  It will
 * simply discard any result that is received.  This is intended for use in
 * cases in which the {@link AsyncRequestID} class is to be used via the
 * {@code java.util.concurrent.Future} API (e.g., to retrieve the result using
 * the {@link AsyncRequestID#get} method.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class DiscardAsyncListener
      implements AsyncResultListener, AsyncCompareResultListener
{
  /**
   * The singleton instance of this async listener.
   */
  private static final DiscardAsyncListener INSTANCE =
       new DiscardAsyncListener();



  /**
   * Creates a new instance of this class.
   */
  private DiscardAsyncListener()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the singleton instance of this async listener.
   *
   * @return The singleton instance of this async listener.
   */
  static DiscardAsyncListener getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ldapResultReceived(final AsyncRequestID requestID,
                                 final LDAPResult ldapResult)
  {
    // No  implementation is required.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void compareResultReceived(final AsyncRequestID requestID,
                                    final CompareResult compareResult)
  {
    // No implementation is required.
  }
}
