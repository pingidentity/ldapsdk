/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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



import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a referral connector that will
 * retain the exception encountered on the last attempt to establish a
 * connection for the purpose of following a referral.
 * <BR><BR>
 * Note that although this class is technically safe to be used concurrently by
 * multiple threads in that it won't result in a deadlock or concurrent
 * modification exception or any other kind of obvious failure, it only retains
 * a single exception, and only from the last attempt made to establish a
 * connection for the purpose of following a referral.  If multiple threads try
 * to use the same instance of this connector concurrently, a call to the
 * {@link #getExceptionFromLastConnectAttempt()} method may return the result
 * from the last attempt made on another thread.  It is therefore recommended
 * that this connector only be used in contexts where it can be safely assumed
 * that it will not be used concurrently across multiple threads.  For example,
 * if a connection is not expected to be concurrently shared by multiple
 * threads, then it may be desirable to use the
 * {@link LDAPConnection#setReferralConnector(ReferralConnector)} to set a
 * different instance of this connector for each connection.  Alternately, the
 * {@link LDAPRequest#setReferralConnector(ReferralConnector)} method may be
 * used to specify a connector that should be used for an individual request.
 */
@ThreadSafety(level=ThreadSafetyLevel.MOSTLY_NOT_THREADSAFE)
public final class RetainConnectExceptionReferralConnector
       implements ReferralConnector
{
  // The wrapped referral connector that will actually be used to establish the
  // connection.
  @Nullable private final ReferralConnector wrappedReferralConnector;

  // The exception caught in the last attempt to establish a connection for the
  // purpose of following a referral.
  @Nullable private volatile LDAPException connectExceptionFromLastAttempt;



  /**
   * Creates a new instance of this referral connector that will use the
   * connection's default referral handler to actually attempt to establish a
   * connection.
   */
  public RetainConnectExceptionReferralConnector()
  {
    this(null);
  }



  /**
   * Creates a new instance of this referral connector that will use the
   * provided connector to actually attempt to establish a connection.
   *
   * @param  wrappedReferralConnector  The referral connector that will be used
   *                                   to actually attempt to establish a
   *                                   connection for the purpose of following a
   *                                   referral.  This may be {@code null} to
   *                                   use the default referral connector for
   *                                   the connection on which the referral was
   *                                   received.
   */
  public RetainConnectExceptionReferralConnector(
              @Nullable final ReferralConnector wrappedReferralConnector)
  {
    this.wrappedReferralConnector = wrappedReferralConnector;

    connectExceptionFromLastAttempt = null;
  }



  /**
   * Retrieves the exception that was caught in the last attempt to establish a
   * connection for the purpose of following a referral, if any.
   *
   * @return  The exception that was caught in the last attempt to establish a
   *          connection for the purpose of following a referral, or
   *          {@code null} if the last connection attempt was successful or if
   *          there have not yet been any connection attempts.
   */
  @Nullable()
  public LDAPException getExceptionFromLastConnectAttempt()
  {
    return connectExceptionFromLastAttempt;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnection getReferralConnection(
                             @NotNull final LDAPURL referralURL,
                             @NotNull final LDAPConnection connection)
                 throws LDAPException
  {
    final ReferralConnector connector;
    if (wrappedReferralConnector == null)
    {
      connector = connection.getReferralConnector();
    }
    else
    {
      connector = wrappedReferralConnector;
    }

    LDAPException connectException = null;
    try
    {
      return connector.getReferralConnection(referralURL, connection);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      connectException = e;
      throw e;
    }
    finally
    {
      connectExceptionFromLastAttempt = connectException;
    }
  }
}
