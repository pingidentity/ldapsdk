/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure which may be used to define a set of
 * constraints that may be used when processing search operations.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the
 * {@link com.unboundid.ldap.sdk.LDAPConnectionOptions} class should be used
 * instead.
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPSearchConstraints
       extends LDAPConstraints
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -487551577157782460L;



  // The result batch size.
  private int batchSize;

  // The alias dereferencing policy.
  private int derefPolicy;

  // The maximum number of results to return for a search.
  private int sizeLimit;

  // The maximum length of time in seconds the server should spend processing a
  // search.
  private int timeLimit;



  /**
   * Creates a new set of search constraints with the default settings.
   */
  public LDAPSearchConstraints()
  {
    super();

    batchSize   = 1;
    derefPolicy = LDAPConnection.DEREF_NEVER;
    sizeLimit   = 1000;
    timeLimit   = 0;
  }



  /**
   * Creates a new set of search constraints with the specified information.
   *
   * @param  msLimit      The maximum length of time in milliseconds to spend
   *                      waiting for the response.
   * @param  dereference  The policy to use when dereferencing aliases.
   * @param  maxResults   The maximum number of entries to return from the
   *                      server.
   * @param  doReferrals  Indicates whether to follow referrals.
   * @param  batchSize    The batch size to use when retrieving results.
   * @param  rebindProc   The object to use to obtain information for
   *                      authenticating the connection for use when following
   *                      referrals.
   * @param  hopLimit     The maximum number of hops to take when following
   *                      referrals.
   */
  public LDAPSearchConstraints(final int msLimit, final int dereference,
                               final int maxResults, final boolean doReferrals,
                               final int batchSize,
                               @Nullable final LDAPRebind rebindProc,
                               final int hopLimit)
  {
    this();

    derefPolicy    = dereference;
    sizeLimit      = maxResults;
    this.batchSize = batchSize;

    setTimeLimit(msLimit);
    setReferrals(doReferrals);
    setRebindProc(rebindProc);
    setHopLimit(hopLimit);
  }



  /**
   * Creates a new set of search constraints with the specified information.
   *
   * @param  msLimit      The maximum length of time in milliseconds to spend
   *                      waiting for the response.
   * @param  timeLimit    The maximum length of time in seconds the server
   *                      should spend processing the request.
   * @param  dereference  The policy to use when dereferencing aliases.
   * @param  maxResults   The maximum number of entries to return from the
   *                      server.
   * @param  doReferrals  Indicates whether to follow referrals.
   * @param  batchSize    The batch size to use when retrieving results.
   * @param  rebindProc   The object to use to obtain information for
   *                      authenticating the connection for use when following
   *                      referrals.
   * @param  hopLimit     The maximum number of hops to take when following
   *                      referrals.
   */
  public LDAPSearchConstraints(final int msLimit, final int timeLimit,
                               final int dereference,
                               final int maxResults, final boolean doReferrals,
                               final int batchSize,
                               @Nullable final LDAPRebind rebindProc,
                               final int hopLimit)
  {
    this();

    derefPolicy    = dereference;
    sizeLimit      = maxResults;
    this.timeLimit = timeLimit;
    this.batchSize = batchSize;

    setTimeLimit(msLimit);
    setReferrals(doReferrals);
    setRebindProc(rebindProc);
    setHopLimit(hopLimit);
  }



  /**
   * Creates a new set of search constraints with the specified information.
   *
   * @param  msLimit      The maximum length of time in milliseconds to spend
   *                      waiting for the response.
   * @param  timeLimit    The maximum length of time in seconds the server
   *                      should spend processing the request.
   * @param  dereference  The policy to use when dereferencing aliases.
   * @param  maxResults   The maximum number of entries to return from the
   *                      server.
   * @param  doReferrals  Indicates whether to follow referrals.
   * @param  batchSize    The batch size to use when retrieving results.
   * @param  bindProc     The object to use to obtain authenticating the
   *                      connection for use when following referrals.
   * @param  hopLimit     The maximum number of hops to take when following
   *                      referrals.
   */
  public LDAPSearchConstraints(final int msLimit, final int timeLimit,
                               final int dereference,
                               final int maxResults, final boolean doReferrals,
                               final int batchSize,
                               @Nullable final LDAPBind bindProc,
                               final int hopLimit)
  {
    this();

    derefPolicy    = dereference;
    sizeLimit      = maxResults;
    this.timeLimit = timeLimit;
    this.batchSize = batchSize;

    setTimeLimit(msLimit);
    setReferrals(doReferrals);
    setBindProc(bindProc);
    setHopLimit(hopLimit);
  }



  /**
   * Retrieves the suggested batch size to use when retrieving results.
   *
   * @return  The suggested batch size to use when retrieving results.
   */
  public int getBatchSize()
  {
    return batchSize;
  }



  /**
   * Specifies the suggested batch size to use when retrieving results.
   *
   * @param  batchSize  The suggested batch size to use when retrieving results.
   */
  public void setBatchSize(final int batchSize)
  {
    if (batchSize < 1)
    {
      this.batchSize = 1;
    }
    else
    {
      this.batchSize = batchSize;
    }
  }



  /**
   * Retrieves the alias dereferencing policy that should be used.
   *
   * @return  The alias dereferencing policy that should be used.
   */
  public int getDereference()
  {
    return derefPolicy;
  }



  /**
   * Specifies the alias dereferencing policy that should be used.
   *
   * @param  dereference  The alias dereferencing policy that should be used.
   */
  public void setDereference(final int dereference)
  {
    derefPolicy = dereference;
  }



  /**
   * Retrieves the maximum number of entries that should be returned for a
   * search.
   *
   * @return  The maximum number of entries that should be returned for a
   *          search.
   */
  public int getMaxResults()
  {
    return sizeLimit;
  }



  /**
   * Specifies the maximum number of entries that should be returned for a
   * search.
   *
   * @param  maxResults  The maximum number of entries that should be returned
   *                     for a search.
   */
  public void setMaxResults(final int maxResults)
  {
    if (maxResults < 0)
    {
      sizeLimit = 0;
    }
    else
    {
      sizeLimit = maxResults;
    }
  }



  /**
   * Retrieves the maximum length of time in seconds that the server should
   * spend processing a search.
   *
   * @return  The maximum length of time in seconds that the server should spend
   *          processing a search.
   */
  public int getServerTimeLimit()
  {
    return timeLimit;
  }



  /**
   * Specifies the maximum length of time in seconds that the server should
   * spend processing a search.
   *
   * @param  limit  The maximum length of time in seconds that the server should
   *                spend processing a search.
   */
  public void setServerTimeLimit(final int limit)
  {
    if (limit < 0)
    {
      timeLimit = 0;
    }
    else
    {
      timeLimit = limit;
    }
  }



  /**
   * Creates a duplicate of this search constraints object.
   *
   * @return  A duplicate of this search constraints object.
   */
  @Override()
  @NotNull()
  public LDAPSearchConstraints duplicate()
  {
    final LDAPSearchConstraints c = new LDAPSearchConstraints();

    c.batchSize   = batchSize;
    c.derefPolicy = derefPolicy;
    c.sizeLimit   = sizeLimit;
    c.timeLimit   = timeLimit;

    c.setBindProc(getBindProc());
    c.setClientControls(getClientControls());
    c.setReferrals(getReferrals());
    c.setHopLimit(getHopLimit());
    c.setRebindProc(getRebindProc());
    c.setServerControls(getServerControls());
    c.setTimeLimit(getTimeLimit());

    return c;
  }



  /**
   * Retrieves a string representation of this search constraints object.
   *
   * @return  A string representation of this search constraints object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();

    buffer.append("LDAPSearchConstraints(constraints=");
    buffer.append(super.toString());
    buffer.append(", batchSize=");
    buffer.append(batchSize);
    buffer.append(", derefPolicy=");
    buffer.append(derefPolicy);
    buffer.append(", maxResults=");
    buffer.append(sizeLimit);
    buffer.append(", serverTimeLimit=");
    buffer.append(timeLimit);
    buffer.append(')');

    return buffer.toString();
  }
}
