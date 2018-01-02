/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a post-connect processor that makes
 * it possible to invoke multiple post-connect processors as a single unit.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AggregatePostConnectProcessor
       implements PostConnectProcessor
{
  // The list of post-connect processors to be invoked.
  private final List<PostConnectProcessor> processors;



  /**
   * Creates a new aggregate post-connect processor that will invoke the given
   * set of post-connect processors in the order they are listed.
   *
   * @param  processors  The set of post-connect processors to be invoked.
   */
  public AggregatePostConnectProcessor(final PostConnectProcessor... processors)
  {
    this(StaticUtils.toList(processors));
  }



  /**
   * Creates a new aggregate post-connect processor that will invoke the given
   * set of post-connect processors in the order they are listed.
   *
   * @param  processors  The set of post-connect processors to be invoked.
   */
  public AggregatePostConnectProcessor(
              final Collection<? extends PostConnectProcessor> processors)
  {
    if (processors == null)
    {
      this.processors = Collections.emptyList();
    }
    else
    {
      this.processors = Collections.unmodifiableList(
           new ArrayList<PostConnectProcessor>(processors));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processPreAuthenticatedConnection(final LDAPConnection connection)
         throws LDAPException
  {
    for (final PostConnectProcessor p : processors)
    {
      p.processPreAuthenticatedConnection(connection);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processPostAuthenticatedConnection(
                   final LDAPConnection connection)
         throws LDAPException
  {
    for (final PostConnectProcessor p : processors)
    {
      p.processPostAuthenticatedConnection(connection);
    }
  }
}
