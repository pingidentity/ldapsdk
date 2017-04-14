/*
 * Copyright 2015-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2017 UnboundID Corp.
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



/**
 * This class provides a post-connect processor that may be used for testing
 * purposes.
 */
public final class TestPostConnectProcessor
       implements PostConnectProcessor
{
  // The exception that should be thrown in post-authentication processing.
  private final LDAPException postAuthException;

  // The exception that should be thrown in pre-authentication processing.
  private final LDAPException preAuthException;



  /**
   * Creates a new post-connect processor with the provided information.
   *
   * @param  preAuthException   The exception that should be thrown in the
   *                            pre-authentication phase of processing.  It may
   *                            be {@code null} if no exception should be thrown
   *                            in the pre-authentication phase.
   * @param  postAuthException  The exception that should be thrown in the
   *                            post-authentication phase of processing.  It may
   *                            be {@code null} if no exception should be thrown
   *                            in the post-authentication phase.
   */
  public TestPostConnectProcessor(final LDAPException preAuthException,
                                  final LDAPException postAuthException)
  {
    this.preAuthException  = preAuthException;
    this.postAuthException = postAuthException;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processPreAuthenticatedConnection(final LDAPConnection connection)
         throws LDAPException
  {
    if (preAuthException != null)
    {
      throw preAuthException;
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
    if (postAuthException != null)
    {
      throw postAuthException;
    }
  }
}
