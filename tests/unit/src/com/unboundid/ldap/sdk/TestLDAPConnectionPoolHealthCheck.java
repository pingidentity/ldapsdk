/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
 * This class provides an implementation of an LDAP connection pool health check
 * that is primarily intended for testing purposes.
 */
public final class TestLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // The exceptions that will be thrown by each of the methods.
  private final LDAPException checkoutException;
  private final LDAPException continuedUseException;
  private final LDAPException newConnectionException;
  private final LDAPException postAuthenticationException;
  private final LDAPException postExceptionException;
  private final LDAPException releaseException;



  /**
   * Creates a new instance of this health check that will never throw an
   * exception.
   */
  public TestLDAPConnectionPoolHealthCheck()
  {
    this(null, null, null, null, null, null);
  }



  /**
   * Creates a new instance of this health check with the provided information.
   *
   * @param  newConnectionException       The exception that should be thrown
   *                                      by the new connection method.
   * @param  postAuthenticationException  The exception that should be thrown by
   *                                      the post-authentication method.
   * @param  checkoutException            The exception that should be thrown by
   *                                      the checkout method.
   * @param  releaseException             The exception that should be thrown by
   *                                      the release method.
   * @param  continuedUseException        The exception that should be thrown by
   *                                      the continued use method.
   * @param  postExceptionException       The exception that should be thrown by
   *                                      the post-exception method.
   */
  public TestLDAPConnectionPoolHealthCheck(
              final LDAPException newConnectionException,
              final LDAPException postAuthenticationException,
              final LDAPException checkoutException,
              final LDAPException releaseException,
              final LDAPException continuedUseException,
              final LDAPException postExceptionException)
  {
    this.newConnectionException      = newConnectionException;
    this.postAuthenticationException = postAuthenticationException;
    this.checkoutException           = checkoutException;
    this.releaseException            = releaseException;
    this.continuedUseException       = continuedUseException;
    this.postExceptionException      = postExceptionException;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureNewConnectionValid(final LDAPConnection connection)
         throws LDAPException
  {
    doThrow(newConnectionException);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidAfterAuthentication(
                   final LDAPConnection connection,
                   final BindResult bindResult)
         throws LDAPException
  {
    doThrow(postAuthenticationException);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForCheckout(final LDAPConnection connection)
         throws LDAPException
  {
    doThrow(checkoutException);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForRelease(final LDAPConnection connection)
         throws LDAPException
  {
    doThrow(releaseException);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidForContinuedUse(
                   final LDAPConnection connection)
         throws LDAPException
  {
    doThrow(continuedUseException);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidAfterException(
                   final LDAPConnection connection,
                   final LDAPException exception)
         throws LDAPException
  {
    doThrow(postExceptionException);
  }



  /**
   * Throws the provided exception if it is non-{@code null}.
   *
   * @param  e  The exception to be thrown, or {@code null} if none.
   *
   * @throws  LDAPException  If the provided exception was non-{@code null}.
   */
  private static void doThrow(final LDAPException e)
          throws LDAPException
  {
    if (e != null)
    {
      throw e;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("TestLDAPConnectionPoolHealthCheck()");
  }
}
