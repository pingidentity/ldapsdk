/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
 * This class provides a simple referral connector that may be used for testing
 * purposes.
 */
public class TestReferralConnector
       implements ReferralConnector
{
  // The bind request to use to try to authenticate the connection.
  private BindRequest bindRequest;

  // The exception to throw on a connection attempt.
  private LDAPException exceptionToThrow;




  /**
   * Creates a new instance of this test referral connector.  By default, it
   * will create unauthenticated connections.
   */
  public TestReferralConnector()
  {
    bindRequest = null;
    exceptionToThrow = null;
  }



  /**
   * Retrieves the bind request that will be used to authenticate connections,
   * if any.
   *
   * @return  The bind request that will be used to authenticate connections, or
   *          {@code null} if connections should not be authenticated.
   */
  public BindRequest getBindRequest()
  {
    return bindRequest;
  }



  /**
   * Specifies the bind request that will be used to authenticate connections.
   *
   * @param  bindRequest  The bind request that will be used to authenticate
   *                      connections.  It may be {@code null} if connections
   *                      should not be authenticated.
   */
  public void setBindRequest(final BindRequest bindRequest)
  {
    this.bindRequest = bindRequest;
  }



  /**
   * Retrieves an exception that should be thrown on a connect attempt, if any.
   *
   * @return  An exception that should be thrown on a connect attempt, or
   *          {@code null} if no exception should be thrown (unless a problem is
   *          encountered while establishing or authenticating the connection).
   */
  public LDAPException getExceptionToThrow()
  {
    return exceptionToThrow;
  }



  /**
   * Specifies the exception that should be thrown on a connect attempt.
   *
   * @param  exceptionToThrow  The exception that should be thrown on a connect
   *                           attempt.  it may be {@code null} if no exception
   *                           should be thrown (unless a problem is encountered
   *                           while establishing or authenticating the
   *                           connection).
   */
  public void setExceptionToThrow(final LDAPException exceptionToThrow)
  {
    this.exceptionToThrow = exceptionToThrow;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDAPConnection getReferralConnection(final LDAPURL referralURL,
                                              final LDAPConnection connection)
         throws LDAPException
  {
    if (exceptionToThrow != null)
    {
      throw exceptionToThrow;
    }

    final LDAPConnection conn =
         new LDAPConnection(referralURL.getHost(), referralURL.getPort());

    if (bindRequest != null)
    {
      try
      {
        conn.bind(bindRequest);
      }
      catch (final LDAPException e)
      {
        conn.close();
        throw e;
      }
    }

    return conn;
  }
}
