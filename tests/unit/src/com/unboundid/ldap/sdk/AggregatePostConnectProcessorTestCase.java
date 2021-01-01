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



import java.util.Collection;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the aggregate post-connect
 * processor.
 */
public final class AggregatePostConnectProcessorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the aggregate post-connect processor that wraps a
   * single post-connect processors that should succeed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulSingleProcessor()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(
              new TestPostConnectProcessor(null, null)));

    assertNotNull(pool.getRootDSE());

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps an
   * empty set of post-connect processors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulEmptyProcessor()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor());

    assertNotNull(pool.getRootDSE());

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps a
   * {@code null} collection of post-connect processors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulNullProcessor()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final Collection<PostConnectProcessor> nullCollection  = null;
    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(nullCollection));

    assertNotNull(pool.getRootDSE());

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps
   * several post-connect processors that should all succeed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSuccessfulMultipleProcessors()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(
              new TestPostConnectProcessor(null, null),
              new TestPostConnectProcessor(null, null),
              new TestPostConnectProcessor(null, null)));

    assertNotNull(pool.getRootDSE());

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps
   * several post-connect processors in which the first should fail in
   * pre-authentication processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailInFirstPreAuth()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(
              new TestPostConnectProcessor(
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "preAuth1"),
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth1")),
              new TestPostConnectProcessor(
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "preAuth2"),
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth2")),
              new TestPostConnectProcessor(
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "preAuth3"),
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth3"))));

    try
    {
      pool.getRootDSE();
      fail("Expected an exception from the first pre-auth processor");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getMessage(), "preAuth1");
    }

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps
   * several post-connect processors in which the first should succeed but a
   * subsequent processor should fail in pre-authentication processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailInSubsequentPreAuth()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(
              new TestPostConnectProcessor(null, null),
              new TestPostConnectProcessor(
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "preAuth2"),
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth2")),
              new TestPostConnectProcessor(
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "preAuth3"),
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth3"))));

    try
    {
      pool.getRootDSE();
      fail("Expected an exception from a subsequent pre-auth processor");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getMessage(), "preAuth2");
    }

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps
   * several post-connect processors in which the first should fail in
   * post-authentication processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailInFirstPostAuth()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(
              new TestPostConnectProcessor(null,
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth1")),
              new TestPostConnectProcessor(null,
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth2")),
              new TestPostConnectProcessor(null,
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth3"))));

    try
    {
      pool.getRootDSE();
      fail("Expected an exception from the first post-auth processor");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getMessage(), "postAuth1");
    }

    pool.close();
  }



  /**
   * Tests the behavior of the aggregate post-connect processor that wraps
   * several post-connect processors in which the first should succeed but a
   * subsequent processor should fail in post-authentication processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailInSubsequentPostAuth()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final SingleServerSet serverSet =
         new SingleServerSet("127.0.0.1", ds.getListenPort());

    final LDAPConnectionPool pool =
         new LDAPConnectionPool(serverSet, null, 0, 1,
         new AggregatePostConnectProcessor(
              new TestPostConnectProcessor(null, null),
              new TestPostConnectProcessor(null,
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth2")),
              new TestPostConnectProcessor(null,
                   new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
                        "postAuth3"))));

    try
    {
      pool.getRootDSE();
      fail("Expected an exception from a subsequent post-auth processor");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getMessage(), "postAuth2");
    }

    pool.close();
  }
}
