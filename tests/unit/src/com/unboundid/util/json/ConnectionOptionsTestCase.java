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
package com.unboundid.util.json;



import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.util.ssl.TrustAllSSLSocketVerifier;



/**
 * This class provides a set of test cases for the connection options
 * class.
 */
public final class ConnectionOptionsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for the case in which the JSON object does not have the
   * connection-options field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final ServerSet serverSet = spec.getServerSet();
    assertNotNull(serverSet);
    assertTrue(serverSet instanceof SingleServerSet);

    final SingleServerSet singleServerSet = (SingleServerSet) serverSet;
    final LDAPConnectionOptions opts =
         singleServerSet.getConnectionOptions();

    assertEquals(opts.getConnectTimeoutMillis(), 60000);

    assertEquals(opts.getResponseTimeoutMillis(), 300000L);

    assertFalse(opts.followReferrals());

    assertFalse(opts.useSchema());

    assertFalse(opts.useSynchronousMode());

    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * connection-options field whose value is an empty object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOptionsEmpty()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-options", new JSONObject()));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final ServerSet serverSet = spec.getServerSet();
    assertNotNull(serverSet);
    assertTrue(serverSet instanceof SingleServerSet);

    final SingleServerSet singleServerSet = (SingleServerSet) serverSet;
    final LDAPConnectionOptions opts =
         singleServerSet.getConnectionOptions();

    assertEquals(opts.getConnectTimeoutMillis(), 60000);

    assertEquals(opts.getResponseTimeoutMillis(), 300000L);

    assertFalse(opts.followReferrals());

    assertFalse(opts.useSchema());

    assertFalse(opts.useSynchronousMode());

    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * connection-options field that specifies non-default values for all options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-options", new JSONObject(
              new JSONField("connect-timeout-millis", 12345L),
              new JSONField("default-response-timeout-millis", 67890L),
              new JSONField("follow-referrals", true),
              new JSONField("use-schema", true),
              new JSONField("use-synchronous-mode", true))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final ServerSet serverSet = spec.getServerSet();
    assertNotNull(serverSet);
    assertTrue(serverSet instanceof SingleServerSet);

    final SingleServerSet singleServerSet = (SingleServerSet) serverSet;
    final LDAPConnectionOptions opts =
         singleServerSet.getConnectionOptions();

    assertEquals(opts.getConnectTimeoutMillis(), 12345);

    assertEquals(opts.getResponseTimeoutMillis(), 67890L);

    assertTrue(opts.followReferrals());

    assertTrue(opts.useSchema());

    assertTrue(opts.useSynchronousMode());

    assertNotNull(opts.getSSLSocketVerifier());
    assertTrue(
         opts.getSSLSocketVerifier() instanceof TrustAllSSLSocketVerifier);
  }



  /**
   * Tests the behavior for the case in which the JSON object has a
   * connection-options field that includes an invalid set of options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testInvalidOptions()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort()))))),
         new JSONField("connection-options", new JSONObject(
              new JSONField("invalid1", true),
              new JSONField("invalid2", "string"),
              new JSONField("invalid3", 12345))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }
}
