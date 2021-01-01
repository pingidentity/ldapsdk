/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.LDAPTestUtils;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code InMemoryDirectoryServer} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInMemoryDirectoryServerExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final File ldifFile = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    final String ldifFilePath = ldifFile.getAbsolutePath();

    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore = new File(resourceDir, "server.keystore");
    assertTrue(serverKeyStore.exists());
    final String serverKeyStorePath = serverKeyStore.getAbsolutePath();
    final char[] serverKeyStorePIN = "password".toCharArray();

    final File serverTrustStore = new File(resourceDir, "server.truststore");
    assertTrue(serverTrustStore.exists());
    final String serverTrustStorePath = serverTrustStore.getAbsolutePath();

    final String clientTrustStorePath = serverKeyStorePath;


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a base configuration for the server.
    InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=Directory Manager",
         "password");

    // Update the configuration to support LDAP (with StartTLS) and LDAPS
    // listeners.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStorePath, serverKeyStorePIN, "JKS",
              "server-cert"),
         new TrustStoreTrustManager(serverTrustStorePath));
    final SSLUtil clientSSLUtil = new SSLUtil(
         new TrustStoreTrustManager(clientTrustStorePath));
    config.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP", // Listener name
              null, // Listen address. (null = listen on all interfaces)
              0, // Listen port (0 = automatically choose an available port)
              serverSSLUtil.createSSLSocketFactory()), // StartTLS factory
         InMemoryListenerConfig.createLDAPSConfig("LDAPS", // Listener name
              null, // Listen address. (null = listen on all interfaces)
              0, // Listen port (0 = automatically choose an available port)
              serverSSLUtil.createSSLServerSocketFactory(), // Server factory
              clientSSLUtil.createSSLSocketFactory())); // Client factory

    // Create and start the server instance and populate it with an initial set
    // of data from an LDIF file.
    InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
    server.importFromLDIF(true, ldifFilePath);

    // Start the server so it will accept client connections.
    server.startListening();

    // Get an unencrypted connection to the server's LDAP listener, then use
    // StartTLS to secure that connection.  Make sure the connection is usable
    // by retrieving the server root DSE.
    LDAPConnection connection = server.getConnection("LDAP");
    connection.processExtendedOperation(new StartTLSExtendedRequest(
         clientSSLUtil.createSSLContext()));
    LDAPTestUtils.assertEntryExists(connection, "");
    connection.close();

    // Establish an SSL-based connection to the LDAPS listener, and make sure
    // that connection is also usable.
    connection = server.getConnection("LDAPS");
    LDAPTestUtils.assertEntryExists(connection, "");
    connection.close();

    // Shut down the server so that it will no longer accept client
    // connections, and close all existing connections.
    server.shutDown(true);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }



  /**
   * Tests the example in the {@code LDAPListener} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDAPListenerExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    // No setup is required.


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Create a canned response request handler that will always return a
    // "SUCCESS" result in response to any request.
    CannedResponseRequestHandler requestHandler =
        new CannedResponseRequestHandler(ResultCode.SUCCESS, null, null,
             null);

    // A listen port of zero indicates that the listener should
    // automatically pick a free port on the system.
    int listenPort = 0;

    // Create and start an LDAP listener to accept requests and blindly
    // return success results.
    LDAPListenerConfig listenerConfig = new LDAPListenerConfig(listenPort,
         requestHandler);
    LDAPListener listener = new LDAPListener(listenerConfig);
    listener.startListening();

    // Establish a connection to the listener and verify that a search
    // request will get a success result.
    LDAPConnection connection = new LDAPConnection("localhost",
         listener.getListenPort());
    SearchResult searchResult = connection.search("dc=example,dc=com",
         SearchScope.BASE, Filter.createPresenceFilter("objectClass"));
    LDAPTestUtils.assertResultCodeEquals(searchResult,
         ResultCode.SUCCESS);

    // Close the connection and stop the listener.
    connection.close();
    listener.shutDown(true);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    // No cleanup is required.
  }
}
