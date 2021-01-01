/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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



import javax.net.SocketFactory;

import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.util.ObjectPair;



/**
 * This class provides a set of test cases for the server set blacklist manager.
 */
public final class ServerSetBlacklistManagerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the blacklist manager with minimal settings.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalSettings()
         throws Exception
  {
    // Create a pair of in-memory directory server instances to use for testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(cfg);
    ds1.startListening();

    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(cfg);
    ds2.startListening();


    // Create a server set and a blacklist manager.
    final String host = "localhost";
    final int port1 = ds1.getListenPort();
    final int port2 = ds2.getListenPort();

    final RoundRobinServerSet serverSet =
         new RoundRobinServerSet(
              new String[] { host, host },
              new int[] { port1, port2 });
    final ServerSetBlacklistManager blacklistManager =
         new ServerSetBlacklistManager(serverSet, null, null, null, null, 1L);


    // Validate the blacklist when it should be empty.
    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Stop the first directory server instance and add it to the blacklist.
    ds1.shutDown(true);

    blacklistManager.addToBlacklist(host, port1, null);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 1);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 1);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Stop the second directory server instance and add it to the blacklist.
    ds2.shutDown(true);

    blacklistManager.addToBlacklist(new ObjectPair<>(host, port2), null);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 2);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 2);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Sleep for at least 10 milliseconds to ensure that the blacklist manager
    // has had plenty of time to fail to re-establish a connection to the
    // blacklisted servers.
    Thread.sleep(10L);


    // Start the first directory server instance and wait for it to be removed
    // from the blacklist.
    ds1.startListening();

    long stopWaitingTime = System.currentTimeMillis() + 60_000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (blacklistManager.isBlacklisted(host, port1))
      {
        Thread.sleep(1L);
      }
      else
      {
        break;
      }
    }

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 1);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 1);

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Start the second directory server instance and wait for it to be removed
    // from the blacklist.
    ds2.startListening();

    stopWaitingTime = System.currentTimeMillis() + 60_000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (blacklistManager.isBlacklisted(host, port2))
      {
        Thread.sleep(1L);
      }
      else
      {
        break;
      }
    }

    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 0);

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Stop the instances again and re-add them to the blacklist.
    ds1.shutDown(true);
    ds2.shutDown(true);

    blacklistManager.addToBlacklist(new ObjectPair<>(host, port1), null);
    blacklistManager.addToBlacklist(host, port2, null);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 2);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 2);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Sleep for at least 10 milliseconds.
    Thread.sleep(10L);


    // With the Directory Server instances still down, manually remove the first
    // server from the blacklist.
    blacklistManager.removeFromBlacklist(host, port1);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 1);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 1);

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Manually remove the second server from the blacklist.
    blacklistManager.removeFromBlacklist(new ObjectPair<>(host, port2));

    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Re-add both servers to the blacklist.
    blacklistManager.addToBlacklist(host, port1, null);
    blacklistManager.addToBlacklist(host, port2, null);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 2);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 2);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Clear the blacklist.
    blacklistManager.clear();

    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    blacklistManager.shutDown();
  }



  /**
   * Tests the blacklist manager with a complete set of options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteSettings()
         throws Exception
  {
    // Create a pair of in-memory directory server instances to use for testing.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    final InMemoryDirectoryServer ds1 = new InMemoryDirectoryServer(cfg);
    ds1.startListening();

    final InMemoryDirectoryServer ds2 = new InMemoryDirectoryServer(cfg);
    ds2.startListening();


    // Create a server set and a blacklist manager.
    final String host = "localhost";
    final int port1 = ds1.getListenPort();
    final int port2 = ds2.getListenPort();

    final SocketFactory socketFactory = SocketFactory.getDefault();
    final LDAPConnectionOptions connectionOptions = new LDAPConnectionOptions();
    final BindRequest bindRequest =
         new SimpleBindRequest("cn=Directory Manager", "password");
    final PostConnectProcessor postConnectProcessor =
         new TestPostConnectProcessor(null, null);
    final RoundRobinServerSet serverSet =
         new RoundRobinServerSet(new String[] { host, host },
              new int[] { port1, port2 }, socketFactory, connectionOptions,
              bindRequest, postConnectProcessor);
    final ServerSetBlacklistManager blacklistManager =
         new ServerSetBlacklistManager(serverSet, socketFactory,
              connectionOptions, bindRequest, postConnectProcessor, 1L);


    // Validate the blacklist when it should be empty.
    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Stop the first directory server instance and add it to the blacklist.
    ds1.shutDown(true);

    final LDAPConnectionPoolHealthCheck healthCheck =
         new GetEntryLDAPConnectionPoolHealthCheck("", 10_000L, false, false,
              false, false, false, false);
    blacklistManager.addToBlacklist(host, port1, healthCheck);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 1);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 1);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Stop the second directory server instance and add it to the blacklist.
    ds2.shutDown(true);

    blacklistManager.addToBlacklist(new ObjectPair<>(host, port2), healthCheck);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 2);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 2);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Sleep for at least 10 milliseconds to ensure that the blacklist manager
    // has had plenty of time to fail to re-establish a connection to the
    // blacklisted servers.
    Thread.sleep(10L);


    // Start the first directory server instance and wait for it to be removed
    // from the blacklist.
    ds1.startListening();

    long stopWaitingTime = System.currentTimeMillis() + 60_000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (blacklistManager.isBlacklisted(host, port1))
      {
        Thread.sleep(1L);
      }
      else
      {
        break;
      }
    }

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 1);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 1);

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Start the second directory server instance and wait for it to be removed
    // from the blacklist.
    ds2.startListening();

    stopWaitingTime = System.currentTimeMillis() + 60_000L;
    while (System.currentTimeMillis() < stopWaitingTime)
    {
      if (blacklistManager.isBlacklisted(host, port2))
      {
        Thread.sleep(1L);
      }
      else
      {
        break;
      }
    }

    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 0);

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Stop the instances again and re-add them to the blacklist.
    ds1.shutDown(true);
    ds2.shutDown(true);

    blacklistManager.addToBlacklist(new ObjectPair<>(host, port1), healthCheck);
    blacklistManager.addToBlacklist(host, port2, healthCheck);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 2);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 2);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Sleep for at least 10 milliseconds.
    Thread.sleep(10L);


    // With the Directory Server instances still down, manually remove the first
    // server from the blacklist.
    blacklistManager.removeFromBlacklist(host, port1);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 1);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 1);

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Manually remove the second server from the blacklist.
    blacklistManager.removeFromBlacklist(new ObjectPair<>(host, port2));

    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Re-add both servers to the blacklist.
    blacklistManager.addToBlacklist(host, port1, healthCheck);
    blacklistManager.addToBlacklist(host, port2, healthCheck);

    assertFalse(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 2);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertFalse(blacklistManager.getBlacklistedServers().isEmpty());
    assertEquals(blacklistManager.getBlacklistedServers().size(), 2);

    assertTrue(blacklistManager.isBlacklisted(host, port1));
    assertTrue(blacklistManager.isBlacklisted(host, port2));

    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertTrue(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    // Clear the blacklist.
    blacklistManager.clear();

    assertTrue(blacklistManager.isEmpty());

    assertEquals(blacklistManager.size(), 0);

    assertNotNull(blacklistManager.getBlacklistedServers());
    assertTrue(blacklistManager.getBlacklistedServers().isEmpty());

    assertFalse(blacklistManager.isBlacklisted(host, port1));
    assertFalse(blacklistManager.isBlacklisted(host, port2));

    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port1)));
    assertFalse(blacklistManager.isBlacklisted(new ObjectPair<>(host, port2)));

    assertNotNull(blacklistManager.toString());


    blacklistManager.shutDown();
  }
}
