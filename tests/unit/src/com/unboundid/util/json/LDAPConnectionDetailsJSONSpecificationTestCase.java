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



import java.io.File;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides a set of test cases for the LDAP connection details
 * JSON specification class.
 */
public final class LDAPConnectionDetailsJSONSpecificationTestCase
       extends LDAPSDKTestCase
{
  // An in-memory directory server instance that may be used for testing.
  private volatile InMemoryDirectoryServer ds = null;



  /**
   * Prepares an in-memory directory server instance to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    // Create the SSL socket factory to use for StartTLS.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"), new TrustAllTrustManager());
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());


    // Create the in-memory directory server instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.setListenerConfigs(
         InMemoryListenerConfig.createLDAPConfig("LDAP", null, 0,
              serverSSLUtil.createSSLSocketFactory()),
         InMemoryListenerConfig.createLDAPSConfig("LDAPS", null, 0,
              serverSSLUtil.createSSLServerSocketFactory(),
              clientSSLUtil.createSSLSocketFactory()));

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
  }



  /**
   * Cleans up after testing is complete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (ds != null)
    {
      ds.shutDown(true);
      ds = null;
    }
  }



  /**
   * Tests a simple specification that only provides information about a
   * single server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicSingleServerSpecification()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "none"))),
         new JSONField("connection-options", new JSONObject(
              new JSONField("connect-timeout-millis", 30000L),
              new JSONField("use-synchronous-mode", true))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", "cn=Directory Manager"),
              new JSONField("password", "password"))),
         new JSONField("connection-pool-options", new JSONObject(
              new JSONField("maximum-connection-age-millis", 300000L))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());
    assertTrue(spec.getServerSet() instanceof SingleServerSet);

    assertNotNull(spec.getBindRequest());
    assertTrue(spec.getBindRequest() instanceof SimpleBindRequest);

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a specification from a JSON object
   * using its string representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromString()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))));
    final String jsonString = o.toString();

    final LDAPConnectionDetailsJSONSpecification spec =
         LDAPConnectionDetailsJSONSpecification.fromString(jsonString);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a specification from a JSON object
   * from a file containing the string representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateFromFile()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))));
    final File jsonFile = createTempFile(o.toString());

    final LDAPConnectionDetailsJSONSpecification spec =
         LDAPConnectionDetailsJSONSpecification.fromFile(
              jsonFile.getAbsolutePath());

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a valid, unencrypted connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnencryptedConnection()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a valid, SSL-encrypted connection
   * in a manner that trusts all server certificates and does not use a client
   * keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLConnectionTrustAllWithoutKeystore()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAPS")))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-all-certificates", true))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a valid, SSL-encrypted connection
   * in a manner that uses key and trust stores.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLConnectionKeyKeyAndTrustStores()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");
    final File pinFile     = createTempFile("password");

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAPS")))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("use-jvm-default-trust-store", true),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-pin-file", pinFile.getAbsolutePath()))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a valid, StartTLS-encrypted
   * connection in a manner that trusts all server certificates and does not use
   * a client keystore.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLSConnectionTrustAllWithoutKeystore()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("trust-all-certificates", true))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a valid, StartTLS-encrypted
   * connection in a manner that uses key and trust stores.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStartTLSConnectionKeyKeyAndTrustStores()
         throws Exception
  {
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File keyStore    = new File(resourceDir, "client.keystore");
    final File trustStore  = new File(resourceDir, "client.truststore");
    final File pinFile     = createTempFile("password");

    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "StartTLS"),
              new JSONField("use-jvm-default-trust-store", false),
              new JSONField("trust-store-file", trustStore.getAbsolutePath()),
              new JSONField("key-store-file", keyStore.getAbsolutePath()),
              new JSONField("key-store-pin-file", pinFile.getAbsolutePath()))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnection conn = spec.createConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    conn = spec.createUnauthenticatedConnection();
    assertNotNull(conn.getRootDSE());
    conn.close();

    LDAPConnectionPool pool = spec.createConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();

    pool = spec.createUnauthenticatedConnectionPool(1, 10);
    assertNotNull(pool.getRootDSE());
    pool.close();
  }



  /**
   * Tests the behavior when configuring the server to verify the address in the
   * certificate.  We can't guarantee that this will pass, so we won't actually
   * create any connections but this will at least get coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLSetVerifyAddress()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAPS")))))),
         new JSONField("communication-security", new JSONObject(
              new JSONField("security-type", "SSL"),
              new JSONField("trust-all-certificates", true),
              new JSONField("verify-address-in-certificate", true))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    assertNotNull(spec.getServerSet());

    assertNull(spec.getBindRequest());

    LDAPConnectionPool pool = spec.createConnectionPool(0, 10);
    pool.close();
  }



  /**
   * Tests the behavior when trying to create a connection to a server that is
   * offline.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConnectFailure()
         throws Exception
  {
    ds.shutDown(true);

    try
    {
      final JSONObject o = new JSONObject(
           new JSONField("server-details", new JSONObject(
                new JSONField("single-server", new JSONObject(
                     new JSONField("address", "localhost"),
                     new JSONField("port", ds.getListenPort("LDAP")))))));

      final LDAPConnectionDetailsJSONSpecification spec =
           new LDAPConnectionDetailsJSONSpecification(o);

      final LDAPConnection conn = spec.createConnection();
      conn.close();
    }
    finally
    {
      ds.startListening();
    }
  }



  /**
   * Tests the behavior when trying to create a connection to a server using
   * invalid authentication credentials.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testBindFailure()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))),
         new JSONField("authentication-details", new JSONObject(
              new JSONField("authentication-type", "simple"),
              new JSONField("dn", "cn=Directory Manager"),
              new JSONField("password", "wrong"))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);

    final LDAPConnection conn = spec.createConnection();
    conn.close();
  }



  /**
   * Tests a specification that has an invalid top-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testInvalidTopLevelField()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")))))),
         new JSONField("invalid-field", new JSONObject()));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Tests a specification that has an invalid lower-level field.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testInvalidLowerLevelField()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("server-details", new JSONObject(
              new JSONField("single-server", new JSONObject(
                   new JSONField("address", "localhost"),
                   new JSONField("port", ds.getListenPort("LDAP")),
                   new JSONField("invalid", "doesn't matter"))))));

    final LDAPConnectionDetailsJSONSpecification spec =
         new LDAPConnectionDetailsJSONSpecification(o);
  }



  /**
   * Provides test coverage for the {@code getBoolean} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBoolean()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("trueField", true),
         new JSONField("falseField", false),
         new JSONField("trueStringField", "true"));

    assertTrue(LDAPConnectionDetailsJSONSpecification.getBoolean(o,
         "trueField", true));
    assertTrue(LDAPConnectionDetailsJSONSpecification.getBoolean(o,
         "trueField", false));

    assertFalse(LDAPConnectionDetailsJSONSpecification.getBoolean(o,
         "falseField", true));
    assertFalse(LDAPConnectionDetailsJSONSpecification.getBoolean(o,
         "falseField", false));

    assertTrue(LDAPConnectionDetailsJSONSpecification.getBoolean(o,
         "missingField", true));
    assertFalse(LDAPConnectionDetailsJSONSpecification.getBoolean(o,
         "missingField", false));

    try
    {
      LDAPConnectionDetailsJSONSpecification.getBoolean(o, "trueStringField",
           true);
      fail("Expected an exception from a field without a boolean value");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getInt} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetInt()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("intField", 1234),
         new JSONField("decimalField", 1234.5),
         new JSONField("stringField", "1234"));

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getInt(o, "intField", 0, null,
              null).intValue(),
         1234);

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getInt(o, "missingField", 0,
              null, null).intValue(),
         0);

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getInt(o, "missingField", null,
              null, null),
         null);

    try
    {
      LDAPConnectionDetailsJSONSpecification.getInt(o, "stringField", 1234,
           null, null);
      fail("Expected an exception from a field with a string value");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.getInt(o, "decimalField", 1234,
           null, null);
      fail("Expected an exception from a field with a decimal value");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.getInt(o, "intField", 1234, 10000,
           20000);
      fail("Expected an exception with a value below the minimum");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.getInt(o, "intField", 1234, 0,
           1000);
      fail("Expected an exception with a value above the maximum");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getLong} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLong()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("longField", 1234),
         new JSONField("decimalField", 1234.5),
         new JSONField("stringField", "1234"));

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getLong(o, "longField", 0L,
              null, null).longValue(),
         1234L);

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getLong(o, "missingField", 0L,
              null, null).longValue(),
         0L);

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getLong(o, "missingField", null,
              null, null),
         null);

    try
    {
      LDAPConnectionDetailsJSONSpecification.getLong(o, "stringField", 1234L,
           null, null);
      fail("Expected an exception from a field with a string value");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.getLong(o, "decimalField", 1234L,
           null, null);
      fail("Expected an exception from a field with a decimal value");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.getLong(o, "longField", 1234L,
           10000L, 20000L);
      fail("Expected an exception with a value below the minimum");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.getLong(o, "longField", 1234L, 0L,
           1000L);
      fail("Expected an exception with a value above the maximum");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getObject} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetObject()
         throws Exception
  {
    final JSONObject emptyObject = JSONObject.EMPTY_OBJECT;
    final JSONObject nonEmptyObject = new JSONObject(
         new JSONField("foo", "bar"));

    final JSONObject o = new JSONObject(
         new JSONField("emptyObject", emptyObject),
         new JSONField("nonEmptyObject", nonEmptyObject),
         new JSONField("stringField", "string"));

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getObject(o, "emptyObject"),
         emptyObject);

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getObject(o, "nonEmptyObject"),
         nonEmptyObject);

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getObject(o, "missingObject"),
         null);

    try
    {
      LDAPConnectionDetailsJSONSpecification.getObject(o, "stringField");
      fail("Expected an exception with a value that is not an object");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetString()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("emptyString", ""),
         new JSONField("nonEmptyString", "foo"),
         new JSONField("integer", 1234));

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getString(o, "emptyString", ""),
         "");
    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getString(o, "emptyString",
              "foo"),
         "");

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getString(o, "nonEmptyString",
              ""),
         "foo");
    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getString(o, "nonEmptyString",
              "foo"),
         "foo");

    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getString(o, "missingString",
              "bar"),
         "bar");
    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getString(o, "missingString",
              null),
         null);

    try
    {
      LDAPConnectionDetailsJSONSpecification.getString(o, "integer", "1234");
      fail("Expected an exception with a value that is not a string");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Provides test coverage for the {@code getStringFromFile} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringFromFile()
         throws Exception
  {
    final File singleLineFile = createTempFile("foo");
    assertEquals(
         LDAPConnectionDetailsJSONSpecification.getStringFromFile(
              singleLineFile.getAbsolutePath(), "x"),
         "foo");

    try
    {
      final File emptyFile = createTempFile();
      LDAPConnectionDetailsJSONSpecification.getStringFromFile(
           emptyFile.getAbsolutePath(), "x");
      fail("Expected an exception with an empty file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      final File singleEmptyLineFile = createTempFile("");
      LDAPConnectionDetailsJSONSpecification.getStringFromFile(
           singleEmptyLineFile.getAbsolutePath(), "x");
      fail("Expected an exception with a single empty line");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      final File multiLineFile = createTempFile("foo", "bar");
      LDAPConnectionDetailsJSONSpecification.getStringFromFile(
           multiLineFile.getAbsolutePath(), "x");
      fail("Expected an exception with multiple lines");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      assertTrue(singleLineFile.delete());
      LDAPConnectionDetailsJSONSpecification.getStringFromFile(
           singleLineFile.getAbsolutePath(), "x");
      fail("Expected an exception with a nonexistent file");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code rejectConflictingFields} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectConflictingFields()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("f1", "one"),
         new JSONField("f2", "two"));

    LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o, "f1",
         "f3");

    try
    {
      LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o, "f1",
           "f2");
      fail("Expected an exception with a conflicting first field");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.rejectConflictingFields(o, "f1",
           "f3", "f2");
      fail("Expected an exception with a conflicting second field");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Provides test coverage for the {@code rejectUnresolvedDependency} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectUnresolvedDependency()
         throws Exception
  {
    final JSONObject o = new JSONObject(
         new JSONField("f1", "one"),
         new JSONField("f2", "two"));

    LDAPConnectionDetailsJSONSpecification.rejectUnresolvedDependency(o, "f3",
         "f4");

    try
    {
      LDAPConnectionDetailsJSONSpecification.rejectUnresolvedDependency(o, "f3",
           "f1");
      fail("Expected an exception with an unresolved first field");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    try
    {
      LDAPConnectionDetailsJSONSpecification.rejectUnresolvedDependency(o, "f3",
           "f4", "f1");
      fail("Expected an exception with an unresolved second field");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }
}
