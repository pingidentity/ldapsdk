/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.LinkedList;

import org.testng.Assert;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.StandardErrorListenerExceptionHandler;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.LDAPTestUtils;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;


import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides the superclass for all LDAP SDK test cases.
 */
@Test(sequential=true)
public abstract class LDAPSDKTestCase
{
  // The set of attributes that may be used to construct the entry specified as
  // the base DN.
  private static Attribute[] baseEntryAttributes;

  // Indicates whether an UnboundID Directory Server instance is available for
  // use.
  private static boolean dsAvailable = false;

  // Indicates whether a second UnboundID Directory Server instance is available
  // for use.
  private static boolean ds2Available = false;

  // Indicates whether a Sun DSEE instance is available for use.
  private static boolean dseeAvailable = false;

  // Indicates whether an SSL-enabled UnboundID Directory Server instance is
  // available for use.
  private static boolean sslDSAvailable = false;

  // Indicates whether a second SSL-enabled UnboundID Directory Server instance
  // is available for use.
  private static boolean sslDS2Available = false;

  // Indicates whether an SSL-enabled Sun DSEE instance is available for use.
  private static boolean sslDSEEAvailable = false;

  // An in-memory directory server instance that can be used for testing.
  private static volatile InMemoryDirectoryServer testDS = null;

  // An SSL-enabled in-memory directory server instance that can be used for
  // testing.
  private static volatile InMemoryDirectoryServer testDSWithSSL = null;

  // The port number of the UnboundID Directory Server instance.
  private static int dsPort = -1;

  // The port number of a second UnboundID Directory Server instance that may
  // be  used for testing.
  private static int ds2Port = -1;

  // The port number of the Sun DSEE instance.
  private static int dseePort = -1;

  // The port number on which the UnboundID Directory Server instance listens
  // for SSL-based connections.
  private static int dsSSLPort = -1;

  // The port number on which the second UnboundID Directory Server instance
  // listens for SSL-based connections.
  private static int ds2SSLPort = -1;

  // The port number on which the Sun DSEE instance listens for SSL-based
  // connections.
  private static int dseeSSLPort = -1;

  // The list of connections created by this class.
  private static LinkedHashMap<LDAPConnection,StackTraceElement[]> connMap =
       new LinkedHashMap<LDAPConnection,StackTraceElement[]>();

  // The base DN for the UnboundID Directory Server and/or Sun DSEE instance.
  private static String dsBaseDN = null;

  // The bind DN for the UnboundID Directory Server and/or Sun DSEE instance.
  private static String dsBindDN = null;

  // The bind password for the UnboundID Directory Server and/or Sun DSEE
  // instance.
  private static String dsBindPassword = null;

  // The address of the UnboundID Directory Server instance.
  private static String dsHost = null;

  // The address of a second UnboundID Directory Server instance that may be
  // used for testing.
  private static String ds2Host = null;

  // The address of the Sun DSEE instance.
  private static String dseeHost = null;



  /**
   * Processes JVM properties to get information about an UnboundID Directory
   * Server and/or Sun DSEE instance that can be used for testing, if one is
   * available.
   */
  static
  {
    dsAvailable   = true;
    ds2Available  = true;
    dseeAvailable = true;

    dsHost = System.getProperty("ds.host");
    if ((dsHost == null) || (dsHost.length() == 0))
    {
      dsAvailable = false;
    }

    ds2Host = System.getProperty("ds2.host");
    if ((ds2Host == null) || (ds2Host.length() == 0))
    {
      ds2Available = false;
    }

    dseeHost = System.getProperty("dsee.host");
    if ((dseeHost == null) || (dseeHost.length() == 0))
    {
      dseeAvailable = false;
    }

    String portStr = System.getProperty("ds.port");
    if ((portStr == null) || (portStr.length() == 0))
    {
      dsAvailable = false;
    }
    else
    {
      try
      {
        dsPort = Integer.parseInt(portStr);
        if ((dsPort < 1) || (dsPort > 65535))
        {
          dsAvailable = false;
          if (dsPort != -1)
          {
            err("WARNING:  The ds.port property value must be between 1 and ",
                "65535.  Test cases that rely on LDAP communication with an ",
                "UnboundID Directory Server instance will only be able to ",
                "perform limited processing.");
          }
        }
      }
      catch (Exception e)
      {
        err("WARNING:  The ds.port property value cannot be parsed as an ",
            "integer.  Test cases that rely on LDAP communication with an",
            "UnboundID Directory Server instance will only be able to ",
            "perform limited processing.");
        dsAvailable = false;
      }
    }

    portStr = System.getProperty("ds.ssl.port");
    if ((portStr != null) && (portStr.length() > 0))
    {
      try
      {
        dsSSLPort = Integer.parseInt(portStr);
        if ((dsSSLPort < 1) || (dsSSLPort > 65535))
        {
          if (dsSSLPort != -1)
          {
            err("WARNING:  The ds.ssl.port property value must be between 1 ",
                "and 65535.  Test cases that rely on SSL-based LDAP ",
                "communication with an UnboundID Directory Server instance ",
                "will only be able to perform limited processing.");
            dsSSLPort = -1;
          }
        }
      }
      catch (Exception e)
      {
        err("WARNING:  The ds.ssl.port property value cannot be parsed as an ",
            "integer.  Test cases that rely on SSL-based LDAP communication ",
            "with an UnboundID Directory Server instance will only be able ",
            "to perform limited processing.");
        dsSSLPort = -1;
      }
    }

    portStr = System.getProperty("ds2.port");
    if ((portStr == null) || (portStr.length() == 0))
    {
      ds2Available = false;
    }
    else
    {
      try
      {
        ds2Port = Integer.parseInt(portStr);
        if ((ds2Port < 1) || (ds2Port > 65535))
        {
          ds2Available = false;
          if (ds2Port != -1)
          {
            err("WARNING:  The ds2.port property value must be between 1 and ",
                "65535.  Test cases that rely on LDAP communication with two ",
                "UnboundID Directory Server instances will only be able to ",
                "perform limited processing.");
          }
        }
      }
      catch (Exception e)
      {
        err("WARNING:  The ds2.port property value cannot be parsed as an ",
            "integer.  Test cases that rely on LDAP communication with two",
            "UnboundID Directory Server instances will only be able to ",
            "perform limited processing.");
        ds2Available = false;
      }
    }

    portStr = System.getProperty("ds2.ssl.port");
    if ((portStr != null) && (portStr.length() > 0))
    {
      try
      {
        ds2SSLPort = Integer.parseInt(portStr);
        if ((ds2SSLPort < 1) || (ds2SSLPort > 65535))
        {
          if (ds2SSLPort != -1)
          {
            err("WARNING:  The ds2.ssl.port property value must be between 1 ",
                "and 65535.  Test cases that rely on SSL-based LDAP ",
                "communication with two UnboundID Directory Server instances ",
                "will only be able to perform limited processing.");
            ds2SSLPort = -1;
          }
        }
      }
      catch (Exception e)
      {
        err("WARNING:  The ds2.ssl.port property value cannot be parsed as an ",
            "integer.  Test cases that rely on SSL-based LDAP communication ",
            "with two UnboundID Directory Server instances will only be able ",
            "to perform limited processing.");
        ds2SSLPort = -1;
      }
    }

    portStr = System.getProperty("dsee.port");
    if ((portStr == null) || (portStr.length() == 0))
    {
      dseeAvailable = false;
    }
    else
    {
      try
      {
        dseePort = Integer.parseInt(portStr);
        if ((dseePort < 1) || (dseePort > 65535))
        {
          dseeAvailable = false;
          if (dsPort != -1)
          {
            err("WARNING:  The dsee.port property value must be between 1 ",
                "and 65535.  Test cases that rely on LDAP communication with ",
                "a Sun DSEE instance will only be able to perform limited ",
                "processing.");
          }
        }
      }
      catch (Exception e)
      {
        err("WARNING:  The dsee.port property value cannot be parsed as an ",
            "integer.  Test cases that rely on LDAP communication with a Sun ",
            "DSEE instance will only be able to perform limited processing.");
        dseeAvailable = false;
      }
    }

    portStr = System.getProperty("dsee.ssl.port");
    if ((portStr != null) && (portStr.length() > 0))
    {
      try
      {
        dseeSSLPort = Integer.parseInt(portStr);
        if ((dseeSSLPort < 1) || (dseeSSLPort > 65535))
        {
          if (dseeSSLPort != -1)
          {
            err("WARNING:  The dsee.ssl.port property value must be between ",
                "1 and 65535.  Test cases that rely on SSL-based LDAP ",
                "communication with a Sun DSEE instance will only be able ",
                "to perform limited processing.");
            dseeSSLPort = -1;
          }
        }
      }
      catch (Exception e)
      {
        err("WARNING:  The dsee.ssl.port property value cannot be parsed as ",
            "an integer.  Test cases that rely on SSL-based LDAP ",
            "communication with a Sun DSEE instance will only be able to ",
            "perform limited processing.");
        dseeSSLPort = -1;
      }
    }

    dsBaseDN = System.getProperty("ds.basedn");
    if ((dsBaseDN == null) || (dsBaseDN.length() == 0))
    {
      dsAvailable   = false;
      dseeAvailable = false;
    }
    else
    {
      try
      {
        DN baseDN = new DN(dsBaseDN);
        RDN rdn = baseDN.getRDN();
        if (rdn.isMultiValued())
        {
          err("WARNING:  The ds.basedn property value contains a DN with a ",
              "multivalued RDN.  This is not supported for use in ",
              "LDAP-enabled test cases.  Test cases that rely on LDAP ",
              "communication with an UnboundID Directory Server or Sun DSEE ",
              "instance will only be able to perform limited processing.");
          dsAvailable   = false;
          dseeAvailable = false;
        }

        String attrName = rdn.getAttributeNames()[0];
        if (attrName.equalsIgnoreCase("dc"))
        {
          baseEntryAttributes = new Attribute[]
          {
            new Attribute("objectClass", "top", "domain"),
            new Attribute("dc", rdn.getAttributeValues()[0])
          };
        }
        else if (attrName.equalsIgnoreCase("o"))
        {
          baseEntryAttributes = new Attribute[]
          {
            new Attribute("objectClass", "top", "organization"),
            new Attribute("o", rdn.getAttributeValues()[0])
          };
        }
        else if (attrName.equalsIgnoreCase("ou"))
        {
          baseEntryAttributes = new Attribute[]
          {
            new Attribute("objectClass", "top", "organizationalUnit"),
            new Attribute("ou", rdn.getAttributeValues()[0])
          };
        }
        else
        {
          err("WARNING:  The ds.basedn property value contains a DN whose ",
              "RDN attribute (", attrName, ") is not supported for use in ",
              "LDAP-enabled test cases.  Only the dc, o, and ou attributes ",
              "are currently supported.  Test cases that rely on LDAP ",
              "communication with an UnboundID Directory Server or Sun DSEE ",
              "instance will only be able to perform limited processing.");
          dsAvailable   = false;
          dseeAvailable = false;
        }
      }
      catch (LDAPException le)
      {
        err("Unable to determine the test base DN and/or create the base ",
            "entry attributes:");
        le.printStackTrace();
        dsAvailable   = false;
        dseeAvailable = false;
      }
    }

    dsBindDN = System.getProperty("ds.binddn");
    if ((dsBindDN == null) || (dsBindDN.length() == 0))
    {
      dsAvailable   = false;
      dseeAvailable = false;
    }

    dsBindPassword = System.getProperty("ds.bindpw");
    if ((dsBindPassword == null) || (dsBindPassword.length() == 0))
    {
      dsAvailable   = false;
      dseeAvailable = false;
    }

    sslDSAvailable   = (dsAvailable && (dsSSLPort > 0));
    sslDSEEAvailable = (dseeAvailable && (dseeSSLPort > 0));

    if (! dsAvailable)
    {
      ds2Available = false;
      sslDS2Available = false;
    }
    else
    {
      sslDS2Available = (ds2Available && (ds2SSLPort > 0));
    }

    if (! (dsAvailable || dseeAvailable))
    {
      err();
      err();
      err("WARNING:  No UnboundID Directory Server or Sun DSEE instance is");
      err("          available for use by tests that rely on LDAP");
      err("          communication.  An instance may be made available by");
      err("          defining the following system properties:");
      err("ds.host       -- The address of the UnboundID DS instance");
      err("ds.port       -- The port of the UnboundID DS instance");
      err("ds.ssl.port   -- The SSL-enabled port of the UnboundID DS instance");
      err("ds2.host      -- The address of a second UnboundID DS instance");
      err("ds2.port      -- The port of a second UnboundID DS instance");
      err("ds2.ssl.port  -- The SSL-enabled port of a second UnboundID DS " +
           "instance");
      err("dsee.host     -- The address of the Sun DSEE instance");
      err("dsee.port     -- The port of the Sun DSEE instance");
      err("dsee.ssl.port -- The SSL-enabled port of the Sun DSEE instance");
      err("ds.basedn     -- The base DN for the UnboundID or DSEE instance");
      err("ds.binddn     -- The DN of a server admin user");
      err("ds.bindpw     -- The password for the admin user");
      err();
      err("At least the ds.port property must be specified to be able to");
      err("run tests which require communication with an UnboundID Directory");
      err("Server instance.  At least the ds2.port property must be specified");
      err("to be able to run tests which require communication with two");
      err("UnboundID Directory Server instances.  At least the dsee.port");
      err("property must be specified to be able to run tests which require");
      err("communication with a Sun/Oracle DSEE instance.  In any case, if an");
      err("SSL port is provided then that server instance should also be");
      err("configured to allow StartTLS communication on the non-SSL port.");
      err();
      err();
    }
  }



  /**
   * Creates the in-memory directory server instance that can be used for
   * testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeSuite()
  public static synchronized void setUpTestSuite()
         throws Exception
  {
    if (testDS != null)
    {
      return;
    }

    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.addAdditionalBindCredentials("cn=Manager", "password");
    cfg.setSchema(Schema.getDefaultStandardSchema());
    cfg.setListenerExceptionHandler(
         new StandardErrorListenerExceptionHandler());

    testDS = new InMemoryDirectoryServer(cfg);
    testDS.startListening();


    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore   = new File(resourceDir, "server.keystore");

    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustAllTrustManager());
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());

    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));

    testDSWithSSL = new InMemoryDirectoryServer(cfg);
    testDSWithSSL.startListening();
  }



  /**
   * Cleans up after all tests in the suite have completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterSuite()
  public static synchronized void cleanUpTestSuite()
         throws Exception
  {
    if (testDS != null)
    {
      testDS.shutDown(true);
      testDS = null;
    }

    if (testDSWithSSL != null)
    {
      testDSWithSSL.shutDown(true);
      testDSWithSSL = null;
    }

    assertEquals(LDAPConnectionInternals.getActiveConnectionCount(), 0L,
         "At least one test seems to have left connections established.");
  }



  /**
   * Retrieves an in-memory directory server instance that can be used for
   * testing purposes.  It will be started, but will not have any data.  It
   * will allow base DNs of "dc=example,dc=com" and "o=example.com" and will
   * have an additional bind DN of "cn=Directory Manager" with a password of
   * "password".  It will be listening on an automatically-selected port.
   *
   * @return  An empty in-memory directory server instance that may be used for
   *          testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static InMemoryDirectoryServer getTestDS()
            throws Exception
  {
    return getTestDS(false, false);
  }



  /**
   * Retrieves an in-memory directory server instance that can be used for
   * testing purposes.  It will be started, and may optionally contain a basic
   * set of entries.
   *
   * @param  addBaseEntry  Indicates whether to add the "dc=example,dc=com"
   *                       entry.  If this is {@code false}, then the server
   *                       instance returned will be empty.
   * @param  addUserEntry  Indicates whether to add
   *                       "ou=People,dc=example,dc=com" and
   *                       "uid=test.user,ou=People,dc=example,dc=com" entries.
   *                       This will only be used if {@code addBaseEntry} is
   *                       {@code true}.
   *
   * @return  An in-memory directory server instance that may be used for
   *          testing, optionally populated with test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static synchronized InMemoryDirectoryServer
                                     getTestDS(final boolean addBaseEntry,
                                               final boolean addUserEntry)
            throws Exception
  {
    testDS.clear();

    if (addBaseEntry)
    {
      testDS.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      if (addUserEntry)
      {
        testDS.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

        testDS.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");
      }
    }

    return testDS;
  }



  /**
   * Retrieves an in-memory directory server instance that can be used for
   * testing purposes.  It will be started, but will not have any data.  It
   * will allow base DNs of "dc=example,dc=com" and "o=example.com" and will
   * have an additional bind DN of "cn=Directory Manager" with a password of
   * "password".  It will be listening on an automatically-selected port.
   *
   * @return  An empty in-memory directory server instance that may be used for
   *          testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static InMemoryDirectoryServer getTestDSWithSSL()
            throws Exception
  {
    return getTestDSWithSSL(false, false);
  }



  /**
   * Retrieves an in-memory directory server instance that can be used for
   * testing purposes.  It will be started, and may optionally contain a basic
   * set of entries.
   *
   * @param  addBaseEntry  Indicates whether to add the "dc=example,dc=com"
   *                       entry.  If this is {@code false}, then the server
   *                       instance returned will be empty.
   * @param  addUserEntry  Indicates whether to add
   *                       "ou=People,dc=example,dc=com" and
   *                       "uid=test.user,ou=People,dc=example,dc=com" entries.
   *                       This will only be used if {@code addBaseEntry} is
   *                       {@code true}.
   *
   * @return  An in-memory directory server instance that may be used for
   *          testing, optionally populated with test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static synchronized InMemoryDirectoryServer
                        getTestDSWithSSL(final boolean addBaseEntry,
                                         final boolean addUserEntry)
            throws Exception
  {
    testDSWithSSL.clear();

    if (addBaseEntry)
    {
      testDSWithSSL.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");

      if (addUserEntry)
      {
        testDSWithSSL.add(
             "dn: ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: People");

        testDSWithSSL.add(
             "dn: uid=test.user,ou=People,dc=example,dc=com",
             "objectClass: top",
             "objectClass: person",
             "objectClass: organizationalPerson",
             "objectClass: inetOrgPerson",
             "uid: test.user",
             "givenName: Test",
             "sn: User",
             "cn: Test User",
             "userPassword: password");
      }
    }

    return testDSWithSSL;
  }



  /**
   * Indicates whether an UnboundID Directory Server instance is available for
   * use in testing.
   *
   * @return  {@code true} if an UnboundID Directory Server instance is
   *          available for use in testing, or {@code false} if not.
   */
  protected static boolean isDirectoryInstanceAvailable()
  {
    return dsAvailable;
  }



  /**
   * Indicates whether an SSL-enabled UnboundID Directory Server instance is
   * available for use in testing.
   *
   * @return  {@code true} if an SSL-enabled UnboundID Directory Server
   *          instance is available for use in testing, or {@code false} if not.
   */
  protected static boolean isSSLEnabledDirectoryInstanceAvailable()
  {
    return sslDSAvailable;
  }



  /**
   * Retrieves the address of the UnboundID Directory Server instance that can
   * be used for testing.  Note that the {@code isDirectoryInstanceAvailable}
   * method should first be called to ensure that an UnboundID Directory Server
   * instance is available for testing.
   *
   * @return  The address of the UnboundID Directory Server instance that can be
   *          used for testing.
   */
  @Nullable()
  protected static String getTestHost()
  {
    return dsHost;
  }



  /**
   * Retrieves the port of the UnboundID Directory Server instance that can be
   * used for testing.  Note that the {@code isDirectoryInstanceAvailable}
   * method should first be called to ensure that an UnboundID Directory Server
   * instance is available for testing.
   *
   * @return  The port of the UnboundID Directory Server instance that can be
   *          used for testing.
   */
  protected static int getTestPort()
  {
    return dsPort;
  }



  /**
   * Retrieves the SSL-enabled port of the UnboundID Directory Server instance
   * that can be used for testing.  Note that the
   * {@code isSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that an UnboundID Directory Server instance is available
   * for testing.
   *
   * @return  The SSL-enabled port of the UnboundID Directory Server instance
   *          that can be used for testing.
   */
  protected static int getTestSSLPort()
  {
    return dsSSLPort;
  }



  /**
   * Indicates whether two UnboundID Directory Server instances are available
   * for use in testing.
   *
   * @return  {@code true} if two UnboundID Directory Server instances are
   *          available for use in testing, or {@code false} if not.
   */
  protected static boolean isSecondDirectoryInstanceAvailable()
  {
    return ds2Available;
  }



  /**
   * Indicates whether two SSL-enabled UnboundID Directory Server instances are
   * available for use in testing.
   *
   * @return  {@code true} if two SSL-enabled UnboundID Directory Server
   *          instances are available for use in testing, or {@code false} if
   *          not.
   */
  protected static boolean isSecondSSLEnabledDirectoryInstanceAvailable()
  {
    return sslDS2Available;
  }



  /**
   * Retrieves the address of the second UnboundID Directory Server instance
   * that can be used for testing.  Note that the
   * {@code isSecondDirectoryInstanceAvailable} method should first be called to
   * ensure that a second UnboundID Directory Server instance is available for
   * testing.
   *
   * @return  The address of a second UnboundID Directory Server instance that
   *          can be used for testing.
   */
  @Nullable()
  protected static String getSecondTestHost()
  {
    return ds2Host;
  }



  /**
   * Retrieves the port of a second UnboundID Directory Server instance that can
   * be used for testing.  Note that the
   * {@code isSecondDirectoryInstanceAvailable} method should first be called to
   * ensure that a second UnboundID Directory Server instance is available for
   * testing.
   *
   * @return  The port of a second UnboundID Directory Server instance that can
   *          be used for testing.
   */
  protected static int getSecondTestPort()
  {
    return ds2Port;
  }



  /**
   * Retrieves the SSL-enabled port of a second UnboundID Directory Server
   * instance that can be used for testing.  Note that the
   * {@code isSecondSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that a second UnboundID Directory Server instance is
   * available for testing.
   *
   * @return  The SSL-enabled port of a second UnboundID Directory Server
   *          instance that can be used for testing.
   */
  protected static int getSecondTestSSLPort()
  {
    return ds2SSLPort;
  }



  /**
   * Indicates whether a Sun DSEE instance is available for use in testing.
   *
   * @return  {@code true} if a Sun DSEE instance is available for use in
   *          testing, or {@code false} if not.
   */
  protected static boolean isDSEEInstanceAvailable()
  {
    return dseeAvailable;
  }



  /**
   * Indicates whether an SSL-enabled Sun DSEE instance is available for use in
   * testing.
   *
   * @return  {@code true} if an SSL-enabled Sun DSEE instance is available for
   *          use in testing, or {@code false} if not.
   */
  protected static boolean isSSLEnabledDSEEInstanceAvailable()
  {
    return sslDSEEAvailable;
  }



  /**
   * Retrieves the address of the Sun DSEE instance that can be used for
   * testing.  Note that the {@code isDSEEInstanceAvailable} method should first
   * be called to ensure that a Sun DSEE instance is available for testing.
   *
   * @return  The address of the Sun DSEE instance that can be used for testing.
   */
  @Nullable()
  protected static String getTestDSEEHost()
  {
    return dseeHost;
  }



  /**
   * Retrieves the port of the Sun DSEE instance that can be used for testing.
   * Note that the {@code isDSEEInstanceAvailable} method should first be called
   * to ensure that a Sun DSEE instance is available for testing.
   *
   * @return  The port of the Sun DSEE instance that can be used for testing.
   */
  protected static int getTestDSEEPort()
  {
    return dseePort;
  }



  /**
   * Retrieves the SSL-enabled port of the Sun DSEE instance that can be used
   * for testing.  Note that the {@code isSSLEnabledDSEEInstanceAvailable}
   * method should first be called to ensure that a Sun DSEE instance is
   * available for testing.
   *
   * @return  The SSL-enabled port of the Sun DSEE instance that can be used for
   *          testing.
   */
  protected static int getTestDSEESSLPort()
  {
    return dseeSSLPort;
  }



  /**
   * Retrieves the base DN of the Directory Server instance that can be used for
   * testing.  Note that the {@code isDirectoryInstanceAvailable} method should
   * first be called to ensure that a Directory Server instance is available for
   * testing.
   *
   * @return  The base DN of the Directory Server instance that can be used for
   *          testing.
   */
  @Nullable()
  protected static String getTestBaseDN()
  {
    return dsBaseDN;
  }



  /**
   * Retrieves the DN of an administrative user in the Directory Server instance
   * that can be used for testing.  Note that the
   * {@code isDirectoryInstanceAvailable} method should first be called to
   * ensure that a Directory Server instance is available for testing.
   *
   * @return  The DN of an administrative user in the Directory Server instance
   *          that can be used for testing.
   */
  @Nullable()
  protected static String getTestBindDN()
  {
    return dsBindDN;
  }



  /**
   * Retrieves the password for the administrative user in the Directory Server
   * instance.  Note that the {@code isDirectoryInstanceAvailable} method should
   * first be called to ensure that a Directory Server instance is available for
   * testing.
   *
   * @return  The password for the administrative user in the Directory Server
   *          instance.
   */
  @Nullable()
  protected static String getTestBindPassword()
  {
    return dsBindPassword;
  }



  /**
   * Retrieves a connection that is established to the UnboundID Directory
   * Server instance without having performed any authentication on that
   * connection.  Note that the {@code isDirectoryInstanceAvailable} method
   * should first be called to ensure that an UnboundID Directory Server
   * instance is available for testing.
   *
   * @return  An unauthenticated connection established to the UnboundID
   *          Directory Server instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         connection to the UnboundID Directory Server
   *                         instance.
   */
  @NotNull()
  protected static LDAPConnection getUnauthenticatedConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dsHost, dsPort);
    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a connection that is established to the UnboundID Directory
   * Server instance and bound as the administrative user.  Note that the
   * {@code isDirectoryInstanceAvailable} method should first be called to
   * ensure that an UnboundID Directory Server instance is available for
   * testing.
   *
   * @return  A connection established to the UnboundID Directory Server
   *          instance and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         connection to the UnboundID Directory Server
   *                         instance.
   */
  @NotNull()
  protected static LDAPConnection getAdminConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dsHost, dsPort, dsBindDN,
                                             dsBindPassword);
    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves an SSL-based connection that is established to the
   * UnboundID Directory Server instance without having performed any
   * authentication on that connection.  Note that the
   * {@code isSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that an SSL-enabled UnboundID Directory Server instance is
   * available for testing.
   *
   * @return  An unauthenticated SSL-based connection established to the
   *          UnboundID Directory Server instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         SSL-based connection to the UnboundID Directory
   *                         Server instance.
   */
  @NotNull()
  protected static LDAPConnection getSSLUnauthenticatedConnection()
            throws LDAPException
  {
    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory(),
                                               dsHost, dsSSLPort);

      connMap.put(conn, Thread.currentThread().getStackTrace());
      return conn;
    }
    catch (GeneralSecurityException gse)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }
  }



  /**
   * Retrieves an SSL-based connection that is established to the UnboundID
   * Directory Server instance and bound as the administrative user.  Note that
   * the {@code isSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that an SSL-enabled UnboundID Directory Server instance is
   * available for testing.
   *
   * @return  A SSL-based connection established to the UnboundID Directory
   *          Server instance and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         SSL-based connection to the UnboundID Directory
   *                         Server instance.
   */
  @NotNull()
  protected static LDAPConnection getSSLAdminConnection()
            throws LDAPException
  {
    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory(),
           dsHost, dsSSLPort, dsBindDN, dsBindPassword);

      connMap.put(conn, Thread.currentThread().getStackTrace());
      return conn;
    }
    catch (GeneralSecurityException gse)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }
  }



  /**
   * Retrieves a StartTLS-based connection that is established to the
   * UnboundID Directory Server instance without having performed any
   * authentication on that connection.  Note that the
   * {@code isSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that an SSL-enabled UnboundID Directory Server instance is
   * available for testing.
   *
   * @return  An unauthenticated StartTLS-based connection established to the
   *          UnboundID Directory Server instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         StartTLS-based connection to the UnboundID
   *                         Directory Server instance.
   */
  @NotNull()
  protected static LDAPConnection getStartTLSUnauthenticatedConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dsHost, dsPort);

    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      ExtendedResult r = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      if (! r.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(r);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
    catch (GeneralSecurityException gse)
    {
      conn.close();
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }

    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a StartTLS-based connection that is established to the UnboundID
   * Directory Server instance and bound as the administrative user.  Note that
   * the {@code isSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that an SSL-enabled UnboundID Directory Server instance is
   * available for testing.
   *
   * @return  A StartTLS-based connection established to the UnboundID Directory
   *          Server instance and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         StartTLS-based connection to the UnboundID
   *                         Directory Server instance.
   */
  @NotNull()
  protected static LDAPConnection getStartTLSAdminConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dsHost, dsPort);

    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      ExtendedResult startTLSResult = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      if (! startTLSResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(startTLSResult);
      }

      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      if (! bindResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(bindResult);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
    catch (GeneralSecurityException gse)
    {
      conn.close();
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }

    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a connection that is established to the second UnboundID
   * Directory Server instance without having performed any authentication on
   * that connection.  Note that the {@code isSecondDirectoryInstanceAvailable}
   * method should first be called to ensure that a second UnboundID Directory
   * Server instance is available for testing.
   *
   * @return  An unauthenticated connection established to the second UnboundID
   *          Directory Server instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         connection to the second UnboundID Directory Server
   *                         instance.
   */
  @NotNull()
  protected static LDAPConnection getSecondUnauthenticatedConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(ds2Host, ds2Port);
    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a connection that is established to the second UnboundID
   * Directory Server instance and bound as the administrative user.  Note that
   * the {@code isSecondDirectoryInstanceAvailable} method should first be
   * called to ensure that a second UnboundID Directory Server instance is
   * available for testing.
   *
   * @return  A connection established to the second UnboundID Directory Server
   *          instance and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         connection to the second UnboundID Directory Server
   *                         instance.
   */
  @NotNull()
  protected static LDAPConnection getSecondAdminConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(ds2Host, ds2Port, dsBindDN,
                                             dsBindPassword);
    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves an SSL-based connection that is established to the second
   * UnboundID Directory Server instance without having performed any
   * authentication on that connection.  Note that the
   * {@code isSecondSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that a second SSL-enabled UnboundID Directory Server
   * instance is available for testing.
   *
   * @return  An unauthenticated SSL-based connection established to the second
   *          UnboundID Directory Server instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         SSL-based connection to the second UnboundID
   *                         Directory Server instance.
   */
  @NotNull()
  protected static LDAPConnection getSecondSSLUnauthenticatedConnection()
            throws LDAPException
  {
    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory(),
                                               ds2Host, ds2SSLPort);

      connMap.put(conn, Thread.currentThread().getStackTrace());
      return conn;
    }
    catch (GeneralSecurityException gse)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }
  }



  /**
   * Retrieves an SSL-based connection that is established to the second
   * UnboundID Directory Server instance and bound as the administrative user.
   * Note that the {@code isSecondSSLEnabledDirectoryInstanceAvailable} method
   * should first be called to ensure that a second SSL-enabled UnboundID
   * Directory Server instance is available for testing.
   *
   * @return  A SSL-based connection established to the second UnboundID
   *          Directory Server instance and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         SSL-based connection to the second UnboundID
   *                         Directory Server instance.
   */
  @NotNull()
  protected static LDAPConnection getSecondSSLAdminConnection()
            throws LDAPException
  {
    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory(),
           ds2Host, ds2SSLPort, dsBindDN, dsBindPassword);

      connMap.put(conn, Thread.currentThread().getStackTrace());
      return conn;
    }
    catch (GeneralSecurityException gse)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }
  }



  /**
   * Retrieves a StartTLS-based connection that is established to the second
   * UnboundID Directory Server instance without having performed any
   * authentication on that connection.  Note that the
   * {@code isSecondSSLEnabledDirectoryInstanceAvailable} method should first be
   * called to ensure that a second SSL-enabled UnboundID Directory Server
   * instance is available for testing.
   *
   * @return  An unauthenticated StartTLS-based connection established to the
   *          second UnboundID Directory Server instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         StartTLS-based connection to the second UnboundID
   *                         Directory Server instance.
   */
  @NotNull()
  protected static LDAPConnection getSecondStartTLSUnauthenticatedConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(ds2Host, ds2Port);

    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      ExtendedResult r = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      if (! r.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(r);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
    catch (GeneralSecurityException gse)
    {
      conn.close();
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }

    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a StartTLS-based connection that is established to the second
   * UnboundID Directory Server instance and bound as the administrative user.
   * Note that the {@code isSecondSSLEnabledDirectoryInstanceAvailable} method
   * should first be called to ensure that a second SSL-enabled UnboundID
   * Directory Server instance is available for testing.
   *
   * @return  A StartTLS-based connection established to the second UnboundID
   *          Directory Server instance and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         StartTLS-based connection to the second UnboundID
   *                         Directory Server instance.
   */
  @NotNull()
  protected static LDAPConnection getSecondStartTLSAdminConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(ds2Host, ds2Port);

    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      ExtendedResult startTLSResult = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      if (! startTLSResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(startTLSResult);
      }

      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      if (! bindResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(bindResult);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
    catch (GeneralSecurityException gse)
    {
      conn.close();
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }

    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a connection that is established to the Sun DSEE instance without
   * having performed any authentication on that connection.  Note that the
   * {@code isDSEEInstanceAvailable} method should first be called to ensure
   * that a Sun DSEE instance is available for testing.
   *
   * @return  An unauthenticated connection established to the Sun DSEE
   *          instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         connection to the Sun DSEE instance.
   */
  @NotNull()
  protected static LDAPConnection getUnauthenticatedDSEEConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dseeHost, dseePort);
    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a connection that is established to the Sun DSEE instance and
   * bound as the administrative user.  Note that the
   * {@code isDSEEInstanceAvailable} method should first be called to ensure
   * that a Sun DSEE instance is available for testing.
   *
   * @return  A connection established to the Sun DSEE instance and bound as the
   *          administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         connection to the Sun DSEE instance.
   */
  @NotNull()
  protected static LDAPConnection getAdminDSEEConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dseeHost, dseePort, dsBindDN,
                                             dsBindPassword);
    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves an SSL-based connection that is established to the Sun DSEE
   * instance without having performed any authentication on that connection.
   * Note that the {@code isSSLEnabledDSEEInstanceAvailable} method should first
   * be called to ensure that an SSL-enabled Sun DSEE instance is available for
   * testing.
   *
   * @return  An unauthenticated SSL-based connection established to the Sun
   *          DSEE instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         SSL-based connection to the Sun DSEE instance.
   */
  @NotNull()
  protected static LDAPConnection getSSLUnauthenticatedDSEEConnection()
            throws LDAPException
  {
    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    try
    {
      LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory(),
                                               dseeHost, dseeSSLPort);

      connMap.put(conn, Thread.currentThread().getStackTrace());
      return conn;
    }
    catch (GeneralSecurityException gse)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }
  }



  /**
   * Retrieves an SSL-based connection that is established to the Sun DSEE
   * instance and bound as the administrative user.  Note that the
   * {@code isSSLEnabledDSEEInstanceAvailable} method should first be called to
   * ensure that an SSL-enabled Sun DSEE instance is available for testing.
   *
   * @return  A SSL-based connection established to the Sun DSEE instance and
   *          bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         SSL-based connection to the Sun DSEE instance.
   */
  @NotNull()
  protected static LDAPConnection getSSLAdminDSEEConnection()
            throws LDAPException
  {
    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());

    try
    {
      LDAPConnection conn = new LDAPConnection(sslUtil.createSSLSocketFactory(),
           dseeHost, dseeSSLPort, dsBindDN, dsBindPassword);

      connMap.put(conn, Thread.currentThread().getStackTrace());
      return conn;
    }
    catch (GeneralSecurityException gse)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }
  }



  /**
   * Retrieves a StartTLS-based connection that is established to the Sun DSEE
   * instance without having performed any authentication on that connection.
   * Note that the {@code isSSLEnabledDSEEInstanceAvailable} method should first
   * be called to ensure that an SSL-enabled Sun DSEE instance is available for
   * testing.
   *
   * @return  An unauthenticated StartTLS-based connection established to the
   *          Sun DSEE instance.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         StartTLS-based connection to the Sun DSEE instance.
   */
  @NotNull()
  protected static LDAPConnection getStartTLSUnauthenticatedDSEEConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dseeHost, dseePort);

    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      ExtendedResult r = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      if (! r.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(r);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
    catch (GeneralSecurityException gse)
    {
      conn.close();
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }

    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Retrieves a StartTLS-based connection that is established to the Sun DSEE
   * instance and bound as the administrative user.  Note that the
   * {@code isSSLEnabledDSEEInstanceAvailable} method should first be called to
   * ensure that an SSL-enabled Sun DSEE instance is available for testing.
   *
   * @return  A StartTLS-based connection established to the SunDSEE instance
   *          and bound as the administrative user.
   *
   * @throws  LDAPException  If an error occurs while attempting to obtain the
   *                         StartTLS-based connection to the Sun DSEE instance.
   */
  @NotNull()
  protected static LDAPConnection getStartTLSAdminDSEEConnection()
            throws LDAPException
  {
    LDAPConnection conn = new LDAPConnection(dseeHost, dseePort);

    try
    {
      SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
      ExtendedResult startTLSResult = conn.processExtendedOperation(
           new StartTLSExtendedRequest(sslUtil.createSSLContext()));
      if (! startTLSResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(startTLSResult);
      }

      BindResult bindResult = conn.bind(getTestBindDN(), getTestBindPassword());
      if (! bindResult.getResultCode().equals(ResultCode.SUCCESS))
      {
        throw new LDAPException(bindResult);
      }
    }
    catch (LDAPException le)
    {
      conn.close();
      throw le;
    }
    catch (GeneralSecurityException gse)
    {
      conn.close();
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to initialize the SSL socket factory:  " +
                getExceptionMessage(gse),
           gse);
    }

    connMap.put(conn, Thread.currentThread().getStackTrace());
    return conn;
  }



  /**
   * Indicates whether there were any connections created by this class that
   * have not been closed.  Those connections will be closed, and the list of
   * created connections will be cleared.
   *
   * @return  {@code true} if any connections were created by this class that
   *          had not been closed, or {@code false} if not.
   */
  @NotNull()
  public static List<StackTraceElement[]> getUnclosedConnectionTraces()
  {
    LinkedList<StackTraceElement[]> connList =
         new LinkedList<StackTraceElement[]>();

    for (LDAPConnection conn : connMap.keySet())
    {
      if (conn.isConnected())
      {
        connList.add(connMap.get(conn));
        conn.close();
      }
    }

    connMap.clear();
    return connList;
  }



  /**
   * Retrieves a set of attributes that may be used to create the base entry in
   * the Directory Server instance.
   *
   * @return  A set of attributes that may be used to create the base entry in
   *          the DirectoryServer instance.
   */
  @NotNull()
  protected static Attribute[] getBaseEntryAttributes()
  {
    return baseEntryAttributes;
  }



  /**
   * Creates and returns a handle to an empty temporary file.  It will be marked
   * for deletion when the JVM exits.
   *
   * @return  A handle to the temporary file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static File createTempFile()
            throws Exception
  {
    File f = File.createTempFile("ldapsdk-", ".tmp");
    f.deleteOnExit();
    return f;
  }



  /**
   * Creates and returns a handle to an empty temporary file with the specified
   * lines.  It will be marked for deletion when the JVM exits.
   *
   * @param  lines  The set of lines to include in the file that is created.
   *
   * @return  A handle to the temporary file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static File createTempFile(@NotNull String... lines)
            throws Exception
  {
    File f = File.createTempFile("ldapsdk-", ".tmp");
    f.deleteOnExit();

    if (lines.length > 0)
    {
      BufferedWriter w = new BufferedWriter(new FileWriter(f));
      try
      {
        for (String line : lines)
        {
          w.write(line);
          w.newLine();
        }
      }
      finally
      {
        w.close();
      }
    }

    return f;
  }



  /**
   * Creates and returns a handle to an empty directory in a temporary working
   * space.  It will not automatically be cleaned up when the JVM exits, but
   * should be cleaned when the build process is re-started.
   *
   * @return  A handle to the directory that was created.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @NotNull()
  protected static File createTempDir()
            throws Exception
  {
    final File f = File.createTempFile("ldapsdk-", ".tmp");
    assertTrue(f.delete());
    assertTrue(f.mkdir());
    return f;
  }



  /**
   * Deletes the specified file.  If the provided file is a directory, then all
   * of the files and directories that it contains will be removed as well.
   *
   * @param  f  The reference to the file or directory to delete.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  protected static void delete(@NotNull File f)
            throws Exception
  {
    if (f.isDirectory())
    {
      for (File subFile : f.listFiles())
      {
        delete(subFile);
      }
    }

    f.delete();
  }



  /**
   * Reads the bytes that comprise the specified file.
   *
   * @param  f  The file to be read.
   *
   * @return  The bytes that comprise the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static byte[] readFileBytes(@NotNull final File f)
            throws Exception
  {
    try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
         FileInputStream inputStream = new FileInputStream(f))
    {
      final byte[] buffer = new byte[8192];
      while (true)
      {
        final int bytesRead = inputStream.read(buffer);
        if (bytesRead < 0)
        {
          return outputStream.toByteArray();
        }

        outputStream.write(buffer, 0, bytesRead);
      }
    }
  }



  /**
   * Reads the lines of the specified file into a list.
   *
   * @param  f  The file to be read.
   *
   * @return  A list of the lines read from the specified file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @NotNull()
  protected static List<String> readFileLines(@NotNull final File f)
            throws Exception
  {
    final List<String> lines = new ArrayList<>(100);
    try (FileReader fileReader = new FileReader(f);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }

        lines.add(line);
      }
    }

    return lines;
  }



  /**
   * Writes the provided content to standard output.  The string representations
   * of the provided objects will be concatenated, and it will be terminated
   * with a line separator.
   *
   * @param  content  The objects that comprise content to be written.
   */
  protected static void out(@NotNull final Object... content)
  {
    for (Object o : content)
    {
      System.out.print(String.valueOf(o));
    }
    System.out.println();
  }



  /**
   * Writes the provided content to standard error.  The string representations
   * of the provided objects will be concatenated, and it will be terminated
   * with a line separator.
   *
   * @param  content  The objects that comprise content to be written.
   */
  protected static void err(@NotNull final Object... content)
  {
    for (Object o : content)
    {
      System.err.print(String.valueOf(o));
    }
    System.err.println();
  }



  /**
   * Calculates an MD5 digest for the contents of the specified file.
   *
   * @param  f  The file for which to retrieve the MD5 digest.
   *
   * @return  The MD5 digest for the requested file.
   *
   * @throws  Exception  If a problem occurs while attempting to compute the MD5
   *                     digest for the specified file.
   */
  @NotNull()
  protected static byte[] getMD5Digest(@NotNull final File f)
            throws Exception
  {

    final FileInputStream inputStream = new FileInputStream(f);

    try
    {
      final MessageDigest md5 = CryptoHelper.getMessageDigest("MD5");
      final byte[] buffer = new byte[8192];

      while (true)
      {
        final int bytesRead = inputStream.read(buffer);
        if (bytesRead < 0)
        {
          break;
        }
        else
        {
          md5.update(buffer, 0, bytesRead);
        }
      }

      return md5.digest();
    }
    finally
    {
      inputStream.close();
    }
  }



  /**
   * Calculates an MD5 digest for the provided array.
   *
   * @param  b  The array for which to calculate the MD5 digest.
   *
   * @return  The MD5 digest for the provided array.
   *
   * @throws  Exception  If a problem occurs while attempting to compute the MD5
   *                     digest for the provided array.
   */
  @NotNull()
  protected static byte[] getMD5Digest(@NotNull final byte[] b)
            throws Exception
  {
    return CryptoHelper.getMessageDigest("MD5").digest(b);
  }



  /**
   * Generates a domain entry with the provided information.  It will include
   * the top and domain object classes and will use dc as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the domain, which will be used
   *                               as the value of the "dc" attribute.  It must
   *                               not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateDomainEntry(@NotNull final String name,
                              @Nullable final String parentDN,
                              @Nullable final Attribute... additionalAttributes)
  {
    return LDAPTestUtils.generateDomainEntry(name, parentDN,
         additionalAttributes);
  }



  /**
   * Generates a domain entry with the provided information.  It will include
   * the top and domain object classes and will use dc as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the domain, which will be used
   *                               as the value of the "dc" attribute.  It must
   *                               not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateDomainEntry(@NotNull final String name,
                 @Nullable final String parentDN,
                 @Nullable final Collection<Attribute> additionalAttributes)
  {
    return LDAPTestUtils.generateDomainEntry(name, parentDN,
         additionalAttributes);
  }



  /**
   * Generates an organization entry with the provided information.  It will
   * include the top and organization object classes and will use o as the RDN
   * attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organization, which will be
   *                               used as the value of the "o" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateOrgEntry(@NotNull final String name,
                              @Nullable final String parentDN,
                              @Nullable final Attribute... additionalAttributes)
  {
    return LDAPTestUtils.generateOrgEntry(name, parentDN, additionalAttributes);
  }



  /**
   * Generates an organization entry with the provided information.  It will
   * include the top and organization object classes and will use o as the RDN
   * attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organization, which will be
   *                               used as the value of the "o" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateOrgEntry(@NotNull final String name,
                 @Nullable final String parentDN,
                 @Nullable final Collection<Attribute> additionalAttributes)
  {
    return LDAPTestUtils.generateOrgEntry(name, parentDN, additionalAttributes);
  }



  /**
   * Generates an organizationalUnit entry with the provided information.  It
   * will include the top and organizationalUnit object classes and will use ou
   * as the RDN attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organizationalUnit, which
   *                               will be used as the value of the "ou"
   *                               attribute.  It must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateOrgUnitEntry(@NotNull final String name,
                              @Nullable final String parentDN,
                              @Nullable final Attribute... additionalAttributes)
  {
    return LDAPTestUtils.generateOrgUnitEntry(name, parentDN,
         additionalAttributes);
  }



  /**
   * Generates an organizationalUnit entry with the provided information.  It
   * will include the top and organizationalUnit object classes and will use ou
   * as the RDN attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organizationalUnit, which
   *                               will be used as the value of the "ou"
   *                               attribute.  It must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateOrgUnitEntry(@NotNull final String name,
                 @Nullable final String parentDN,
                 @Nullable final Collection<Attribute> additionalAttributes)
  {
    return LDAPTestUtils.generateOrgUnitEntry(name, parentDN,
         additionalAttributes);
  }



  /**
   * Generates a country entry with the provided information.  It will include
   * the top and country object classes and will use c as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the country (typically a
   *                               two-character country code), which will be
   *                               used as the value of the "c" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateCountryEntry(@NotNull final String name,
                              @Nullable final String parentDN,
                              @Nullable final Attribute... additionalAttributes)
  {
    return LDAPTestUtils.generateCountryEntry(name, parentDN,
         additionalAttributes);
  }



  /**
   * Generates a country entry with the provided information.  It will include
   * the top and country object classes and will use c as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the country (typically a
   *                               two-character country code), which will be
   *                               used as the value of the "c" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateCountryEntry(@NotNull final String name,
                 @Nullable final String parentDN,
                 @Nullable final Collection<Attribute> additionalAttributes)
  {
    return LDAPTestUtils.generateCountryEntry(name, parentDN,
         additionalAttributes);
  }



  /**
   * Generates a user entry with the provided information.  It will include the
   * top, person, organizationalPerson, and inetOrgPerson object classes, will
   * use uid as the RDN attribute, and will have givenName, sn, and cn
   * attributes.  It may optionally include additional attributes.
   *
   * @param  uid                   The value to use for the "uid: attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  firstName             The first name for the user.  It must not be
   *                               {@code null}.
   * @param  lastName              The last name for the user.  It must not be
   *                               {@code null}.
   * @param  password              The password for the user.  It may be
   *                               {@code null} if the user should not have a
   *                               password.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateUserEntry(@NotNull final String uid,
                              @Nullable final String parentDN,
                              @NotNull final String firstName,
                              @NotNull final String lastName,
                              @Nullable final String password,
                              @Nullable final Attribute... additionalAttributes)
  {
    return LDAPTestUtils.generateUserEntry(uid, parentDN, firstName, lastName,
         password, additionalAttributes);
  }



  /**
   * Generates a user entry with the provided information.  It will include the
   * top, person, organizationalPerson, and inetOrgPerson object classes, will
   * use uid as the RDN attribute, and will have givenName, sn, and cn
   * attributes.  It may optionally include additional attributes.
   *
   * @param  uid                   The value to use for the "uid: attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  firstName             The first name for the user.  It must not be
   *                               {@code null}.
   * @param  lastName              The last name for the user.  It must not be
   *                               {@code null}.
   * @param  password              The password for the user.  It may be
   *                               {@code null} if the user should not have a
   *                               password.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateUserEntry(@NotNull final String uid,
                 @Nullable final String parentDN,
                 @NotNull final String firstName,
                 @NotNull final String lastName,
                 @Nullable final String password,
                 @Nullable final Collection<Attribute> additionalAttributes)
  {
    return LDAPTestUtils.generateUserEntry(uid, parentDN, firstName, lastName,
         password, additionalAttributes);
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateGroupOfNamesEntry(@NotNull final String name,
                 @Nullable final String parentDN,
                 @NotNull final String... memberDNs)
  {
    return LDAPTestUtils.generateGroupOfNamesEntry(name, parentDN, memberDNs);
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateGroupOfNamesEntry(@NotNull final String name,
                              @Nullable final String parentDN,
                              @NotNull final Collection<String> memberDNs)
  {
    return LDAPTestUtils.generateGroupOfNamesEntry(name, parentDN, memberDNs);
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfUniqueNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateGroupOfUniqueNamesEntry(
                 @NotNull final String name,
                 @Nullable final String parentDN,
                 @NotNull final String... memberDNs)
  {
    return LDAPTestUtils.generateGroupOfUniqueNamesEntry(name, parentDN,
         memberDNs);
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfUniqueNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  protected static Entry generateGroupOfUniqueNamesEntry(
                 @NotNull final String name,
                 @Nullable final String parentDN,
                 @NotNull final Collection<String> memberDNs)
  {
    return LDAPTestUtils.generateGroupOfUniqueNamesEntry(name, parentDN,
         memberDNs);
  }



  /**
   * Indicates whether the specified entry exists in the server.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dn    The DN of the entry for which to make the determination.
   *
   * @return  {@code true} if the entry exists, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  protected static boolean entryExists(@NotNull final LDAPInterface conn,
                                       @NotNull final String dn)
            throws LDAPException
  {
    return LDAPTestUtils.entryExists(conn, dn);
  }



  /**
   * Indicates whether the specified entry exists in the server and matches the
   * given filter.
   *
   * @param  conn    The connection to use to communicate with the directory
   *                 server.
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  The filter the entry is expected to match.
   *
   * @return  {@code true} if the entry exists and matches the specified filter,
   *          or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  protected static boolean entryExists(@NotNull final LDAPInterface conn,
                                       @NotNull final String dn,
                                       @NotNull final String filter)
            throws LDAPException
  {
    return LDAPTestUtils.entryExists(conn, dn, filter);
  }



  /**
   * Indicates whether the specified entry exists in the server.  This will
   * return {@code true} only if the target entry exists and contains all values
   * for all attributes of the provided entry.  The entry will be allowed to
   * have attribute values not included in the provided entry.
   *
   * @param  conn   The connection to use to communicate with the directory
   *                server.
   * @param  entry  The entry to compare against the directory server.
   *
   * @return  {@code true} if the entry exists in the server and is a superset
   *          of the provided entry, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  protected static boolean entryExists(@NotNull final LDAPInterface conn,
                                       @NotNull final Entry entry)
            throws LDAPException
  {
    return LDAPTestUtils.entryExists(conn, entry);
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dn    The DN of the entry for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist.
   */
  protected static void assertEntryExists(@NotNull final LDAPInterface conn,
                                          @NotNull final String dn)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertEntryExists(conn, dn);
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  conn    The connection to use to communicate with the directory
   *                 server.
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  A filter that the target entry must match.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  protected static void assertEntryExists(@NotNull final LDAPInterface conn,
                                          @NotNull final String dn,
                                          @NotNull final String filter)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertEntryExists(conn, dn, filter);
  }



  /**
   * Ensures that an entry exists in the directory with the same DN and all
   * attribute values contained in the provided entry.  The server entry may
   * contain additional attributes and/or attribute values not included in the
   * provided entry.
   *
   * @param  conn   The connection to use to communicate with the directory
   *                server.
   * @param  entry  The entry expected to be present in the directory server.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  protected static void assertEntryExists(@NotNull final LDAPInterface conn,
                                          @NotNull final Entry entry)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertEntryExists(conn, entry);
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  protected static List<String> getMissingEntryDNs(
                 @NotNull final LDAPInterface conn,
                 @NotNull final String... dns)
            throws LDAPException
  {
    return LDAPTestUtils.getMissingEntryDNs(conn, dns);
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  protected static List<String> getMissingEntryDNs(
                 @NotNull final LDAPInterface conn,
                 @NotNull final Collection<String> dns)
            throws LDAPException
  {
    return LDAPTestUtils.getMissingEntryDNs(conn, dns);
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  protected static void assertEntriesExist(@NotNull final LDAPInterface conn,
                                           @NotNull final String... dns)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertEntriesExist(conn, dns);
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  protected static void assertEntriesExist(@NotNull final LDAPInterface conn,
                 @NotNull final Collection<String> dns)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertEntriesExist(conn, dns);
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  protected static List<String> getMissingAttributeNames(
                                     @NotNull final LDAPInterface conn,
                                     @NotNull final String dn,
                                     @NotNull final String... attributeNames)
            throws LDAPException
  {
    return LDAPTestUtils.getMissingAttributeNames(conn, dn, attributeNames);
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  protected static List<String> getMissingAttributeNames(
                 @NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final Collection<String> attributeNames)
            throws LDAPException
  {
    return LDAPTestUtils.getMissingAttributeNames(conn, dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  protected static void assertAttributeExists(@NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String... attributeNames)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertAttributeExists(conn, dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  protected static void assertAttributeExists(@NotNull final LDAPInterface conn,
                             @NotNull final String dn,
                             @NotNull final Collection<String> attributeNames)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertAttributeExists(conn, dn, attributeNames);
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  protected static List<String> getMissingAttributeValues(
                                     @NotNull final LDAPInterface conn,
                                     @NotNull final String dn,
                                     @NotNull final String attributeName,
                                     @NotNull final String... attributeValues)
            throws LDAPException
  {
    return LDAPTestUtils.getMissingAttributeValues(conn, dn, attributeName,
         attributeValues);
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.  The target attribute may or may not contain
   * additional values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  protected static List<String> getMissingAttributeValues(
                 @NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String attributeName,
                 @NotNull final Collection<String> attributeValues)
            throws LDAPException
  {
    return LDAPTestUtils.getMissingAttributeValues(conn, dn, attributeName,
         attributeValues);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  protected static void assertValueExists(@NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String attributeName,
                 @NotNull final String... attributeValues)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertValueExists(conn, dn, attributeName, attributeValues);
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  protected static void assertValueExists(@NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String attributeName,
                 @NotNull final Collection<String> attributeValues)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertValueExists(conn, dn, attributeName, attributeValues);
  }



  /**
   * Ensures that the specified entry does not exist in the directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dn    The DN of the entry expected to be missing.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is found in the server.
   */
  protected static void assertEntryMissing(@NotNull final LDAPInterface conn,
                                           @NotNull final String dn)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertEntryMissing(conn, dn);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  protected static void assertAttributeMissing(
                 @NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String... attributeNames)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertAttributeMissing(conn, dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  protected static void assertAttributeMissing(
                 @NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final Collection<String> attributeNames)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertAttributeMissing(conn, dn, attributeNames);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  protected static void assertValueMissing(@NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String attributeName,
                 @NotNull final String... attributeValues)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertValueMissing(conn, dn, attributeName, attributeValues);
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  protected static void assertValueMissing(@NotNull final LDAPInterface conn,
                 @NotNull final String dn,
                 @NotNull final String attributeName,
                 @NotNull final Collection<String> attributeValues)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertValueMissing(conn, dn, attributeName, attributeValues);
  }



  /**
   * Ensures that the result code for the provided result matches one of the
   * given acceptable result codes.
   *
   * @param  result                 The LDAP result to examine.
   * @param  acceptableResultCodes  The set of result codes that are considered
   *                                acceptable.
   *
   * @throws  AssertionError  If the result code from the provided result did
   *                          not match any of the acceptable values.
   */
  protected static void assertResultCodeEquals(@NotNull final LDAPResult result,
                 @NotNull final ResultCode... acceptableResultCodes)
            throws AssertionError
  {
    LDAPTestUtils.assertResultCodeEquals(result, acceptableResultCodes);
  }



  /**
   * Ensures that the result code for the provided LDAP exception matches one of
   * the given acceptable result codes.
   *
   * @param  exception              The LDAP exception to examine.
   * @param  acceptableResultCodes  The set of result codes that are considered
   *                                acceptable.
   *
   * @throws  AssertionError  If the result code from the provided exception did
   *                          not match any of the acceptable values.
   */
  protected static void assertResultCodeEquals(
                 @NotNull final LDAPException exception,
                 @NotNull final ResultCode... acceptableResultCodes)
            throws AssertionError
  {
    LDAPTestUtils.assertResultCodeEquals(exception, acceptableResultCodes);
  }



  /**
   * Processes the provided request using the given connection and ensures that
   * the result code matches one of the provided acceptable values.
   *
   * @param  conn                   The connection to use to communicate with
   *                                the directory server.
   * @param  request                The request to be processed.
   * @param  acceptableResultCodes  The set of result codes that are considered
   *                                acceptable.
   *
   * @return  The result returned from processing the requested operation.
   *
   * @throws  AssertionError  If the result code returned by the server did not
   *                          match any acceptable values.
   */
  @NotNull()
  protected static LDAPResult assertResultCodeEquals(
                 @NotNull final LDAPConnection conn,
                 @NotNull final LDAPRequest request,
                 @NotNull final ResultCode... acceptableResultCodes)
            throws AssertionError
  {
    return LDAPTestUtils.assertResultCodeEquals(conn, request,
         acceptableResultCodes);
  }



  /**
   * Ensures that the result code for the provided result does not match any of
   * the given unacceptable result codes.
   *
   * @param  result                   The LDAP result to examine.
   * @param  unacceptableResultCodes  The set of result codes that are
   *                                  considered unacceptable.
   *
   * @throws  AssertionError  If the result code from the provided result
   *                          matched any of the unacceptable values.
   */
  protected static void assertResultCodeNot(@NotNull final LDAPResult result,
                 @NotNull final ResultCode... unacceptableResultCodes)
            throws AssertionError
  {
    LDAPTestUtils.assertResultCodeNot(result, unacceptableResultCodes);
  }



  /**
   * Ensures that the result code for the provided result does not match any of
   * the given unacceptable result codes.
   *
   * @param  exception                The LDAP exception to examine.
   * @param  unacceptableResultCodes  The set of result codes that are
   *                                  considered unacceptable.
   *
   * @throws  AssertionError  If the result code from the provided result
   *                          matched any of the unacceptable values.
   */
  protected static void assertResultCodeNot(
                 @NotNull final LDAPException exception,
                 @NotNull final ResultCode... unacceptableResultCodes)
            throws AssertionError
  {
    LDAPTestUtils.assertResultCodeNot(exception, unacceptableResultCodes);
  }



  /**
   * Processes the provided request using the given connection and ensures that
   * the result code does not match any of the given unacceptable values.
   *
   * @param  conn                     The connection to use to communicate with
   *                                  the directory server.
   * @param  request                  The request to be processed.
   * @param  unacceptableResultCodes  The set of result codes that are
   *                                  considered unacceptable.
   *
   * @return  The result returned from processing the requested operation.
   *
   * @throws  AssertionError  If the result code from the provided result
   *                          matched any of the unacceptable values.
   */
  @NotNull()
  protected static LDAPResult assertResultCodeNot(
                 @NotNull final LDAPConnection conn,
                 @NotNull final LDAPRequest request,
                 @NotNull final ResultCode... unacceptableResultCodes)
            throws AssertionError
  {
    return LDAPTestUtils.assertResultCodeNot(conn, request,
         unacceptableResultCodes);
  }



  /**
   * Ensures that the provided LDAP result contains a matched DN value.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result did not contain a matched
   *                          DN value.
   */
  protected static void assertContainsMatchedDN(
                 @NotNull final LDAPResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertContainsMatchedDN(result);
  }



  /**
   * Ensures that the provided LDAP exception contains a matched DN value.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception did not contain a
   *                          matched DN value.
   */
  protected static void assertContainsMatchedDN(
                 @NotNull final LDAPException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertContainsMatchedDN(exception);
  }



  /**
   * Ensures that the provided LDAP result does not contain a matched DN value.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result contained a matched DN
   *                          value.
   */
  protected static void assertMissingMatchedDN(
                 @NotNull final LDAPResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingMatchedDN(result);
  }



  /**
   * Ensures that the provided LDAP exception does not contain a matched DN
   * value.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception contained a matched DN
   *                          value.
   */
  protected static void assertMissingMatchedDN(
                 @NotNull final LDAPException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingMatchedDN(exception);
  }



  /**
   * Ensures that the provided LDAP result has the given matched DN value.
   *
   * @param  result     The LDAP result to examine.
   * @param  matchedDN  The matched DN value expected to be found in the
   *                    provided result.  It must not be {@code null}.
   *
   * @throws  LDAPException  If either the found or expected matched DN values
   *                         could not be parsed as a valid DN.
   *
   * @throws  AssertionError  If the provided LDAP result did not contain a
   *                          matched DN, or if it had a matched DN that
   *                          differed from the expected value.
   */
  protected static void assertMatchedDNEquals(@NotNull final LDAPResult result,
                                              @NotNull final String matchedDN)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertMatchedDNEquals(result, matchedDN);
  }



  /**
   * Ensures that the provided LDAP exception has the given matched DN value.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  matchedDN  The matched DN value expected to be found in the
   *                    provided exception.  It must not be {@code null}.
   *
   * @throws  LDAPException  If either the found or expected matched DN values
   *                         could not be parsed as a valid DN.
   *
   * @throws  AssertionError  If the provided LDAP exception did not contain a
   *                          matched DN, or if it had a matched DN that
   *                          differed from the expected value.
   */
  protected static void assertMatchedDNEquals(
                 @NotNull final LDAPException exception,
                 @NotNull final String matchedDN)
            throws LDAPException, AssertionError
  {
    LDAPTestUtils.assertMatchedDNEquals(exception, matchedDN);
  }



  /**
   * Ensures that the provided LDAP result contains a diagnostic message.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result did not contain a
   *                          diagnostic message.
   */
  protected static void assertContainsDiagnosticMessage(
                 @NotNull final LDAPResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertContainsDiagnosticMessage(result);
  }



  /**
   * Ensures that the provided LDAP exception contains a diagnostic message.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception did not contain a
   *                          diagnostic message.
   */
  protected static void assertContainsDiagnosticMessage(
                             @NotNull final LDAPException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertContainsDiagnosticMessage(exception);
  }



  /**
   * Ensures that the provided LDAP result does not contain a diagnostic
   * message.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result contained a diagnostic
   *                          message.
   */
  protected static void assertMissingDiagnosticMessage(
                 @NotNull final LDAPResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingDiagnosticMessage(result);
  }



  /**
   * Ensures that the provided LDAP exception does not contain a diagnostic
   * message.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception contained a diagnostic
   *                          message.
   */
  protected static void assertMissingDiagnosticMessage(
                             @NotNull final LDAPException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingDiagnosticMessage(exception);
  }



  /**
   * Ensures that the provided LDAP result has the given diagnostic message.
   *
   * @param  result             The LDAP result to examine.
   * @param  diagnosticMessage  The diagnostic message expected to be found in
   *                            the provided result.  It must not be
   *                            {@code null}.
   *
   * @throws  AssertionError  If the provided LDAP result did not contain a
   *                          diagnostic message, or if it had a diagnostic
   *                          message that differed from the expected value.
   */
  protected static void assertDiagnosticMessageEquals(
                 @NotNull final LDAPResult result,
                 @NotNull final String diagnosticMessage)
            throws AssertionError
  {
    LDAPTestUtils.assertDiagnosticMessageEquals(result, diagnosticMessage);
  }



  /**
   * Ensures that the provided LDAP exception has the given diagnostic message.
   *
   * @param  exception          The LDAP exception to examine.
   * @param  diagnosticMessage  The diagnostic message expected to be found in
   *                            the provided exception.  It must not be
   *                            {@code null}.
   *
   * @throws  AssertionError  If the provided LDAP exception did not contain a
   *                          diagnostic message, or if it had a diagnostic
   *                          message that differed from the expected value.
   */
  protected static void assertDiagnosticMessageEquals(
                             @NotNull final LDAPException exception,
                             @NotNull final String diagnosticMessage)
            throws AssertionError
  {
    LDAPTestUtils.assertDiagnosticMessageEquals(exception, diagnosticMessage);
  }



  /**
   * Ensures that the provided LDAP result has one or more referral URLs.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result does not have any referral
   *                          URLs.
   */
  protected static void assertHasReferral(@NotNull final LDAPResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertHasReferral(result);
  }



  /**
   * Ensures that the provided LDAP exception has one or more referral URLs.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception does not have any
   *                          referral URLs.
   */
  protected static void assertHasReferral(
                 @NotNull final LDAPException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertHasReferral(exception);
  }



  /**
   * Ensures that the provided LDAP result does not have any referral URLs.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result has one or more referral
   *                          URLs.
   */
  protected static void assertMissingReferral(@NotNull final LDAPResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingReferral(result);
  }



  /**
   * Ensures that the provided LDAP exception does not have any referral URLs.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception has one or more referral
   *                          URLs.
   */
  protected static void assertMissingReferral(
                 @NotNull final LDAPException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingReferral(exception);
  }



  /**
   * Ensures that the provided LDAP result includes at least one control with
   * the specified OID.
   *
   * @param  result  The LDAP result to examine.
   * @param  oid     The OID of the control which is expected to be present in
   *                 the result.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided LDAP result does not include any
   *                          control with the specified OID.
   */
  @NotNull()
  protected static Control assertHasControl(@NotNull final LDAPResult result,
                                            @NotNull final String oid)
            throws AssertionError
  {
    return LDAPTestUtils.assertHasControl(result, oid);
  }



  /**
   * Ensures that the provided LDAP exception includes at least one control with
   * the specified OID.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  oid        The OID of the control which is expected to be present
   *                    in the exception.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided LDAP exception does not include
   *                          any control with the specified OID.
   */
  @NotNull()
  protected static Control assertHasControl(
                 @NotNull final LDAPException exception,
                 @NotNull final String oid)
            throws AssertionError
  {
    return LDAPTestUtils.assertHasControl(exception, oid);
  }



  /**
   * Ensures that the provided search result entry includes at least one control
   * with the specified OID.
   *
   * @param  entry  The search result entry to examine.
   * @param  oid    The OID of the control which is expected to be present in
   *                the search result entry.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided search result entry does not
   *                          include any control with the specified OID.
   */
  @NotNull()
  protected static Control assertHasControl(
                 @NotNull final SearchResultEntry entry,
                 @NotNull final String oid)
            throws AssertionError
  {
    return LDAPTestUtils.assertHasControl(entry, oid);
  }



  /**
   * Ensures that the provided search result reference includes at least one
   * control with the specified OID.
   *
   * @param  reference  The search result reference to examine.
   * @param  oid        The OID of the control which is expected to be present
   *                    in the search result reference.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided search result reference does not
   *                          include any control with the specified OID.
   */
  @NotNull()
  protected static Control assertHasControl(
                 @NotNull final SearchResultReference reference,
                 @NotNull final String oid)
            throws AssertionError
  {
    return LDAPTestUtils.assertHasControl(reference, oid);
  }



  /**
   * Ensures that the provided LDAP result does not include any control with
   * the specified OID.
   *
   * @param  result  The LDAP result to examine.
   * @param  oid     The OID of the control which is not expected to be present
   *                 in the result.
   *
   * @throws  AssertionError  If the provided LDAP result includes any control
   *                          with the specified OID.
   */
  protected static void assertMissingControl(@NotNull final LDAPResult result,
                                             @NotNull final String oid)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingControl(result, oid);
  }



  /**
   * Ensures that the provided LDAP exception does not include any control with
   * the specified OID.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  oid        The OID of the control which is not expected to be
   *                    present in the exception.
   *
   * @throws  AssertionError  If the provided LDAP exception includes any
   *                          control with the specified OID.
   */
  protected static void assertMissingControl(
                 @NotNull final LDAPException exception,
                 @NotNull final String oid)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingControl(exception, oid);
  }



  /**
   * Ensures that the provided search result entry does not includes any control
   * with the specified OID.
   *
   * @param  entry  The search result entry to examine.
   * @param  oid    The OID of the control which is not expected to be present
   *                in the search result entry.
   *
   * @throws  AssertionError  If the provided search result entry includes any
   *                          control with the specified OID.
   */
  protected static void assertMissingControl(
                 @NotNull final SearchResultEntry entry,
                 @NotNull final String oid)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingControl(entry, oid);
  }



  /**
   * Ensures that the provided search result reference does not includes any
   * control with the specified OID.
   *
   * @param  reference  The search result reference to examine.
   * @param  oid        The OID of the control which is not expected to be
   *                    present in the search result reference.
   *
   * @throws  AssertionError  If the provided search result reference includes
   *                          any control with the specified OID.
   */
  protected static void assertMissingControl(
                             @NotNull final SearchResultReference reference,
                             @NotNull final String oid)
            throws AssertionError
  {
    LDAPTestUtils.assertMissingControl(reference, oid);
  }



  /**
   * Ensures that the provided search result indicates that at least one search
   * result entry was returned.
   *
   * @param  result  The search result to examine.
   *
   * @return  The number of search result entries that were returned.
   *
   * @throws  AssertionError  If the provided search result indicates that no
   *                          entries were returned.
   */
  protected static int assertEntryReturned(@NotNull final SearchResult result)
            throws AssertionError
  {
    return LDAPTestUtils.assertEntryReturned(result);
  }



  /**
   * Ensures that the provided search exception indicates that at least one
   * search result entry was returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @return  The number of search result entries that were returned.
   *
   * @throws  AssertionError  If the provided search exception indicates that no
   *                          entries were returned.
   */
  protected static int assertEntryReturned(
                 @NotNull final LDAPSearchException exception)
            throws AssertionError
  {
    return LDAPTestUtils.assertEntryReturned(exception);
  }



  /**
   * Ensures that the specified search result entry was included in provided
   * search result.
   *
   * @param  result  The search result to examine.
   * @param  dn      The DN of the entry expected to be included in the
   *                 search result.
   *
   * @return  The search result entry with the provided DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   *
   * @throws  AssertionError  If the specified entry was not included in the
   *                          set of entries that were returned, or
   *                          {@code null} if a search result listener was used
   *                          which makes the determination impossible.
   */
  @NotNull()
  protected static SearchResultEntry assertEntryReturned(
                                          @NotNull final SearchResult result,
                                          @NotNull final String dn)
            throws LDAPException, AssertionError
  {
    return LDAPTestUtils.assertEntryReturned(result, dn);
  }



  /**
   * Ensures that the specified search result entry was included in provided
   * search exception.
   *
   * @param  exception  The search exception to examine.
   * @param  dn         The DN of the entry expected to be included in the
   *                    search exception.
   *
   * @return  The search result entry with the provided DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   *
   * @throws  AssertionError  If the specified entry was not included in the
   *                          set of entries that were returned, or if a search
   *                          result listener was used which makes the
   *                          determination impossible.
   */
  @NotNull()
  protected static SearchResultEntry assertEntryReturned(
                 @NotNull final LDAPSearchException exception,
                 @NotNull final String dn)
            throws LDAPException, AssertionError
  {
    return LDAPTestUtils.assertEntryReturned(exception, dn);
  }



  /**
   * Ensures that the provided search result indicates that no search result
   * entries were returned.
   *
   * @param  result  The search result to examine.
   *
   * @throws  AssertionError  If the provided search result indicates that one
   *                          or more entries were returned.
   */
  protected static void assertNoEntriesReturned(
                 @NotNull final SearchResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertNoEntriesReturned(result);
  }



  /**
   * Ensures that the provided search exception indicates that no search result
   * entries were returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @throws  AssertionError  If the provided search exception indicates that
   *                          one or more entries were returned.
   */
  protected static void assertNoEntriesReturned(
                             @NotNull final LDAPSearchException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertNoEntriesReturned(exception);
  }



  /**
   * Ensures that the provided search result indicates that the expected number
   * of entries were returned.
   *
   * @param  result              The search result to examine.
   * @param  expectedEntryCount  The number of expected search result entries.
   *
   * @throws  AssertionError  If the number of entries returned does not match
   *                          the expected value.
   */
  protected static void assertEntriesReturnedEquals(
                 @NotNull final SearchResult result,
                 @NotNull final int expectedEntryCount)
            throws AssertionError
  {
    LDAPTestUtils.assertEntriesReturnedEquals(result, expectedEntryCount);
  }



  /**
   * Ensures that the provided search exception indicates that the expected
   * number of entries were returned.
   *
   * @param  exception           The search exception to examine.
   * @param  expectedEntryCount  The number of expected search result entries.
   *
   * @throws  AssertionError  If the number of entries returned does not match
   *                          the expected value.
   */
  protected static void assertEntriesReturnedEquals(
                             @NotNull final LDAPSearchException exception,
                             @NotNull final int expectedEntryCount)
            throws AssertionError
  {
    LDAPTestUtils.assertEntriesReturnedEquals(exception, expectedEntryCount);
  }



  /**
   * Ensures that the provided search result indicates that at least one search
   * result reference was returned.
   *
   * @param  result  The search result to examine.
   *
   * @return  The number of search result references that were returned.
   *
   * @throws  AssertionError  If the provided search result indicates that no
   *                          references were returned.
   */
  protected static int assertReferenceReturned(
                 @NotNull final SearchResult result)
            throws AssertionError
  {
    return LDAPTestUtils.assertReferenceReturned(result);
  }



  /**
   * Ensures that the provided search exception indicates that at least one
   * search result reference was returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @return  The number of search result references that were returned.
   *
   * @throws  AssertionError  If the provided search exception indicates that no
   *                          references were returned.
   */
  protected static int assertReferenceReturned(
                            @NotNull final LDAPSearchException exception)
            throws AssertionError
  {
    return LDAPTestUtils.assertReferenceReturned(exception);
  }



  /**
   * Ensures that the provided search result indicates that no search result
   * references were returned.
   *
   * @param  result  The search result to examine.
   *
   * @throws  AssertionError  If the provided search result indicates that one
   *                          or more references were returned.
   */
  protected static void assertNoReferencesReturned(
                 @NotNull final SearchResult result)
            throws AssertionError
  {
    LDAPTestUtils.assertNoReferencesReturned(result);
  }



  /**
   * Ensures that the provided search exception indicates that no search result
   * references were returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @throws  AssertionError  If the provided search exception indicates that
   *                          one or more references were returned.
   */
  protected static void assertNoReferencesReturned(
                             @NotNull final LDAPSearchException exception)
            throws AssertionError
  {
    LDAPTestUtils.assertNoReferencesReturned(exception);
  }



  /**
   * Ensures that the provided search result indicates that the expected number
   * of references were returned.
   *
   * @param  result                  The search result to examine.
   * @param  expectedReferenceCount  The number of expected search result
   *                                 references.
   *
   * @throws  AssertionError  If the number of references returned does not
   *                          match the expected value.
   */
  protected static void assertReferencesReturnedEquals(
                             @NotNull final SearchResult result,
                             @NotNull final int expectedReferenceCount)
            throws AssertionError
  {
    LDAPTestUtils.assertReferencesReturnedEquals(result,
         expectedReferenceCount);
  }



  /**
   * Ensures that the provided search exception indicates that the expected
   * number of references were returned.
   *
   * @param  exception               The search exception to examine.
   * @param  expectedReferenceCount  The number of expected search result
   *                                 references.
   *
   * @throws  AssertionError  If the number of references returned does not
   *                          match the expected value.
   */
  protected static void assertReferencesReturnedEquals(
                             @NotNull final LDAPSearchException exception,
                             @NotNull final int expectedReferenceCount)
            throws AssertionError
  {
    LDAPTestUtils.assertReferencesReturnedEquals(exception,
         expectedReferenceCount);
  }



  /**
   * Ensures that the provided condition is true.
   *
   * @param  condition  The condition to ensure is true.
   *
   * @throws  AssertionError  If the condition is not true.
   */
  protected static void assertTrue(final boolean condition)
            throws AssertionError
  {
    Assert.assertTrue(condition);
  }



  /**
   * Ensures that the provided condition is true.
   *
   * @param  condition  The condition to ensure is true.
   * @param  message    The message to use if the condition is not true.
   *
   * @throws  AssertionError  If the condition is not true.
   */
  protected static void assertTrue(final boolean condition,
                                   @NotNull final String message)
            throws AssertionError
  {
    Assert.assertTrue(condition, message);
  }



  /**
   * Ensures that the provided condition is false.
   *
   * @param  condition  The condition to ensure is false.
   *
   * @throws  AssertionError  If the condition is not false.
   */
  protected static void assertFalse(final boolean condition)
            throws AssertionError
  {
    Assert.assertFalse(condition);
  }



  /**
   * Ensures that the provided condition is false.
   *
   * @param  condition  The condition to ensure is false.
   * @param  message    The message to use if the condition is not false.
   *
   * @throws  AssertionError  If the condition is not false.
   */
  protected static void assertFalse(final boolean condition,
                                    @NotNull final String message)
            throws AssertionError
  {
    Assert.assertFalse(condition, message);
  }



  /**
   * Ensures that the provided object is {@code null}.
   *
   * @param  o  The object for which to make the determination.
   *
   * @throws  AssertionError  If the provided object is not {@code null}.
   */
  protected static void assertNull(@Nullable final Object o)
            throws AssertionError
  {
    Assert.assertNull(o);
  }



  /**
   * Ensures that the provided object is {@code null}.
   *
   * @param  o        The object for which to make the determination.
   * @param  message  The message to use if the object is not {@code null}.
   *
   * @throws  AssertionError  If the provided object is not {@code null}.
   */
  protected static void assertNull(@Nullable final Object o,
                                   @NotNull final String message)
            throws AssertionError
  {
    Assert.assertNull(o, message);
  }



  /**
   * Ensures that the provided object is not {@code null}.
   *
   * @param  o  The object for which to make the determination.
   *
   * @throws  AssertionError  If the provided object is {@code null}.
   */
  protected static void assertNotNull(@Nullable final Object o)
            throws AssertionError
  {
    Assert.assertNotNull(o);
  }



  /**
   * Ensures that the provided object is not {@code null}.
   *
   * @param  o        The object for which to make the determination.
   * @param  message  The message to use if the object is {@code null}.
   *
   * @throws  AssertionError  If the provided object is {@code null}.
   */
  protected static void assertNotNull(@Nullable final Object o,
                                      @NotNull final String message)
            throws AssertionError
  {
    Assert.assertNotNull(o, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final boolean actual,
                                     final boolean expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final boolean actual,
                                     final boolean expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final byte actual,
                                     final byte expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final byte actual,
                                     final byte expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final byte[] actual,
                                     @Nullable final byte[] expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final byte[] actual,
                                     @Nullable final byte[] expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final char actual,
                                     final char expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final char actual,
                                     final char expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final double actual,
                                     final double expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final double actual,
                                     final double expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final float actual,
                                     final float expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final float actual,
                                     final float expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final int actual,
                                     final int expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final int actual,
                                     final int expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final long actual,
                                     final long expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final long actual,
                                     final long expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final short actual,
                                     final short expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(final short actual,
                                     final short expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final String actual,
                                     @Nullable final String expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final String actual,
                                     @Nullable final String expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided values are logically equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final Object actual,
                                     @Nullable final Object expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided values are logically equal.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final Object actual,
                                     @Nullable final Object expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided arrays contain values which are logically equal
   * and in the same order.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final Object[] actual,
                                     @Nullable final Object[] expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided arrays contain values which are logically equal
   * and in the same order.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final Object[] actual,
                                     @Nullable final Object[] expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided collections contain values which are logically
   * equal and in the same order.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final Collection<?> actual,
                                     @Nullable final Collection<?> expected)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected);
  }



  /**
   * Ensures that the provided collections contain values which are logically
   * equal and in the same order.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEquals(@Nullable final Collection<?> actual,
                                     @Nullable final Collection<?> expected,
                                     @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEquals(actual, expected, message);
  }



  /**
   * Ensures that the provided arrays contain values which are logically
   * equivalent.  The order in which the elements occur is irrelevant.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEqualsNoOrder(@Nullable final Object[] actual,
                                            @Nullable final Object[] expected)
            throws AssertionError
  {
    Assert.assertEqualsNoOrder(actual, expected);
  }



  /**
   * Ensures that the provided arrays contain values which are logically
   * equivalent.  The order in which the elements occur is irrelevant.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use if the values are not equal.
   *
   * @throws  AssertionError  If the provided values are not equal.
   */
  protected static void assertEqualsNoOrder(@Nullable final Object[] actual,
                                            @Nullable final Object[] expected,
                                            @NotNull final String message)
            throws AssertionError
  {
    Assert.assertEqualsNoOrder(actual, expected, message);
  }



  /**
   * Ensures that the provided objects are references to the same element.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   *
   * @throws  AssertionError  If the provided objects are not the same.
   */
  protected static void assertSame(@Nullable final Object actual,
                                   @Nullable final Object expected)
            throws AssertionError
  {
    Assert.assertSame(actual, expected);
  }



  /**
   * Ensures that the provided objects are references to the same element.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The expected value.
   * @param  message   The message to use for the assertion error if the objects
   *                   are not the same.
   *
   * @throws  AssertionError  If the provided objects are not the same.
   */
  protected static void assertSame(@Nullable final Object actual,
                                   @Nullable final Object expected,
                                   @NotNull final String message)
            throws AssertionError
  {
    Assert.assertSame(actual, expected, message);
  }



  /**
   * Ensures that the provided objects are references to different elements.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The value expected to be different.
   *
   * @throws  AssertionError  If the provided objects are the same.
   */
  protected static void assertNotSame(@Nullable final Object actual,
                                      @Nullable final Object expected)
            throws AssertionError
  {
    Assert.assertNotSame(actual, expected);
  }



  /**
   * Ensures that the provided objects are references to different elements.
   *
   * @param  actual    The actual value encountered.
   * @param  expected  The value expected to be different.
   * @param  message   The message to use for the assertion error if the objects
   *                   are the same.
   *
   * @throws  AssertionError  If the provided objects are the same.
   */
  protected static void assertNotSame(@Nullable final Object actual,
                                      @Nullable final Object expected,
                                      @NotNull final String message)
            throws AssertionError
  {
    Assert.assertNotSame(actual, expected, message);
  }



  /**
   * Ensures that the provided two strings represent the same DN.
   *
   * @param  s1  The first string to examine.
   * @param  s2  The second string to examine.
   *
   * @throws  AssertionError  If the provided strings do not represent the same
   *                          DN.
   */
  protected static void assertDNsEqual(@NotNull final String s1,
                                       @NotNull final String s2)
            throws AssertionError
  {
    LDAPTestUtils.assertDNsEqual(s1, s2);
  }



  /**
   * Throws an {@code AssertionError}.
   *
   * @throws  AssertionError  Always.
   */
  protected static void fail()
            throws AssertionError
  {
    Assert.fail();
  }



  /**
   * Throws an {@code AssertionError}.
   *
   * @param  message  The message to use for the {@code AssertionError}.
   *
   * @throws  AssertionError  Always.
   */
  protected static void fail(@NotNull final String message)
            throws AssertionError
  {
    Assert.fail(message);
  }



  /**
   * Throws an {@code AssertionError}.
   *
   * @param  message  The message to use for the {@code AssertionError}.
   * @param  cause    The exception that triggered the failure.
   *
   * @throws  AssertionError  Always.
   */
  protected static void fail(@NotNull final String message,
                             @Nullable final Throwable cause)
            throws AssertionError
  {
    Assert.fail(message, cause);
  }
}
