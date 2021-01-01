/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.net.Socket;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;



/**
 * This class provides test coverage for the {@code LDAPConnection} class.
 */
public class LDAPConnectionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of tests for a connection that is not established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnestablishedConnectionDefaultConstructor()
         throws Exception
  {
    LDAPConnection c = new LDAPConnection();

    assertNotNull(c.getSDKConnection());

    assertNull(c.getHost());

    c.getPort();

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.setConnectTimeout(10);
    assertEquals(c.getConnectTimeout(), 10);

    c.setConnectTimeout(-1);
    assertEquals(c.getConnectTimeout(), 0);

    assertNull(c.getSocketFactory());
    c.setSocketFactory(new TestLDAPSocketFactory());
    assertNotNull(c.getSocketFactory());
    c.setSocketFactory(null);
    assertNull(c.getSocketFactory());

    assertNotNull(c.getConstraints());
    c.setConstraints(new LDAPConstraints());
    assertNotNull(c.getConstraints());
    c.setConstraints(null);
    assertNotNull(c.getConstraints());

    assertNotNull(c.getSearchConstraints());
    c.setSearchConstraints(new LDAPSearchConstraints());
    assertNotNull(c.getSearchConstraints());
    c.setSearchConstraints(null);
    assertNotNull(c.getSearchConstraints());

    assertFalse(c.isConnected());

    assertNull(c.getResponseControls());

    c.disconnect();

    try
    {
      c.finalize();
    } catch (Throwable t) {}
  }



  /**
   * Performs a set of tests for a connection that is not established with a
   * custom socket factory.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUnestablishedConnectionCustomSocketFactory()
         throws Exception
  {
    LDAPConnection c = new LDAPConnection(new TestLDAPSocketFactory());

    assertNotNull(c.getSDKConnection());

    assertNull(c.getHost());

    c.getPort();

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.setConnectTimeout(10);
    assertEquals(c.getConnectTimeout(), 10);

    c.setConnectTimeout(-1);
    assertEquals(c.getConnectTimeout(), 0);

    assertNotNull(c.getSocketFactory());
    c.setSocketFactory(new TestLDAPSocketFactory());
    assertNotNull(c.getSocketFactory());
    c.setSocketFactory(null);
    assertNull(c.getSocketFactory());

    assertNotNull(c.getConstraints());
    c.setConstraints(new LDAPConstraints());
    assertNotNull(c.getConstraints());
    c.setConstraints(null);
    assertNotNull(c.getConstraints());

    assertNotNull(c.getSearchConstraints());
    c.setSearchConstraints(new LDAPSearchConstraints());
    assertNotNull(c.getSearchConstraints());
    c.setSearchConstraints(null);
    assertNotNull(c.getSearchConstraints());

    assertFalse(c.isConnected());

    assertNull(c.getResponseControls());

    c.disconnect();

    try
    {
      c.finalize();
    } catch (Throwable t) {}
  }



  /**
   * Provides test coverage for the {@code connect} method which takes only a
   * host and port.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectHostPort()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    assertNotNull(c.getSDKConnection());

    c.connect(getTestHost(), getTestPort());

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.reconnect();

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code connect} method in which it is not
   * possible to successfully establish a connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testConnectHostPortUnsuccessful()
         throws Exception
  {
    Socket s = new Socket();
    s.bind(null);

    int unusedPort = s.getLocalPort();

    s.close();


    LDAPConnection c = new LDAPConnection();

    assertNotNull(c.getSDKConnection());

    c.connect("127.0.0.1", unusedPort);
  }



  /**
   * Provides test coverage for the {@code connect} method which takes a host,
   * port, bind DN, and password, using non-null credentials.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectHostPortDNPasswordNonNull()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    assertNotNull(c.getSDKConnection());

    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.reconnect();

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code connect} method which takes a host,
   * port, bind DN, and password, using invalid credentials.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectHostPortDNPasswordInvalid()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    try
    {
      c.connect(getTestHost(), getTestPort(), getTestBindDN(),
           "wrong-" + getTestBindPassword());
      fail("Expected an exception when trying to authenticate with the wrong " +
           "password");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.INVALID_CREDENTIALS);
    }

    assertFalse(c.isConnected());

    assertNull(c.getHost());

    c.getPort();

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.setConnectTimeout(10);
    assertEquals(c.getConnectTimeout(), 10);

    c.setConnectTimeout(-1);
    assertEquals(c.getConnectTimeout(), 0);

    assertNull(c.getSocketFactory());
    c.setSocketFactory(new TestLDAPSocketFactory());
    assertNotNull(c.getSocketFactory());
    c.setSocketFactory(null);
    assertNull(c.getSocketFactory());

    assertNotNull(c.getConstraints());
    c.setConstraints(new LDAPConstraints());
    assertNotNull(c.getConstraints());
    c.setConstraints(null);
    assertNotNull(c.getConstraints());

    assertNotNull(c.getSearchConstraints());
    c.setSearchConstraints(new LDAPSearchConstraints());
    assertNotNull(c.getSearchConstraints());
    c.setSearchConstraints(null);
    assertNotNull(c.getSearchConstraints());

    assertFalse(c.isConnected());

    assertNull(c.getResponseControls());

    c.disconnect();

    try
    {
      c.finalize();
    } catch (Throwable t) {}
  }



  /**
   * Provides test coverage for the {@code connect} method which takes a host,
   * port, bind DN, and password, using null credentials.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectHostPortDNPasswordNull()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    c.connect(getTestHost(), getTestPort(), null, null);

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.reconnect();

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNull(c.getAuthenticationDN());

    assertNull(c.getAuthenticationPassword());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code connect} method which takes a
   * protocol version, host, port, bind DN, and password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectVersionHostPortDNPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    c.connect(3, getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.reconnect();

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code connect} method which takes a host,
   * port, bind DN, and password, and constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectHostPortDNPasswordConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword(), new LDAPConstraints());

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.reconnect();

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code connect} method which takes a
   * protocol version, host, port, bind DN, and password, and constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConnectVeresionHostPortDNPasswordConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();

    c.connect(3, getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword(), null);

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.reconnect();

    assertTrue(c.isConnected());

    assertNotNull(c.getHost());
    assertEquals(c.getHost(), getTestHost());

    assertEquals(c.getPort(), getTestPort());

    assertNotNull(c.getAuthenticationDN());
    assertEquals(c.getAuthenticationDN(), getTestBindDN());

    assertNotNull(c.getAuthenticationPassword());
    assertEquals(c.getAuthenticationPassword(), getTestBindPassword());

    c.disconnect();
  }



  /**
   * Tests the ability to process various types of operations.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperations()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());


    // Test the various versions of the authenticate method.
    c.authenticate(getTestBindDN(), getTestBindPassword());
    c.authenticate(getTestBindDN(), getTestBindPassword(),
         new LDAPConstraints());
    c.authenticate(3, getTestBindDN(), getTestBindPassword());
    c.authenticate(3, getTestBindDN(), getTestBindPassword(),
         new LDAPConstraints());


    // Test the various versions of the bind method.
    c.bind(getTestBindDN(), getTestBindPassword());
    c.bind(getTestBindDN(), getTestBindPassword(),
         new LDAPConstraints());
    c.bind(3, getTestBindDN(), getTestBindPassword());
    c.bind(3, getTestBindDN(), getTestBindPassword(),
         new LDAPConstraints());


    // Verify that we cannot add an entry below the base entry before that base
    // entry exists.
    try
    {
      c.add(new LDAPEntry(new Entry(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test")));
      fail("Expected an exception when trying to add a child below a parent " +
           "that doesn't exist");
    }
    catch (LDAPException le)
    {
      // This was expected.
    }


    // Add the base entry to the server.
    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));


    // Verify that we can read the base entry.
    LDAPEntry e = c.read(getTestBaseDN());
    assertNotNull(e);
    assertTrue(LDAPDN.equals(e.getDN(), getTestBaseDN()));


    // Add an entry immediately below the base.
    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));


    // Verify that we can read the new entry.
    e = c.read("ou=test," + getTestBaseDN());
    assertNotNull(e);
    assertTrue(LDAPDN.equals(e.getDN(), "ou=Test," + getTestBaseDN()));


    // Verify that we can update the new entry.
    c.modify("ou=test," + getTestBaseDN(), new LDAPModification(
         LDAPModification.REPLACE, new LDAPAttribute("description", "foo")));


    // Verify that we cannot update an entry that does not exist.
    try
    {
      c.modify("ou=nonexistent," + getTestBaseDN(), new LDAPModification(
           LDAPModification.REPLACE, new LDAPAttribute("description", "foo")));
      fail("Expected an exception when trying to modify an entry that does " +
           "not exist");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.NO_SUCH_OBJECT);
    }


    // Verify that we can perform a compare operation against the new entry.
    assertTrue(c.compare("ou=test," + getTestBaseDN(),
         new LDAPAttribute("description", "foo")));


    // Verify that we cannot perform a compare operation against a nonexistent
    // entry.
    try
    {
      c.compare("ou=nonexistent," + getTestBaseDN(),
           new LDAPAttribute("description", "foo"));
      fail("Expected an exception when trying to compare an entry that " +
           "doesn't exist");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.NO_SUCH_OBJECT);
    }


    // Verify that we can perform a search to retrieve both the base and child
    // entries.
    int numEntries = 0;
    LDAPSearchResults results = c.search(getTestBaseDN(),
         LDAPConnection.SCOPE_SUB, "(objectClass=*)", null, false);
    while (results.hasMoreElements())
    {
      e = results.next();
      assertNotNull(e);
      numEntries++;
    }
    assertEquals(numEntries, 2);


    // Send a request to abandon the search.  This will have no effect, but will
    // provide coverage.
    c.abandon(results);


    // Verify that we cannot perform a search with a nonexistent base.
    try
    {
      results = c.search("ou=nonexistent," + getTestBaseDN(),
           LDAPConnection.SCOPE_SUB, "(objectClass=*)", null, false);
      while (results.hasMoreElements())
      {
        results.next();
      }
      fail("Expected an exception when trying to search with a nonexistent " +
           "base");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.NO_SUCH_OBJECT);
    }


    // Verify that we can rename the child entry.
    c.rename("ou=test," + getTestBaseDN(), "ou=test2", true);


    // Verify that we cannot rename an entry that does not exist.
    try
    {
      c.rename("ou=nonexistent," + getTestBaseDN(), "ou=nonexistent2", true,
           null);
      fail("Expected an exception when trying to rename a nonexistent entry");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.NO_SUCH_OBJECT);
    }


    // Verify that we can read the new child entry.
    e = c.read("ou=test2," + getTestBaseDN());
    assertNotNull(e);


    // Verify that we can no longer read the original child entry.
    try
    {
      c.read("ou=test," + getTestBaseDN());
      fail("Expected an exception when trying to read an entry after it has " +
           "been renamed");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.NO_SUCH_OBJECT);
    }


    // Verify that we can delete the new child entry.
    c.delete("ou=test2," + getTestBaseDN());


    // Verify that we can no longer delete the new child entry.
    try
    {
      c.delete("ou=test2," + getTestBaseDN());
      fail("Expected an exception when trying to delete an entry that no " +
           "longer exists");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(), LDAPException.NO_SUCH_OBJECT);
    }


    // Verify that we can delete the base entry.
    c.delete(getTestBaseDN());


    // Send a call to abandon a request.  This won't do anything constructive,
    // but will provide test coverage.
    c.abandon(1);

    c.disconnect();
  }



  /**
   * Provides test coverage for the abandon method on a connection that is not
   * established.  This is about the only reliable way to get test coverage for
   * the case in which sending an abandon request throws an exception.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testAbandonNotConnected()
         throws Exception
  {
    LDAPConnection c = new LDAPConnection();
    c.abandon(1);
  }



  /**
   * Provides test coverage for the modify method which takes an array of
   * modifications and no constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyMultipleNoConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));

    LDAPModification[] mods =
    {
      new LDAPModification(LDAPModification.ADD,
           new LDAPAttribute("description", "foo")),
      new LDAPModification(LDAPModification.ADD,
           new LDAPAttribute("description", "bar")),
    };

    c.modify("ou=test," + getTestBaseDN(), mods);

    c.delete("ou=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the modify method which takes a modification set
   * and no constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifySetNoConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));

    LDAPModificationSet mods = new LDAPModificationSet();
    mods.add(LDAPModification.ADD, new LDAPAttribute("description", "foo"));
    mods.add(LDAPModification.ADD, new LDAPAttribute("description", "bar"));

    c.modify("ou=test," + getTestBaseDN(), mods);

    c.delete("ou=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the modify method which takes a modification set
   * and with constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifySetWithConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));

    LDAPModificationSet mods = new LDAPModificationSet();
    mods.add(LDAPModification.ADD, new LDAPAttribute("description", "foo"));
    mods.add(LDAPModification.ADD, new LDAPAttribute("description", "bar"));

    c.modify("ou=test," + getTestBaseDN(), mods, new LDAPConstraints());

    c.delete("ou=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the ability to process a modify operation which
   * includes the post-read control.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyWithPostReadControl()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));

    LDAPConstraints constraints = new LDAPConstraints();
    constraints.setServerControls(new LDAPControl(
         new PostReadRequestControl("description")));

    LDAPModification mod = new LDAPModification(LDAPModification.REPLACE,
         new LDAPAttribute("description", "foo"));

    c.modify("ou=test," + getTestBaseDN(), mod, constraints);

    LDAPControl[] responseControls = c.getResponseControls();
    assertNotNull(responseControls);
    assertEquals(responseControls.length, 1);

    PostReadResponseControl postReadResponse =
         new PostReadResponseControl(responseControls[0].getID(), false,
              new ASN1OctetString(responseControls[0].getValue()));

    Entry e = postReadResponse.getEntry();
    assertNotNull(e);
    assertTrue(e.hasAttributeValue("description", "foo"));

    c.delete("ou=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code read} method which takes a DN and
   * search constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDNWithConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    assertNotNull(c.read("", new LDAPSearchConstraints()));

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code read} method which takes a DN and
   * set of attributes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadDNAndAttributes()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    assertNotNull(c.read("", new String[] { "objectClass" }));

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code rename} method which takes a DN, new
   * RDN, deleteOldRDN flag, and constraints
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameDNNewRDNDeleteOldRDNConstraints()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));

    c.rename("ou=test," + getTestBaseDN(), "ou=test2", true,
         new LDAPConstraints());

    c.delete("ou=test2," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the {@code rename} method which takes a DN, new
   * RDN, deleteOldRDN flag, and new superior DN
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRenameDNNewRDNDeleteOldRDNNewSuperior()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: ou=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test")));

    c.rename("ou=test," + getTestBaseDN(), "ou=test2", null, true);

    c.delete("ou=test2," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the methods used to invoke extended operations
   * with a cancel extended request.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCancelExtendedOperation()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    try
    {
      c.extendedOperation(
           new LDAPExtendedOperation(new CancelExtendedRequest(1)));
      fail("Expected an exception when trying to cancel a nonexistent op");
    }
    catch (LDAPException le)
    {
      assertEquals(le.getLDAPResultCode(),
           ResultCode.NO_SUCH_OPERATION_INT_VALUE);
    }

    c.disconnect();
  }



  /**
   * Provides test coverage for the methods used to invoke extended operations
   * with a password modify extended request including a new password.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordModifyExtendedOperationWithNewPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: uid=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password")));

    LDAPExtendedOperation extendedResult = c.extendedOperation(
         new LDAPExtendedOperation(new PasswordModifyExtendedRequest(
              "dn:uid=test," + getTestBaseDN(), null, "newpassword")));

    assertNotNull(extendedResult);

    assertNull(extendedResult.getID());

    assertNull(extendedResult.getValue());

    c.delete("uid=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Provides test coverage for the methods used to invoke extended operations
   * with a password modify extended request without providing a new password
   * so that a value will be provided.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordModifyExtendedOperationNoNewPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection c = new LDAPConnection();
    c.connect(getTestHost(), getTestPort(), getTestBindDN(),
         getTestBindPassword());

    c.add(new LDAPEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes())));

    c.add(new LDAPEntry(new Entry(
         "dn: uid=test," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password")));

    LDAPExtendedOperation extendedResult = c.extendedOperation(
         new LDAPExtendedOperation(new PasswordModifyExtendedRequest(
              "dn:uid=test," + getTestBaseDN(), null, (String) null)));

    assertNotNull(extendedResult);

    assertNull(extendedResult.getID());

    assertNotNull(extendedResult.getValue());

    c.delete("uid=test," + getTestBaseDN());
    c.delete(getTestBaseDN());

    c.disconnect();
  }



  /**
   * Tests the ability to communicate with the Directory Server using SSL.
   * <BR><BR>
   * Access to an SSL-enabled Directory Server instance is required for complete
   * processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSSLCommunication()
         throws Exception
  {
    if (! isSSLEnabledDirectoryInstanceAvailable())
    {
      return;
    }

    SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
    JavaToLDAPSocketFactory f =
         new JavaToLDAPSocketFactory(sslUtil.createSSLSocketFactory());

    LDAPConnection c = new LDAPConnection(f);
    c.connect(getTestHost(), getTestSSLPort(), getTestBindDN(),
         getTestBindPassword());

    assertTrue(c.isConnected());

    assertNotNull(c.read(""));

    c.disconnect();
  }
}
