/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.CompareResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.PLAINBindRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.TestUnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IgnoreNoUserModificationRequestControl;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.MemoryBasedLogHandler;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;



/**
 * This class provides a set of test cases for the in-memory directory server.
 */
public final class InMemoryDirectoryServerTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create an in-memory directory server instance using
   * only a set of base DNs, and then perform a basic set of operations using
   * that server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBaseDNConstructor()
         throws Exception
  {
    final InMemoryDirectoryServer ds =
         new InMemoryDirectoryServer("dc=example,dc=com");

    assertNull(ds.getListenAddress());
    assertEquals(ds.getListenPort(), -1);
    assertNull(ds.getClientSocketFactory());

    assertNotNull(ds.getSchema());

    assertNotNull(ds.getBaseDNs());
    assertFalse(ds.getBaseDNs().isEmpty());
    assertEquals(ds.getBaseDNs().size(), 1);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));

    try
    {
      ds.getConnection();
      fail("Expected an exception when trying to get a connection to a " +
           "server that hasn't been started yet.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONNECT_ERROR);
    }

    ds.startListening();

    final int listenPort = ds.getListenPort();
    assertTrue((listenPort >= 1) && (listenPort <= 65535));
    assertEquals(listenPort, ds.getListenPort());

    assertNull(ds.getListenAddress());

    assertNull(ds.getClientSocketFactory());


    final LDAPConnection conn = ds.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    assertNull(conn.getSSLSession());


    final RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);
    assertNotNull(rootDSE.getNamingContextDNs());
    assertEquals(rootDSE.getNamingContextDNs().length, 1);
    assertEquals(new DN(rootDSE.getNamingContextDNs()[0]),
         new DN("dc=example,dc=com"));

    assertNotNull(ds.getEntry(""));


    final Schema schema = conn.getSchema();
    assertNotNull(schema);

    assertNotNull(ds.getEntry("cn=schema"));


    LDAPResult result = conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = conn.add(
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
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    result = conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    result = conn.compare("uid=test.user,ou=People,dc=example,dc=com", "cn",
         "Test User");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);


    result = conn.delete("uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    final ExtendedResult extendedResult =
         conn.processExtendedOperation("1.2.3.4");
    assertNotNull(extendedResult);
    assertEquals(extendedResult.getResultCode(),
         ResultCode.UNWILLING_TO_PERFORM);


    result = conn.modify(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    result = conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    SearchResult searchResult = conn.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    assertNotNull(searchResult);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 2);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=Users,dc=example,dc=com"));

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);


    final LDAPConnectionPool pool = ds.getConnectionPool(10);
    assertNotNull(pool);

    searchResult = pool.search("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    assertNotNull(searchResult);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 2);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=Users,dc=example,dc=com"));

    pool.close();


    assertEquals(ds.countEntries(), 2);

    ds.clear();
    assertEquals(ds.countEntries(), 0);

    ds.shutDown(true);

    assertNull(ds.getListenAddress());
    assertEquals(ds.getListenPort(), -1);
    assertNull(ds.getClientSocketFactory());
  }



  /**
   * Tests the ability to perform basic kinds of operations with indexing
   * enabled for a number of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicIndexing()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.setEqualityIndexAttributes("objectClass", "uid", "givenName", "sn",
         "cn");
    config.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);

    assertNull(ds.getListenAddress());
    assertEquals(ds.getListenPort(), -1);
    assertNull(ds.getClientSocketFactory());

    assertNotNull(ds.getSchema());

    assertNotNull(ds.getBaseDNs());
    assertFalse(ds.getBaseDNs().isEmpty());
    assertEquals(ds.getBaseDNs().size(), 1);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));

    try
    {
      ds.getConnection();
      fail("Expected an exception when trying to get a connection to a " +
           "server that hasn't been started yet.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONNECT_ERROR);
    }

    ds.startListening();

    final int listenPort = ds.getListenPort();
    assertTrue((listenPort >= 1) && (listenPort <= 65535));
    assertEquals(listenPort, ds.getListenPort());

    assertNull(ds.getListenAddress());

    assertNull(ds.getClientSocketFactory());


    final LDAPConnection conn = ds.getConnection();
    assertNotNull(conn);
    assertTrue(conn.isConnected());
    assertNull(conn.getSSLSession());


    final RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);
    assertNotNull(rootDSE.getNamingContextDNs());
    assertEquals(rootDSE.getNamingContextDNs().length, 1);
    assertEquals(new DN(rootDSE.getNamingContextDNs()[0]),
         new DN("dc=example,dc=com"));

    assertNotNull(ds.getEntry(""));


    final Schema schema = conn.getSchema();
    assertNotNull(schema);

    assertNotNull(ds.getEntry("cn=schema"));


    LDAPResult result = conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    result = conn.add(
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
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    result = conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    result = conn.compare("uid=test.user,ou=People,dc=example,dc=com", "cn",
         "Test User");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.COMPARE_TRUE);


    result = conn.delete("uid=test.user,ou=People,dc=example,dc=com");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    final ExtendedResult extendedResult =
         conn.processExtendedOperation("1.2.3.4");
    assertNotNull(extendedResult);
    assertEquals(extendedResult.getResultCode(),
         ResultCode.UNWILLING_TO_PERFORM);


    result = conn.modify(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    result = conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
    assertNotNull(result);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    SearchResult searchResult = conn.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    assertNotNull(searchResult);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 2);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=Users,dc=example,dc=com"));

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);


    final LDAPConnectionPool pool = ds.getConnectionPool(10);
    assertNotNull(pool);

    searchResult = pool.search("dc=example,dc=com", SearchScope.SUB,
         "(objectClass=*)");

    assertNotNull(searchResult);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);

    assertEquals(searchResult.getEntryCount(), 2);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=Users,dc=example,dc=com"));

    pool.close();


    assertEquals(ds.countEntries(), 2);

    ds.clear();
    assertEquals(ds.countEntries(), 0);

    ds.shutDown(true);

    assertNull(ds.getListenAddress());
    assertEquals(ds.getListenPort(), -1);
    assertNull(ds.getClientSocketFactory());
  }



  /**
   * Tests the constructor with invalid arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidConstructorArguments()
         throws Exception
  {
    // Test with an empty set of DNs.
    try
    {
      final InMemoryDirectoryServerConfig cfg =
           new InMemoryDirectoryServerConfig(new DN[0]);
      new InMemoryDirectoryServer(cfg);
      fail("Expected an exception when trying to use an empty set of DNs.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    // Test with a null base DN.
    try
    {
      final InMemoryDirectoryServerConfig cfg =
           new InMemoryDirectoryServerConfig(DN.NULL_DN);
      new InMemoryDirectoryServer(cfg);
      fail("Expected an exception when trying to use an null base DN");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    // Test with a base DN that matches the subschema subentry DN.
    try
    {
      final InMemoryDirectoryServerConfig cfg =
           new InMemoryDirectoryServerConfig("cn=schema");
      new InMemoryDirectoryServer(cfg);
      fail("Expected an exception when trying to use a base DN that matches " +
           "the subschema subentry DN.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
  }



  /**
   * Tests operations involving LDIF import and export.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testLDIFImportAndExport()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setAccessLogHandler(new MemoryBasedLogHandler());
    cfg.setLDAPDebugLogHandler(new MemoryBasedLogHandler());
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);
    cfg.setSchema(Schema.getDefaultStandardSchema());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    assertNotNull(ds);
    assertEquals(ds.countEntries(), 0);
    assertNull(ds.getEntry("dc=example,dc=com"));

    assertNotNull(ds.getSchema());

    assertNotNull(ds.getBaseDNs());
    assertFalse(ds.getBaseDNs().isEmpty());
    assertEquals(ds.getBaseDNs().size(), 1);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));

    final File ldifFile1 = createTempFile(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=user.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1",
         "userPassword: password");

    final File ldifFile2 = createTempFile(
         "dn: uid=user.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.2",
         "givenName: User",
         "sn: 2",
         "cn: User 2",
         "userPassword: password",
         "",
         "dn: uid=user.3,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.3",
         "givenName: User",
         "sn: 3",
         "cn: User 3",
         "userPassword: password",
         "",
         "dn: uid=user.4,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.4",
         "givenName: User",
         "sn: 4",
         "cn: User 4",
         "userPassword: password",
         "",
         "dn: uid=user.5,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: user.5",
         "givenName: User",
         "sn: 5",
         "cn: User 5",
         "userPassword: password");

    final File ldifFile3 = createTempFile(
         "This is not a valid LDIF file.",
         "Attempting to import it shouldn't have any effect on existing data.");

    assertEquals(ds.importFromLDIF(true, ldifFile1.getAbsolutePath()), 3);
    assertEquals(ds.countEntries(), 3);
    assertNotNull(ds.getEntry("dc=example,dc=com"));
    assertNotNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("uid=user.1,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("uid=user.2,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("uid=user.3,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("uid=user.4,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("uid=user.5,ou=People,dc=example,dc=com"));

    assertEquals(ds.importFromLDIF(false, ldifFile2.getAbsolutePath()), 4);
    assertEquals(ds.countEntries(), 7);
    assertNotNull(ds.getEntry("dc=example,dc=com"));
    assertNotNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("uid=user.1,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("uid=user.2,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("uid=user.3,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("uid=user.4,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("uid=user.5,ou=People,dc=example,dc=com"));


    // Test an export and verify that all entries are written out.
    final File exportFile = createTempFile();
    assertEquals(ds.exportToLDIF(exportFile.getAbsolutePath(), false, true), 7);


    // Test an export with an invalid path.
    try
    {
      final String badPath =
           exportFile.getAbsolutePath() + File.separator + "bogus";
      ds.exportToLDIF(badPath, false, true);
      fail("Expected an exception when trying to export to a bad path.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.LOCAL_ERROR);
    }


    // Re-initialize the data set with the exported LDIF file.
    assertEquals(ds.importFromLDIF(true, exportFile.getAbsolutePath()), 7);
    assertEquals(ds.countEntries(), 7);


    // Try to add entries that already exist.
    try
    {
      ds.importFromLDIF(false, ldifFile1.getAbsolutePath());
      fail("Expected an exception for an import with entries that already " +
           "exist");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      assertEquals(ds.countEntries(), 7);
    }

    // Try to clear and add entries not starting with the base DN.
    try
    {
      ds.importFromLDIF(true, ldifFile2.getAbsolutePath());
      fail("Expected an exception for an import without top entries.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      assertEquals(ds.countEntries(), 7);
    }

    // Try to clear and import from a file that doesn't exist.
    try
    {
      ds.importFromLDIF(true, ldifFile2.getAbsolutePath() + ".missing");
      fail("Expected an exception for an import from a missing file.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      assertEquals(ds.countEntries(), 7);
    }

    // Try to clear and import from a malformed file.
    try
    {
      ds.importFromLDIF(true, ldifFile3.getAbsolutePath());
      fail("Expected an exception for an import from a malformed file.");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {
      assertEquals(ds.countEntries(), 7);
    }

    // Try to clear and add entries starting with the base DN.
    assertEquals(ds.importFromLDIF(true, ldifFile1.getAbsolutePath()), 3);
    assertEquals(ds.countEntries(), 3);
  }



  /**
   * Tests operations involving applying changes from LDIF.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testApplyChangesFromLDIF()
         throws Exception
  {
    // Create the in-memory directory server.  Enable a changelog.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setAccessLogHandler(new MemoryBasedLogHandler());
    cfg.setLDAPDebugLogHandler(new MemoryBasedLogHandler());
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);
    cfg.setSchema(Schema.getDefaultStandardSchema());
    cfg.setMaxChangeLogEntries(1000);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);


    // Make sure that the server has the expected state.
    assertNotNull(ds);
    assertEquals(ds.countEntries(), 0);
    assertNull(ds.getEntry("dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=changelog"));
    assertNotNull(ds.getEntry("", "changeLog").getAttribute("changeLog"));
    assertNotNull(ds.getEntry("", "firstChangeNumber").getAttribute(
         "firstChangeNumber"));
    assertEquals(
         ds.getEntry("", "firstChangeNumber").getAttributeValue(
              "firstChangeNumber"),
         "0");
    assertNotNull(ds.getEntry("", "lastChangeNumber").getAttribute(
         "lastChangeNumber"));
    assertEquals(
         ds.getEntry("", "lastChangeNumber").getAttributeValue(
              "lastChangeNumber"),
         "0");

    assertNotNull(ds.getSchema());

    assertNotNull(ds.getBaseDNs());
    assertFalse(ds.getBaseDNs().isEmpty());
    assertEquals(ds.getBaseDNs().size(), 2);
    assertTrue(ds.getBaseDNs().contains(new DN("dc=example,dc=com")));
    assertTrue(ds.getBaseDNs().contains(new DN("cn=changelog")));


    // Create an LDIF file with all types of changes.  Include a change that
    // will fail as the last item.
    final File ldifFile1 = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: cn=Test User",
         "deleteoldrdn: 0",
         "",
         "dn: cn=Test User,ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: delete");


    // Try to apply the changes.  Make sure we get an LDAPException.
    try
    {
      ds.applyChangesFromLDIF(ldifFile1.getAbsolutePath());
      fail("Expected an exception when trying to apply changes from LDIF " +
           "when the last change should fail.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }


    // Make sure that the server is still empty, and that there are no
    // changelog records.
    assertNotNull(ds);
    assertEquals(ds.countEntries(), 0);
    assertNull(ds.getEntry("dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=changelog"));
    assertNotNull(ds.getEntry("", "changeLog").getAttribute("changeLog"));
    assertNotNull(ds.getEntry("", "firstChangeNumber").getAttribute(
         "firstChangeNumber"));
    assertEquals(
         ds.getEntry("", "firstChangeNumber").getAttributeValue(
              "firstChangeNumber"),
         "0");
    assertNotNull(ds.getEntry("", "lastChangeNumber").getAttribute(
         "lastChangeNumber"));
    assertEquals(
         ds.getEntry("", "lastChangeNumber").getAttributeValue(
              "lastChangeNumber"),
         "0");


    // Create another LDIF file with the same set of changes, minus the last one
    // that failed.  We should be able to apply this successfully.
    final File ldifFile2 = createTempFile(
         "dn: dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "",
         "dn: ou=People,dc=example,dc=com",
         "changetype: add",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo",
         "",
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: moddn",
         "newrdn: cn=Test User",
         "deleteoldrdn: 0",
         "",
         "dn: cn=Test User,ou=People,dc=example,dc=com",
         "changetype: delete");


    // Try to apply the changes.  Make sure that it succeeds and that the
    // return value is what we expected.
    final int changesApplied = ds.applyChangesFromLDIF(
         ldifFile2.getAbsolutePath());
    assertEquals(changesApplied, 6);


    // Make sure that the server is now not empty.  It should have two
    // entries and six changelog records.
    assertNotNull(ds);
    assertEquals(ds.countEntries(), 2);
    assertNotNull(ds.getEntry("dc=example,dc=com"));
    assertNotNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=changelog"));
    assertNotNull(ds.getEntry("", "changeLog").getAttribute("changeLog"));
    assertNotNull(ds.getEntry("", "firstChangeNumber").getAttribute(
         "firstChangeNumber"));
    assertEquals(
         ds.getEntry("", "firstChangeNumber").getAttributeValue(
              "firstChangeNumber"),
         "1");
    assertNotNull(ds.getEntry("", "lastChangeNumber").getAttribute(
         "lastChangeNumber"));
    assertEquals(
         ds.getEntry("", "lastChangeNumber").getAttributeValue(
              "lastChangeNumber"),
         "6");


    // Create a third LDIF file with a malformed LDIF record.
    final File ldifFile3 = createTempFile(
         "dn: ou=People,dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: dc=example,dc=com",
         "changetype: delete",
         "",
         "dn: malformedrecord",
         "changetype: malformed");


    // Try to apply the changes.  Make sure that we get an exception.
    try
    {
      ds.applyChangesFromLDIF(ldifFile3.getAbsolutePath());
      fail("Expected an LDAPException from trying to apply changes from an " +
           "LDIF file with a malformed record.");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }


    // Make sure that the server still has the same content it had before the
    // change attempt.
    assertNotNull(ds);
    assertEquals(ds.countEntries(), 2);
    assertNotNull(ds.getEntry("dc=example,dc=com"));
    assertNotNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=changelog"));
    assertNotNull(ds.getEntry("", "changeLog").getAttribute("changeLog"));
    assertNotNull(ds.getEntry("", "firstChangeNumber").getAttribute(
         "firstChangeNumber"));
    assertEquals(
         ds.getEntry("", "firstChangeNumber").getAttributeValue(
              "firstChangeNumber"),
         "1");
    assertNotNull(ds.getEntry("", "lastChangeNumber").getAttribute(
         "lastChangeNumber"));
    assertEquals(
         ds.getEntry("", "lastChangeNumber").getAttributeValue(
              "lastChangeNumber"),
         "6");
  }



  /**
   * Provides a various set of test cases for add operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAdd()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setSchema(Schema.getDefaultStandardSchema());
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    // Test adding the base entry.
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    // Tests adding a non-base entry.
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    // Test adding an entry using invalid LDIF.
    try
    {
      ds.add(
           "invalid_ldif_line_1",
           "invalid_ldif_line_2");
      fail("Expected an exception when trying to add an entry using invalid " +
           "LDIF.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
    }

    // Test adding an entry with a malformed DN.
    try
    {
      ds.add(new Entry("malformed",
           new Attribute("objectClass", "top", "organizationalUnit"),
           new Attribute("ou", "malformed DN")));
      fail("Expected an exception when trying to add an entry with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Test adding an entry that already exists.
    try
    {
      ds.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      fail("Expected an exception when trying to add an entry that already " +
           "exists.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }

    // Test adding an entry below a parent that doesn't exist.
    try
    {
      ds.add(
           "dn: cn=test,cn=missing,dc=example,dc=com",
           "objectClass: top",
           "objectClass: namedObject",
           "cn: test");
      fail("Expected an exception when trying to add an entry below a parent " +
           "that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }

    // Test adding an entry that violates schema (missing required sn).
    try
    {
      ds.add(
           "dn: cn=test,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "cn: test");
      fail("Expected an exception when trying to add an entry below a parent " +
           "that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    // Test adding an entry with the same DN as the root DSE.
    try
    {
      ds.add(
           "dn: ",
           "objectClass: top",
           "objectClass: namedObject",
           "objectClass: extensibleObject",
           "cn: Test Root DSE");
      fail("Expected an exception when trying to add an entry with the null " +
           "DN");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }

    // Test adding an entry with the same DN as the subschema subentry DN.
    try
    {
      ds.add(
           "dn: cn=schema",
           "objectClass: top",
           "objectClass: ldapSubEntry",
           "objectClass: subSchema",
           "cn: Schema");
      fail("Expected an exception when trying to add an entry with the null " +
           "DN");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }

    // Test the behavior when trying to add an entry outside the base DN.
    try
    {
      ds.add(
           "dn: o=example.com",
           "objectClass: top",
           "objectClass: organization",
           "o: example.com");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNull(le.getMatchedDN());
    }

    // Tests the behavior when adding multiple valid, acceptable entries.
    assertEquals(ds.countEntries(), 2);
    final Entry[] acceptableEntries =
    {
      new Entry(
           "dn: ou=test 1,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 1"),

      new Entry(
           "dn: ou=test 2,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 2"),
    };
    ds.addEntries(acceptableEntries);
    assertEquals(ds.countEntries(), 4);

    // Tests the behavior when adding entries in which one is unacceptable, and
    // verify that the entry set remains unchanged.
    try
    {
      ds.addEntries(
           "dn: ou=test 3,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 3",
           "",
           "dn: ou=test 3,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 3");
      fail("Expected an exception when trying to add multiple entries in " +
           "which a subsequent entry is invalid.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }
    finally
    {
      assertEquals(ds.countEntries(), 4);
    }

    // Tests the behavior when adding entries by LDIF string in which the LDIF
    // is malformed.
    try
    {
      ds.addEntries(
           "malformed-entry-line-1",
           "malformed-entry-line-2",
           "",
           "malformed-entry-line-3",
           "malformed-entry-line-4");
      fail("Expected an exception trying to add entries with malformed lines");
    }
    catch (final LDAPException  le)
    {
      assertEquals(le.getResultCode(), ResultCode.PARAM_ERROR);
    }

    // Tests the ability to add valid entries from LDIF lines.
    ds.addEntries(
         "dn: ou=test 3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 3",
         "",
         "dn: ou=test 4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 4");
    assertEquals(ds.countEntries(), 6);
  }



  /**
   * Provides a various set of test cases for add operations with indexing
   * enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddWithIndexing()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setEqualityIndexAttributes("objectClass", "uid", "givenName", "sn",
         "cn");
    cfg.setSchema(Schema.getDefaultStandardSchema());
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    // Test adding the base entry.
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    // Tests adding a non-base entry.
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    // Test adding an entry using invalid LDIF.
    try
    {
      ds.add(
           "invalid_ldif_line_1",
           "invalid_ldif_line_2");
      fail("Expected an exception when trying to add an entry using invalid " +
           "LDIF.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
    }

    // Test adding an entry with a malformed DN.
    try
    {
      ds.add(new Entry("malformed",
           new Attribute("objectClass", "top", "organizationalUnit"),
           new Attribute("ou", "malformed DN")));
      fail("Expected an exception when trying to add an entry with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Test adding an entry that already exists.
    try
    {
      ds.add(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");
      fail("Expected an exception when trying to add an entry that already " +
           "exists.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }

    // Test adding an entry below a parent that doesn't exist.
    try
    {
      ds.add(
           "dn: cn=test,cn=missing,dc=example,dc=com",
           "objectClass: top",
           "objectClass: namedObject",
           "cn: test");
      fail("Expected an exception when trying to add an entry below a parent " +
           "that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }

    // Test adding an entry that violates schema (missing required sn).
    try
    {
      ds.add(
           "dn: cn=test,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "cn: test");
      fail("Expected an exception when trying to add an entry below a parent " +
           "that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    // Test adding an entry with the same DN as the root DSE.
    try
    {
      ds.add(
           "dn: ",
           "objectClass: top",
           "objectClass: namedObject",
           "objectClass: extensibleObject",
           "cn: Test Root DSE");
      fail("Expected an exception when trying to add an entry with the null " +
           "DN");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }

    // Test adding an entry with the same DN as the subschema subentry DN.
    try
    {
      ds.add(
           "dn: cn=schema",
           "objectClass: top",
           "objectClass: ldapSubEntry",
           "objectClass: subSchema",
           "cn: Schema");
      fail("Expected an exception when trying to add an entry with the null " +
           "DN");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }

    // Test the behavior when trying to add an entry outside the base DN.
    try
    {
      ds.add(
           "dn: o=example.com",
           "objectClass: top",
           "objectClass: organization",
           "o: example.com");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNull(le.getMatchedDN());
    }

    // Tests the behavior when adding multiple valid, acceptable entries.
    assertEquals(ds.countEntries(), 2);
    final Entry[] acceptableEntries =
    {
      new Entry(
           "dn: ou=test 1,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 1"),

      new Entry(
           "dn: ou=test 2,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 2"),
    };
    ds.addEntries(acceptableEntries);
    assertEquals(ds.countEntries(), 4);

    // Tests the behavior when adding entries in which one is unacceptable, and
    // verify that the entry set remains unchanged.
    try
    {
      ds.addEntries(
           "dn: ou=test 3,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 3",
           "",
           "dn: ou=test 3,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test 3");
      fail("Expected an exception when trying to add multiple entries in " +
           "which a subsequent entry is invalid.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }
    finally
    {
      assertEquals(ds.countEntries(), 4);
    }

    // Tests the behavior when adding entries by LDIF string in which the LDIF
    // is malformed.
    try
    {
      ds.addEntries(
           "malformed-entry-line-1",
           "malformed-entry-line-2",
           "",
           "malformed-entry-line-3",
           "malformed-entry-line-4");
      fail("Expected an exception trying to add entries with malformed lines");
    }
    catch (final LDAPException  le)
    {
      assertEquals(le.getResultCode(), ResultCode.PARAM_ERROR);
    }

    // Tests the ability to add valid entries from LDIF lines.
    ds.addEntries(
         "dn: ou=test 3,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 3",
         "",
         "dn: ou=test 4,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test 4");
    assertEquals(ds.countEntries(), 6);
  }



  /**
   * Provides a number of tests for bind processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBind()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    final LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setBindWithDNRequiresPassword(false);

    final LDAPConnection conn = ds.getConnection(options);


    //  Test the ability to bind as a user in the data set with the right
    // password.
    BindResult bindResult =
         conn.bind("uid=test.user,ou=People,dc=example,dc=com", "password");
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    //  Test the ability to with additional bind credentials.
    bindResult = conn.bind("cn=Directory Manager", "password");
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    //  Test the ability to bind with anonymous credentials.
    bindResult = conn.bind("", "");
    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    // Test the behavior when trying to bind as a user that doesn't exist.
    try
    {
      conn.bind("uid=missing,dc=example,dc=com", "password");
      fail("Expected an exception when trying to bind as a user that doesn't " +
           "exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }

    // Test the behavior when trying to bind with the wrong password for a
    // regular user.
    try
    {
      conn.bind("uid=test.user,ou=People,dc=example,dc=com", "wrong");
      fail("Expected an exception when trying to bind with the wrong " +
           "password for a normal user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }

    // Test the behavior when trying to bind with the wrong password for an
    // additional bind user.
    try
    {
      conn.bind("cn=Directory Manager", "wrong");
      fail("Expected an exception when trying to bind with the wrong " +
           "password for an additional bind user.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }

    // Test the behavior when trying to bind with a malformed DN.
    try
    {
      conn.bind("malformed-user-dn", "password");
      fail("Expected an exception when trying to bind with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Test the behavior when trying to bind with a non-empty DN and an empty
    // password.
    try
    {
      conn.bind("uid=test.user,ou=People,dc=example,dc=com", "");
      fail("Expected an exception when trying to bind with an empty password " +
           "and non-empty DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    // Test the behavior when trying to bind with a null DN and non-empty
    // password.
    try
    {
      conn.bind("", "password");
      fail("Expected an exception when trying to bind with an empty DN " +
           "and non-empty password.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }

    // Test the behavior when trying to bind as a user without a password.
    final LDAPResult addResult = conn.add(
         "dn: uid=test.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.2",
         "givenName: Test",
         "sn: 2",
         "cn: Test 2");
    assertEquals(addResult.getResultCode(), ResultCode.SUCCESS);
    try
    {
      conn.bind("uid=test.2,ou=People,dc=example,dc=com", "password");
      fail("Expected an exception when trying to bind as a user without a " +
           "password.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }

    // Test the behavior when trying to bind using SASL authentication.
    try
    {
      conn.bind(new CRAMMD5BindRequest(
           "dn:uid=test.user,ou=People,dc=example,dc=com", "password"));
      fail("Expected an exception when trying to perform an unsupported SASL " +
           "bind.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.AUTH_METHOD_NOT_SUPPORTED);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Provides a set of tests covering the ability to perform a bind directly
   * against the {@code InMemoryDirectoryServer} class without using a
   * connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindDirect()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    BindResult bindResult = ds.bind("cn=Directory Manager", "password");
    assertResultCodeEquals(bindResult, ResultCode.SUCCESS);

    try
    {
      ds.bind("cn=Directory Manager", "wrong");
      fail("Expected an exception when trying to perform a direct simple " +
           "bind with the wrong password");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.INVALID_CREDENTIALS);
    }

    bindResult = ds.bind(new PLAINBindRequest("dn:cn=Directory Manager",
         "password"));
    assertResultCodeEquals(bindResult, ResultCode.SUCCESS);

    try
    {
      ds.bind(new PLAINBindRequest("dn:cn=Directory Manager", "wrong"));
      fail("Expected an exception when trying to perform a direct PLAIN " +
           "bind with the wrong password");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.INVALID_CREDENTIALS);
    }

    try
    {
      ds.bind(new CRAMMD5BindRequest("dn:cn=Directory Manager", "password"));
      fail("Expected an exception when trying to perform a direct CRAM-MD5 " +
           "bind with the wrong password");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.AUTH_METHOD_NOT_SUPPORTED);
    }
  }



  /**
   * Provides a number of tests for compare processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompare()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    // Test the behavior with a compare that matches.
    CompareResult compareResult = conn.compare(
         "uid=test.user,ou=People,dc=example,dc=com", "uid", "test.user");
    assertTrue(compareResult.compareMatched());

    // Test the behavior with a compare that doesn't match, but that has a
    // different value for the target attribute.
    compareResult = conn.compare("uid=test.user,ou=People,dc=example,dc=com",
         "uid", "not.test.user");
    assertFalse(compareResult.compareMatched());

    // Test the behavior with a compare against an entry that doesn't contain
    // the target attribute.
    compareResult = conn.compare("uid=test.user,ou=People,dc=example,dc=com",
         "employeeNumber", "0");
    assertFalse(compareResult.compareMatched());

    // Test the behavior when targeting the root DSE.
    compareResult = conn.compare("", "objectClass", "top");
    assertTrue(compareResult.compareMatched());

    // Test the behavior when targeting the schema subentry.
    compareResult = conn.compare("cn=schema", "cn", "schema");
    assertTrue(compareResult.compareMatched());

    // Test the behavior with a compare against an entry that doesn't exist.
    try
    {
      conn.compare("uid=missing,ou=People,dc=example,dc=com", "uid", "missing");
      fail("Expected an exception when trying to perform a compare for an " +
           "entry that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()),
           new DN("ou=People,dc=example,dc=com"));
    }

    // Test the behavior with a compare with a malformed DN.
    try
    {
      conn.compare("malformed-entry-dn", "uid", "missing");
      fail("Expected an exception when trying to perform a compare with a " +
           "malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Provides a number of tests for delete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDelete()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    // Test the behavior when trying to delete an entry that has a subordinate
    // entry.
    try
    {
      ds.delete("ou=People,dc=example,dc=com");
      fail("Expected an exception when trying to delete an entry with " +
           "children.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_NONLEAF);
    }

    // Test the behavior when trying to perform a delete with a malformed DN.
    try
    {
      ds.delete("malformed-dn");
      fail("Expected an exception when trying to delete with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Test the behavior when trying to perform a delete with a missing entry.
    try
    {
      ds.delete("uid=missing,ou=People,dc=example,dc=com");
      fail("Expected an exception when trying to delete a missing entry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()),
           new DN("ou=People,dc=example,dc=com"));
    }

    // Test the behavior when trying to delete all existing entries in the
    // appropriate order.
    ds.delete("uid=test.user,ou=People,dc=example,dc=com");
    ds.delete("ou=People,dc=example,dc=com");
    ds.delete("dc=example,dc=com");

    // Test the behavior when trying to delete the root DSE.
    try
    {
      conn.delete("");
      fail("Expected an exception when trying to delete the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    // Test the behavior when trying to delete the subschema subentry.
    try
    {
      conn.delete("cn=schema");
      fail("Expected an exception when trying to delete the subschema " +
           "subentry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Provides a number of tests for delete processing with a number of indexes
   * defined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteWithIndexing()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setEqualityIndexAttributes("objectClass", "uid", "givenName", "sn",
         "cn");
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.add(
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

    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    // Test the behavior when trying to delete an entry that has a subordinate
    // entry.
    try
    {
      ds.delete("ou=People,dc=example,dc=com");
      fail("Expected an exception when trying to delete an entry with " +
           "children.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_NONLEAF);
    }

    // Test the behavior when trying to perform a delete with a malformed DN.
    try
    {
      ds.delete("malformed-dn");
      fail("Expected an exception when trying to delete with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Test the behavior when trying to perform a delete with a missing entry.
    try
    {
      ds.delete("uid=missing,ou=People,dc=example,dc=com");
      fail("Expected an exception when trying to delete a missing entry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()),
           new DN("ou=People,dc=example,dc=com"));
    }

    // Test the behavior when trying to delete all existing entries in the
    // appropriate order.
    ds.delete("uid=test.user,ou=People,dc=example,dc=com");
    ds.delete("ou=People,dc=example,dc=com");
    ds.delete("dc=example,dc=com");

    // Test the behavior when trying to delete the root DSE.
    try
    {
      conn.delete("");
      fail("Expected an exception when trying to delete the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    // Test the behavior when trying to delete the subschema subentry.
    try
    {
      conn.delete("cn=schema");
      fail("Expected an exception when trying to delete the subschema " +
           "subentry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    ds.shutDown(true);
  }



  /**
   * Tests the behavior of the method that may be used to delete a subtree.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteSubtree()
         throws Exception
  {
    InMemoryDirectoryServer ds = getTestDS(true, true);
    assertEquals(ds.countEntries(), 3);

    // Test with a malformed base DN.
    try
    {
      ds.deleteSubtree("malformed-base-dn");
      fail("Expected an exception when trying to delete below a malformed " +
           "base DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Test with a base DN equal to the root DSE.
    try
    {
      ds.deleteSubtree("");
      fail("Expected an exception when trying to delete below a the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    // Test deleting everything starting at the base DN.
    assertEquals(ds.deleteSubtree("dc=example,dc=com"), 3);
    assertEquals(ds.countEntries(), 0);

    // Re-populate the server.
    ds = getTestDS(true, true);
    assertEquals(ds.countEntries(), 3);

    // Test deleting a subtree below the base DN.
    assertEquals(ds.deleteSubtree("ou=People,dc=example,dc=com"), 2);
    assertEquals(ds.countEntries(), 1);

    // Re-populate the server.
    ds = getTestDS(true, true);
    assertEquals(ds.countEntries(), 3);

    // Test deleting a leaf entry.
    assertEquals(
         ds.deleteSubtree("uid=test.user,ou=People,dc=example,dc=com"), 1);
    assertEquals(ds.countEntries(), 2);

    // Re-populate the server.
    ds = getTestDS(true, true);
    assertEquals(ds.countEntries(), 3);

    // Test deleting a nonexistent entry.
    assertEquals(
         ds.deleteSubtree("ou=Nonexistent,dc=example,dc=com"), 0);
    assertEquals(ds.countEntries(), 3);
  }



  /**
   * Provides a number of tests for modify processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModify()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    ds.add(
         "dn: employeeNumber=1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "employeeNumber: 1",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1");

    // Provide basic coverage for the various modify methods with
    // successful modifications
    ds.modify("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"));

    ds.modify("dc=example,dc=com", Arrays.asList(
         new Modification(ModificationType.REPLACE, "description", "bar")));

    ds.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: baz");

    // Tests the behavior when trying to modify an entry that doesn't exist.
    try
    {
      ds.modify(
           "dn: cn=missing,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
      fail("Expected an exception when trying to modify a nonexistent entry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }

    // Tests the behavior when trying to perform a modify with a malformed DN.
    try
    {
      ds.modify(
           "dn: malformed-dn",
           "changetype: modify",
           "replace: description",
           "description: foo");
      fail("Expected an exception when trying to modify with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Tests the behavior when trying to perform a modify with malformed LDIF.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: malformed");
      fail("Expected an exception when trying to modify with malformed LDIF.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
    }

    // Tests the behavior when trying to perform a modify that would violate
    // schema.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "add: uid",
           "uid: attribute.not.allowed");
      fail("Expected an exception when trying to modify with a schema " +
           "violation");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    // Tests the behavior when trying to perform a modify that would remove the
    // entire RDN attribute.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "delete: dc");
      fail("Expected an exception when trying to delete the RDN attribute.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to perform a modify that would remove the
    // RDN value.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "delete: dc",
           "dc: example");
      fail("Expected an exception when trying to delete the RDN value.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to perform a modify that would replace the
    // RDN value.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: dc",
           "dc: new");
      fail("Expected an exception when trying to replace the RDN value.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to perform a modify that would increment
    // the RDN value.
    try
    {
      ds.modify(
           "dn: employeeNumber=1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "increment: employeeNumber",
           "employeeNumber: 1");
      fail("Expected an exception when trying to increment the RDN value.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to modify the root DSE.
    try
    {
      ds.modify(
           "dn: ",
           "changetype: modify",
           "add: supportedFeatures",
           "supportedFeatures: 1.2.3.4");
      fail("Expected an exception when trying to modify the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }
  }



  /**
   * Provides a number of tests for modify processing with indexing enabled.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyWithIndexing()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setEqualityIndexAttributes("objectClass", "uid", "givenName", "sn",
         "cn");
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.add(
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
    ds.add(
         "dn: employeeNumber=1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "employeeNumber: 1",
         "uid: user.1",
         "givenName: User",
         "sn: 1",
         "cn: User 1");

    // Provide basic coverage for the various modify methods with
    // successful modifications
    ds.modify("dc=example,dc=com",
         new Modification(ModificationType.REPLACE, "description", "foo"));

    ds.modify("dc=example,dc=com", Arrays.asList(
         new Modification(ModificationType.REPLACE, "description", "bar")));

    ds.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: baz");

    // Tests the behavior when trying to modify an entry that doesn't exist.
    try
    {
      ds.modify(
           "dn: cn=missing,dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
      fail("Expected an exception when trying to modify a nonexistent entry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }

    // Tests the behavior when trying to perform a modify with a malformed DN.
    try
    {
      ds.modify(
           "dn: malformed-dn",
           "changetype: modify",
           "replace: description",
           "description: foo");
      fail("Expected an exception when trying to modify with a malformed DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    // Tests the behavior when trying to perform a modify with malformed LDIF.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: malformed");
      fail("Expected an exception when trying to modify with malformed LDIF.");
    }
    catch (final LDIFException le)
    {
      // This was expected.
    }

    // Tests the behavior when trying to perform a modify that would violate
    // schema.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "add: uid",
           "uid: attribute.not.allowed");
      fail("Expected an exception when trying to modify with a schema " +
           "violation");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    // Tests the behavior when trying to perform a modify that would remove the
    // entire RDN attribute.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "delete: dc");
      fail("Expected an exception when trying to delete the RDN attribute.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to perform a modify that would remove the
    // RDN value.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "delete: dc",
           "dc: example");
      fail("Expected an exception when trying to delete the RDN value.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to perform a modify that would replace the
    // RDN value.
    try
    {
      ds.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: dc",
           "dc: new");
      fail("Expected an exception when trying to replace the RDN value.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to perform a modify that would increment
    // the RDN value.
    try
    {
      ds.modify(
           "dn: employeeNumber=1,ou=People,dc=example,dc=com",
           "changetype: modify",
           "increment: employeeNumber",
           "employeeNumber: 1");
      fail("Expected an exception when trying to increment the RDN value.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NOT_ALLOWED_ON_RDN);
    }

    // Tests the behavior when trying to modify the root DSE.
    try
    {
      ds.modify(
           "dn: ",
           "changetype: modify",
           "add: supportedFeatures",
           "supportedFeatures: 1.2.3.4");
      fail("Expected an exception when trying to modify the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }
  }



  /**
   * Provides a number of tests for modify DN processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDN()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();


    // Test the behavior when trying to rename a leaf entry.
    assertNotNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));

    Entry e = ds.getEntry("uid=test.user,ou=People,dc=example,dc=com");
    assertTrue(e.hasAttributeValue("uid", "test.user"));
    assertTrue(e.hasAttributeValue("cn", "Test User"));

    LDAPResult result =
         conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
              "cn=Test User", false);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));

    e = ds.getEntry("cn=Test User,ou=People,dc=example,dc=com");
    assertNotNull(e);
    assertTrue(e.hasAttributeValue("uid", "test.user"));
    assertTrue(e.hasAttributeValue("cn", "Test User"));


    // Test the behavior when trying to rename a nonleaf entry.
    assertNotNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("ou=Users,dc=example,dc=com"));

    e = ds.getEntry("ou=People,dc=example,dc=com");
    assertNotNull(e);
    assertTrue(e.hasAttributeValue("ou", "People"));
    assertFalse(e.hasAttributeValue("ou", "Users"));

    result = conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("ou=Users,dc=example,dc=com"));

    e = ds.getEntry("ou=Users,dc=example,dc=com");
    assertNotNull(e);
    assertFalse(e.hasAttributeValue("ou", "People"));
    assertTrue(e.hasAttributeValue("ou", "Users"));

    assertNotNull(ds.getEntry("cn=Test User,ou=Users,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));


    // Test the behavior when trying to move an entry below a new parent.
    result = conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=Test User,ou=Users,dc=example,dc=com"));

    result = conn.modifyDN("cn=Test User,ou=Users,dc=example,dc=com",
         "uid=test.user", false, "ou=People,dc=example,dc=com");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));


    // Test the behavior when trying to perform a modify DN with a malformed
    // target DN, new RDN, and new superior DN.
    try
    {
      conn.modifyDN("malformed-target-dn", "cn=New RDN", false);
      fail("Expected an exception when trying to perform a modify DN with a " +
           "malformed target DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "malformed",
           false);
      fail("Expected an exception when trying to perform a modify DN with a " +
           "malformed new RDN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=Test User",
           false, "malformed-new-superior");
      fail("Expected an exception when trying to perform a modify DN with a " +
           "malformed new superior DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test the behavior when trying to perform a modify DN in which the target
    // entry does not exist.
    try
    {
      conn.modifyDN("cn=missing,dc=example,dc=com", "cn=new", true);
      fail("Expected an exception when trying to rename an entry that " +
           "doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test the behavior when trying to perform a modify DN in which the new
    // superior entry doesn't exist.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "cn=Test User", false, "cn=missing,dc=example,dc=com");
      fail("Expected an exception when trying to rename an entry with a new " +
           "superior that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test the behavior when trying to perform a modify DN in a manner that
    // would conflict with an existing entry.
    ds.add(
         "dn: uid=another.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: another.user",
         "givenName: Another",
         "sn: User",
         "cn: Another User");

    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "uid=another.user", true);
      fail("Expected an exception when trying to rename an entry in a manner " +
           "that conflicts with an existing entry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }


    // Test the behavior when trying to rename the root DSE.
    try
    {
      conn.modifyDN("", "cn=Root DSE", false, "dc=example,dc=com");
      fail("Expected an exception when trying to rename the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Test the behavior when trying to rename an entry to the root DSE.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "", false, "");
      fail("Expected an exception when trying to rename an entry to be the " +
           "root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test the behavior when trying to rename the schema subentry.
    try
    {
      conn.modifyDN("cn=schema", "cn=old schema", false, "dc=example,dc=com");
      fail("Expected an exception when trying to rename the schema subentry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Test the behavior when trying to rename an entry to the schema subentry.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=schema",
           false, "");
      fail("Expected an exception when trying to rename an entry to be the " +
           "schema subentry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }


    // Test the behavior when trying to perform a rename in which the new DN
    // matches the old DN.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "uid=test.user", false);
      fail("Expected an exception when trying to rename an entry with the " +
           "same DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Test the behavior when trying to rename an entry that was previously a
    // base DN.
    ds.add(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com");
    assertNotNull(ds.getEntry("o=example.com"));
    assertNull(ds.getEntry("o=example.com,dc=example,dc=com"));

    result = conn.modifyDN("o=example.com", "o=example.com", false,
         "dc=example,dc=com");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("o=example.com"));
    assertNotNull(ds.getEntry("o=example.com,dc=example,dc=com"));


    // Test the behavior when trying to rename a non-base entry to be a
    // base DN.
    result = conn.modifyDN("o=example.com,dc=example,dc=com", "o=example.com",
         false, "");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(ds.getEntry("o=example.com"));
    assertNull(ds.getEntry("o=example.com,dc=example,dc=com"));


    // Test the behavior when trying to perform a modify DN in a manner that
    // would violate the schema.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "dc=not allowed in user", false, null);
      fail("Expected an exception when trying to perform a modify DN in a " +
           "manner that would violate schema.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Provides a number of tests for modify DN processing with indexes
   * configured.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyDNWithIndexing()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    cfg.setEqualityIndexAttributes("objectClass", "uid", "givenName", "sn",
         "cn");
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.add(
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

    ds.startListening();

    final LDAPConnection conn = ds.getConnection();


    // Test the behavior when trying to rename a leaf entry.
    assertNotNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));

    Entry e = ds.getEntry("uid=test.user,ou=People,dc=example,dc=com");
    assertTrue(e.hasAttributeValue("uid", "test.user"));
    assertTrue(e.hasAttributeValue("cn", "Test User"));

    LDAPResult result =
         conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
              "cn=Test User", false);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));

    e = ds.getEntry("cn=Test User,ou=People,dc=example,dc=com");
    assertNotNull(e);
    assertTrue(e.hasAttributeValue("uid", "test.user"));
    assertTrue(e.hasAttributeValue("cn", "Test User"));


    // Test the behavior when trying to rename a nonleaf entry.
    assertNotNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("ou=Users,dc=example,dc=com"));

    e = ds.getEntry("ou=People,dc=example,dc=com");
    assertNotNull(e);
    assertTrue(e.hasAttributeValue("ou", "People"));
    assertFalse(e.hasAttributeValue("ou", "Users"));

    result = conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("ou=Users,dc=example,dc=com"));

    e = ds.getEntry("ou=Users,dc=example,dc=com");
    assertNotNull(e);
    assertFalse(e.hasAttributeValue("ou", "People"));
    assertTrue(e.hasAttributeValue("ou", "Users"));

    assertNotNull(ds.getEntry("cn=Test User,ou=Users,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));


    // Test the behavior when trying to move an entry below a new parent.
    result = conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNotNull(ds.getEntry("cn=Test User,ou=Users,dc=example,dc=com"));

    result = conn.modifyDN("cn=Test User,ou=Users,dc=example,dc=com",
         "uid=test.user", false, "ou=People,dc=example,dc=com");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(ds.getEntry("uid=test.user,ou=People,dc=example,dc=com"));
    assertNull(ds.getEntry("cn=Test User,ou=People,dc=example,dc=com"));


    // Test the behavior when trying to perform a modify DN with a malformed
    // target DN, new RDN, and new superior DN.
    try
    {
      conn.modifyDN("malformed-target-dn", "cn=New RDN", false);
      fail("Expected an exception when trying to perform a modify DN with a " +
           "malformed target DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "malformed",
           false);
      fail("Expected an exception when trying to perform a modify DN with a " +
           "malformed new RDN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=Test User",
           false, "malformed-new-superior");
      fail("Expected an exception when trying to perform a modify DN with a " +
           "malformed new superior DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test the behavior when trying to perform a modify DN in which the target
    // entry does not exist.
    try
    {
      conn.modifyDN("cn=missing,dc=example,dc=com", "cn=new", true);
      fail("Expected an exception when trying to rename an entry that " +
           "doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test the behavior when trying to perform a modify DN in which the new
    // superior entry doesn't exist.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "cn=Test User", false, "cn=missing,dc=example,dc=com");
      fail("Expected an exception when trying to rename an entry with a new " +
           "superior that doesn't exist.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test the behavior when trying to perform a modify DN in a manner that
    // would conflict with an existing entry.
    ds.add(
         "dn: uid=another.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: another.user",
         "givenName: Another",
         "sn: User",
         "cn: Another User");

    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "uid=another.user", true);
      fail("Expected an exception when trying to rename an entry in a manner " +
           "that conflicts with an existing entry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }


    // Test the behavior when trying to rename the root DSE.
    try
    {
      conn.modifyDN("", "cn=Root DSE", false, "dc=example,dc=com");
      fail("Expected an exception when trying to rename the root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Test the behavior when trying to rename an entry to the root DSE.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "", false, "");
      fail("Expected an exception when trying to rename an entry to be the " +
           "root DSE.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test the behavior when trying to rename the schema subentry.
    try
    {
      conn.modifyDN("cn=schema", "cn=old schema", false, "dc=example,dc=com");
      fail("Expected an exception when trying to rename the schema subentry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Test the behavior when trying to rename an entry to the schema subentry.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=schema",
           false, "");
      fail("Expected an exception when trying to rename an entry to be the " +
           "schema subentry.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.ENTRY_ALREADY_EXISTS);
    }


    // Test the behavior when trying to perform a rename in which the new DN
    // matches the old DN.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "uid=test.user", false);
      fail("Expected an exception when trying to rename an entry with the " +
           "same DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }


    // Test the behavior when trying to rename an entry that was previously a
    // base DN.
    ds.add(
         "dn: o=example.com",
         "objectClass: top",
         "objectClass: organization",
         "o: example.com");
    assertNotNull(ds.getEntry("o=example.com"));
    assertNull(ds.getEntry("o=example.com,dc=example,dc=com"));

    result = conn.modifyDN("o=example.com", "o=example.com", false,
         "dc=example,dc=com");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNull(ds.getEntry("o=example.com"));
    assertNotNull(ds.getEntry("o=example.com,dc=example,dc=com"));


    // Test the behavior when trying to rename a non-base entry to be a
    // base DN.
    result = conn.modifyDN("o=example.com,dc=example,dc=com", "o=example.com",
         false, "");
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    assertNotNull(ds.getEntry("o=example.com"));
    assertNull(ds.getEntry("o=example.com,dc=example,dc=com"));


    // Test the behavior when trying to perform a modify DN in a manner that
    // would violate the schema.
    try
    {
      conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com",
           "dc=not allowed in user", false, null);
      fail("Expected an exception when trying to perform a modify DN in a " +
           "manner that would violate schema.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    ds.shutDown(true);
  }



  /**
   * Provides a number of tests for search processing in the directory server
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithoutConnection()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    assertEquals(ds.countEntries(), 3);


    // Test a basic search that returns everything.
    SearchResult searchResult = ds.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    List<SearchResultEntry> entryList = searchResult.getSearchEntries();

    assertEquals(entryList.size(), 3);
    assertEquals(entryList.get(0).getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test the same search with a base-level scope.
    searchResult = ds.search("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 1);
    assertEquals(entryList.get(0).getParsedDN(), new DN("dc=example,dc=com"));


    // Test the same search with a single-level scope.
    searchResult = ds.search("dc=example,dc=com", SearchScope.ONE,
         "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 1);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));


    // Test the same search with a subordinate subtree scope.
    searchResult = ds.search("dc=example,dc=com",
         SearchScope.SUBORDINATE_SUBTREE, "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 2);
    assertEquals(entryList.get(0).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a search with a filter that doesn't match anything.
    searchResult = ds.search("dc=example,dc=com", SearchScope.SUB,
         "(cn=does not match)");
    entryList = searchResult.getSearchEntries();
    assertTrue(entryList.isEmpty());


    // Test a search with a missing base DN.
    try
    {
      ds.search("cn=missing,dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)");
      fail("Expected an exception with a missing search base.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test a search with a malformed base DN.
    try
    {
      ds.search("malformed-base-dn", SearchScope.BASE, "(objectClass=*)");
      fail("Expected an exception with a malformed search base.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test a search to retrieve the root DSE.
    searchResult = ds.search("", SearchScope.BASE, "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 1);
    assertEquals(entryList.get(0).getParsedDN(), DN.NULL_DN);


    // Test a search to retrieve entries below the root DSE.
    searchResult = ds.search("", SearchScope.SUB, "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 3);
    assertEquals(entryList.get(0).getParsedDN(), new DN("dc=example,dc=com"));
    assertEquals(entryList.get(1).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(entryList.get(2).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a single-level search below the root DSE.
    searchResult = ds.search("", SearchScope.ONE, "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 1);
    assertEquals(entryList.get(0).getParsedDN(), new DN("dc=example,dc=com"));


    // Test a search to retrieve the schema subentry.
    searchResult = ds.search("cn=schema", SearchScope.BASE, "(objectClass=*)");
    entryList = searchResult.getSearchEntries();
    assertEquals(entryList.size(), 1);
    assertEquals(entryList.get(0).getParsedDN(), new DN("cn=schema"));
  }



  /**
   * Provides a number of tests for search processing as an LDAP client.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithConnection()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();
    assertEquals(ds.countEntries(), 3);

    // Test a basic search that returns everything.
    SearchResult searchResult = conn.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(2).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test the same search with a base-level scope.
    searchResult = conn.search("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));


    // Test the same search with a one-level scope.
    searchResult = conn.search("dc=example,dc=com", SearchScope.ONE,
         "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));


    // Test the same search with a subordinate subtree scope.
    searchResult = conn.search("dc=example,dc=com",
         SearchScope.SUBORDINATE_SUBTREE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a search with a filter that doesn't match anything.
    searchResult = conn.search("dc=example,dc=com", SearchScope.SUB,
         "(cn=does not match)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 0);


    // Test a search with a missing base DN.
    try
    {
      conn.search("cn=missing,dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)");
      fail("Expected an exception for a search with a missing base DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test a search with a malformed base DN.
    try
    {
      conn.search("malformed-base-dn", SearchScope.BASE,
           "(objectClass=*)");
      fail("Expected an exception for a search with a malformed base DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test a search to retrieve the root DSE.
    searchResult = conn.search("", SearchScope.BASE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertTrue(searchResult.getSearchEntries().get(0).getParsedDN().isNullDN());


    // Test a search to retrieve entries below the root DSE.
    searchResult = conn.search("", SearchScope.SUB, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(2).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a single-level search below the root DSE.
    searchResult = conn.search("", SearchScope.ONE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));


    // Test a search to retrieve the schema subentry.
    searchResult =
         conn.search("cn=schema", SearchScope.BASE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("cn=schema"));


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Provides a number of tests for search processing as an LDAP client with
   * indexes defined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithIndex()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setEqualityIndexAttributes("objectClass", "uid", "givenName", "sn",
         "cn");
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    ds.add(
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

    ds.startListening();

    final LDAPConnection conn = ds.getConnection();
    assertEquals(ds.countEntries(), 3);

    // Test a basic search that returns everything.
    SearchResult searchResult = conn.search("dc=example,dc=com",
         SearchScope.SUB, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(2).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test the same search with a base-level scope.
    searchResult = conn.search("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));


    // Test the same search with a one-level scope.
    searchResult = conn.search("dc=example,dc=com", SearchScope.ONE,
         "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));


    // Test the same search with a subordinate subtree scope.
    searchResult = conn.search("dc=example,dc=com",
         SearchScope.SUBORDINATE_SUBTREE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 2);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a search with a filter that doesn't match anything.
    searchResult = conn.search("dc=example,dc=com", SearchScope.SUB,
         "(cn=does not match)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 0);


    // Test a search with a missing base DN.
    try
    {
      conn.search("cn=missing,dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)");
      fail("Expected an exception for a search with a missing base DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.NO_SUCH_OBJECT);
      assertNotNull(le.getMatchedDN());
      assertEquals(new DN(le.getMatchedDN()), new DN("dc=example,dc=com"));
    }


    // Test a search with a malformed base DN.
    try
    {
      conn.search("malformed-base-dn", SearchScope.BASE,
           "(objectClass=*)");
      fail("Expected an exception for a search with a malformed base DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }


    // Test a search to retrieve the root DSE.
    searchResult = conn.search("", SearchScope.BASE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertTrue(searchResult.getSearchEntries().get(0).getParsedDN().isNullDN());


    // Test a search to retrieve entries below the root DSE.
    searchResult = conn.search("", SearchScope.SUB, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 3);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(1).getParsedDN(),
         new DN("ou=People,dc=example,dc=com"));
    assertEquals(searchResult.getSearchEntries().get(2).getParsedDN(),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test a single-level search below the root DSE.
    searchResult = conn.search("", SearchScope.ONE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("dc=example,dc=com"));


    // Test a search to retrieve the schema subentry.
    searchResult =
         conn.search("cn=schema", SearchScope.BASE, "(objectClass=*)");
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 1);
    assertEquals(searchResult.getSearchEntries().get(0).getParsedDN(),
         new DN("cn=schema"));


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    ds.shutDown(true);
  }



  /**
   * Tests to ensure that search requests with a requested attribute list are
   * processed correctly.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRequestedAttributes()
         throws Exception
  {
    final Schema s = Schema.getDefaultStandardSchema();

    final InMemoryDirectoryServer ds = getTestDS(true, true);


    // Update the test entry to include an attribute with options.
    ds.modify(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "changetype: modify",
         "add: description",
         "description: Test Generic",
         "-",
         "add: description;lang-en-us;x-my-option",
         "description;lang-en-us;x-my-option: Test English",
         "-",
         "add: description;lang-es;x-my-option",
         "description;lang-es;x-my-option: Test Espanol");


    final LDAPConnection conn = ds.getConnection();


    // Test the root DSE without any requested attributes, so only user
    // attributes should be returned.
    Entry e = conn.getEntry("");
    assertNotNull(e);
    for (final Attribute a : e.getAttributes())
    {
      assertFalse(isOperational(a, s), "Search with no requested attrs " +
           "returned an operational attribute " + a);
    }
    assertTrue(e.hasAttribute("objectClass"));
    assertFalse(e.hasAttribute("subschemaSubentry"));


    // Test the root DSE with an explicitly-requested "*", so only user
    // attributes should be returned.
    e = conn.getEntry("", "*");
    assertNotNull(e);
    for (final Attribute a : e.getAttributes())
    {
      assertFalse(isOperational(a, s), "Search with requested attrs '*' " +
           "returned an operational attribute " + a);
    }
    assertTrue(e.hasAttribute("objectClass"));
    assertFalse(e.hasAttribute("subschemaSubentry"));


    // Test the root DSE with an explicitly-requested "+", so only operational
    // attributes should be returned.
    e = conn.getEntry("", "+");
    assertNotNull(e);
    for (final Attribute a : e.getAttributes())
    {
      assertTrue(isOperational(a, s), "Search with requested attrs '+' " +
           "returned a user attribute " + a);
    }
    assertFalse(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttribute("subschemaSubentry"));


    // Test the root DSE with an explicitly-requested "*" and "+", so both user
    // and operational attributes should be returned.
    e = conn.getEntry("", "*", "+");
    assertNotNull(e);

    boolean userFound = false;
    boolean operationalFound = false;
    for (final Attribute a : e.getAttributes())
    {
      if (isOperational(a, s))
      {
        operationalFound = true;
      }
      else
      {
        userFound = true;
      }
    }
    assertTrue(userFound, "Search with requested attrs '*,+' didn't return " +
         "any user attributes");
    assertTrue(operationalFound, "Search with requested attrs '*,+' didn't " +
         "return any operational attributes");
    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttribute("subschemaSubentry"));


    // Test the root DSE with an explicitly-requested "1.1", so no attributes
    // should be returned.
    e = conn.getEntry("", "1.1");
    assertNotNull(e);
    assertTrue(e.getAttributes().isEmpty());
    assertFalse(e.hasAttribute("objectClass"));
    assertFalse(e.hasAttribute("subschemaSubentry"));


    // Test the root DSE with an explicitly-requested subschemaSubentry
    // attribute so only it should be returned.
    e = conn.getEntry("", "subschemaSubentry");
    assertNotNull(e);
    assertEquals(e.getAttributes().size(), 1);
    assertTrue(e.hasAttribute("subschemaSubentry"));


    // Test the ability to retrieve attributes by object class.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com",
         "@person");
    assertNotNull(e);
    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttribute("cn"));
    assertTrue(e.hasAttribute("sn"));
    assertTrue(e.hasAttribute("userPassword"));
    assertFalse(e.hasAttribute("uid"));
    assertFalse(e.hasAttribute("givenName"));


    // Test the ability to retrieve a mix of explicit attributes and attributes
    // by object class.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com", "uid",
         "@person");
    assertNotNull(e);
    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttribute("cn"));
    assertTrue(e.hasAttribute("sn"));
    assertTrue(e.hasAttribute("userPassword"));
    assertTrue(e.hasAttribute("uid"));
    assertFalse(e.hasAttribute("givenName"));


    // Test to ensure that a request to retrieve an attribute without options
    // retrieves all attributes with that base name and all sets of options.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com",
         "description");
    assertNotNull(e);
    assertTrue(e.hasAttribute("description"));
    assertTrue(e.hasAttribute("description;lang-en-us;x-my-option"));
    assertTrue(e.hasAttribute("description;lang-es;x-my-option"));


    // Test to ensure that a request to retrieve an attribute with options
    // retrieves only attributes that have those options.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com",
         "description;x-my-option");
    assertNotNull(e);
    assertFalse(e.hasAttribute("description"));
    assertTrue(e.hasAttribute("description;lang-en-us;x-my-option"));
    assertTrue(e.hasAttribute("description;lang-es;x-my-option"));


    // Test with multiple options in a different order.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com",
         "description;x-my-option;lang-en-us");
    assertNotNull(e);
    assertFalse(e.hasAttribute("description"));
    assertTrue(e.hasAttribute("description;lang-en-us;x-my-option"));
    assertFalse(e.hasAttribute("description;lang-es;x-my-option"));


    // Test to ensure that a request to retrieve a superior type will also
    // return all subtypes.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com", "name");
    assertNotNull(e);
    assertTrue(e.hasAttribute("cn"));
    assertTrue(e.hasAttribute("givenName"));
    assertTrue(e.hasAttribute("sn"));


    // Test to ensure that a request to retrieve an attribute not defined in
    // the schema will be handled when by itself.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com", "undefined");
    assertNotNull(e);
    assertTrue(e.getAttributes().isEmpty());


    // Test to ensure that a request to retrieve an attribute not defined in
    // the schema will be handled when mixed with other attributes.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com", "name",
         "undefined");
    assertNotNull(e);
    assertTrue(e.hasAttribute("cn"));
    assertTrue(e.hasAttribute("givenName"));
    assertTrue(e.hasAttribute("sn"));


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that the server will return an error response when trying
   * to perform a search with an unsupported filter type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSupportedFilterTypes()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    try (LDAPConnection conn = ds.getConnection())
    {
      // Presence filters should always be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createPresenceFilter("objectClass")),
           ResultCode.SUCCESS);

      // Presence filters should always be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createPresenceFilter("objectClass"),
                     Filter.createPresenceFilter("uid"))),
           ResultCode.SUCCESS);

      // Presence filters should always be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createPresenceFilter("objectClass"),
                     Filter.createPresenceFilter("uid"))),
           ResultCode.SUCCESS);

      // Presence filters should always be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createPresenceFilter("objectClass"))),
           ResultCode.SUCCESS);

      // Equality filters should always be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createEqualityFilter("uid", "test.user")),
           ResultCode.SUCCESS);

      // Equality filters should always be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createEqualityFilter("givenName", "Test"),
                     Filter.createEqualityFilter("sn", "User"))),
           ResultCode.SUCCESS);

      // Equality filters should always be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createEqualityFilter("givenName", "Test"),
                     Filter.createEqualityFilter("sn", "User"))),
           ResultCode.SUCCESS);

      // Equality filters should always be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createEqualityFilter("uid", "test.user"))),
           ResultCode.SUCCESS);

      // Substring filters should always be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createSubstringFilter("givenName", "T", null, null)),
           ResultCode.SUCCESS);

      // Substring filters should always be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createSubstringFilter("givenName", "T", null, null),
                     Filter.createSubstringFilter("sn", "U", null, null))),
           ResultCode.SUCCESS);

      // Substring filters should always be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createSubstringFilter("givenName", "T", null, null),
                     Filter.createSubstringFilter("sn", "U", null, null))),
           ResultCode.SUCCESS);

      // Substring filters should always be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createSubstringFilter("givenName", "T", null,
                          null))),
           ResultCode.SUCCESS);

      // Greater-or-equal filters should always be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createGreaterOrEqualFilter("givenName", "T")),
           ResultCode.SUCCESS);

      // Greater-or-equal filters should always be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createGreaterOrEqualFilter("givenName", "T"),
                     Filter.createGreaterOrEqualFilter("sn", "U"))),
           ResultCode.SUCCESS);

      // Greater-or-equal filters should always be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createGreaterOrEqualFilter("givenName", "T"),
                     Filter.createGreaterOrEqualFilter("sn", "U"))),
           ResultCode.SUCCESS);

      // Greater-or-equal filters should always be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createGreaterOrEqualFilter("givenName", "T"))),
           ResultCode.SUCCESS);

      // Less-or-equal filters should always be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createLessOrEqualFilter("givenName", "T")),
           ResultCode.SUCCESS);

      // Less-or-equal filters should always be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createLessOrEqualFilter("givenName", "T"),
                     Filter.createLessOrEqualFilter("sn", "U"))),
           ResultCode.SUCCESS);

      // Less-or-equal filters should always be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createLessOrEqualFilter("givenName", "T"),
                     Filter.createLessOrEqualFilter("sn", "U"))),
           ResultCode.SUCCESS);

      // Less-or-equal filters should always be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createLessOrEqualFilter("givenName", "T"))),
           ResultCode.SUCCESS);

      // Approximate-match filters should never be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createApproximateMatchFilter("givenName", "Test")),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Approximate-match filters should never be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createApproximateMatchFilter("givenName", "Test"),
                     Filter.createApproximateMatchFilter("sn", "User"))),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Approximate-match filters should never be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createApproximateMatchFilter("givenName", "Test"),
                     Filter.createApproximateMatchFilter("sn", "User"))),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Approximate-match filters should never be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createApproximateMatchFilter("uid", "test.user"))),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Extensible-match filters should never be supported on their own.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createExtensibleMatchFilter("givenName", null, false,
                     "Test")),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Extensible-match filters should never be supported inside an AND.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createANDFilter(
                     Filter.createExtensibleMatchFilter("givenName", null,
                          false, "Test"),
                     Filter.createExtensibleMatchFilter("sn", null, false,
                          "User"))),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Extensible-match filters should never be supported inside an OR.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createORFilter(
                     Filter.createExtensibleMatchFilter("givenName", null,
                          false, "Test"),
                     Filter.createExtensibleMatchFilter("sn", null, false,
                          "User"))),
           ResultCode.INAPPROPRIATE_MATCHING);

      // Extensible-match filters should never be supported inside a NOT.
      assertResultCodeEquals(conn,
           new SearchRequest("uid=test.user,ou=People,dc=example,dc=com",
                SearchScope.BASE,
                Filter.createNOTFilter(
                     Filter.createExtensibleMatchFilter("uid", null, false,
                          "test.user"))),
           ResultCode.INAPPROPRIATE_MATCHING);
    }
  }



  /**
   * Indicates whether the provided attribute is operational.
   *
   * @param  a  The attribute for which to make the determination.
   * @param  s  The schema to use when making the determination.
   *
   * @return  {@code true} if the attribute is operational, or {@code false} if
   *          not.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static boolean isOperational(final Attribute a, final Schema s)
          throws Exception
  {
    final String baseName = a.getBaseName();
    final AttributeTypeDefinition at = s.getAttributeType(baseName);
    return at.isOperational();
  }



  /**
   * Tests to ensure that requests containing unsupported controls will fail.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectControls()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final Control control = new Control("1.2.3.4", true);


    // Test an add request.
    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test");
    addRequest.addControl(control);

    try
    {
      conn.add(addRequest);
      fail("Expected an exception when trying to process an add with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    // Test a bind request.
    final SimpleBindRequest bindRequest =
         new SimpleBindRequest("", "", control);

    try
    {
      conn.bind(bindRequest);
      fail("Expected an exception when trying to process a bind with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    // Test a compare request.
    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "dc", "example");
    compareRequest.addControl(control);

    try
    {
      conn.compare(compareRequest);
      fail("Expected an exception when trying to process a compare with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    // Test a delete request.
    final DeleteRequest deleteRequest =
         new DeleteRequest("uid=test.user,ou=People,dc=example,dc=com");
    deleteRequest.addControl(control);

    try
    {
      conn.delete(deleteRequest);
      fail("Expected an exception when trying to process a delete with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    // Test a modify request.
    final ModifyRequest modifyRequest =
         new ModifyRequest(
              "dn: dc=example,dc=com",
              "changetype: modify",
              "replace: description",
              "description: foo");
    modifyRequest.addControl(control);

    try
    {
      conn.modify(modifyRequest);
      fail("Expected an exception when trying to process a modify with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    // Test a modify DN request.
    final ModifyDNRequest modifyDNRequest =
         new ModifyDNRequest("ou=People,dc=example,dc=com", "ou=Users", false);
    modifyDNRequest.addControl(control);

    try
    {
      conn.modifyDN(modifyDNRequest);
      fail("Expected an exception when trying to process a modify DN with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    // Test a search request.
    final SearchRequest searchRequest =
         new SearchRequest("dc=example,dc=com", SearchScope.SUB,
              "(objectClass=*)");
    searchRequest.addControl(control);

    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to process a search with an " +
           "unsupported critical control.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that entries including the extensibleObject object class
   * will be allowed to include attributes that would otherwise not be allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExtensibleObject()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final Entry e = new Entry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "member: uid=test.user,ou=People,dc=example,dc=com");

    // Ensure that the add attempt fails without extensible object.
    try
    {
      conn.add(e);
      fail("Expected an exception when trying to add an entry with a " +
           "non-allowed attribute and without extensibleObject.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.OBJECT_CLASS_VIOLATION);
    }

    // Add the extensibleObject object class and verify that the add is allowed.
    e.addAttribute("objectClass", "extensibleObject");
    final LDAPResult result = conn.add(e);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that an add will automatically include RDN attribute values
   * if they weren't present in the entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMissingRDNAttributes()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    Entry e = new Entry(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit");
    assertFalse(e.hasAttribute("ou"));
    assertFalse(e.hasAttributeValue("ou", "test"));

    final LDAPResult result = conn.add(e);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);

    e = ds.getEntry("ou=test,dc=example,dc=com");
    assertNotNull(e);
    assertTrue(e.hasAttribute("ou"));
    assertTrue(e.hasAttributeValue("ou", "test"));

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that write attempts will be rejected if they target
   * attributes marked with NO-USER-MODIFICATION.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoUserModification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();


    // Ensure that an add is properly rejected.
    try
    {
      conn.add(
           "dn: ou=test,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test",
           "entryUUID: " + UUID.randomUUID().toString());
      fail("Expected an exception when trying to add an entry with a " +
           "NO-USER-MODIFICATION attribute.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONSTRAINT_VIOLATION);
    }


    // Ensure that the add is allowed if the ignore NO-USER-MODIFICATION request
    // control is included in the request.
    final AddRequest addRequest = new AddRequest(
         "dn: ou=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: test",
         "entryUUID: " + UUID.randomUUID().toString());
    addRequest.addControl(new IgnoreNoUserModificationRequestControl());
    assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);
    assertResultCodeEquals(conn,
         new DeleteRequest("ou=test,dc=example,dc=com"), ResultCode.SUCCESS);


    // Ensure that a modification is properly rejected.
    try
    {
      conn.modify(
           "dn: ou=People,dc=example,dc=com",
           "changetype: modify",
           "replace: entryUUID",
           "entryUUID: " + UUID.randomUUID().toString());
      fail("Expected an exception when trying to modify an attribute with " +
           "NO-USER-MODIFICATION.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONSTRAINT_VIOLATION);
    }


    // Ensure that modify requests can't have the ignore NO-USER-MODIFICATION
    // request control, whether it is critical or non-critical.
    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: ou=People,dc=example,dc=com",
         "changetype: modify",
         "replace: entryUUID",
         "entryUUID: " + UUID.randomUUID().toString());
    modifyRequest.addControl(new Control(
         IgnoreNoUserModificationRequestControl.
              IGNORE_NO_USER_MODIFICATION_REQUEST_OID,
         true));
    assertResultCodeEquals(conn, modifyRequest,
         ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);

    modifyRequest.setControls(new Control(
         IgnoreNoUserModificationRequestControl.
              IGNORE_NO_USER_MODIFICATION_REQUEST_OID,
         false));
    assertResultCodeEquals(conn, modifyRequest,
         ResultCode.CONSTRAINT_VIOLATION);


    // It should be possible to rename an entry to use its existing entryUUID.
    final Entry userEntry =
         ds.getEntry("uid=test.user,ou=People,dc=example,dc=com", "*", "+");
    assertNotNull(userEntry);

    final String entryUUID = userEntry.getAttributeValue("entryUUID");
    assertNotNull(entryUUID);

    final LDAPResult result = conn.modifyDN(
         "uid=test.user,ou=People,dc=example,dc=com", "entryUUID=" + entryUUID,
         false);
    assertEquals(result.getResultCode(), ResultCode.SUCCESS);


    // Ensure that an attempt to alter a NO-USER-MODIFICATION attribute with a
    // modify DN will be rejected if it would add a new value.
    try
    {

      conn.modifyDN("entryUUID=" + entryUUID + ",ou=People,dc=example,dc=com",
           "entryUUID=" + UUID.randomUUID(), true);
      fail("Expected an exception when trying to insert a new " +
           "NO-USER-MODIFICATION attribute by a modify DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONSTRAINT_VIOLATION,
           le.toString());
    }


    // Ensure that an attempt to alter a NO-USER-MODIFICATION attribute with a
    // modify DN will be rejected if it would remove an existing value.
    try
    {

      conn.modifyDN("entryUUID=" + entryUUID + ",ou=People,dc=example,dc=com",
           "uid=test.user", true);
      fail("Expected an exception when trying to remove a " +
           "NO-USER-MODIFICATION attribute by a modify DN.");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.CONSTRAINT_VIOLATION);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that search time limits are respected, at least when it
   * comes to interjecting a delay in processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchTimeLimit()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    ds.setProcessingDelayMillis(1100L);

    try
    {
      // Send a search request to retrieve the base entry, and use a time limit
      // of one second.  The processing delay should cause the search to return
      // a "time limit exceeded" result.
      assertResultCodeEquals(conn,
           new SearchRequest("dc=example,dc=com", SearchScope.BASE,
                DereferencePolicy.NEVER, 0, 1, false, "(objectClass=*)"),
           ResultCode.TIME_LIMIT_EXCEEDED);
    }
    finally
    {
      ds.setProcessingDelayMillis(0L);
      conn.close();
    }
  }



  /**
   * Tests to ensure that search size limits are respected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchSizeLimit()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();


    // Add 10 entries to the server.
    for (int i=1; i <= 10; i++)
    {
      conn.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    // Create a search request without a size limit.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(givenName=User)");
    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 10);


    // Set a size limit equal to the number of entries returned and verify
    // that the search still works.
    searchRequest.setSizeLimit(10);
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 10);


    // Set the size limit to one below the matching number of entries and verify
    // that a size limit exceeded result is returned.
    searchRequest.setSizeLimit(9);
    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search with a size limit " +
           "less than the number of matching entries.");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
      assertEquals(lse.getEntryCount(), 9);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that search size limits are respected when the server is
   * configured with a maximum size limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchSizeLimitWithServerMaximum()
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    assertEquals(config.getMaxSizeLimit(), 0);
    config.setMaxSizeLimit(10);
    assertEquals(config.getMaxSizeLimit(), 10);
    config.setMaxSizeLimit(-1);
    assertEquals(config.getMaxSizeLimit(), 0);
    config.setMaxSizeLimit(9);
    assertEquals(config.getMaxSizeLimit(), 9);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();
    final LDAPConnection conn = ds.getConnection();

    // Add the directory structure and 10 user entries to the server.
    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    for (int i=1; i <= 10; i++)
    {
      conn.add(
           "dn: uid=user." + i + ",ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i);
    }


    // Create a search request without a size limit.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(givenName=User)");
    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search with a max server " +
           "size limit less than the number of matching entries.");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
      assertEquals(lse.getEntryCount(), 9);
    }


    // Set a size limit equal to the number of matching entries and verify that
    // the maximum size limit still applies.
    searchRequest.setSizeLimit(10);
    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search with a max server " +
           "size limit less than the number of matching entries.");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
      assertEquals(lse.getEntryCount(), 9);
    }


    // Delete one of the user entries and re-run the previous searches.
    conn.delete("uid=user.10,ou=People,dc=example,dc=com");

    searchRequest.setSizeLimit(0);
    SearchResult searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 9);

    searchRequest.setSizeLimit(10);
    searchResult = conn.search(searchRequest);
    assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
    assertEquals(searchResult.getEntryCount(), 9);


    // Set the request size limit to one below the matching number of entries
    // and verify that a size limit exceeded result is returned.
    searchRequest.setSizeLimit(8);
    try
    {
      conn.search(searchRequest);
      fail("Expected an exception when trying to search with a size limit " +
           "less than the number of matching entries.");
    }
    catch (final LDAPSearchException lse)
    {
      assertEquals(lse.getResultCode(), ResultCode.SIZE_LIMIT_EXCEEDED);
      assertEquals(lse.getEntryCount(), 8);
    }

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    ds.shutDown(true);
  }



  /**
   * Tests to ensure that certain operational attributes are automatically
   * generated.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOperationalAttributes()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    conn.bind("cn=Directory Manager", "password");

    // First, perform a search without any specific requested attributes and
    // verify that the auto-generated operational attributes are not returned.
    Entry e = conn.getEntry("dc=example,dc=com");
    assertFalse(e.hasAttribute("createTimestamp"));
    assertFalse(e.hasAttribute("creatorsName"));
    assertFalse(e.hasAttribute("entryDN"));
    assertFalse(e.hasAttribute("entryUUID"));
    assertFalse(e.hasAttribute("subschemaSubentry"));
    assertFalse(e.hasAttribute("modifiersName"));
    assertFalse(e.hasAttribute("modifyTimestamp"));


    // Next, perform the same search requesting all operational attributes and
    // verify that the appropriate attributes are included.
    e = conn.getEntry("dc=example,dc=com", "+");
    assertTrue(e.hasAttribute("createTimestamp"));
    assertTrue(e.hasAttribute("creatorsName"));
    assertTrue(e.hasAttribute("entryDN"));
    assertTrue(e.hasAttribute("entryUUID"));
    assertTrue(e.hasAttribute("subschemaSubentry"));
    assertTrue(e.hasAttribute("modifiersName"));
    assertTrue(e.hasAttribute("modifyTimestamp"));

    assertTrue(e.hasAttributeValue("entryDN", "dc=example,dc=com"));


    // Modify the entry and verify that modifiersName and modifyTimestamp are
    // now set.
    conn.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    e = conn.getEntry("dc=example,dc=com", "+");
    assertTrue(e.hasAttribute("createTimestamp"));
    assertTrue(e.hasAttribute("creatorsName"));
    assertTrue(e.hasAttribute("entryDN"));
    assertTrue(e.hasAttribute("entryUUID"));
    assertTrue(e.hasAttribute("subschemaSubentry"));
    assertTrue(e.hasAttribute("modifiersName"));
    assertTrue(e.hasAttribute("modifyTimestamp"));

    assertTrue(e.hasAttributeValue("entryDN", "dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("modifiersName", "cn=Directory Manager"));


    // Get the user entry and verify that it has an appropriate set of
    // operational attributes.
    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com", "+");
    assertTrue(e.hasAttribute("createTimestamp"));
    assertTrue(e.hasAttribute("creatorsName"));
    assertTrue(e.hasAttribute("entryDN"));
    assertTrue(e.hasAttribute("entryUUID"));
    assertTrue(e.hasAttribute("subschemaSubentry"));
    assertTrue(e.hasAttribute("modifiersName"));
    assertTrue(e.hasAttribute("modifyTimestamp"));

    assertTrue(e.hasAttributeValue("entryDN",
         "uid=test.user,ou=People,dc=example,dc=com"));


    // Rename the user entry and verify that it now has modifiersName and
    // modifyTimestamp values, and that entryDN has been updated.
    conn.modifyDN("uid=test.user,ou=People,dc=example,dc=com", "cn=Test User",
         false);

    e = conn.getEntry("cn=Test User,ou=People,dc=example,dc=com", "+");
    assertTrue(e.hasAttribute("createTimestamp"));
    assertTrue(e.hasAttribute("creatorsName"));
    assertTrue(e.hasAttribute("entryDN"));
    assertTrue(e.hasAttribute("entryUUID"));
    assertTrue(e.hasAttribute("subschemaSubentry"));
    assertTrue(e.hasAttribute("modifiersName"));
    assertTrue(e.hasAttribute("modifyTimestamp"));

    assertTrue(e.hasAttributeValue("entryDN",
         "cn=Test User,ou=People,dc=example,dc=com"));
    assertTrue(e.hasAttributeValue("modifiersName", "cn=Directory Manager"));

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that any missing superior object classes are added to
   * entries if they are missing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddSuperiorObjectClasses()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();


    // Test an add missing only the top object class.
    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: domain");

    Entry e = conn.getEntry("dc=example,dc=com");

    assertTrue(e.hasAttribute("dc"));
    assertTrue(e.hasAttributeValue("dc", "example"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "domain"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertEquals(e.getAttributeValues("objectClass").length, 2);


    // Test an add not missing any object classes.
    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit");

    e = conn.getEntry("ou=People,dc=example,dc=com");

    assertTrue(e.hasAttribute("ou"));
    assertTrue(e.hasAttributeValue("ou", "People"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "organizationalUnit"));
    assertEquals(e.getAttributeValues("objectClass").length, 2);


    // Test an add missing multiple superior classes.
    conn.add(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: inetOrgPerson",
         "cn: Test User",
         "sn: User");

    e = conn.getEntry("uid=test.user,ou=People,dc=example,dc=com");

    assertTrue(e.hasAttribute("uid"));
    assertTrue(e.hasAttributeValue("uid", "test.user"));

    assertTrue(e.hasAttribute("objectClass"));
    assertTrue(e.hasAttributeValue("objectClass", "top"));
    assertTrue(e.hasAttributeValue("objectClass", "person"));
    assertTrue(e.hasAttributeValue("objectClass", "organizationalPerson"));
    assertTrue(e.hasAttributeValue("objectClass", "inetOrgPerson"));
    assertEquals(e.getAttributeValues("objectClass").length, 4);


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests to ensure that the server will not allow superior classes to be
   * deleted from an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteAllObjectClasses()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection conn = ds.getConnection();


    // Verify that the entire set of object classes cannot be removed from an
    // entry.
    try
    {
      conn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "delete:  objectClass");
      fail("Expected an exception when trying to remove all object classes");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    }
  }



  /**
   * Tests to ensure that the server will not allow superior classes to be
   * deleted from an entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDeleteSuperiorObjectClasses()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, false);
    final LDAPConnection conn = ds.getConnection();


    // Verify that the "top" object class cannot be removed from an entry.
    try
    {
      conn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "delete:  objectClass",
           "objectClass: top");
      fail("Expected an exception when trying to remove a superior class");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }
    finally
    {

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    }
  }



  /**
   * Provides test coverage for the ability to process a SASL bind operation,
   * including the authorization identity request control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSASLBindWithAuthorizationIdentity()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();

    final RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);

    assertTrue(rootDSE.supportsSASLMechanism("PLAIN"));
    assertTrue(rootDSE.supportsControl(AuthorizationIdentityRequestControl.
         AUTHORIZATION_IDENTITY_REQUEST_OID));


    // Test a successful anonymous bind.
    PLAINBindRequest bindRequest = new PLAINBindRequest("dn:", "",
         new AuthorizationIdentityRequestControl());
    BindResult bindResult = conn.bind(bindRequest);

    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    AuthorizationIdentityResponseControl authzIDResponse =
         AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);

    String authzID = authzIDResponse.getAuthorizationID();
    assertNotNull(authzID);
    assertTrue(authzID.equals("dn:"));


    // Perform the same test without the authorization identity request control.
    bindRequest = new PLAINBindRequest("dn:", "");
    bindResult = conn.bind(bindRequest);

    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    assertFalse(bindResult.hasResponseControl(
         AuthorizationIdentityResponseControl.
              AUTHORIZATION_IDENTITY_RESPONSE_OID));


    // Test an anonymous bind with a password.
    bindRequest = new PLAINBindRequest("dn:", "password");
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind anonymously with a " +
           "password");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Test an anonymous bind with an authzID.
    bindRequest = new PLAINBindRequest("dn:", "dn:cn=Directory Manager", "");
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind anonymously with an " +
           "authorization ID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Test with a DN-style authID and no authzID.
    bindRequest = new PLAINBindRequest(
         "dn:uid=test.user,ou=People,dc=example,dc=com", "password",
         new AuthorizationIdentityRequestControl());
    bindResult = conn.bind(bindRequest);

    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);

    authzID = authzIDResponse.getAuthorizationID();
    assertNotNull(authzID);
    assertTrue(authzID.startsWith("dn:"));
    assertEquals(new DN(authzID.substring(3)),
         new DN("uid=test.user,ou=People,dc=example,dc=com"));


    // Test with a DN-style authID that is an additional bind user.
    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager", "password",
         new AuthorizationIdentityRequestControl());
    bindResult = conn.bind(bindRequest);

    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);

    authzID = authzIDResponse.getAuthorizationID();
    assertNotNull(authzID);
    assertTrue(authzID.startsWith("dn:"));
    assertEquals(new DN(authzID.substring(3)),
         new DN("cn=Directory Manager"));


    // Test with a u-style authID and an authzID that is an additional bind
    // user.
    bindRequest = new PLAINBindRequest("u:test.user", "dn:cn=Directory Manager",
         "password", new AuthorizationIdentityRequestControl());
    bindResult = conn.bind(bindRequest);

    assertEquals(bindResult.getResultCode(), ResultCode.SUCCESS);

    authzIDResponse = AuthorizationIdentityResponseControl.get(bindResult);
    assertNotNull(authzIDResponse);

    authzID = authzIDResponse.getAuthorizationID();
    assertNotNull(authzID);
    assertTrue(authzID.startsWith("dn:"));
    assertEquals(new DN(authzID.substring(3)),
         new DN("cn=Directory Manager"));


    // Test a bind as a nonexistent dn-style authentication ID.
    bindRequest = new PLAINBindRequest("dn:cn=missing", "password");
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind with a nonexistent " +
           "dn-style authentication ID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Test a bind as a nonexistent u-style authentication ID.
    bindRequest = new PLAINBindRequest("u:missing", "password");
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind with a nonexistent " +
           "u-style authentication ID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Test a bind as a nonexistent dn-style authorization ID.
    bindRequest = new PLAINBindRequest("dn:cn=Directory Manager",
         "dn:cn=missing", "password");
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind with a nonexistent " +
           "authorization ID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Test a bind with an incorrect password.
    bindRequest = new PLAINBindRequest("u:test.user", "wrong");
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind anonymously with an " +
           "authorization ID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_CREDENTIALS);
    }


    // Test a bind with an unsupported critical control.
    bindRequest = new PLAINBindRequest("u:test.user", "wrong",
         new Control("1.2.3.4", true));
    try
    {
      bindResult = conn.bind(bindRequest);
      fail("Expected an exception when trying to bind anonymously with an " +
           "authorization ID");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(),
           ResultCode.UNAVAILABLE_CRITICAL_EXTENSION);
    }


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Tests methods that are available only in the in-memory request handler.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestHandlerMethods()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com",
              "o=example.com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.addAdditionalBindCredentials("cn=Manager", "password");
    cfg.setSchema(Schema.getDefaultStandardSchema());
    cfg.setListenerExceptionHandler(
         new StandardErrorListenerExceptionHandler());

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    final InMemoryRequestHandler rh = ds.getInMemoryRequestHandler();
    assertNotNull(rh);

    // The request handler instance won't have a connection associated with
    // it, so the best we can do is just call methods to get coverage.
    assertNull(rh.getClientConnection());

    assertFalse(rh.getAuthenticatedDN().isNullDN());

    rh.setAuthenticatedDN(new DN("cn=Directory Manager"));
    assertEquals(rh.getAuthenticatedDN(), new DN("cn=Directory Manager"));

    rh.setAuthenticatedDN(null);
    assertTrue(rh.getAuthenticatedDN().isNullDN());

    assertNotNull(rh.getAdditionalBindCredentials());
    assertNotNull(rh.getAdditionalBindCredentials(
         new DN("cn=Directory Manager")));

    assertNotNull(rh.getConnectionState());
  }



  /**
   * Tests the ability to create an in-memory directory server instance that
   * uses SSL for secure communication and will use an explicit trust store for
   * client connections created by the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerWithSSLAndClientTrustStore()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");
    final File clientTrustStore = new File(resourceDir, "client.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray()),
         new TrustStoreTrustManager(serverTrustStore));

    final SSLUtil clientSSLUtil = new SSLUtil(
         new TrustStoreTrustManager(clientTrustStore));


    // Create the in-memory directory server instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    final int listenPort = ds.getListenPort();
    assertNotNull(ds.getClientSocketFactory());


    // Verify that we can use the server's getConnection method.
    final LDAPConnection dsProvidedConn = ds.getConnection();
    assertNotNull(dsProvidedConn.getSSLSession());
    assertNotNull(dsProvidedConn.getSSLSession().getPeerCertificateChain());
    assertTrue(dsProvidedConn.getSSLSession().
         getPeerCertificateChain().length > 0);

    RootDSE rootDSE = dsProvidedConn.getRootDSE();
    assertNotNull(rootDSE);

    dsProvidedConn.close();
    assertNull(dsProvidedConn.getSSLSession());


    // Verify that we can create an SSL client connection with a trust all
    // trust manager.
    final SSLUtil trustAllSSLUtil = new SSLUtil(new TrustAllTrustManager());
    final LDAPConnection trustAllConn =
         new LDAPConnection(trustAllSSLUtil.createSSLSocketFactory(),
              "127.0.0.1", listenPort);
    assertNotNull(trustAllConn.getSSLSession());
    assertNotNull(trustAllConn.getSSLSession().getPeerCertificateChain());
    assertTrue(trustAllConn.getSSLSession().
         getPeerCertificateChain().length > 0);

    rootDSE = trustAllConn.getRootDSE();
    assertNotNull(rootDSE);

    trustAllConn.close();
    assertNull(trustAllConn.getSSLSession());


    ds.shutDown(true);
  }



  /**
   * Tests the ability to create an in-memory directory server instance that
   * uses SSL for secure communication and will use a "trust all" approach for
   * client connections created by the server.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerWithSSLAndClientTrustAll()
         throws Exception
  {
    // Get the paths to the client and server key and trust stores.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));

    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final File serverTrustStore = new File(resourceDir, "server.truststore");


    // Create SSLUtil objects for client and server use.
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"),
         new TrustStoreTrustManager(serverTrustStore));

    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());


    // Create the in-memory directory server instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPSConfig("LDAPS",
         null, 0, serverSSLUtil.createSSLServerSocketFactory(),
         clientSSLUtil.createSSLSocketFactory()));
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    final int listenPort = ds.getListenPort();
    assertNotNull(ds.getClientSocketFactory());


    // Verify that we can use the server's getConnection method.
    final LDAPConnection dsProvidedConn = ds.getConnection();
    assertNotNull(dsProvidedConn.getSSLSession());
    assertNotNull(dsProvidedConn.getSSLSession().getPeerCertificateChain());
    assertTrue(dsProvidedConn.getSSLSession().
         getPeerCertificateChain().length > 0);

    final RootDSE rootDSE = dsProvidedConn.getRootDSE();
    assertNotNull(rootDSE);

    dsProvidedConn.close();
    assertNull(dsProvidedConn.getSSLSession());

    ds.shutDown(true);
  }



  /**
   * Tests the ability to communicate securely with the default SSL-enabled
   * server provided by the unit test framework.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultUnitTestServerWithSSLAndNoEntries()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL();
    assertNotNull(ds.getClientSocketFactory());

    // Verify that we can use the server's getConnection method.
    LDAPConnection dsProvidedConn = ds.getConnection();
    assertNotNull(dsProvidedConn.getSSLSession());

    // Work around a bug in the TLSv3 implementation in some versions of Java 11
    // that interfere with the ability to get peer certificates when resuming
    // a TLS session.  To prevent that from happening here, invalidate the
    // TLS session and create a new connection so that it gets a new session.
    assertNotNull(dsProvidedConn.getRootDSE());
    dsProvidedConn.getSSLSession().invalidate();
    dsProvidedConn.close();
    dsProvidedConn = ds.getConnection();
    assertNotNull(dsProvidedConn.getSSLSession());
    // End the workaround.

    assertNotNull(dsProvidedConn.getSSLSession().getPeerCertificateChain());
    assertTrue(dsProvidedConn.getSSLSession().
         getPeerCertificateChain().length > 0);

    final RootDSE rootDSE = dsProvidedConn.getRootDSE();
    assertNotNull(rootDSE);

    assertEntryMissing(dsProvidedConn, "dc=example,dc=com");
    assertEntryMissing(dsProvidedConn, "ou=People,dc=example,dc=com");
    assertEntryMissing(dsProvidedConn,
         "uid=test.user,ou=People,dc=example,dc=com");

    dsProvidedConn.close();
    assertNull(dsProvidedConn.getSSLSession());
  }



  /**
   * Tests the ability to communicate securely with the default SSL-enabled
   * server provided by the unit test framework.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultUnitTestServerWithSSLAndTestEntries()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDSWithSSL(true, true);
    assertNotNull(ds.getClientSocketFactory());

    // Verify that we can use the server's getConnection method.
    LDAPConnection dsProvidedConn = ds.getConnection();
    assertNotNull(dsProvidedConn.getSSLSession());

    // Work around a bug in the TLSv3 implementation in some versions of Java 11
    // that interfere with the ability to get peer certificates when resuming
    // a TLS session.  To prevent that from happening here, invalidate the
    // TLS session and create a new connection so that it gets a new session.
    assertNotNull(dsProvidedConn.getRootDSE());
    dsProvidedConn.getSSLSession().invalidate();
    dsProvidedConn.close();
    dsProvidedConn = ds.getConnection();
    assertNotNull(dsProvidedConn.getSSLSession());
    // End the workaround.

    assertNotNull(dsProvidedConn.getSSLSession().getPeerCertificateChain());
    assertTrue(dsProvidedConn.getSSLSession().
         getPeerCertificateChain().length > 0);

    final RootDSE rootDSE = dsProvidedConn.getRootDSE();
    assertNotNull(rootDSE);

    assertEntryExists(dsProvidedConn, "dc=example,dc=com");
    assertEntryExists(dsProvidedConn, "ou=People,dc=example,dc=com");
    assertEntryExists(dsProvidedConn,
         "uid=test.user,ou=People,dc=example,dc=com");

    dsProvidedConn.close();
    assertNull(dsProvidedConn.getSSLSession());
  }



  /**
   * Tests the ability to create an in-memory directory server instance that
   * supports the StartTLS extended operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testServerWithStartTLS()
         throws Exception
  {
    // Create the SSL socket factory to use for StartTLS.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File serverKeyStore   = new File(resourceDir, "server.keystore");
    final SSLUtil serverSSLUtil = new SSLUtil(
         new KeyStoreKeyManager(serverKeyStore, "password".toCharArray(),
              "JKS", "server-cert"), new TrustAllTrustManager());

    // Create the in-memory directory server instance.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(
         "LDAP+StartTLS", null, 0, serverSSLUtil.createSSLSocketFactory()));
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();
    final int listenPort = ds.getListenPort();


    // Verify that we can use the server's getConnection method.
    final LDAPConnection conn = ds.getConnection();
    assertNull(conn.getSSLSession());

    RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);
    assertTrue(rootDSE.supportsExtendedOperation(
         StartTLSExtendedRequest.STARTTLS_REQUEST_OID));


    // Use the StartTLS extended operation to secure the connection.
    final SSLUtil clientSSLUtil = new SSLUtil(new TrustAllTrustManager());
    final ExtendedResult startTLSResult =
         conn.processExtendedOperation(new StartTLSExtendedRequest(
              clientSSLUtil.createSSLContext()));

    assertNotNull(startTLSResult);
    assertEquals(startTLSResult .getResultCode(), ResultCode.SUCCESS);
    assertNotNull(conn.getSSLSession());
    assertNotNull(conn.getSSLSession().getPeerCertificateChain());
    assertTrue(conn.getSSLSession().getPeerCertificateChain().length > 0);


    // Test an additional set of operations over the newly-secured connection.
    conn.bind("cn=Directory Manager", "password");

    conn.processExtendedOperation(new WhoAmIExtendedRequest());

    conn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    conn.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    conn.modify(
         "dn: ou=People,dc=example,dc=com",
         "changeType: modify",
         "replace: description",
         "description: foo");

    assertTrue(conn.compare("ou=People,dc=example,dc=com", "description",
         "foo").compareMatched());

    conn.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");

    conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);

    conn.delete("ou=Users,dc=example,dc=com");

    conn.delete("dc=example,dc=com");

    final Control[] abandonControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.abandon(InternalSDKHelper.createAsyncRequestID(1, conn),
         abandonControls);

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    assertNull(conn.getSSLSession());


    ds.shutDown(true);
  }



  /**
   * Provides test coverage for searches using the typesOnly flag.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithTypesOnly()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);
    final LDAPConnection conn = ds.getConnection();


    // Test the behavior when returning all user attributes with typesOnly set
    // to false.
    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.SUB, "(uid=test.user)");

    Entry entry = conn.searchForEntry(searchRequest);

    Attribute attr = entry.getAttribute("objectClass");
    assertNotNull(attr);
    assertEquals(attr.size(), 4);

    attr = entry.getAttribute("uid");
    assertNotNull(attr);
    assertEquals(attr.size(), 1);

    attr = entry.getAttribute("entryUUID");
    assertNull(attr);


    // Test the same search with typesOnly set to true.
    searchRequest.setTypesOnly(true);

    entry = conn.searchForEntry(searchRequest);

    attr = entry.getAttribute("objectClass");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);

    attr = entry.getAttribute("uid");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);

    attr = entry.getAttribute("entryUUID");
    assertNull(attr);


    // Test the behavior when returning all user and operational attributes with
    // typesOnly set to false.
    searchRequest.setTypesOnly(false);
    searchRequest.setAttributes("*", "+");

    entry = conn.searchForEntry(searchRequest);

    attr = entry.getAttribute("objectClass");
    assertNotNull(attr);
    assertEquals(attr.size(), 4);

    attr = entry.getAttribute("uid");
    assertNotNull(attr);
    assertEquals(attr.size(), 1);

    attr = entry.getAttribute("entryUUID");
    assertNotNull(attr);
    assertEquals(attr.size(), 1);


    // Test the same search with typesOnly set to true.
    searchRequest.setTypesOnly(true);

    entry = conn.searchForEntry(searchRequest);

    attr = entry.getAttribute("objectClass");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);

    attr = entry.getAttribute("uid");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);

    attr = entry.getAttribute("entryUUID");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);


    // Test the behavior when returning only specific attributes with typesOnly
    // set to false.
    searchRequest.setTypesOnly(false);
    searchRequest.setAttributes("uid", "entryUUID");

    entry = conn.searchForEntry(searchRequest);

    attr = entry.getAttribute("objectClass");
    assertNull(attr);

    attr = entry.getAttribute("uid");
    assertNotNull(attr);
    assertEquals(attr.size(), 1);

    attr = entry.getAttribute("entryUUID");
    assertNotNull(attr);
    assertEquals(attr.size(), 1);


    // Test the same search with typesOnly set to true.
    searchRequest.setTypesOnly(true);

    entry = conn.searchForEntry(searchRequest);

    attr = entry.getAttribute("objectClass");
    assertNull(attr);

    attr = entry.getAttribute("uid");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);

    attr = entry.getAttribute("entryUUID");
    assertNotNull(attr);
    assertEquals(attr.size(), 0);


    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
  }



  /**
   * Provides a set of test cases to that operations are properly rejected if
   * they are not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectNotAllowedOperationTypes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setAllowedOperationTypes();
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection conn = ds.getConnection();

    try
    {
      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    try
    {
      conn.bind("", "");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    try
    {
      conn.compare("", "supportedLDAPVersion", "3");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    assertTrue(ds.compare("", "supportedLDAPVersion", "3").compareMatched());

    try
    {
      conn.processExtendedOperation(new WhoAmIExtendedRequest());
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    assertEquals(
         ds.processExtendedOperation(new WhoAmIExtendedRequest()).
              getResultCode(),
         ResultCode.SUCCESS);

    try
    {
      conn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    ds.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    try
    {
      conn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    ds.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);

    try
    {
      conn.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    ds.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");

    try
    {
      conn.delete("ou=Users,dc=example,dc=com");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.UNWILLING_TO_PERFORM);
    }

    ds.delete("ou=Users,dc=example,dc=com");

    final Control[] unbindControls =
    {
      new Control("1.2.3.4", false),
      new Control("1.2.3.5", false, new ASN1OctetString("foo")),
    };
    conn.close(unbindControls);
    ds.shutDown(true);
  }



  /**
   * Provides a set of test cases that cover the ability to process operations
   * on unauthenticated connections when authentication is required.
   *
   * Provides a set of test cases to that operations are properly rejected if
   * they are not allowed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthenticationRequiredOperationTypes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setAuthenticationRequiredOperationTypes(
         EnumSet.allOf(OperationType.class));
    cfg.addAdditionalBindCredentials("cn=Directory Manager", "password");
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final LDAPConnection unauthenticatedConn = ds.getConnection();

    try
    {
      // Ensure that an anonymous simple bind is not allowed.
      unauthenticatedConn.bind("", "");
      fail("Expected an anonymous simple bind to fail when authentication is " +
           "required for bind operations");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.INVALID_CREDENTIALS);
    }

    try
    {
      // Ensure that an anonymous SASL bind is not allowed.
      unauthenticatedConn.bind(new PLAINBindRequest("dn:", ""));
      fail("Expected an anonymous PLAIN bind to fail when authentication is " +
           "required for bind operations");
    }
    catch (final LDAPException le)
    {
      assertResultCodeEquals(le, ResultCode.INVALID_CREDENTIALS);
    }

    final LDAPConnection authenticatedConn = ds.getConnection();
    authenticatedConn.bind("cn=Directory Manager", "password");


    try
    {
      unauthenticatedConn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    authenticatedConn.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");


    try
    {
      unauthenticatedConn.compare("dc=example,dc=com", "dc", "example");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    assertTrue(authenticatedConn.compare("dc=example,dc=com", "dc",
         "example").compareMatched());

    assertTrue(ds.compare("dc=example,dc=com", "dc",
         "example").compareMatched());


    try
    {
      unauthenticatedConn.processExtendedOperation(new WhoAmIExtendedRequest());
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    assertEquals(
         authenticatedConn.processExtendedOperation(
              new WhoAmIExtendedRequest()).getResultCode(),
         ResultCode.SUCCESS);

    assertEquals(
         ds.processExtendedOperation(
              new WhoAmIExtendedRequest()).getResultCode(),
         ResultCode.SUCCESS);


    try
    {
      unauthenticatedConn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: foo");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    authenticatedConn.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");

    ds.modify(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: bar");


    try
    {
      unauthenticatedConn.modifyDN("ou=People,dc=example,dc=com", "ou=Users",
           true);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    authenticatedConn.modifyDN("ou=People,dc=example,dc=com", "ou=Users", true);

    ds.modifyDN("ou=Users,dc=example,dc=com", "ou=Persons", true);


    try
    {
      unauthenticatedConn.search("dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    authenticatedConn.search("dc=example,dc=com", SearchScope.BASE,
         "(objectClass=*)");

    ds.search("dc=example,dc=com", SearchScope.BASE, "(objectClass=*)");


    try
    {
      unauthenticatedConn.delete("ou=Persons,dc=example,dc=com");
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
    }

    authenticatedConn.delete("ou=Persons,dc=example,dc=com");

    ds.delete("dc=example,dc=com");


    authenticatedConn.close();
    unauthenticatedConn.close();
    ds.shutDown(true);
  }



  /**
   * Provides test coverage for valid schema modifications.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSchemaModification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();

    final Schema originalSchema = ds.getSchema();
    assertNotNull(originalSchema);
    assertNull(originalSchema.getAttributeType("testAttr"));
    assertNull(originalSchema.getObjectClass("testOC"));
    assertNull(originalSchema.getNameFormByName("testNF"));
    assertNull(originalSchema.getDITContentRule("testDCR"));
    assertNull(originalSchema.getDITStructureRuleByID(1234));
    assertNull(originalSchema.getMatchingRuleUse("testMRU"));

    ds.modify(
         "dn: cn=schema",
         "changetype: modify",
         "add: attributeTypes",
         "attributeTypes: ( 1.2.3.4 NAME 'testAttr' )",
         "-",
         "add: objectClasses",
         "objectClasses: ( 1.2.3.5 NAME 'testOC' )",
         "-",
         "add: nameForms",
         "nameForms: ( 1.2.3.6 NAME 'testNF' OC person MUST uid )",
         "-",
         "add: dITContentRules",
         "dITContentRules: ( 1.2.3.5 NAME 'testDCR' )",
         "-",
         "add: dITStructureRules",
         "dITStructureRules: ( 1234 NAME 'testDSR' FORM testNF )",
         "-",
         "add: matchingRuleUse",
         "matchingRuleUse: ( 2.5.13.16 NAME 'testMRU' APPLIES ( cn ) )");

    final Schema schemaAfterAdds = ds.getSchema();
    assertNotNull(schemaAfterAdds);
    assertFalse(schemaAfterAdds.equals(originalSchema));
    assertNotNull(schemaAfterAdds.getAttributeType("testAttr"));
    assertNotNull(schemaAfterAdds.getObjectClass("testOC"));
    assertNotNull(schemaAfterAdds.getNameFormByName("testNF"));
    assertNotNull(schemaAfterAdds.getDITContentRule("testDCR"));
    assertNotNull(schemaAfterAdds.getDITStructureRuleByID(1234));
    assertNotNull(schemaAfterAdds.getMatchingRuleUse("testMRU"));

    ds.modify(
         "dn: cn=schema",
         "changetype: modify",
         "delete: attributeTypes",
         "attributeTypes: ( 1.2.3.4 NAME 'testAttr' )",
         "-",
         "delete: objectClasses",
         "objectClasses: ( 1.2.3.5 NAME 'testOC' )",
         "-",
         "delete: nameForms",
         "nameForms: ( 1.2.3.6 NAME 'testNF' OC person MUST uid )",
         "-",
         "delete: dITContentRules",
         "dITContentRules: ( 1.2.3.5 NAME 'testDCR' )",
         "-",
         "delete: dITStructureRules",
         "dITStructureRules: ( 1234 NAME 'testDSR' FORM testNF )",
         "-",
         "delete: matchingRuleUse",
         "matchingRuleUse: ( 2.5.13.16 NAME 'testMRU' APPLIES ( cn ) )");

    final Schema schemaAfterDeletes = ds.getSchema();
    assertNotNull(schemaAfterDeletes);
    assertTrue(schemaAfterDeletes.equals(originalSchema));
    assertFalse(schemaAfterDeletes.equals(schemaAfterAdds));
    assertNull(schemaAfterDeletes.getAttributeType("testAttr"));
    assertNull(schemaAfterDeletes.getObjectClass("testOC"));
    assertNull(schemaAfterDeletes.getNameFormByName("testNF"));
    assertNull(schemaAfterDeletes.getDITContentRule("testDCR"));
    assertNull(schemaAfterDeletes.getDITStructureRuleByID(1234));
    assertNull(schemaAfterDeletes.getMatchingRuleUse("testMRU"));
  }



  /**
   * Provides test coverage for the case in which an attempt to modify the
   * server schema fails because it does not have a schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSchemaModificationWithoutSchema()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setSchema(null);
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);

    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "add: attributeTypes",
           "attributeTypes: ( 1.2.3.4 NAME 'testAttr' )",
           "-",
           "add: objectClasses",
           "objectClasses: ( 1.2.3.5 NAME 'testOC' )",
           "-",
           "add: nameForms",
           "nameForms: ( 1.2.3.6 NAME 'testNF' OC person MUST uid )",
           "-",
           "add: dITContentRules",
           "dITContentRules: ( 1.2.3.5 NAME 'testDCR' )",
           "-",
           "add: dITStructureRules",
           "dITStructureRules: ( 1234 NAME 'testDSR' FORM testNF )",
           "-",
           "add: matchingRuleUse",
           "matchingRuleUse: ( 2.5.13.16 NAME 'testMRU' APPLIES ( cn ) )");
      fail("Expected an exception when trying to modify the server schema");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }

    ds.shutDown(true);
  }



  /**
   * Provides test coverage for schema modification attempts that should be
   * rejected.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRejectedSchemaModification()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    assertNotNull(ds.getSchema());


    // Verify that syntax modifications are not allowed.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: ldapSyntaxes",
           "ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.6 " +
                "DESC 'Bit String' X-ORIGIN 'RFC 4517')");
      fail("Expected an exception when trying to modify ldapSyntaxes");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Verify that matching rule modifications are not allowed.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: matchingRules",
           "matchingRules: ( 2.5.13.16 NAME 'bitStringMatch' " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 X-ORIGIN 'RFC 4517' )");
      fail("Expected an exception when trying to modify matchingRules");
    }
    catch (final LDAPException le)
    {
      // This was expected.
    }


    // Verify that we cannot add a malformed attribute type definition.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: attributeTypes",
           "attributeTypes: malformed");
      fail("Expected an exception when trying to add a malformed attribute " +
           "type");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot add a malformed object class definition.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: objectClasses",
           "objectClasses: malformed");
      fail("Expected an exception when trying to add a malformed object class");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot add a malformed name form definition.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: nameForms",
           "nameForms: malformed");
      fail("Expected an exception when trying to add a malformed name form");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot add a malformed DIT content rule definition.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: dITContentRules",
           "dITContentRules: malformed");
      fail("Expected an exception when trying to add a malformed DIT content " +
           "rule");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot add a malformed DIT structure rule definition.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: dITStructureRules",
           "dITStructureRules: malformed");
      fail("Expected an exception when trying to add a malformed DIT " +
           "structure rule");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot add a malformed matching rule use definition.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "delete: matchingRuleUse",
           "matchingRuleUse: malformed");
      fail("Expected an exception when trying to add a malformed matching " +
           "rule use");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot replace the set of attribute type definitions.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "replace: attributeTypes");
      fail("Expected an exception when trying to replace attribute types");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot replace the set of object class definitions.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "replace: objectClasses");
      fail("Expected an exception when trying to replace object clases");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot replace the set of name form definitions.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "replace: nameForms");
      fail("Expected an exception when trying to replace name forms");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot replace the set of DIT content rule definitions.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "replace: dITContentRules");
      fail("Expected an exception when trying to replace DIT content rules");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot replace the set of DIT structure rule definitions.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "replace: dITStructureRules");
      fail("Expected an exception when trying to replace DIT structure rules");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }


    // Verify that we cannot replace the set of matching rule use definitions.
    try
    {
      ds.modify(
           "dn: cn=schema",
           "changetype: modify",
           "replace: matchingRuleUse");
      fail("Expected an exception when trying to replace matching rule uses");
    }
    catch (final LDAPException le)
    {
      // This was expected
    }
  }



  /**
   * Tests the ability of the directory server to present a custom root DSE
   * entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCustomRootDSEEntry()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setCodeLogDetails(createTempFile().getAbsolutePath(), true);

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    assertFalse(ds.getRootDSE().hasAttribute("description"));
    ds.shutDown(true);

    cfg.setRootDSEEntry(new Entry(
         "dn: ",
         "objectClass: top",
         "objectClass: rootDSE",
         "description: Predefined root DSE"));

    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    assertTrue(ds.getRootDSE().hasAttribute("description"));
    ds.shutDown(true);
  }



  /**
   * Tests the ability of the directory server to present a dynamically
   * generated root DSE that includes custom static attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCustomRootDSEAttributes()
         throws Exception
  {
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setMaxChangeLogEntries(Integer.MAX_VALUE);

    InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    RootDSE rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 1L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 1L);

    assertFalse(rootDSE.hasAttribute("description"));

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 1L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 2L);

    assertFalse(rootDSE.hasAttribute("description"));


    ds.shutDown(true);
    cfg.setCustomRootDSEAttributes(Collections.singletonList(
         new Attribute("description", "custom description 1")));
    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 1L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 1L);

    assertTrue(rootDSE.hasAttribute("description"));
    assertEquals(rootDSE.getAttributeValue("description"),
         "custom description 1");

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 1L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 2L);

    assertTrue(rootDSE.hasAttribute("description"));
    assertEquals(rootDSE.getAttributeValue("description"),
         "custom description 1");


    ds.shutDown(true);
    cfg.setCustomRootDSEAttributes(Arrays.asList(
         new Attribute("description", "custom description 2"),
         new Attribute("firstChangeNumber", "123"),
         new Attribute("lastChangeNumber", "456")));
    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 123L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 456L);

    assertTrue(rootDSE.hasAttribute("description"));
    assertEquals(rootDSE.getAttributeValue("description"),
         "custom description 2");

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 123L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 456L);

    assertTrue(rootDSE.hasAttribute("description"));
    assertEquals(rootDSE.getAttributeValue("description"),
         "custom description 2");


    ds.shutDown(true);
    cfg.setCustomRootDSEAttributes(null);
    ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    ds.add(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");


    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 1L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 1L);

    assertFalse(rootDSE.hasAttribute("description"));

    ds.add(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People");

    rootDSE = ds.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getChangelogDN());
    assertDNsEqual(rootDSE.getChangelogDN(), "cn=changelog");

    assertNotNull(rootDSE.getFirstChangeNumber());
    assertEquals(rootDSE.getFirstChangeNumber().longValue(), 1L);

    assertNotNull(rootDSE.getLastChangeNumber());
    assertEquals(rootDSE.getLastChangeNumber().longValue(), 2L);

    assertFalse(rootDSE.hasAttribute("description"));

    ds.shutDown(true);
  }



  /**
   * Tests to ensure that hte server will properly handle a limit on the maximum
   * number of concurrent connections that may be established.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMaxConnections()
         throws Exception
  {
    // Create an in-memory directory server instance with a maximum of five
    // concurrent connections.
    final InMemoryDirectoryServerConfig cfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    cfg.setMaxConnections(5);

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(cfg);
    ds.startListening();

    final TestUnsolicitedNotificationHandler unHandler =
         new TestUnsolicitedNotificationHandler();

    final LDAPConnectionOptions opts = new LDAPConnectionOptions();
    opts.setUnsolicitedNotificationHandler(unHandler);


    // Establish five connections and verify that they are all valid.
    final ArrayList<LDAPConnection> connList = new ArrayList<LDAPConnection>(5);
    for (int i=0; i < 5; i++)
    {
      final LDAPConnection conn = ds.getConnection(opts);
      assertNotNull(conn.getRootDSE());
      connList.add(conn);
      assertEquals(unHandler.getNotificationCount(), 0);
    }


    // Try to establish another connection and verify that it isn't valid.
    try
    {
      final LDAPConnection conn = ds.getConnection(opts);
      conn.getRootDSE();
      conn.close();
      fail("Expected an exception when trying to get the root DSE over a " +
           "connection that should have been closed because of the maximum " +
           "connection limit");
    }
    catch (final LDAPException e)
    {
      // This was expected.
      assertEquals(unHandler.getNotificationCount(), 1);
    }


    // Verify that all of the previously-established connections are still
    // valid.
    for (final LDAPConnection conn : connList)
    {
      assertNotNull(conn.getRootDSE());
    }


    // Close one of the existing connections and verify that we can establish
    // only one more new connection.
    LDAPConnection conn = connList.remove(3);
    assertNotNull(conn);

    conn.close();
    Thread.sleep(500L);  // Give the server time to register the closure.

    conn = ds.getConnection(opts);
    assertNotNull(conn.getRootDSE());
    connList.add(conn);

    try
    {
      conn = ds.getConnection(opts);
      conn.getRootDSE();
      conn.close();
      fail("Expected an exception when trying to get the root DSE over a " +
           "connection that should have been closed because of the maximum " +
           "connection limit");
    }
    catch (final LDAPException e)
    {
      assertEquals(unHandler.getNotificationCount(), 2);
    }


    // Closed all the remaining connections.
    for (final LDAPConnection c : connList)
    {
      c.close();
    }
    connList.clear();


    ds.shutDown(true);
  }
}
