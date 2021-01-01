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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.SortedSet;
import java.util.Set;
import java.util.Stack;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldap.sdk.schema.AttributeSyntaxDefinition;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.unboundidds.controls.AttributeRight;
import com.unboundid.ldap.sdk.unboundidds.controls.EffectiveRightsEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.EntryRight;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetEffectiveRightsRequestControl;



/**
 * This class provides a set of test cases that provide the ability to
 * communicate with a Sun DSEE instance.
 */
public class DSEETestCase
       extends LDAPSDKTestCase
{
  // Indicates whether to run the tests against a non-secure DSEE instance.
  private boolean available;

  // Indicates whether to run the tests against a secure DSEE instance.
  private boolean sslAvailable;



  /**
   * Determines whether the DSEE instance is available and ensures that it is
   * empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDSEEInstanceAvailable())
    {
      available    = false;
      sslAvailable = false;
      return;
    }

    LDAPConnection c = getAdminDSEEConnection();
    try
    {
      Entry baseEntry = c.getEntry(getTestBaseDN());
      if (baseEntry == null)
      {
        available    = true;
        sslAvailable = isSSLEnabledDirectoryInstanceAvailable();
      }
      else
      {
        available    = false;
        sslAvailable = false;
        fail("Unable to perform tests against the DSEE instance because the " +
             "base entry exists");
      }
    }
    catch (Throwable t)
    {
      t.printStackTrace();
    }
    finally
    {
      c.close();
    }
  }



  /**
   * Ensures that no entries have been inadvertently left in the DSEE instance.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection c = getAdminDSEEConnection();
    try
    {
      Entry baseEntry = c.getEntry(getTestBaseDN());
      if (baseEntry == null)
      {
        return;
      }

      err("WARNING:  One or more entries were left in the DSEE instance after ",
          "DSEETestCase tests.  Cleaning them up.");

      SearchResult searchResult = c.search(getTestBaseDN(), SearchScope.SUB,
           "(objectClass=*)", "1.1");

      EntrySorter sorter = new EntrySorter(true);
      SortedSet<Entry> sortedEntries =
           sorter.sort(searchResult.getSearchEntries());

      Stack<Entry> entryStack = new Stack<Entry>();
      for (Entry e : sortedEntries)
      {
        entryStack.push(e);
      }

      while (! entryStack.isEmpty())
      {
        Entry e = entryStack.pop();
        c.delete(e.getDN());
      }
    }
    finally
    {
      c.close();
    }
  }



  /**
   * Tests the ability to establish a non-SSL connection to a Sun DSEE instance
   * and retrieve the server root DSE.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRootDSEOverLDAP()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getNamingContextDNs());

    boolean found = false;
    for (String s : rootDSE.getNamingContextDNs())
    {
      found |= DN.equals(s, getTestBaseDN());
    }
    assertTrue(found);

    assertTrue(rootDSE.supportsControl(AuthorizationIdentityRequestControl.
         AUTHORIZATION_IDENTITY_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(GetEffectiveRightsRequestControl.
         GET_EFFECTIVE_RIGHTS_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(ProxiedAuthorizationV1RequestControl.
         PROXIED_AUTHORIZATION_V1_REQUEST_OID));

    assertTrue(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

    conn.close();
  }



  /**
   * Tests the ability to establish an SSL-based connection to a Sun DSEE
   * instance and retrieve the server root DSE.
   * <BR><BR>
   * Access to an SSL-enabled Sun DSEE instance is required for complete
   * processing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRootDSEOverSSL()
         throws Exception
  {
    if (! sslAvailable)
    {
      return;
    }

    LDAPConnection conn = getSSLAdminDSEEConnection();

    RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getNamingContextDNs());

    boolean found = false;
    for (String s : rootDSE.getNamingContextDNs())
    {
      found |= DN.equals(s, getTestBaseDN());
    }
    assertTrue(found);

    assertTrue(rootDSE.supportsControl(AuthorizationIdentityRequestControl.
         AUTHORIZATION_IDENTITY_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(GetEffectiveRightsRequestControl.
         GET_EFFECTIVE_RIGHTS_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(ProxiedAuthorizationV1RequestControl.
         PROXIED_AUTHORIZATION_V1_REQUEST_OID));

    assertTrue(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

    conn.close();
  }



  /**
   * Tests the ability to establish a StartTLS-based connection to a Sun DSEE
   * instance and retrieve the server root DSE.
   * <BR><BR>
   * Access to an SSL-enabled Sun DSEE instance is required for complete
   * processing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRootDSEOverStartTLS()
         throws Exception
  {
    if (! sslAvailable)
    {
      return;
    }

    LDAPConnection conn = getStartTLSAdminDSEEConnection();

    RootDSE rootDSE = conn.getRootDSE();
    assertNotNull(rootDSE);

    assertNotNull(rootDSE.getNamingContextDNs());

    boolean found = false;
    for (String s : rootDSE.getNamingContextDNs())
    {
      found |= DN.equals(s, getTestBaseDN());
    }
    assertTrue(found);

    assertTrue(rootDSE.supportsControl(AuthorizationIdentityRequestControl.
         AUTHORIZATION_IDENTITY_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(GetEffectiveRightsRequestControl.
         GET_EFFECTIVE_RIGHTS_REQUEST_OID));
    assertTrue(rootDSE.supportsControl(ProxiedAuthorizationV1RequestControl.
         PROXIED_AUTHORIZATION_V1_REQUEST_OID));

    assertTrue(rootDSE.supportsExtendedOperation(
         WhoAmIExtendedRequest.WHO_AM_I_REQUEST_OID));

    conn.close();
  }



  /**
   * Tests the ability to validate all attribute syntax descriptions contained
   * in the server schema.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseAttributeSyntaxes()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    LinkedHashMap<String,String> invalidDefinitions =
         new LinkedHashMap<String,String>();

    try
    {
      Entry e = conn.getEntry("cn=schema", "ldapSyntaxes");
      assertNotNull(e);

      Attribute a = e.getAttribute("ldapSyntaxes");
      assertNotNull(a);
      assertTrue(a.hasValue());

      for (String s : a.getValues())
      {
        try
        {
          new AttributeSyntaxDefinition(s);
        }
        catch (LDAPException le)
        {
          invalidDefinitions.put(s, le.getMessage());
        }
      }
    }
    finally
    {
      conn.close();
    }

    for (Map.Entry<String,String> e : invalidDefinitions.entrySet())
    {
      err("Unable to parse attribute syntax:  ", e.getKey(), " -- ",
          e.getValue());
    }

    assertTrue(invalidDefinitions.isEmpty());
  }



  /**
   * Tests the ability to validate all attribute type descriptions contained in
   * the server schema.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseAttributeTypes()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    LinkedHashMap<String,String> invalidDefinitions =
         new LinkedHashMap<String,String>();

    try
    {
      Entry e = conn.getEntry("cn=schema", "attributeTypes");
      assertNotNull(e);

      Attribute a = e.getAttribute("attributeTypes");
      assertNotNull(a);
      assertTrue(a.hasValue());

      for (String s : a.getValues())
      {
        try
        {
          new AttributeTypeDefinition(s);
        }
        catch (LDAPException le)
        {
          invalidDefinitions.put(s, le.getMessage());
        }
      }
    }
    finally
    {
      conn.close();
    }

    for (Map.Entry<String,String> e : invalidDefinitions.entrySet())
    {
      err("Unable to parse attribute type:  ", e.getKey(), " -- ",
          e.getValue());
    }

    assertTrue(invalidDefinitions.isEmpty());
  }



  /**
   * Tests the ability to validate all object class descriptions contained in
   * the server schema.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseObjectClasses()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    LinkedHashMap<String,String> invalidDefinitions =
         new LinkedHashMap<String,String>();

    try
    {
      Entry e = conn.getEntry("cn=schema", "objectClasses");
      assertNotNull(e);

      Attribute a = e.getAttribute("objectClasses");
      assertNotNull(a);
      assertTrue(a.hasValue());

      for (String s : a.getValues())
      {
        try
        {
          new ObjectClassDefinition(s);
        }
        catch (LDAPException le)
        {
          invalidDefinitions.put(s, le.getMessage());
        }
      }
    }
    finally
    {
      conn.close();
    }

    for (Map.Entry<String,String> e : invalidDefinitions.entrySet())
    {
      err("Unable to parse object class:  ", e.getKey(), " -- ",
          e.getValue());
    }

    assertTrue(invalidDefinitions.isEmpty());
  }



  /**
   * Tests the ability to perform a basic set of operations against a Sun DSEE
   * server.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicOperations()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    try
    {
      conn.add(getTestBaseDN(), getBaseEntryAttributes());
      conn.add(
           "dn: ou=People," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People");

      conn.modify(
           "dn: ou=People," + getTestBaseDN(),
           "changetype: modify",
           "replace: description",
           "description: foo");

      assertTrue(conn.compare("ou=People," + getTestBaseDN(), "description",
           "foo").compareMatched());

      conn.modifyDN("ou=People," + getTestBaseDN(), "ou=Users", true);

      SearchResult searchResult = conn.search(getTestBaseDN(), SearchScope.SUB,
           "(objectClass=*)");
      assertEquals(searchResult.getEntryCount(), 2);

      conn.delete("ou=Users," + getTestBaseDN());
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to use the authorization identity request and response
   * controls.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthorizationIdentityControls()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getUnauthenticatedDSEEConnection();

    try
    {
      SimpleBindRequest bindRequest = new SimpleBindRequest(getTestBindDN(),
           getTestBindPassword(), new AuthorizationIdentityRequestControl());

      BindResult bindResult = conn.bind(bindRequest);

      String oid = AuthorizationIdentityResponseControl.
           AUTHORIZATION_IDENTITY_RESPONSE_OID;
      assertTrue(bindResult.hasResponseControl(oid));

      Control c = bindResult.getResponseControl(oid);
      assertTrue(c instanceof AuthorizationIdentityResponseControl);

      AuthorizationIdentityResponseControl authzIDResponseControl =
           (AuthorizationIdentityResponseControl) c;

      String authzID = authzIDResponseControl.getAuthorizationID();
      assertNotNull(authzID);
      assertTrue(authzID.startsWith("dn:"));
      assertEquals(new DN(authzID.substring(3)),
                   new DN(getTestBindDN()));
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to use the "Who Am I?" extended request and result.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWhoAmI()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    try
    {
      ExtendedResult extendedResult = conn.processExtendedOperation(
           new WhoAmIExtendedRequest());
      assertNotNull(extendedResult);
      assertEquals(extendedResult.getResultCode(), ResultCode.SUCCESS);

      assertTrue(extendedResult instanceof WhoAmIExtendedResult);
      WhoAmIExtendedResult whoAmIResult = (WhoAmIExtendedResult) extendedResult;

      String authzID = whoAmIResult.getAuthorizationID();
      assertNotNull(authzID);
      assertTrue(authzID.startsWith("dn:"));
      assertEquals(new DN(authzID.substring(3)),
                   new DN(getTestBindDN()));
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to use the proxied authorization V1 request control
   * against a Sun DSEE instance.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProxiedAuthV1()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    try
    {
      LinkedList<Attribute> attrList = new LinkedList<Attribute>();
      attrList.addAll(Arrays.asList(getBaseEntryAttributes()));
      attrList.add(new Attribute("aci",
           "(targetattr=\"*\")(version 3.0; acl \"Admin Rights\"; allow " +
                "(all) userdn=\"ldap:///uid=admin," + getTestBaseDN() + "\";)",
           "(targetattr=\"*\")(version 3.0; acl \"Proxy Rights\"; allow " +
                "(proxy) userdn=\"ldap:///uid=proxy," + getTestBaseDN() +
                "\";)",
           "(targetattr=\"description\")(version 3.0; " +
                "acl \"Deny Description Write for Proxy User\"; deny (write) " +
                "userdn=\"ldap:///uid=proxy," + getTestBaseDN() + "\";)"));

      conn.add(getTestBaseDN(), attrList);

      conn.add(
           "dn: uid=admin," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: admin",
           "givenName: Admin",
           "sn: User",
           "cn: Admin User",
           "userPassword: password");

      conn.add(
           "dn: uid=proxy," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: proxy",
           "givenName: Proxy",
           "sn: User",
           "cn: Proxy User",
           "userPassword: password");

      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test",
           "description: foo");


      // Establish a second connection that is authenticated as the proxy user.
      LDAPConnection proxyConn = new LDAPConnection(getTestDSEEHost(),
           getTestDSEEPort(), "uid=proxy," + getTestBaseDN(), "password");


      // Verify that an attempt to modify the description of the test entry will
      // fail without the proxied authorization control.
      ModifyRequest modifyRequest = new ModifyRequest(
           "dn: ou=test," + getTestBaseDN(),
           "changetype: modify",
           "replace: description",
           "description: bar");

      try
      {
        proxyConn.modify(modifyRequest);
        fail("Expected a failure when trying to modify description as the " +
             "proxy user without the proxied authorization V1 request control");
      }
      catch (LDAPException le)
      {
        assertEquals(le.getResultCode(), ResultCode.INSUFFICIENT_ACCESS_RIGHTS);
      }


      // Verify that the modification is successful once the proxied auth V1
      // request control is added to perform it as the admin user.
      modifyRequest.addControl(new ProxiedAuthorizationV1RequestControl(
           "uid=admin," + getTestBaseDN()));
      proxyConn.modify(modifyRequest);


      proxyConn.close();


      conn.delete("uid=admin," + getTestBaseDN());
      conn.delete("uid=proxy," + getTestBaseDN());
      conn.delete("ou=test," + getTestBaseDN());
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
    }
  }



  /**
   * Tests the ability to use the get effective rights control against a Sun
   * DSEE instance.
   * <BR><BR>
   * Access to a Sun DSEE instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetEffectiveRights()
         throws Exception
  {
    if (! available)
    {
      return;
    }

    LDAPConnection conn = getAdminDSEEConnection();

    try
    {
      LinkedList<Attribute> attrList = new LinkedList<Attribute>();
      attrList.addAll(Arrays.asList(getBaseEntryAttributes()));
      attrList.add(new Attribute("aci",
           "(targetattr=\"*\")(version 3.0; acl \"Admin Rights\"; allow " +
                "(all) userdn=\"ldap:///uid=admin," + getTestBaseDN() + "\";)",
           "(targetattr=\"*\")(version 3.0; acl \"Proxy Rights\"; allow " +
                "(proxy) userdn=\"ldap:///uid=proxy," + getTestBaseDN() +
                "\";)"));

      conn.add(getTestBaseDN(), attrList);

      conn.add(
           "dn: uid=admin," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: admin",
           "givenName: Admin",
           "sn: User",
           "cn: Admin User",
           "userPassword: password");

      conn.add(
           "dn: uid=proxy," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: proxy",
           "givenName: Proxy",
           "sn: User",
           "cn: Proxy User",
           "userPassword: password");

      conn.add(
           "dn: ou=test," + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test",
           "description: foo");


      // Test effective rights for the admin user without any attributes.
      SearchRequest searchRequest = new SearchRequest(
           "ou=test," + getTestBaseDN(), SearchScope.BASE, "(objectClass=*)",
           "aclRights");
      searchRequest.addControl(new GetEffectiveRightsRequestControl(
           "dn:uid=admin," + getTestBaseDN()));

      SearchResult searchResult = conn.search(searchRequest);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      EffectiveRightsEntry e =
           new EffectiveRightsEntry(searchResult.getSearchEntries().get(0));
      assertNotNull(e);

      Set<EntryRight> entryRights = e.getEntryRights();
      assertTrue(entryRights.contains(EntryRight.ADD));
      assertTrue(entryRights.contains(EntryRight.DELETE));
      assertTrue(entryRights.contains(EntryRight.READ));
      assertTrue(entryRights.contains(EntryRight.WRITE));
      assertFalse(entryRights.contains(EntryRight.PROXY));


      // Test effective rights for the admin user with an attribute.
      searchRequest = new SearchRequest(
           "ou=test," + getTestBaseDN(), SearchScope.BASE, "(objectClass=*)",
           "aclRights", "description");
      searchRequest.addControl(new GetEffectiveRightsRequestControl(
           "dn:uid=admin," + getTestBaseDN(), "description"));

      searchResult = conn.search(searchRequest);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      e = new EffectiveRightsEntry(searchResult.getSearchEntries().get(0));
      assertNotNull(e);

      entryRights = e.getEntryRights();
      assertTrue(entryRights.contains(EntryRight.ADD));
      assertTrue(entryRights.contains(EntryRight.DELETE));
      assertTrue(entryRights.contains(EntryRight.READ));
      assertTrue(entryRights.contains(EntryRight.WRITE));
      assertFalse(entryRights.contains(EntryRight.PROXY));

      Set<AttributeRight> attrRights = e.getAttributeRights("description");
      assertTrue(attrRights.contains(AttributeRight.READ));
      assertTrue(attrRights.contains(AttributeRight.SEARCH));
      assertTrue(attrRights.contains(AttributeRight.COMPARE));
      assertTrue(attrRights.contains(AttributeRight.WRITE));
      assertTrue(attrRights.contains(AttributeRight.SELFWRITE_ADD));
      assertFalse(attrRights.contains(AttributeRight.PROXY));


      // Test effective rights for the proxy user without any attributes.
      searchRequest = new SearchRequest("ou=test," + getTestBaseDN(),
           SearchScope.BASE, "(objectClass=*)", "aclRights");
      searchRequest.addControl(new GetEffectiveRightsRequestControl(
           "dn:uid=proxy," + getTestBaseDN()));

      searchResult = conn.search(searchRequest);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      e = new EffectiveRightsEntry(searchResult.getSearchEntries().get(0));
      assertNotNull(e);

      entryRights = e.getEntryRights();
      assertTrue(entryRights.contains(EntryRight.PROXY));


      // Test effective rights for the proxy user with an attribute.
      searchRequest = new SearchRequest("ou=test," + getTestBaseDN(),
           SearchScope.BASE, "(objectClass=*)", "aclRights", "description");
      searchRequest.addControl(new GetEffectiveRightsRequestControl(
           "dn:uid=proxy," + getTestBaseDN(), "description"));

      searchResult = conn.search(searchRequest);
      assertEquals(searchResult.getResultCode(), ResultCode.SUCCESS);
      assertEquals(searchResult.getEntryCount(), 1);

      e = new EffectiveRightsEntry(searchResult.getSearchEntries().get(0));
      assertNotNull(e);

      entryRights = e.getEntryRights();
      assertTrue(entryRights.contains(EntryRight.PROXY));

      attrRights = e.getAttributeRights("description");
      assertTrue(attrRights.contains(AttributeRight.PROXY));


      conn.delete("uid=admin," + getTestBaseDN());
      conn.delete("uid=proxy," + getTestBaseDN());
      conn.delete("ou=test," + getTestBaseDN());
      conn.delete(getTestBaseDN());
    }
    finally
    {
      conn.close();
    }
  }
}
