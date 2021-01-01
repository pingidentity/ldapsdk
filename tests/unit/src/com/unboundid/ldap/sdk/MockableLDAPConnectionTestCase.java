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



import java.util.Arrays;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;



/**
 * This class provides a set of test cases for the
 * {@code MockableLDAPConnection} class.
 */
public final class MockableLDAPConnectionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the mockable LDAP connection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMockableLDAPConnection()
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS(true, true);

    try (LDAPConnection wrappedConn = ds.getConnection();
         MockableLDAPConnection conn = new MockableLDAPConnection(wrappedConn))
    {
      assertNotNull(conn.getWrappedConnection());

      assertNotNull(conn.getRootDSE());

      assertNotNull(conn.getSchema());

      assertNotNull(conn.getSchema(""));

      assertNotNull(conn.getEntry("dc=example,dc=com"));

      assertNotNull(conn.getEntry("dc=example,dc=com", "objectClass"));

      assertNotNull(conn.add("ou=test1,dc=example,dc=com",
           new Attribute("objectClass", "top", "organizationalUnit"),
           new Attribute("ou", "test1")));

      assertNotNull(conn.add("ou=test2,dc=example,dc=com",
           Arrays.asList(
                new Attribute("objectClass", "top", "organizationalUnit"),
                new Attribute("ou", "test2"))));

      assertNotNull(conn.add(new Entry(
           "dn: ou=test3,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test3")));

      assertNotNull(conn.add(
           "dn: ou=test4,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test4"));

      assertNotNull(conn.add(new AddRequest(
           "dn: ou=test5,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test5")));

      assertNotNull(conn.add((ReadOnlyAddRequest) new AddRequest(
           "dn: ou=test6,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: test6")));

      assertNotNull(conn.bind("cn=Directory Manager", "password"));

      assertNotNull(conn.bind(new SimpleBindRequest("cn=Directory Manager",
           "password")));

      assertNotNull(conn.compare("dc=example,dc=com", "dc", "example"));

      assertNotNull(conn.compare(new CompareRequest("dc=example,dc=com", "dc",
           "example")));

      assertNotNull(conn.compare((ReadOnlyCompareRequest)
           new CompareRequest("dc=example,dc=com", "dc", "example")));

      assertNotNull(conn.delete("ou=test1,dc=example,dc=com"));

      assertNotNull(conn.delete(
           new DeleteRequest("ou=test2,dc=example,dc=com")));

      assertNotNull(conn.delete((ReadOnlyDeleteRequest)
           new DeleteRequest("ou=test3,dc=example,dc=com")));

      assertNotNull(conn.processExtendedOperation("1.2.3.4"));

      assertNotNull(conn.processExtendedOperation("1.2.3.4",
           new ASN1OctetString("foo")));

      assertNotNull(conn.processExtendedOperation(new ExtendedRequest("1.2.3.4",
           new ASN1OctetString("foo"))));

      assertNotNull(conn.modify("dc=example,dc=com",
           new Modification(ModificationType.REPLACE, "description", "a")));

      assertNotNull(conn.modify("dc=example,dc=com",
           new Modification[]
           {
             new Modification(ModificationType.REPLACE, "description", "b")
           }));

      assertNotNull(conn.modify("dc=example,dc=com",
           Collections.singletonList(
                new Modification(ModificationType.REPLACE, "description",
                     "c"))));

      assertNotNull(conn.modify(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: d"));

      assertNotNull(conn.modify(new ModifyRequest(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: e")));

      assertNotNull(conn.modify((ReadOnlyModifyRequest) new ModifyRequest(
           "dn: dc=example,dc=com",
           "changetype: modify",
           "replace: description",
           "description: f")));

      assertNotNull(conn.modifyDN("ou=test4,dc=example,dc=com", "ou=Test Four",
           true));

      assertNotNull(conn.modifyDN("ou=Test Four,dc=example,dc=com",
           "ou=Test IV", true, "dc=example,dc=com"));

      assertNotNull(conn.modifyDN(new ModifyDNRequest(
           "ou=Test IV,dc=example,dc=com", "ou=Test 1234", true)));

      assertNotNull(conn.modifyDN((ReadOnlyModifyDNRequest) new ModifyDNRequest(
           "ou=Test 1234,dc=example,dc=com", "ou=test4", true)));

      assertNotNull(conn.search("dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)"));

      assertNotNull(conn.search("dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass")));

      assertNotNull(conn.search(null, "dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)"));

      assertNotNull(conn.search(null, "dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass")));

      assertNotNull(conn.search("dc=example,dc=com", SearchScope.BASE,
           DereferencePolicy.NEVER, 0, 0, false, "(objectClass=*)"));

      assertNotNull(conn.search("dc=example,dc=com", SearchScope.BASE,
           DereferencePolicy.NEVER, 0, 0, false,
           Filter.createPresenceFilter("objectClass")));

      assertNotNull(conn.search(null, "dc=example,dc=com", SearchScope.BASE,
           DereferencePolicy.NEVER, 0, 0, false, "(objectClass=*)"));

      assertNotNull(conn.search(null, "dc=example,dc=com", SearchScope.BASE,
           DereferencePolicy.NEVER, 0, 0, false,
           Filter.createPresenceFilter("objectClass")));

      assertNotNull(conn.search(new SearchRequest("dc=example,dc=com",
           SearchScope.BASE, Filter.createPresenceFilter("objectClass"))));

      assertNotNull(conn.search((ReadOnlySearchRequest) new SearchRequest(
           "dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass"))));

      assertNotNull(conn.searchForEntry("dc=example,dc=com", SearchScope.BASE,
           "(objectClass=*)"));

      assertNotNull(conn.searchForEntry("dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass")));

      assertNotNull(conn.searchForEntry("dc=example,dc=com", SearchScope.BASE,
           DereferencePolicy.NEVER, 0, false, "(objectClass=*)"));

      assertNotNull(conn.searchForEntry("dc=example,dc=com", SearchScope.BASE,
           DereferencePolicy.NEVER, 0, false,
           Filter.createPresenceFilter("objectClass")));

      assertNotNull(conn.searchForEntry(new SearchRequest("dc=example,dc=com",
           SearchScope.BASE, Filter.createPresenceFilter("objectClass"))));

      assertNotNull(conn.searchForEntry((ReadOnlySearchRequest)
           new SearchRequest("dc=example,dc=com", SearchScope.BASE,
           Filter.createPresenceFilter("objectClass"))));
    }
  }
}
