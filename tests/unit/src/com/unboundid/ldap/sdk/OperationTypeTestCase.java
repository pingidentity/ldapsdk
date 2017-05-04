/*
 * Copyright 2011-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011-2017 Ping Identity Corporation
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



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.extensions.CancelExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;



/**
 * This class provides a set of test cases for the operation type enum.
 */
public final class OperationTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic functionality for the operation type enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasic()
         throws Exception
  {
    assertNotNull(OperationType.values());
    for (final OperationType t : OperationType.values())
    {
      assertNotNull(t);
      assertNotNull(t.name());
      assertEquals(OperationType.valueOf(t.name()), t);
    }

    assertEquals(OperationType.valueOf("ABANDON"), OperationType.ABANDON);
    assertEquals(OperationType.valueOf("ADD"), OperationType.ADD);
    assertEquals(OperationType.valueOf("BIND"), OperationType.BIND);
    assertEquals(OperationType.valueOf("COMPARE"), OperationType.COMPARE);
    assertEquals(OperationType.valueOf("DELETE"), OperationType.DELETE);
    assertEquals(OperationType.valueOf("EXTENDED"), OperationType.EXTENDED);
    assertEquals(OperationType.valueOf("MODIFY"), OperationType.MODIFY);
    assertEquals(OperationType.valueOf("MODIFY_DN"), OperationType.MODIFY_DN);
    assertEquals(OperationType.valueOf("SEARCH"), OperationType.SEARCH);
    assertEquals(OperationType.valueOf("UNBIND"), OperationType.UNBIND);
  }



  /**
   * Provides test coverage for the {@code Request.getOperationType} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequestGetOperationType()
         throws Exception
  {
    final AddRequest addRequest = new AddRequest(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");
    assertEquals(addRequest.getOperationType(), OperationType.ADD);

    final SimpleBindRequest simpleBindRequest =
         new SimpleBindRequest("cn=Directory Manager", "password");
    assertEquals(simpleBindRequest.getOperationType(), OperationType.BIND);

    final PLAINBindRequest plainBindRequest =
         new PLAINBindRequest("u:test.user", "password");
    assertEquals(plainBindRequest.getOperationType(), OperationType.BIND);

    final CompareRequest compareRequest =
         new CompareRequest("dc=example,dc=com", "foo", "bar");
    assertEquals(compareRequest.getOperationType(), OperationType.COMPARE);

    final DeleteRequest deleteRequest = new DeleteRequest("dc=example,dc=com");
    assertEquals(deleteRequest.getOperationType(), OperationType.DELETE);

    final CancelExtendedRequest cancelRequest = new CancelExtendedRequest(1);
    assertEquals(cancelRequest.getOperationType(), OperationType.EXTENDED);

    final WhoAmIExtendedRequest whoAmIRequest = new WhoAmIExtendedRequest();
    assertEquals(whoAmIRequest.getOperationType(), OperationType.EXTENDED);

    final ModifyRequest modifyRequest = new ModifyRequest(
         "dn: dc=example,dc=com",
         "changetype: modify",
         "replace: description",
         "description: foo");
    assertEquals(modifyRequest.getOperationType(), OperationType.MODIFY);

    final ModifyDNRequest modifyDNRequest = new ModifyDNRequest(
         "ou=People,dc=example,dc=com", "ou=Users", true);
    assertEquals(modifyDNRequest.getOperationType(), OperationType.MODIFY_DN);

    final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
         SearchScope.BASE, "(objectClass=*)");
    assertEquals(searchRequest.getOperationType(), OperationType.SEARCH);
  }
}
