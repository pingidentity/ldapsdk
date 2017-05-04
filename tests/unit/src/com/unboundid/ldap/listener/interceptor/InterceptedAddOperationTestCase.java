/*
 * Copyright 2014-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2017 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import org.testng.annotations.Test;

import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the intercepted in-memory add
 * operation.
 */
public final class InterceptedAddOperationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for an intercepted add operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    // Create an intercepted add operation.  We'll use a null connection, which
    // shouldn't happen naturally but will be sufficient for this test.
    final AddRequestProtocolOp requestOp =
         new AddRequestProtocolOp(new AddRequest(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    final InterceptedAddOperation o = new InterceptedAddOperation(
         null, 1, requestOp);
    assertNotNull(o.toString());


    // Test methods for a generic intercepted operation.
    assertNull(o.getClientConnection());

    assertEquals(o.getConnectionID(), -1L);

    assertNull(o.getConnectedAddress());

    assertEquals(o.getConnectedPort(), -1);

    assertEquals(o.getMessageID(), 1);

    assertNull(o.getProperty("propX"));

    o.setProperty("propX", "valX");
    assertNotNull(o.getProperty("propX"));
    assertEquals(o.getProperty("propX"), "valX");
    assertNotNull(o.toString());

    o.setProperty("propX", null);
    assertNull(o.getProperty("propX"));


    // Test methods specific to an intercepted add operation.
    assertNotNull(o.getRequest());
    assertFalse(o.getRequest().hasAttribute("description"));

    final AddRequest r = o.getRequest().duplicate();
    r.addAttribute("description", "foo");
    o.setRequest(r);

    assertNotNull(o.getRequest());
    assertTrue(o.getRequest().hasAttributeValue("description", "foo"));
    assertNotNull(o.toString());

    assertNull(o.getResult());

    o.setResult(new LDAPResult(o.getMessageID(), ResultCode.SUCCESS));
    assertNotNull(o.getResult());
    assertNotNull(o.toString());
  }
}
