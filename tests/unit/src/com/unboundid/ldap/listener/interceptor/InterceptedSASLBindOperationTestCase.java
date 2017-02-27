/*
 * Copyright 2014-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2017 UnboundID Corp.
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

import com.unboundid.ldap.protocol.BindRequestProtocolOp;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.GenericSASLBindRequest;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the intercepted in-memory SASL bind
 * operation.
 */
public final class InterceptedSASLBindOperationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for an intercepted SASL bind operation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    // Create an intercepted SASL bind operation.  We'll use a null connection,
    // which shouldn't happen naturally but will be sufficient for this test.
    final BindRequestProtocolOp requestOp =
         new BindRequestProtocolOp(
              new GenericSASLBindRequest(null, "MECH-A", null));

    final InterceptedSASLBindOperation o = new InterceptedSASLBindOperation(
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


    // Test methods specific to an intercepted SASL bind operation.
    assertNotNull(o.getRequest());
    assertEquals(o.getRequest().getSASLMechanismName(), "MECH-A");
    assertNotNull(o.toString());

    final GenericSASLBindRequest r =
         new GenericSASLBindRequest(null, "MECH-B", null);
    o.setRequest(r);

    assertNotNull(o.getRequest());
    assertEquals(o.getRequest().getSASLMechanismName(), "MECH-B");
    assertNotNull(o.toString());

    assertNull(o.getResult());

    o.setResult(new BindResult(o.getMessageID(), ResultCode.SUCCESS, null, null,
         null, null));
    assertNotNull(o.getResult());
    assertNotNull(o.toString());
  }
}
