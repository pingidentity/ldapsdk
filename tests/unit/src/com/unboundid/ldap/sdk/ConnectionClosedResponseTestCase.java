/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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



/**
 * This class provides a set of test cases for the connection closed response
 * class.
 */
public class ConnectionClosedResponseTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor with a non-{@code null} message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNonNullMessage()
         throws Exception
  {
    ConnectionClosedResponse ccr = new ConnectionClosedResponse(
         ResultCode.SERVER_DOWN, "foo");

    assertNotNull(ccr);

    assertEquals(ccr.getMessageID(), -1);

    assertNotNull(ccr.getMessage());
    assertEquals(ccr.getMessage(), "foo");

    assertNotNull(ccr.toString());
  }



  /**
   * Tests the constructor with a {@code null} message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNullMessage()
         throws Exception
  {
    ConnectionClosedResponse ccr = new ConnectionClosedResponse(
         ResultCode.SERVER_DOWN, null);

    assertNotNull(ccr);

    assertEquals(ccr.getMessageID(), -1);

    assertNull(ccr.getMessage());

    assertNotNull(ccr.toString());
  }
}
