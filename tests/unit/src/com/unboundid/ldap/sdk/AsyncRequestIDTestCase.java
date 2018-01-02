/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
 * This class provides a set of test cases for the AsyncRequestID class.
 */
public class AsyncRequestIDTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    AsyncRequestID requestID = new AsyncRequestID(1234, null);

    assertEquals(requestID.getMessageID(), 1234);

    assertEquals(requestID.hashCode(), 1234);

    assertNotNull(requestID.toString());
  }



  /**
   * Tests the {@code equals} method with various cases.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    AsyncRequestID requestID = new AsyncRequestID(1234, null);

    assertFalse(requestID.equals(null));
    assertTrue(requestID.equals(requestID));
    assertFalse(requestID.equals("foo"));
    assertTrue(requestID.equals(new AsyncRequestID(1234, null)));
    assertFalse(requestID.equals(new AsyncRequestID(5678, null)));
  }
}
