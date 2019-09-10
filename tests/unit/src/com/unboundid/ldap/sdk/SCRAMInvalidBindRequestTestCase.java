/*
 * Copyright 2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Ping Identity Corporation
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

import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for a SCRAM bind request with invalid
 * digest and MAC algorithms.
 */
public final class SCRAMInvalidBindRequestTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to get a digest instance for an invalid
   * algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testGetDigest()
         throws Exception
  {
    final SCRAMInvalidBindRequest bindRequest =
         new SCRAMInvalidBindRequest("user", "pencil");
    bindRequest.digest(StaticUtils.byteArray(1, 2, 3, 4));
  }



  /**
   * Tests the behavior when trying to get a MAC instance for an invalid
   * algorithm.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPBindException.class })
  public void testGetMAC()
         throws Exception
  {
    final SCRAMInvalidBindRequest bindRequest =
         new SCRAMInvalidBindRequest("user", "pencil");
    bindRequest.mac(StaticUtils.byteArray(1, 2, 3, 4),
         StaticUtils.byteArray(5, 6, 7, 8));
  }
}
