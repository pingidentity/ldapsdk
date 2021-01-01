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
