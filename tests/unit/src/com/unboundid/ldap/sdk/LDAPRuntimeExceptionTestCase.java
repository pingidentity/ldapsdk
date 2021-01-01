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
package com.unboundid.ldap.sdk;



import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides test coverage for the LDAPRuntimeException class.
 */
public final class LDAPRuntimeExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the runtime version of {@code LDAPException}.
   *
   * @param  le  The LDAP exception to use for the runtime exception.
   *
   * @throws  Exception  If a problem is encountered while processing.
   */
  @Test(dataProvider = "testExceptions",
        expectedExceptions = { LDAPException.class })
  public void testLDAPRuntimeException(final LDAPException le)
         throws Exception
  {
    final LDAPRuntimeException lre = new LDAPRuntimeException(le);

    assertEquals(lre.getLDAPException(), le);

    assertEquals(lre.getMessage(), le.getMessage());

    assertEquals(lre.getResultCode(), le.getResultCode());

    assertEquals(lre.getDiagnosticMessage(), le.getDiagnosticMessage());

    assertEquals(lre.getMatchedDN(), le.getMatchedDN());

    assertEquals(lre.getReferralURLs(), le.getReferralURLs());

    assertEquals(lre.getResponseControls(), le.getResponseControls());

    assertEquals(lre.hasResponseControl(), le.hasResponseControl());

    for (final Control c : le.getResponseControls())
    {
      assertNotNull(lre.getResponseControl(c.getOID()));
      assertEquals(lre.getResponseControl(c.getOID()),
           le.getResponseControl(c.getOID()));
      assertTrue(lre.hasResponseControl(c.getOID()));
    }

    assertEquals(lre.getCause(), le.getCause());

    assertNotNull(lre.toLDAPResult());

    assertEquals(lre.getExceptionMessage(), le.getExceptionMessage());

    assertEquals(lre.toString(), le.toString());

    lre.throwLDAPException();
  }



  /**
   * Retrieves a set of exceptions that can be used for testing.
   *
   * @return  A set of exceptions that can be used for testing.
   */
  @DataProvider(name = "testExceptions")
  public Object[][] getTestExceptions()
  {
    final String nullDiagnosticMessage = null;

    final String nonNullDiagnosticMessage = "diagnostic message";

    final String nullMatchedDN = null;

    final String nonNullMatchedDN = "dc=example,dc=com";

    final String[] nullRefs = null;

    final String[] noRefs = new String[0];

    final String[] oneRef =
    {
      "ldap://server.example.com/dc=example,dc=com"
    };

    final String[] multipleRefs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com"
    };

    final Control[] nullControls = null;

    final Control[] noControls = new Control[0];

    final Control[] oneControl =
    {
      new Control("1.2.3.4")
    };

    final Control[] multipleControls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5")
    };

    final Throwable nullCause = null;

    final Throwable nonNullCause = new Exception();

    return new Object[][]
    {
      new Object[]
      {
        new LDAPException(ResultCode.OTHER, nullDiagnosticMessage,
             nullMatchedDN, nullRefs, nullControls, nullCause)
      },

      new Object[]
      {
        new LDAPException(ResultCode.OTHER, nullDiagnosticMessage,
             nullMatchedDN, noRefs, noControls, nullCause)
      },

      new Object[]
      {
        new LDAPException(ResultCode.OTHER, nonNullDiagnosticMessage,
             nonNullMatchedDN, oneRef, oneControl, nonNullCause)
      },

      new Object[]
      {
        new LDAPException(ResultCode.OTHER, nonNullDiagnosticMessage,
             nonNullMatchedDN, multipleRefs, multipleControls, nonNullCause)
      },
    };
  }
}
