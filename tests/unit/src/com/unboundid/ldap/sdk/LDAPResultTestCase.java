/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
 * This class provides a set of test cases for the LDAPResult class.
 */
public class LDAPResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the LDAP result class with the provide information.
   *
   * @param  resultCode         The result code for the LDAP result.
   * @param  diagnosticMessage  The diagnostic message for the LDAP result.
   * @param  matchedDN          The matched DN for the LDAP result.
   * @param  referralURLs       The set of referral URLs for the LDAP result.
   * @param  responseControls   The set of response controls for the LDAP
   *                            result.
   */
  @Test(dataProvider = "testLDAPResultData")
  public void testLDAPResult(ResultCode resultCode, String diagnosticMessage,
                             String matchedDN, String[] referralURLs,
                             Control[] responseControls)
  {
    LDAPResult ldapResult = new LDAPResult(1, resultCode, diagnosticMessage,
                                           matchedDN, referralURLs,
                                           responseControls);

    assertEquals(ldapResult.getMessageID(), 1);

    assertEquals(ldapResult.getResultCode(), resultCode);

    if (diagnosticMessage == null)
    {
      assertNull(ldapResult.getDiagnosticMessage());
    }
    else
    {
      assertNotNull(ldapResult.getDiagnosticMessage());
      assertEquals(ldapResult.getDiagnosticMessage(), diagnosticMessage);
    }

    if (matchedDN == null)
    {
      assertNull(ldapResult.getMatchedDN());
    }
    else
    {
      assertNotNull(ldapResult.getMatchedDN());
      assertEquals(ldapResult.getMatchedDN(), matchedDN);
    }

    assertNotNull(ldapResult.getReferralURLs());
    if (referralURLs == null)
    {
      assertEquals(ldapResult.getReferralURLs().length, 0);
    }
    else
    {
      assertEquals(ldapResult.getReferralURLs().length, referralURLs.length);
      for (int i=0; i < referralURLs.length; i++)
      {
        assertEquals(ldapResult.getReferralURLs()[i], referralURLs[i]);
      }
    }

    assertNotNull(ldapResult.getResponseControls());
    if (responseControls == null)
    {
      assertFalse(ldapResult.hasResponseControl());
      assertEquals(ldapResult.getResponseControls().length, 0);
      assertFalse(ldapResult.hasResponseControl("1.2.3.4"));
      assertNull(ldapResult.getResponseControl("1.2.3.4"));
    }
    else
    {
      if (responseControls.length == 0)
      {
        assertFalse(ldapResult.hasResponseControl());
        assertFalse(ldapResult.hasResponseControl("1.2.3.4"));
      }
      else
      {
        assertTrue(ldapResult.hasResponseControl());
        assertTrue(ldapResult.hasResponseControl("1.2.3.4"));
      }

      assertFalse(ldapResult.hasResponseControl("1.2.3.6"));

      assertEquals(ldapResult.getResponseControls().length,
                   responseControls.length);
      for (int i=0; i < responseControls.length; i++)
      {
        assertEquals(ldapResult.getResponseControls()[i], responseControls[i]);
      }
      if (responseControls.length > 0)
      {
        assertNotNull(ldapResult.getResponseControl(
             ldapResult.getResponseControls()[0].getOID()));
        assertNull(ldapResult.getResponseControl("1.1.1.1"));
      }
    }
    assertNotNull(ldapResult.toString());

    assertNotNull(ldapResult.getResultString());
  }



  /**
   * Retrieves a set of test data that may be used to create LDAP result
   * objects.
   *
   * @return  A set of test data that may be used to create LDAP result objects.
   */
  @DataProvider(name = "testLDAPResultData")
  public Object[][] getTestLDAPResultData()
  {
    return new Object[][]
    {
      new Object[]
      {
        ResultCode.SUCCESS,
        null,
        null,
        null,
        null
      },

      new Object[]
      {
        ResultCode.SUCCESS,
        "",
        "",
        new String[0],
        new Control[0]
      },

      new Object[]
      {
        ResultCode.NO_SUCH_OBJECT,
        "The target entry does not exist.",
        "dc=example,dc=com",
        new String[] { "ldap://test.example.com/ou=People,dc=example,dc=com" },
        new Control[] { new Control("1.2.3.4") }
      },

      new Object[]
      {
        ResultCode.NO_SUCH_OBJECT,
        "The target entry does not exist.",
        "dc=example,dc=com",
        new String[] { "ldap://test1.example.com/ou=People,dc=example,dc=com",
                       "ldap://test2.example.com/ou=People,dc=example,dc=com" },
        new Control[] { new Control("1.2.3.4"), new Control("1.2.3.5") }
      },
    };
  }
}
