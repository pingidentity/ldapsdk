/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.examples;



import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.util.Base64;



/**
 * This class provides a set of test cases for the LDAPCompare class.
 */
public class LDAPCompareTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs the necessary setup before running these test cases.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    conn.close();
  }



  /**
   * Performs the necessary cleanup after running these test cases.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.delete(getTestBaseDN());
    conn.close();
  }



  /**
   * Provides general test coverage for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void provideGeneralTestCoverage()
         throws Exception
  {
    final LDAPCompare tool = new LDAPCompare(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the LDAPCompare command with an argument that takes a value but
   * without providing it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArgumentMissingValue()
         throws Exception
  {
    String[] args = { "-h" };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPCompare command with only one argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOneArgument()
         throws Exception
  {
    String[] args = { "objectclass:top" };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPCompare command with a malformed attribute-value assertion.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedAVA()
         throws Exception
  {
    String[] args = { "malformed", "dc=example,dc=com" };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPCompare command with a malformed attribute-value assertion
   * where the value is thought to be base64-encoded but isn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAValueNotBase64()
         throws Exception
  {
    String[] args = { "malformed::malformed", "dc=example,dc=com" };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPCompare command using the showUsage option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShowUsage()
         throws Exception
  {
    String[] args = { "--help" };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPCompare command with a valid compare operation that matches.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareMatching()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "objectclass:top",
      getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPCompare command with a valid compare operation that doesn't
   * match.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareNonMatching()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "objectclass:nonmatching",
      getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPCompare command with a valid base64-encoded assertion.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareBase64Assertion()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "objectclass::dG9w",
      getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPCompare command with bind and compare controls.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareWithControls()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "--bindControl", AuthorizationIdentityRequestControl.
           AUTHORIZATION_IDENTITY_REQUEST_OID,
      "--control", AssertionRequestControl.ASSERTION_REQUEST_OID + ':' + true +
         "::" + Base64.encode(new AssertionRequestControl(
              "(objectClass=unknown)").getValue().getValue()),
      "objectclass:top",
      getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.ASSERTION_FAILED);
  }



  /**
   * Tests the LDAPCompare command with an incorrect port number.  Surely no one
   * would try to run a server on port 2.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncorrectPort()
         throws Exception
  {
    if ((! isDirectoryInstanceAvailable()) || (getTestPort() == 2))
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", "2",
      "objectclass:top",
      getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.CONNECT_ERROR);
  }



  /**
   * Tests the LDAPCompare command with no authentication.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoAuthentication()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "objectclass:top",
      getTestBaseDN()
    };
    ResultCode rc = LDAPCompare.main(args, null, null);
    assertTrue((rc == ResultCode.SUCCESS) ||
               (rc == ResultCode.INSUFFICIENT_ACCESS_RIGHTS));
  }



  /**
   * Tests the LDAPCompare command with invalid credentials.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareInvalidCredentials()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String password;
    if (getTestBindPassword().equalsIgnoreCase("wrong"))
    {
      password = "reallywrong";
    }
    else
    {
      password = "wrong";
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", password,
      "objectclass:top",
      getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.INVALID_CREDENTIALS);
  }



  /**
   * Tests the LDAPCompare command with a target entry that doesn't exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareNoSuchObject()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "objectclass:top",
      "cn=nonexistent," + getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.NO_SUCH_OBJECT);
  }



  /**
   * Tests the LDAPCompare command with multiple target entries, the second of
   * which doesn't exist.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompareMultipleWithNoSuchObject()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "objectclass:top",
      getTestBaseDN(),
      "cn=nonexistent," + getTestBaseDN()
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.NO_SUCH_OBJECT);
  }



  /**
   * Performs a test that simply displays usage information for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelp()
         throws Exception
  {
    String[] args =
    {
      "-H"
    };
    assertEquals(LDAPCompare.main(args, null, null),
                 ResultCode.SUCCESS);
  }
}
