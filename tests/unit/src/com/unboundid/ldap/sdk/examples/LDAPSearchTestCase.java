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
 * This class provides a set of test cases for the LDAPSearch class.
 */
public class LDAPSearchTestCase
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
    final LDAPSearch tool = new LDAPSearch(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.defaultToPromptForBindPassword());

    assertNotNull(tool.getOriginalOut());
    assertNotNull(tool.getOriginalErr());
  }



  /**
   * Tests the LDAPSearch command without the required base DN argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingRequiredBaseDNArgument()
         throws Exception
  {
    String[] args = { "(objectClass=*)" };
    assertEquals(LDAPSearch.main(args, null, null),
         ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPSearch command without any trailing arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoTrailingArgs()
         throws Exception
  {
    String[] args = { "-b", "dc=example,dc=com" };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPSearch command using the showUsage option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShowUsage()
         throws Exception
  {
    String[] args = { "--help" };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that matches an entry and does
   * not include any requested attributes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchMatchesNoAttributes()
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
      "-b", getTestBaseDN(),
      "-s", "base",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that matches an entry and does
   * include a set of requested attributes.  The search will also be repeated
   * five times.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchMatchesWithAttributes()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String outputFilePath = createTempFile().getAbsolutePath();

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", getTestBaseDN(),
      "-s", "base",
      "-i", "100",
      "-n", "5",
      "--outputFile", outputFilePath,
      "(objectClass=*)",
      "objectClass",
      "description"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that uses a scope of "one".
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchScopeOne()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String outputFilePath = createTempFile().getAbsolutePath();

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", getTestBaseDN(),
      "-s", "one",
      "--outputFile", outputFilePath,
      "--appendToOutputFile",
      "--teeOutput",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that uses a scope of "sub".
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchScopeSub()
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
      "-b", getTestBaseDN(),
      "-s", "sub",
      "-t",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that uses a scope of
   * "subord".
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchScopeSubordinate()
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
      "-b", getTestBaseDN(),
      "-s", "subord",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that uses an invalid scope.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchInvalidScope()
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
      "-b", getTestBaseDN(),
      "-s", "invalid",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPSearch command with a search that contains an invalid filter.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchInvalidFilter()
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
      "-b", getTestBaseDN(),
      "-s", "base",
      "invalid"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPSearch command with an incorrect port number.  Surely no one
   * would try to run a server on port 2.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchIncorrectPort()
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
      "-b", getTestBaseDN(),
      "-s", "base",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.CONNECT_ERROR);
  }



  /**
   * Tests the LDAPSearch command with a search that does not perform
   * authentication.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchNoAuthentication()
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
      "-b", getTestBaseDN(),
      "-s", "base",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPSearch command with a search that fails to authenticate.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchAuthenticationFailure()
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
      "-b", getTestBaseDN(),
      "-s", "base",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.INVALID_CREDENTIALS);
  }



  /**
   * Tests the LDAPSearch command with a search that uses a nonexistent base DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchNonexistentBase()
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
      "-b", "cn=nonexistent," + getTestBaseDN(),
      "-s", "base",
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.NO_SUCH_OBJECT);
  }



  /**
   * Tests the LDAPSearch command with bind and search controls.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchWithControls()
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
      "-b", getTestBaseDN(),
      "-s", "base",
      "--bindControl", AuthorizationIdentityRequestControl.
           AUTHORIZATION_IDENTITY_REQUEST_OID,
      "--control", AssertionRequestControl.ASSERTION_REQUEST_OID + ':' + true +
         "::" + Base64.encode(new AssertionRequestControl(
              "(objectClass=unknown)").getValue().getValue()),
      "(objectClass=*)"

    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.ASSERTION_FAILED);
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
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Performs a test that simply displays SASL usage information for the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHelpSAL()
         throws Exception
  {
    String[] args =
    {
      "--helpSASL"
    };
    assertEquals(LDAPSearch.main(args, null, null),
                 ResultCode.SUCCESS);
  }
}
