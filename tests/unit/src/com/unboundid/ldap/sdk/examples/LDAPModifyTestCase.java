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



import java.io.File;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;



/**
 * This class provides a set of test cases for the LDAPModify class.
 */
public class LDAPModifyTestCase
       extends LDAPSDKTestCase
{
  // The path to a file containing malformed LDIF data.
  private File malformedLDIF;

  // The path to a file containing valid LDIF data but that includes a target
  // entry that doesn't exist.
  private File missingEntryLDIF;

  // The path to a file containing valid LDIF data.
  private File validLDIF;

  // The path to a file containing valid LDIF data and an add record that does
  // not contain a changetype.
  private File validLDIFWithoutChangeType;



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

    malformedLDIF = createTempFile("what's this doing here?",
                                   "",
                                   "and how about this?",
                                   "",
                                   " see the space at the beginning?",
                                   "",
                                   "it prevents us from getting here");

    missingEntryLDIF = createTempFile("dn: cn=nonexistent," + getTestBaseDN(),
                                      "changetype: modify",
                                      "replace: description",
                                      "description: nonexistent",
                                      "",
                                      "dn: " + getTestBaseDN(),
                                      "changetype: modify",
                                      "replace: description",
                                      "description: foo",
                                      "",
                                      "dn: " + getTestBaseDN(),
                                      "changetype: modify",
                                      "replace: description",
                                      "description: bar");

    validLDIF = createTempFile("dn: " + getTestBaseDN(),
                               "changetype: modify",
                               "replace: description",
                               "description: foo",
                               "",
                               "dn: " + getTestBaseDN(),
                               "changetype: modify",
                               "replace: description",
                               "description: bar");

    validLDIFWithoutChangeType = createTempFile(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People",
         "",
         "dn: ou=People," + getTestBaseDN(),
         "changetype: delete");
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

    malformedLDIF.delete();
    missingEntryLDIF.delete();
    validLDIF.delete();
    validLDIFWithoutChangeType.delete();
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
    final LDAPModify tool = new LDAPModify(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the LDAPModify command with an argument that takes a value but
   * without providing it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testArgumentMissingValue()
         throws Exception
  {
    String[] args = { "-h" };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPModify command with a malformed attribute-value assertion
   * where the value is thought to be base64-encoded but isn't.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAVAValueNotBase64()
         throws Exception
  {
    String[] args = { "malformed::malformed", "dc=example,dc=com" };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPModify command using the showUsage option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testShowUsage()
         throws Exception
  {
    String[] args = { "--help" };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPModify command with a valid set of changes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyValidChanges()
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
      "-f", validLDIF.getAbsolutePath()
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPModify command with a valid set of changes in which an add
   * record is missing a changetype but the defaultAdd option was provided.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyValidChangesMissingChangeTypeWithDefaultAdd()
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
      "-f", validLDIFWithoutChangeType.getAbsolutePath(),
      "-a"
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPModify command with a valid set of changes in which an add
   * record is missing a changetype and the defaultAdd option was not provided.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyValidChangesMissingChangeTypeWithoutDefaultAdd()
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
      "-f", validLDIFWithoutChangeType.getAbsolutePath()
    };
    assertFalse(LDAPModify.main(args, null, null) ==
                ResultCode.SUCCESS);
  }



  /**
   * Tests the LDAPModify command with a malformed set of changes without
   * continue on error set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyMalformedChangesWithoutContinue()
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
      "-f", malformedLDIF.getAbsolutePath()
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.DECODING_ERROR);
  }



  /**
   * Tests the LDAPModify command with a malformed set of changes with continue
   * on error set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyMalformedChangesWithContinue()
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
      "-f", malformedLDIF.getAbsolutePath(),
      "-c"
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.DECODING_ERROR);
  }



  /**
   * Tests the LDAPModify command with an nonexistent set of changes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyNonexistentChanges()
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
      "-f", malformedLDIF.getAbsolutePath() + ".nonexistent"
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the LDAPModify command with an incorrect port number.  Surely no one
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
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-f", validLDIF.getAbsolutePath()
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.CONNECT_ERROR);
  }



  /**
   * Tests the LDAPModify command with invalid credentials.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyInvalidCredentials()
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
      "-f", validLDIF.getAbsolutePath()
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.INVALID_CREDENTIALS);
  }



  /**
   * Tests the LDAPModify command with a target entry that doesn't exist and
   * without continue on error.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyNoSuchObjectNoContinue()
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
      "-f", missingEntryLDIF.getAbsolutePath()
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.NO_SUCH_OBJECT);
  }



  /**
   * Tests the LDAPModify command with a target entry that doesn't exist but
   * with continue on error set.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModifyNoSuchObjectWithContinue()
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
      "-f", missingEntryLDIF.getAbsolutePath(),
      "-c"
    };
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.SUCCESS);
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
    assertEquals(LDAPModify.main(args, null, null),
                 ResultCode.SUCCESS);
  }
}
