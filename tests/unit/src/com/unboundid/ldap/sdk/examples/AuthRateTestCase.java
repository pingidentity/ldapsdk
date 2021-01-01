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

import java.io.File;


/**
 * This class provides a set of test cases for the AuthRate class.
 */
public class AuthRateTestCase
       extends LDAPSDKTestCase
{
  /**
   * Populates the directory server with a set of test entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createTestEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());
    for (int i=1; i <= 10; i++)
    {
      conn.add("dn: uid=user." + i + ',' + getTestBaseDN(),
               "objectClass: top",
               "objectClass: person",
               "objectClass: organizationalPerson",
               "objectClass: inetOrgPerson",
               "uid: user." + i,
               "givenName: User",
               "sn: " + i,
               "cn: User " + i,
               "userPassword: password",
               "description:  This is the description for user " + i);
    }

    conn.close();
  }



  /**
   * Removes the test entries from the server.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void removeTestEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection conn = getAdminConnection();
    for (int i=1; i <= 10; i++)
    {
      conn.delete("uid=user." + i + ',' + getTestBaseDN());
    }
    conn.delete(getTestBaseDN());

    conn.close();
  }



  /**
   * Performs a test using a valid set of arguments against a single entry using
   * CSV output.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleEntryWithCSV()
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
      "-b", "uid=user.1," + getTestBaseDN(),
      "-s", "base",
      "-A", "1.1",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "-r", "100",
      "-R", "0",
      "-c",
      "--suppressErrorResultCodes",
    };
    assertEquals(AuthRate.main(args, null, null),
         ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid set of arguments against multiple entries
   * (specified using a variable base DN) using the standard output mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleEntriesByBaseDNNormalOutput()
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
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.[1-11]," + getTestBaseDN(),
      "-s", "base",
      "-A", "*",
      "-A", "+",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "--timestampFormat", "with-date",
      "--warmUpIntervals", "1"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid set of arguments against multiple entries
   * (specified using a variable filter) using the standard output mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleEntriesByFilterNormalOutput()
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
      "-f", "(uid=user.[1-10])",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "--timestampFormat", "without-date"
    };
    assertEquals(AuthRate.main(args, null, null),
         ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid set of arguments against multiple entries
   * with SASL PLAIN using the standard output mode.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleEntriesByFilterNormalOutputPLAIN()
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
      "-f", "(uid=user.[1-10])",
      "-C", "password",
      "-a", "PLAIN",
      "-t", "10",
      "-i", "1",
      "-I", "2",
       "--timestampFormat", "none"
    };
    assertEquals(AuthRate.main(args, null, null),
                 ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid set of arguments with a search that doesn't
   * match any entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchNoMatches()
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
      "-A", "*",
      "-A", "+",
      "-f", "(uid=user.11)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid set of arguments with a search that matches
   * multiple entries.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchMultipleMatches()
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
      "-A", "*",
      "-A", "+",
      "-f", "(objectClass=person)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using the wrong password with CRAM-MD5 authentication.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrongPasswordCRAMMD5()
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
      "-f", "(uid=user.[1-10])",
      "-C", "wrong",
      "-a", "CRAM-MD5",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using the wrong password with DIGEST-MD5 authentication.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWrongPasswordDIGESTMD5()
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
      "-f", "(uid=user.[1-10])",
      "-C", "wrong",
      "-a", "DIGEST-MD5",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using an invalid authentication type.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidAuthType()
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
      "-f", "(uid=user.[1-10])",
      "-C", "password",
      "-a", "invalid",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using an invalid scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidScope()
         throws Exception
  {
    String[] args =
    {
      "-h", "127.0.0.1",
      "-p", "389",
      "-b", "dc=example,dc=com",
      "-s", "invalid",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using an invalid base DN pattern.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidDNPattern()
         throws Exception
  {
    String[] args =
    {
      "-h", "127.0.0.1",
      "-p", "389",
      "-b", "uid=user.[1-10,dc=example,dc=com",
      "-s", "one",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using an invalid filter pattern.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidFilterPattern()
         throws Exception
  {
    String[] args =
    {
      "-h", "127.0.0.1",
      "-p", "389",
      "-b", "dc=example,dc=com",
      "-s", "subord",
      "-f", "(uid=user.[1-10)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test in which it is not possible to obtain a connection.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCannotConnect()
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
      "-w", "wrong" + getTestBindPassword(),
      "-b", getTestBaseDN(),
      "-s", "subord",
      "-f", "(uid=user.[1-10])",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a base DN that does not exist in the server.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBadBaseDN()
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
      "-b", "ou=missing," + getTestBaseDN(),
      "-s", "base",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid filter pattern but an invalid string
   * representation of a filter.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidFilterString()
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
      "-f", "(user.[1-10]",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
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
    assertEquals(AuthRate.main(args, null, null),
         ResultCode.SUCCESS);
  }



  /**
   * Performs a test that has multiple hostname arguments but only a single
   * port argument.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleHostnamesSinglePort()
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
      "-h", getTestHost(),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.1," + getTestBaseDN(),
      "-s", "base",
      "-A", "1.1",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "-r", "100",
      "-c"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test that has a single hostname argument but multiple port
   * arguments.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleHostnameMultiplePorts()
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
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.1," + getTestBaseDN(),
      "-s", "base",
      "-A", "1.1",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "-r", "100",
      "-c"
    };
    assertFalse(AuthRate.main(args, null, null) == ResultCode.SUCCESS);
  }



  /**
   * Performs a test of --variableRate without the rates repeating.  The command
   * should complete when all of the rates have been processed.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(timeOut = 10000)
  public void testVariableRate()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File repeatingRatesFile = createTempFile(
         "format=rate-and-duration",
         "END HEADER",
         "1000,50ms",
         "1.0,50ms"
    );

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.1," + getTestBaseDN(),
      "-s", "base",
      "-A", "1.1",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-r", "100",
      "--variableRateData", repeatingRatesFile.getAbsolutePath()
    };
    assertEquals(AuthRate.main(args, null, null), ResultCode.SUCCESS);
  }



  /**
   * Performs a test of --variableRate with the rates repeating.  The command
   * should complete because the number of intervals is specified.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(timeOut = 10000)
  public void testVariableRateWithRepeat()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File repeatingRatesFile = createTempFile(
         "format=rate-and-duration",
         "repeat=true",
         "END HEADER",
         "1000,50ms",
         "1.0,10ms"
    );

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.1," + getTestBaseDN(),
      "-s", "base",
      "-A", "1.1",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "-r", "100",
      "--variableRateData", repeatingRatesFile.getAbsolutePath()
    };
    assertEquals(AuthRate.main(args, null, null), ResultCode.SUCCESS);
  }



  /**
   * Performs a test of --variableRate with an invalid input file.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(timeOut = 10000)
  public void testVariableRateWithInvalidFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    File repeatingRatesFile = createTempFile(
         "format=unknown",
         "END HEADER",
         "1000,50ms",
         "1.0,10ms"
    );

    String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.1," + getTestBaseDN(),
      "-s", "base",
      "-A", "1.1",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-r", "100",
      "--variableRateData", repeatingRatesFile.getAbsolutePath()
    };
    assertEquals(AuthRate.main(args, null, null), ResultCode.PARAM_ERROR);
  }



  /**
   * Tests the generateSampleRateFile argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenerateSampleRateFile()
         throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());
    assertFalse(f.exists());

    String[] args =
    {
      "--generateSampleRateFile", f.getAbsolutePath()
    };
    assertEquals(AuthRate.main(args, null, null), ResultCode.SUCCESS);
    assertTrue(f.exists());
    assertTrue(f.length() > 0);
  }



  /**
   * Tests to ensure that the {@code stopRunning} method can be used to stop
   * the tool programmatically.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(timeOut = 10000)
  public void testStopRunning()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final AuthRate authRate = new AuthRate(null, null);

    assertTrue(authRate.supportsInteractiveMode());
    assertTrue(authRate.defaultsToInteractiveMode());

    final String[] args =
    {
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-h", getTestHost(),
      "-p", String.valueOf(getTestPort()),
      "-D", getTestBindDN(),
      "-w", getTestBindPassword(),
      "-b", "uid=user.[1-10]," + getTestBaseDN(),
      "-s", "base",
      "-A", "*",
      "-A", "+",
      "-f", "(objectClass=*)",
      "-C", "password",
      "-t", "10"
    };

    new Thread()
    {
      @Override()
      public void run()
      {
        try
        {
          Thread.sleep(500L);
        } catch (final Exception e) {}
        authRate.stopRunning();
      }
    }.start();

    assertEquals(authRate.runTool(args), ResultCode.SUCCESS);
  }



  /**
   * Performs a test using a valid set of arguments that makes use of the
   * bindOnly argument and includes request controls.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBindOnlyWithControls()
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
      "-b", "uid=user.[1-10]," + getTestBaseDN(),
      "-C", "password",
      "-t", "10",
      "-i", "1",
      "-I", "2",
      "-r", "100",
      "-R", "0",
      "--suppressErrorResultCodes",
      "--bindOnly",
      "--authorizationIdentityRequestControl",
      "--passwordPolicyRequestControl",
      "--searchControl", "2.16.840.1.113730.3.4.2:false",
      "--bindControl", "1.3.6.1.4.1.30221.2.5.6:false"
    };
    assertEquals(AuthRate.main(args, null, null),
         ResultCode.SUCCESS);
  }
}
