/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.examples;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.TreeSet;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;



/**
 * This class provides a set of test cases for the {@code DumpDNs} class.
 */
public final class DumpDNsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Adds a number of entries to the Directory Server.
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

    // Add a base entry and 10 subordinate entries.
    final LDAPConnection conn = getAdminConnection();
    conn.add(getTestBaseDN(), getBaseEntryAttributes());

    for (int i=1; i <= 10; i++)
    {
      conn.add(
           "dn: ou=" + i + ',' + getTestBaseDN(),
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: " + i);
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
  public void cleanUp()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
    deleteRequest.addControl(new SubtreeDeleteRequestControl(true));

    final LDAPConnection conn = getAdminConnection();
    conn.delete(deleteRequest);
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
    final DumpDNs tool = new DumpDNs(null, null);
    assertNotNull(tool.getExampleUsages());

    assertTrue(tool.supportsInteractiveMode());
    assertTrue(tool.defaultsToInteractiveMode());
  }



  /**
   * Tests the behavior of the tool when an output file is given.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithOutputFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File outFile = createTempFile();

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--baseDN", getTestBaseDN(),
      "--outputFile", outFile.getAbsolutePath()
    };

    final ResultCode resultCode = DumpDNs.main(args, null, null);
    assertEquals(resultCode, ResultCode.SUCCESS);

    // Make sure that a total of eleven DNs were output.
    final TreeSet<DN> dnSet = readDNs(outFile);
    assertEquals(dnSet.size(), 11);
    assertTrue(dnSet.contains(new DN(getTestBaseDN())));
    for (int i=1; i <= 10; i++)
    {
      assertTrue(dnSet.contains(new DN("ou=" + i + ',' + getTestBaseDN())));
    }
  }



  /**
   * Tests the behavior of the tool when no output file is given.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoOutputFile()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final File outFile = createTempFile();
    final File errFile = createTempFile();
    final PrintStream newOut = new PrintStream(outFile);
    final PrintStream newErr = new PrintStream(errFile);

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", getTestBindPassword(),
      "--baseDN", getTestBaseDN()
    };

    final ResultCode resultCode = DumpDNs.main(args, newOut, newErr);
    assertEquals(resultCode, ResultCode.SUCCESS);

    newOut.close();
    newErr.close();

    // Make sure that a total of eleven DNs were output.
    final TreeSet<DN> dnSet = readDNs(outFile);
    assertEquals(dnSet.size(), 11);
    assertTrue(dnSet.contains(new DN(getTestBaseDN())));
    for (int i=1; i <= 10; i++)
    {
      assertTrue(dnSet.contains(new DN("ou=" + i + ',' + getTestBaseDN())));
    }
  }



  /**
   * Tests the behavior of the tool when an incorrect password is given.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIncorrectPassword()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", "wrong-" + getTestBindPassword(),
      "--baseDN", getTestBaseDN()
    };

    final ResultCode resultCode = DumpDNs.main(args, null, null);
    assertFalse(resultCode.equals(ResultCode.SUCCESS));
  }



  /**
   * Tests the behavior of the tool when an invalid base DN is given.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidBaseDN()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    final String[] args =
    {
      "--hostname", getTestHost(),
      "--port", String.valueOf(getTestPort()),
      "--bindDN", getTestBindDN(),
      "--bindPassword", "wrong-" + getTestBindPassword(),
      "--baseDN", "ou=missing," + getTestBaseDN()
    };

    final ResultCode resultCode = DumpDNs.main(args, null, null);
    assertFalse(resultCode.equals(ResultCode.SUCCESS));
  }



  /**
   * Provides test coverage for the {@code getExampleUsages} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExampleUsages()
         throws Exception
  {
    final DumpDNs dumpDNs = new DumpDNs(null, null);
    final LinkedHashMap<String[],String> examples = dumpDNs.getExampleUsages();
    assertNotNull(examples);
    assertFalse(examples.isEmpty());
    assertEquals(examples.size(), 1);
  }



  /**
   * Reads the contents of the specified file into a set of DNs.
   *
   * @param  f  The file to be read.
   *
   * @return  The set of DNs that was read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static TreeSet<DN> readDNs(final File f)
          throws Exception
  {
    final TreeSet<DN> dnSet = new TreeSet<DN>();

    int dnsRead = 0;
    final BufferedReader reader = new BufferedReader(new FileReader(f));

    while (true)
    {
      final String line = reader.readLine();
      if (line == null)
      {
        break;
      }

      dnSet.add(new DN(line));
      dnsRead++;
    }

    reader.close();
    assertEquals(dnSet.size(), dnsRead);

    return dnSet;
  }
}
