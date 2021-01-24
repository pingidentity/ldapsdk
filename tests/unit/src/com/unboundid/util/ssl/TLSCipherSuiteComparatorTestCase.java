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
package com.unboundid.util.ssl;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the TLS cipher suite comparator.
 */
public final class TLSCipherSuiteComparatorTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the comparator with a set of TLS cipher suites
   * loaded from the specified file.
   *
   * @param  filename  The name of the file (in the unit test resource
   *                   directory) containing the cipher suites.  The suites
   *                   should be listed in the expected order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="cipherSuiteFileNames")
  public void testCipherSuiteOrdering(final String filename)
         throws Exception
  {
    // Read a file with a set of TLS cipher suites in the expected order.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File cipherSuiteFile = new File(resourceDir, filename);

    final List<String> expectedCipherSuiteOrder = new ArrayList<>(500);
    try (FileReader fileReader = new FileReader(cipherSuiteFile);
         BufferedReader bufferedReader = new BufferedReader(fileReader))
    {
      while (true)
      {
        final String line = bufferedReader.readLine();
        if (line == null)
        {
          break;
        }
        else if (line.isEmpty() || line.startsWith("#"))
        {
          continue;
        }
        else
        {
          expectedCipherSuiteOrder.add(line);
        }
      }
    }


    // Create a copy of the cipher stream list in random order.
    final List<String> randomizedCipherSuiteList =
         new ArrayList<>(expectedCipherSuiteOrder);
    Collections.shuffle(randomizedCipherSuiteList);
    assertFalse(randomizedCipherSuiteList.equals(expectedCipherSuiteOrder));


    // Use the comparator to sort the list of cipher suites.
    final TreeSet<String> sortedCipherSuiteSet =
         new TreeSet<>(TLSCipherSuiteComparator.getInstance());
    for (final String cipherSuite : randomizedCipherSuiteList)
    {
      sortedCipherSuiteSet.add(cipherSuite);
    }


    // Make sure that the sorted list is in the expected order.
    final List<String> sortedCipherSuiteList =
         new ArrayList<>(sortedCipherSuiteSet);
    if (! sortedCipherSuiteList.equals(expectedCipherSuiteOrder))
    {
      final StringBuilder errorMessage = new StringBuilder();
      errorMessage.append("The expected order did not match the computed " +
           "order.");
      errorMessage.append(StaticUtils.EOL);
      errorMessage.append(StaticUtils.EOL);
      errorMessage.append("Expected order:");
      errorMessage.append(StaticUtils.EOL);
      errorMessage.append(StaticUtils.EOL);
      for (final String s : expectedCipherSuiteOrder)
      {
        errorMessage.append(s);
        errorMessage.append(StaticUtils.EOL);
      }

      errorMessage.append(StaticUtils.EOL);
      errorMessage.append("Computed order:");
      errorMessage.append(StaticUtils.EOL);
      errorMessage.append(StaticUtils.EOL);
      for (final String s : sortedCipherSuiteList)
      {
        errorMessage.append(s);
        errorMessage.append(StaticUtils.EOL);
      }

      fail(errorMessage.toString());
    }
  }



  /**
   * Retrieves the names of files containing cipher suites to use for testing.
   *
   * @return  The names of files containing cipher suites to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="cipherSuiteFileNames")
  public Object[][] getCipherSuiteFileNames()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        "comprehensive-list-of-tls-cipher-suites.txt"
      },

      new Object[]
      {
        "java-7-tls-cipher-suites.txt"
      },

      new Object[]
      {
        "java-8-tls-cipher-suites.txt"
      },

      new Object[]
      {
        "java-11-tls-cipher-suites.txt"
      },

      new Object[]
      {
        "java-12-tls-cipher-suites.txt"
      },

      new Object[]
      {
        "java-13-tls-cipher-suites.txt"
      },

      new Object[]
      {
        "java-8-tls-cipher-suites-all-ssl-prefixes.txt"
      },

      new Object[]
      {
        "java-13-tls-cipher-suites-all-ssl-prefixes.txt"
      }
    };
  }



  /**
   * Tests a number of corner cases that are not currently covered by any of
   * the defined cipher suites.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCornerCases()
         throws Exception
  {
    // Test a cipher suite with an unknown protocol.
    final TLSCipherSuiteComparator comparator =
         TLSCipherSuiteComparator.getInstance();
    assertTrue(comparator.compare("TLS_AES_256_GCM_SHA384",
         "UNKNOWN_AES_256_GCM_SHA384") < 0);
    assertTrue(comparator.compare("UNKNOWN_AES_256_GCM_SHA384",
         "TLS_AES_256_GCM_SHA384") > 0);
    assertTrue(comparator.compare("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
         "UNKNOWN_DHE_DSS_WITH_3DES_EDE_CBC_SHA") < 0);
    assertTrue(comparator.compare("UNKNOWN_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
         "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA") > 0);
    assertEquals(
         comparator.compare("UNKNOWN_AES_256_GCM_SHA384",
              "UNKNOWN_AES_256_GCM_SHA384"),
         0);


    // AES without bit size (with and without GCM)
    assertTrue(comparator.compare("TLS_AES_256_GCM_SHA384",
         "TLS_AES_GCM_SHA384") < 0);
    assertTrue(comparator.compare("TLS_AES_GCM_SHA384",
         "TLS_AES_256_GCM_SHA384") > 0);
    assertTrue(comparator.compare("TLS_AES_128_GCM_SHA256",
         "TLS_AES_GCM_SHA256") < 0);
    assertTrue(comparator.compare("TLS_AES_GCM_SHA256",
         "TLS_AES_128_GCM_SHA256") > 0);

    assertTrue(comparator.compare("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
         "TLS_ECDHE_ECDSA_WITH_AES_CBC_SHA384") < 0);
    assertTrue(comparator.compare("TLS_ECDHE_ECDSA_WITH_AES_CBC_SHA384",
         "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384") > 0);
    assertTrue(comparator.compare("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
         "TLS_ECDHE_ECDSA_WITH_AES_CBC_SHA256") < 0);
    assertTrue(comparator.compare("TLS_ECDHE_ECDSA_WITH_AES_CBC_SHA256",
         "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256") > 0);


    // 512-bit digest
    assertTrue(comparator.compare("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA512",
         "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384") < 0);
    assertTrue(comparator.compare("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
         "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA512") > 0);
  }



  /**
   * Provides test coverage for the {@code equals} and {@code hashCode} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsAndHashCode()
         throws Exception
  {
    final TLSCipherSuiteComparator comparator =
         TLSCipherSuiteComparator.getInstance();

    assertTrue(comparator.equals(comparator));
    assertFalse(comparator.equals("not the comparator"));
    assertFalse(comparator.equals(null));

    assertEquals(comparator.hashCode(), comparator.hashCode());
  }
}
