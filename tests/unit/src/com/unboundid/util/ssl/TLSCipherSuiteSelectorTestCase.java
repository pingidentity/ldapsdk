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
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;



/**
 * This class provides test coverage for the TLS cipher suite selector.
 */
public final class TLSCipherSuiteSelectorTestCase
     extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the static methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStaticMethods()
       throws Exception
  {
    assertNotNull(TLSCipherSuiteSelector.getSupportedCipherSuites());
    assertFalse(TLSCipherSuiteSelector.getSupportedCipherSuites().isEmpty());

    assertNotNull(TLSCipherSuiteSelector.getDefaultCipherSuites());
    assertFalse(TLSCipherSuiteSelector.getDefaultCipherSuites().isEmpty());

    assertNotNull(TLSCipherSuiteSelector.getRecommendedCipherSuites());
    assertFalse(TLSCipherSuiteSelector.getRecommendedCipherSuites().isEmpty());

    assertNotNull(TLSCipherSuiteSelector.getRecommendedCipherSuiteArray());
    assertEquals(TLSCipherSuiteSelector.getRecommendedCipherSuiteArray().length,
         TLSCipherSuiteSelector.getRecommendedCipherSuites().size());

    assertNotNull(TLSCipherSuiteSelector.getNonRecommendedCipherSuites());
    assertFalse(
         TLSCipherSuiteSelector.getNonRecommendedCipherSuites().isEmpty());

    TLSCipherSuiteSelector.recompute();

    assertNotNull(TLSCipherSuiteSelector.getSupportedCipherSuites());
    assertFalse(TLSCipherSuiteSelector.getSupportedCipherSuites().isEmpty());

    assertNotNull(TLSCipherSuiteSelector.getDefaultCipherSuites());
    assertFalse(TLSCipherSuiteSelector.getDefaultCipherSuites().isEmpty());

    assertNotNull(TLSCipherSuiteSelector.getRecommendedCipherSuites());
    assertFalse(TLSCipherSuiteSelector.getRecommendedCipherSuites().isEmpty());

    assertNotNull(TLSCipherSuiteSelector.getRecommendedCipherSuiteArray());
    assertEquals(TLSCipherSuiteSelector.getRecommendedCipherSuiteArray().length,
         TLSCipherSuiteSelector.getRecommendedCipherSuites().size());

    assertNotNull(TLSCipherSuiteSelector.getNonRecommendedCipherSuites());
    assertFalse(
         TLSCipherSuiteSelector.getNonRecommendedCipherSuites().isEmpty());


    assertFalse(TLSCipherSuiteSelector.allowRSAKeyExchange());
    for (final String cipherSuite :
         TLSCipherSuiteSelector.getRecommendedCipherSuites())
    {
      assertFalse(cipherSuite.startsWith("TLS_RSA_"));
    }

    TLSCipherSuiteSelector.setAllowRSAKeyExchange(true);
    assertTrue(TLSCipherSuiteSelector.allowRSAKeyExchange());

    boolean jvmSupportsRSAExchangeSuites = false;
    for (final String suite :
         CryptoHelper.getDefaultSSLContext().getSupportedSSLParameters().
              getCipherSuites())
    {
      if (suite.startsWith("TLS_RSA_"))
      {
        jvmSupportsRSAExchangeSuites = true;
        break;
      }
    }

    if (jvmSupportsRSAExchangeSuites)
    {
      boolean foundSuiteUsingRSAKeyExchange = false;
      for (final String cipherSuite :
           TLSCipherSuiteSelector.getRecommendedCipherSuites())
      {
        foundSuiteUsingRSAKeyExchange = true;
        break;
      }
      assertTrue(foundSuiteUsingRSAKeyExchange);
    }

    TLSCipherSuiteSelector.setAllowRSAKeyExchange(false);
    assertFalse(TLSCipherSuiteSelector.allowRSAKeyExchange());
    for (final String cipherSuite :
         TLSCipherSuiteSelector.getRecommendedCipherSuites())
    {
      assertFalse(cipherSuite.startsWith("TLS_RSA_"));
    }


    assertFalse(TLSCipherSuiteSelector.allowSHA1());
    for (final String cipherSuite :
         TLSCipherSuiteSelector.getRecommendedCipherSuites())
    {
      assertFalse(cipherSuite.endsWith("_SHA"));
    }

    TLSCipherSuiteSelector.setAllowSHA1(true);
    assertTrue(TLSCipherSuiteSelector.allowSHA1());

    boolean jvmSupportsSHA1Suites = false;
    for (final String suite :
         CryptoHelper.getDefaultSSLContext().getSupportedSSLParameters().
              getCipherSuites())
    {
      if (suite.endsWith("_SHA"))
      {
        jvmSupportsSHA1Suites = true;
        break;
      }
    }

    if (jvmSupportsSHA1Suites)
    {
      boolean foundSuiteUsingSHA1Suite = false;
      for (final String cipherSuite :
           TLSCipherSuiteSelector.getRecommendedCipherSuites())
      {
        foundSuiteUsingSHA1Suite = true;
        break;
      }
      assertTrue(foundSuiteUsingSHA1Suite);
    }

    TLSCipherSuiteSelector.setAllowSHA1(false);
    assertFalse(TLSCipherSuiteSelector.allowSHA1());
    for (final String cipherSuite :
         TLSCipherSuiteSelector.getRecommendedCipherSuites())
    {
      assertFalse(cipherSuite.endsWith("_SHA"));
    }
  }



  /**
   * Tests the behavior of the selector with a set of TLS cipher suites
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
    // Read a file with a non-pared-down set of TLS cipher suites in the
    // expected order.
    final File resourceDir = new File(System.getProperty("unit.resource.dir"));
    final File nonParedDownCipherSuiteFile = new File(resourceDir, filename);

    final List<String> nonParedDownCipherSuiteList = new ArrayList<>(500);
    try (FileReader fileReader = new FileReader(nonParedDownCipherSuiteFile);
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
          nonParedDownCipherSuiteList.add(line);
        }
      }
    }


    // Read a file with the pared-down set of TLS cipher suites in the
    // expected order.
    final File paredDownCipherSuiteFile =
         new File(resourceDir, "recommended-from-" + filename);

    final List<String> paredDownCipherSuiteList = new ArrayList<>(500);
    try (FileReader fileReader = new FileReader(paredDownCipherSuiteFile);
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
          paredDownCipherSuiteList.add(line);
        }
      }
    }


    // Create a copy of the cipher stream list in random order.
    final List<String> randomizedCipherSuiteList =
         new ArrayList<>(paredDownCipherSuiteList);
    Collections.shuffle(randomizedCipherSuiteList);
    assertFalse(randomizedCipherSuiteList.equals(paredDownCipherSuiteList));


    // Use the TLS cipher suite selector to pare down and sort the full set of
    // cipher suites.
    final ObjectPair<SortedSet<String>, SortedMap<String,List<String>>>
         selectedPair = TLSCipherSuiteSelector.selectCipherSuites(
              nonParedDownCipherSuiteList.toArray(StaticUtils.NO_STRINGS));


    // Make sure that the set of selected cipher suites matches the expected
    // set, including the order.
    final List<String> selectedCipherSuiteList =
         new ArrayList<>(selectedPair.getFirst());
    assertEquals(selectedCipherSuiteList, paredDownCipherSuiteList,
         "Selected:  " + selectedCipherSuiteList + ", Expected:  " +
         paredDownCipherSuiteList);


    // Make sure that the non-recommended suites isn't empty.
    assertNotNull(selectedPair.getSecond());
    assertFalse(selectedPair.getSecond().isEmpty());


    // Get the supported set of suites from the complete and pared-down sets.
    assertNotNull(TLSCipherSuiteSelector.selectSupportedCipherSuites(
         nonParedDownCipherSuiteList));
    assertNotNull(TLSCipherSuiteSelector.selectSupportedCipherSuites(
         paredDownCipherSuiteList));
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
      }
    };
  }



  /**
   * Provides test coverage for the {@code selectSupportedCipherSuites} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSelectSupportedCipherSuites()
         throws Exception
  {
    Set<String> selectedSuites =
         TLSCipherSuiteSelector.selectSupportedCipherSuites(null);
    assertNotNull(selectedSuites);
    assertTrue(selectedSuites.isEmpty());

    selectedSuites = TLSCipherSuiteSelector.selectSupportedCipherSuites(
         Collections.<String>emptyList());
    assertNotNull(selectedSuites);
    assertTrue(selectedSuites.isEmpty());

    selectedSuites = TLSCipherSuiteSelector.selectSupportedCipherSuites(
         Collections.<String>emptySet());
    assertNotNull(selectedSuites);
    assertTrue(selectedSuites.isEmpty());

    selectedSuites = TLSCipherSuiteSelector.selectSupportedCipherSuites(
         TLSCipherSuiteSelector.getSupportedCipherSuites());
    assertNotNull(selectedSuites);
    assertFalse(selectedSuites.isEmpty());
    assertEquals(selectedSuites,
         TLSCipherSuiteSelector.getSupportedCipherSuites());

    selectedSuites = TLSCipherSuiteSelector.selectSupportedCipherSuites(
         TLSCipherSuiteSelector.getDefaultCipherSuites());
    assertNotNull(selectedSuites);
    assertFalse(selectedSuites.isEmpty());
    assertEquals(selectedSuites,
         TLSCipherSuiteSelector.getDefaultCipherSuites());

    selectedSuites = TLSCipherSuiteSelector.selectSupportedCipherSuites(
         TLSCipherSuiteSelector.getRecommendedCipherSuites());
    assertNotNull(selectedSuites);
    assertFalse(selectedSuites.isEmpty());
    assertEquals(selectedSuites,
         TLSCipherSuiteSelector.getRecommendedCipherSuites());

    selectedSuites = TLSCipherSuiteSelector.selectSupportedCipherSuites(
         Arrays.asList("unsupported1", "unsupported2", "unsupported3"));
    assertNotNull(selectedSuites);
    assertTrue(selectedSuites.isEmpty());
  }



  /**
   * Tests the ability to invoke the TLS cipher suite selector as a command-line
   * tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCommandLineTool()
         throws Exception
  {
    final OutputStream out = null;
    assertEquals(TLSCipherSuiteSelector.main(out, out),
         ResultCode.SUCCESS);

    final TLSCipherSuiteSelector tool = new TLSCipherSuiteSelector(out, out);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "tls-cipher-suite-selector");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);
  }
}
