/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the
 * {@code SASLQualityOfProtection} enum.
 */
public final class SASLQualityOfProtectionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for SASL quality of protection values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasics()
         throws Exception
  {
    for (final SASLQualityOfProtection qop : SASLQualityOfProtection.values())
    {
      assertNotNull(qop.toString());

      assertNotNull(SASLQualityOfProtection.forName(qop.name()));
      assertEquals(SASLQualityOfProtection.forName(qop.name()), qop);

      assertNotNull(SASLQualityOfProtection.forName(qop.toString()));
      assertEquals(SASLQualityOfProtection.forName(qop.toString()), qop);

      assertNotNull(SASLQualityOfProtection.valueOf(qop.name()));
      assertEquals(SASLQualityOfProtection.valueOf(qop.name()), qop);

      assertNotNull(SASLQualityOfProtection.toString(Arrays.asList(qop)));
      assertNotNull(SASLQualityOfProtection.decodeQoPList(
           SASLQualityOfProtection.toString(Arrays.asList(qop))));
      assertEquals(
           SASLQualityOfProtection.decodeQoPList(
                SASLQualityOfProtection.toString(Arrays.asList(qop))),
           Arrays.asList(qop));
    }

    assertNull(SASLQualityOfProtection.forName("invalid-name"));

    try
    {
      SASLQualityOfProtection.valueOf("invalid-name");
      fail("Expected an exception from valueOf with an invalid name");
    }
    catch (final IllegalArgumentException iae)
    {
      // This is expected.
    }
  }



  /**
   * Tests the method for generating the string representation of a list of QoP
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testListToString()
         throws Exception
  {
    String qopString = SASLQualityOfProtection.toString(null);
    assertNotNull(qopString);
    assertEquals(qopString, "auth");

    qopString = SASLQualityOfProtection.toString(
         Arrays.<SASLQualityOfProtection>asList());
    assertNotNull(qopString);
    assertEquals(qopString, "auth");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH));
    assertNotNull(qopString);
    assertEquals(qopString, "auth");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH_INT));
    assertNotNull(qopString);
    assertEquals(qopString, "auth-int");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH_CONF));
    assertNotNull(qopString);
    assertEquals(qopString, "auth-conf");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH, SASLQualityOfProtection.AUTH_INT));
    assertNotNull(qopString);
    assertEquals(qopString, "auth,auth-int");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH_CONF, SASLQualityOfProtection.AUTH_INT));
    assertNotNull(qopString);
    assertEquals(qopString, "auth-conf,auth-int");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH, SASLQualityOfProtection.AUTH_INT,
         SASLQualityOfProtection.AUTH_CONF));
    assertNotNull(qopString);
    assertEquals(qopString, "auth,auth-int,auth-conf");

    qopString = SASLQualityOfProtection.toString(Arrays.asList(
         SASLQualityOfProtection.AUTH_CONF, SASLQualityOfProtection.AUTH_INT,
         SASLQualityOfProtection.AUTH));
    assertNotNull(qopString);
    assertEquals(qopString, "auth-conf,auth-int,auth");
  }



  /**
   * Tests the method for decoding a string to a list of QoP values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeQoPList()
         throws Exception
  {
    List<SASLQualityOfProtection> qopList =
         SASLQualityOfProtection.decodeQoPList(null);
    assertEquals(qopList,
         Arrays.<SASLQualityOfProtection>asList());

    qopList = SASLQualityOfProtection.decodeQoPList("");
    assertEquals(qopList,
         Arrays.<SASLQualityOfProtection>asList());

    qopList =
         SASLQualityOfProtection.decodeQoPList("auth");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH));

    qopList = SASLQualityOfProtection.decodeQoPList("auth-int");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH_INT));

    qopList = SASLQualityOfProtection.decodeQoPList("auth-conf");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF));

    qopList = SASLQualityOfProtection.decodeQoPList("auth,auth-int");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH,
              SASLQualityOfProtection.AUTH_INT));

    qopList = SASLQualityOfProtection.decodeQoPList("auth-conf,auth-int");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT));

    qopList = SASLQualityOfProtection.decodeQoPList("auth,auth-int,auth-conf");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH,
              SASLQualityOfProtection.AUTH_INT,
              SASLQualityOfProtection.AUTH_CONF));

    qopList = SASLQualityOfProtection.decodeQoPList("auth-conf,auth-int,auth");
    assertEquals(qopList,
         Arrays.asList(SASLQualityOfProtection.AUTH_CONF,
              SASLQualityOfProtection.AUTH_INT,
              SASLQualityOfProtection.AUTH));

    try
    {
      SASLQualityOfProtection.decodeQoPList("invalid");
      fail("Expected an exception when trying to decode an invalid QoP list");
    }
    catch (final Exception e)
    {
      // This is expected.
    }
  }



  /**
   * Tests the {@code forName} method with automated tests based on the actual
   * name of the enum values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameAutomated()
         throws Exception
  {
    for (final SASLQualityOfProtection value : SASLQualityOfProtection.values())
    {
      for (final String name : getNames(value.name()))
      {
        assertNotNull(SASLQualityOfProtection.forName(name));
        assertEquals(SASLQualityOfProtection.forName(name), value);
      }
    }

    assertNull(SASLQualityOfProtection.forName("some undefined name"));
  }



  /**
   * Retrieves a set of names for testing the {@code forName} method based on
   * the provided set of names.
   *
   * @param  baseNames  The base set of names to use to generate the full set of
   *                    names.  It must not be {@code null} or empty.
   *
   * @return  The full set of names to use for testing.
   */
  private static Set<String> getNames(final String... baseNames)
  {
    final HashSet<String> nameSet = new HashSet<>(10);
    for (final String name : baseNames)
    {
      nameSet.add(name);
      nameSet.add(name.toLowerCase());
      nameSet.add(name.toUpperCase());

      final String nameWithDashesInsteadOfUnderscores = name.replace('_', '-');
      nameSet.add(nameWithDashesInsteadOfUnderscores);
      nameSet.add(nameWithDashesInsteadOfUnderscores.toLowerCase());
      nameSet.add(nameWithDashesInsteadOfUnderscores.toUpperCase());

      final String nameWithUnderscoresInsteadOfDashes = name.replace('-', '_');
      nameSet.add(nameWithUnderscoresInsteadOfDashes);
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toLowerCase());
      nameSet.add(nameWithUnderscoresInsteadOfDashes.toUpperCase());

      final StringBuilder nameWithoutUnderscoresOrDashes = new StringBuilder();
      for (final char c : name.toCharArray())
      {
        if ((c != '-') && (c != '_'))
        {
          nameWithoutUnderscoresOrDashes.append(c);
        }
      }
      nameSet.add(nameWithoutUnderscoresOrDashes.toString());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toLowerCase());
      nameSet.add(nameWithoutUnderscoresOrDashes.toString().toUpperCase());
    }

    return nameSet;
  }
}
