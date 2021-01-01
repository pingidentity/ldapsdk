/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the HealthCheckState class.
 */
public class HealthCheckStateTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code getName} method.
   */
  @Test()
  public void testGetName()
  {
    assertEquals(HealthCheckState.AVAILABLE.getName(), "available");
    assertEquals(HealthCheckState.DEGRADED.getName(), "degraded");
    assertEquals(HealthCheckState.UNAVAILABLE.getName(), "unavailable");
  }



  /**
   * Tests the {@code forName} method.
   */
  @Test()
  public void testForName()
  {
    assertEquals(HealthCheckState.forName("available"),
                 HealthCheckState.AVAILABLE);
    assertEquals(HealthCheckState.forName("degraded"),
                 HealthCheckState.DEGRADED);
    assertEquals(HealthCheckState.forName("unavailable"),
                 HealthCheckState.UNAVAILABLE);
    assertEquals(HealthCheckState.forName("no-local-servers"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.forName("no_local_servers"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.forName("no-remote-servers"),
                 HealthCheckState.NO_REMOTE_SERVERS);
    assertEquals(HealthCheckState.forName("no_remote_servers"),
                 HealthCheckState.NO_REMOTE_SERVERS);

    assertEquals(HealthCheckState.forName("AVAILABLE"),
                 HealthCheckState.AVAILABLE);
    assertEquals(HealthCheckState.forName("DEGRADED"),
                 HealthCheckState.DEGRADED);
    assertEquals(HealthCheckState.forName("UNAVAILABLE"),
                 HealthCheckState.UNAVAILABLE);
    assertEquals(HealthCheckState.forName("NO-LOCAL-SERVERS"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.forName("NO_LOCAL_SERVERS"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.forName("NO-REMOTE-SERVERS"),
                 HealthCheckState.NO_REMOTE_SERVERS);
    assertEquals(HealthCheckState.forName("NO_REMOTE_SERVERS"),
                 HealthCheckState.NO_REMOTE_SERVERS);

    assertEquals(HealthCheckState.forName("aVaIlAbLe"),
                 HealthCheckState.AVAILABLE);
    assertEquals(HealthCheckState.forName("dEgRaDeD"),
                 HealthCheckState.DEGRADED);
    assertEquals(HealthCheckState.forName("uNaVaIlAbLe"),
                 HealthCheckState.UNAVAILABLE);
    assertEquals(HealthCheckState.forName("nO-lOcAl-SeRvErS"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.forName("No_LoCaL_sErVeRs"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.forName("No-ReMoTe-SeRvErS"),
                 HealthCheckState.NO_REMOTE_SERVERS);
    assertEquals(HealthCheckState.forName("nO_rEmOtE_sErVeRs"),
                 HealthCheckState.NO_REMOTE_SERVERS);

    assertNull(HealthCheckState.forName("invalid"));
  }



  /**
   * Tests the {@code valueOf} method.
   */
  @Test()
  public void testValueOf()
  {
    assertEquals(HealthCheckState.valueOf("AVAILABLE"),
                 HealthCheckState.AVAILABLE);
    assertEquals(HealthCheckState.valueOf("DEGRADED"),
                 HealthCheckState.DEGRADED);
    assertEquals(HealthCheckState.valueOf("UNAVAILABLE"),
                 HealthCheckState.UNAVAILABLE);
    assertEquals(HealthCheckState.valueOf("NO_LOCAL_SERVERS"),
                 HealthCheckState.NO_LOCAL_SERVERS);
    assertEquals(HealthCheckState.valueOf("NO_REMOTE_SERVERS"),
                 HealthCheckState.NO_REMOTE_SERVERS);
  }



  /**
   * Tests the {@code toString} method.
   */
  @Test()
  public void testToString()
  {
    assertEquals(HealthCheckState.AVAILABLE.toString(), "available");
    assertEquals(HealthCheckState.DEGRADED.toString(), "degraded");
    assertEquals(HealthCheckState.UNAVAILABLE.toString(), "unavailable");
    assertEquals(HealthCheckState.NO_LOCAL_SERVERS.toString(),
         "no-local-servers");
    assertEquals(HealthCheckState.NO_REMOTE_SERVERS.toString(),
         "no-remote-servers");
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    assertEquals(HealthCheckState.values().length, 5);
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
    for (final HealthCheckState value : HealthCheckState.values())
    {
      for (final String name : getNames(value.name(), value.getName()))
      {
        assertNotNull(HealthCheckState.forName(name));
        assertEquals(HealthCheckState.forName(name), value);
      }
    }

    assertNull(HealthCheckState.forName("some undefined name"));
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
