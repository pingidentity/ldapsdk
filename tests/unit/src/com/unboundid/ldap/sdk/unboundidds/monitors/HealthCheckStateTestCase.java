/*
 * Copyright 2009-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2017 Ping Identity Corporation
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
}
