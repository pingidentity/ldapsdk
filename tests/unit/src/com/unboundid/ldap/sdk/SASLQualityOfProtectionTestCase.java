/*
 * Copyright 2014-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2017 UnboundID Corp.
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
import java.util.List;

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
}
