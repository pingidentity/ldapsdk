/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the AlertSeverity class.
 */
public class AlertSeverityTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the {@code getName} method.
   */
  @Test()
  public void testGetName()
  {
    assertEquals(AlertSeverity.ERROR.getName(), "error");
    assertEquals(AlertSeverity.FATAL.getName(), "fatal");
    assertEquals(AlertSeverity.INFO.getName(), "info");
    assertEquals(AlertSeverity.WARNING.getName(), "warning");
  }



  /**
   * Tests the {@code forName} method.
   */
  @Test()
  public void testForName()
  {
    assertEquals(AlertSeverity.forName("error"), AlertSeverity.ERROR);
    assertEquals(AlertSeverity.forName("fatal"), AlertSeverity.FATAL);
    assertEquals(AlertSeverity.forName("info"), AlertSeverity.INFO);
    assertEquals(AlertSeverity.forName("warning"), AlertSeverity.WARNING);

    assertEquals(AlertSeverity.forName("ERROR"), AlertSeverity.ERROR);
    assertEquals(AlertSeverity.forName("FATAL"), AlertSeverity.FATAL);
    assertEquals(AlertSeverity.forName("INFO"), AlertSeverity.INFO);
    assertEquals(AlertSeverity.forName("WARNING"), AlertSeverity.WARNING);

    assertEquals(AlertSeverity.forName("eRrOr"), AlertSeverity.ERROR);
    assertEquals(AlertSeverity.forName("fAtAl"), AlertSeverity.FATAL);
    assertEquals(AlertSeverity.forName("iNfO"), AlertSeverity.INFO);
    assertEquals(AlertSeverity.forName("wArNiNg"), AlertSeverity.WARNING);

    assertNull(AlertSeverity.forName("invalid"));
  }



  /**
   * Tests the {@code valueOf} method.
   */
  @Test()
  public void testValueOf()
  {
    assertEquals(AlertSeverity.valueOf("ERROR"), AlertSeverity.ERROR);
    assertEquals(AlertSeverity.valueOf("FATAL"), AlertSeverity.FATAL);
    assertEquals(AlertSeverity.valueOf("INFO"), AlertSeverity.INFO);
    assertEquals(AlertSeverity.valueOf("WARNING"), AlertSeverity.WARNING);
  }



  /**
   * Tests the {@code toString} method.
   */
  @Test()
  public void testToString()
  {
    assertEquals(AlertSeverity.ERROR.toString(), "error");
    assertEquals(AlertSeverity.FATAL.toString(), "fatal");
    assertEquals(AlertSeverity.INFO.toString(), "info");
    assertEquals(AlertSeverity.WARNING.toString(), "warning");
  }



  /**
   * Tests the {@code values} method.
   */
  @Test()
  public void testValues()
  {
    assertEquals(AlertSeverity.values().length, 4);
  }
}
