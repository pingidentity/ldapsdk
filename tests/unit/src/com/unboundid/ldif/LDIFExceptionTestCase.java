/*
 * Copyright 2007-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2018 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the LDIFException class.
 */
public class LDIFExceptionTestCase
       extends LDIFTestCase
{
  /**
   * Tests the first constructor.
   */
  @Test()
  public void testConstructor1()
  {
    LDIFException le = new LDIFException("No colon found on line 5.", 5,
                                         true);

    assertNotNull(le);

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "No colon found on line 5.");

    assertEquals(le.getLineNumber(), 5);

    assertTrue(le.mayContinueReading());

    assertNull(le.getDataLines());

    assertNull(le.getCause());

    assertNotNull(le.toString());
  }



  /**
   * Tests the first constructor with a {@code null} message argument.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullMessage()
  {
    new LDIFException(null, 5, true);
  }



  /**
   * Tests the second constructor.
   */
  @Test()
  public void testConstructor2()
  {
    LDIFException le = new LDIFException("No colon found on line 5.", 5, false,
                                         new Exception());

    assertNotNull(le);

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "No colon found on line 5.");

    assertEquals(le.getLineNumber(), 5);

    assertFalse(le.mayContinueReading());

    assertNull(le.getDataLines());

    assertNotNull(le.getCause());

    assertNotNull(le.toString());
  }



  /**
   * Tests the second constructor with a {@code null} message argument.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullMessage()
  {
    new LDIFException(null, 5, false, new Exception());
  }



  /**
   * Tests the second constructor with a {@code null} cause.
   */
  @Test()
  public void testConstructor2NullCause()
  {
    LDIFException le = new LDIFException("No colon found on line 5.", 5, true,
                                         null);

    assertNotNull(le);

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "No colon found on line 5.");

    assertEquals(le.getLineNumber(), 5);

    assertTrue(le.mayContinueReading());

    assertNull(le.getDataLines());

    assertNull(le.getCause());

    assertNotNull(le.toString());
  }



  /**
   * Tests the third constructor.
   */
  @Test()
  public void testConstructor3()
  {
    String[] ldifLines =
    {
      "dn: malformed",
       "also malformed"
    };

    LDIFException le = new LDIFException("No colon found on line 5.", 5, false,
                                         ldifLines, new Exception());

    assertNotNull(le);

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "No colon found on line 5.");

    assertEquals(le.getLineNumber(), 5);

    assertFalse(le.mayContinueReading());

    assertNotNull(le.getDataLines());

    assertNotNull(le.getCause());

    assertNotNull(le.toString());
  }



  /**
   * Tests the fourth constructor.
   */
  @Test()
  public void testConstructor4()
  {
    String[] ldifLines =
    {
      "dn: malformed",
       "also malformed"
    };

    LDIFException le = new LDIFException("No colon found on line 5.", 5, false,
                                         Arrays.asList(ldifLines),
                                         new Exception());

    assertNotNull(le);

    assertNotNull(le.getMessage());
    assertEquals(le.getMessage(), "No colon found on line 5.");

    assertEquals(le.getLineNumber(), 5);

    assertFalse(le.mayContinueReading());

    assertNotNull(le.getDataLines());

    assertNotNull(le.getCause());

    assertNotNull(le.toString());
  }



  /**
   * Provides coverage for the {@code getExceptionMessage} methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetExceptionMessage()
         throws Exception
  {
    final LDIFException le = new LDIFException("Could not parse", 1, true,
         new NullPointerException("NPE"));

    final String defaultMessage = le.getExceptionMessage(false, false);
    assertFalse(defaultMessage.contains("trace="));
    assertFalse(defaultMessage.contains("cause="));

    final String messageWithCause = le.getExceptionMessage(true, false);
    assertFalse(messageWithCause.contains("trace="));
    assertTrue(messageWithCause.contains("cause="));

    final String messageWithTrace = le.getExceptionMessage(false, true);
    assertTrue(messageWithTrace.contains("trace="));
    assertTrue(messageWithTrace.contains("cause="));
  }
}
