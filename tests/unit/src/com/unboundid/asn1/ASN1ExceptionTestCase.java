/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.asn1;



import org.testng.annotations.Test;



/**
 * This class provides test coverage for the ASN1Exception class.
 */
public class ASN1ExceptionTestCase
       extends ASN1TestCase
{
  /**
   * Tests the first constructor, which takes only a string message.
   */
  @Test()
  public void testConstructor1()
  {
    ASN1Exception ae = new ASN1Exception("Test");
    assertEquals(ae.getMessage(), "Test");
    assertNull(ae.getCause());
  }



  /**
   * Tests the second constructor, which takes both a message and a cause.
   */
  @Test()
  public void testConstructor2()
  {
    ASN1Exception ae = new ASN1Exception("Test", null);
    assertEquals(ae.getMessage(), "Test");
    assertNull(ae.getCause());

    ASN1Exception ae2 = new ASN1Exception("Test 2", ae);
    assertEquals(ae2.getMessage(), "Test 2");
    assertNotNull(ae2.getCause());
    assertEquals(ae2.getCause(), ae);
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
    final ASN1Exception ae = new ASN1Exception("This is the message",
         new NullPointerException("NPE"));

    final String defaultMessage = ae.getExceptionMessage(false, false);
    assertFalse(defaultMessage.contains("trace="));
    assertFalse(defaultMessage.contains("cause="));

    final String messageWithCause = ae.getExceptionMessage(true, false);
    assertFalse(messageWithCause.contains("trace="));
    assertTrue(messageWithCause.contains("cause="));

    final String messageWithTrace = ae.getExceptionMessage(false, true);
    assertTrue(messageWithTrace.contains("trace="));
    assertTrue(messageWithTrace.contains("cause="));
  }
}
