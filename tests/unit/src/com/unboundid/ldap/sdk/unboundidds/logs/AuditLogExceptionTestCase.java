/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the audit log exception class.
 */
public final class AuditLogExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to create an exception from an empty list
   * and without a cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyListNullCause()
         throws Exception
  {
    final AuditLogException e = new AuditLogException(
         Collections.<String>emptyList(), "Empty list and null cause");

    assertNotNull(e.getLogMessageLines());
    assertTrue(e.getLogMessageLines().isEmpty());

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "Empty list and null cause");

    assertNull(e.getCause());
  }



  /**
   * Tests the behavior when trying to create an exception from a non-empty list
   * and without a cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyListNullCause()
         throws Exception
  {
    final List<String> lines = Arrays.asList(
         "# Malformed header line",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final AuditLogException e =
         new AuditLogException(lines, "Non-empty list and null cause");

    assertNotNull(e.getLogMessageLines());
    assertFalse(e.getLogMessageLines().isEmpty());
    assertEquals(e.getLogMessageLines(), lines);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "Non-empty list and null cause");

    assertNull(e.getCause());
  }



  /**
   * Tests the behavior when trying to create an exception from an empty list
   * and with a cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyListNonNullCause()
         throws Exception
  {
    final Exception cause = new Exception("This is the cause");

    final AuditLogException e = new AuditLogException(
         Collections.<String>emptyList(), "Empty list and non-null cause",
         cause);

    assertNotNull(e.getLogMessageLines());
    assertTrue(e.getLogMessageLines().isEmpty());

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "Empty list and non-null cause");

    assertNotNull(e.getCause());
    assertEquals(e.getCause().getMessage(), cause.getMessage());
  }



  /**
   * Tests the behavior when trying to create an exception from a non-empty list
   * and with a cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonEmptyListNonNullCause()
         throws Exception
  {
    final List<String> lines = Arrays.asList(
         "# Malformed header line",
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    final Exception cause = new Exception("This is the cause");

    final AuditLogException e = new AuditLogException(lines,
         "Non-empty list and non-null cause", cause);

    assertNotNull(e.getLogMessageLines());
    assertFalse(e.getLogMessageLines().isEmpty());
    assertEquals(e.getLogMessageLines(), lines);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "Non-empty list and non-null cause");

    assertNotNull(e.getCause());
    assertEquals(e.getCause().getMessage(), cause.getMessage());
  }
}
