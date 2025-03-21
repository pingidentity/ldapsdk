/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.syntax;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of tests for the redacted value exception.
 */
public final class RedactedValueExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when creating an exception with just a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithoutCause()
         throws Exception
  {
    final RedactedValueException e = new RedactedValueException("foo");

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "foo");

    assertNull(e.getCause());
  }



  /**
   * Tests the behavior when creating an exception with a message and a
   * {@code null} cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithNullCause()
         throws Exception
  {
    final RedactedValueException e = new RedactedValueException("bar", null);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "bar");

    assertNull(e.getCause());
  }



  /**
   * Tests the behavior when creating an exception with a message and a
   * non-{@code null} cause.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithNonNullCause()
         throws Exception
  {
    final Exception cause = new Exception("cause");

    final RedactedValueException e = new RedactedValueException("baz", cause);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "baz");

    assertNotNull(e.getCause());
    assertEquals(e.getCause(), cause);
  }
}
