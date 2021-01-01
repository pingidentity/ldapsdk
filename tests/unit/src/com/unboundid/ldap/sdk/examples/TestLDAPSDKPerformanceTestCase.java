/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.examples;



import java.io.ByteArrayOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the test-ldap-sdk-performance
 * tool.
 */
public class TestLDAPSDKPerformanceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides coverage for tool methods that can be invoked without actually
   * running the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testToolMethods()
         throws Exception
  {
    final TestLDAPSDKPerformance tool = new TestLDAPSDKPerformance(null, null);

    assertNotNull(tool.getToolName());
    assertEquals(tool.getToolName(), "test-ldap-sdk-performance");

    assertNotNull(tool.getToolDescription());
    assertFalse(tool.getToolDescription().isEmpty());

    assertNotNull(tool.getAdditionalDescriptionParagraphs());
    assertFalse(tool.getAdditionalDescriptionParagraphs().isEmpty());

    assertNotNull(tool.getToolVersion());
    assertEquals(tool.getToolVersion(), Version.NUMERIC_VERSION_STRING);

    assertTrue(tool.supportsInteractiveMode());

    assertTrue(tool.defaultsToInteractiveMode());

    assertTrue(tool.supportsPropertiesFile());

    assertTrue(tool.supportsOutputFile());

    assertNull(tool.getToolCompletionMessage());

    assertNotNull(tool.getExampleUsages());
    assertFalse(tool.getExampleUsages().isEmpty());
  }



  /**
   * Tests the behavior when using searchrate.  Provide a complete set of
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchRate()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = TestLDAPSDKPerformance.main(out, out,
         "--useSSL",
         "--entriesPerSearch", "0",
         "--resultCode", "0",
         "--diagnosticMessage", "diagnostic message",
         "--numThreads", "10",
         "--numIntervals", "1",
         "--warmUpIntervals", "1",
         "--intervalDurationSeconds", "1");
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the behavior when using modrate.  Provide a complete set of
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testModRate()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = TestLDAPSDKPerformance.main(out, out,
         "--tool", "modrate",
         "--useSSL",
         "--resultCode", "0",
         "--diagnosticMessage", "diagnostic message",
         "--numThreads", "10",
         "--numIntervals", "1",
         "--warmUpIntervals", "1",
         "--intervalDurationSeconds", "1");
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the behavior when using authrate in the default mode when performing
   * both searches and binds.  Provide a minimal set of arguments, but still try
   * to complete as quickly as possible.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthRateWithSearchesAndBinds()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = TestLDAPSDKPerformance.main(out, out,
         "--tool", "authrate",
         "--numIntervals", "1",
         "--intervalDurationSeconds", "1");
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the behavior when using authrate.  Provide a complete set of
   * arguments, and use bind-only mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAuthRateBindOnl()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = TestLDAPSDKPerformance.main(out, out,
         "--tool", "authrate",
         "--useSSL",
         "--bindOnly",
         "--resultCode", "0",
         "--diagnosticMessage", "diagnostic message",
         "--numThreads", "10",
         "--numIntervals", "1",
         "--warmUpIntervals", "1",
         "--intervalDurationSeconds", "1");
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));
  }



  /**
   * Tests the behavior when using search-and-mod.  Provide a complete set of
   * arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSearchAndModRate()
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ResultCode resultCode = TestLDAPSDKPerformance.main(out, out,
         "--tool", "search-and-mod-rate",
         "--useSSL",
         "--resultCode", "0",
         "--diagnosticMessage", "diagnostic message",
         "--numThreads", "10",
         "--numIntervals", "1",
         "--warmUpIntervals", "1",
         "--intervalDurationSeconds", "1");
    assertEquals(resultCode, ResultCode.SUCCESS,
         StaticUtils.toUTF8String(out.toByteArray()));
  }
}
