/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.ByteArrayOutputStream;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of tests for the ability to have a custom
 * interactive mode for command-line tools.
 */
public final class CustomInteractiveModeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the tool when run in non-interactive mode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonInteractiveMode()
         throws Exception
  {
    assertOutputEquals("non-interactive message",
         "--message", "non-interactive message");
  }



  /**
   * Tests the behavior of the tool when it defaults to interactive mode because
   * it is run without any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultToInteractiveMode()
         throws Exception
  {
    assertOutputEquals("default message");
  }



  /**
   * Tests the behavior of the tool when it is run in an explicit interactive
   * mode without any other arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitInteractiveModeWithoutMessageArgument()
         throws Exception
  {
    assertOutputEquals("default message",
         "--interactive");
  }



  /**
   * Tests the behavior of the tool when it is run in an explicit interactive
   * mode without any other arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExplicitInteractiveModeWithMessageArgument()
         throws Exception
  {
    assertOutputEquals("default message",
         "--interactive",
         "--message", "non-interactive message");
  }



  /**
   * Ensures that the tool has the expected output when invoked with the given
   * set of arguments.
   *
   * @param  expectedOutput  The output that is expected when the tool is run
   *                         with the provided set of arguments.
   * @param  args            The command-line arguments to provide to the tool.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static void assertOutputEquals(final String expectedOutput,
                                         final String... args)
          throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final ByteArrayOutputStream err = new ByteArrayOutputStream();

    final ResultCode exitCode = TestCustomInteractiveTool.main(out, err, args);
    assertEquals(exitCode, ResultCode.SUCCESS);

    final byte[] outBytes = out.toByteArray();
    assertNotNull(outBytes);
    final String outString = StaticUtils.toUTF8String(outBytes);
    final List<String> outLines = StaticUtils.stringToLines(outString);
    assertEquals(outLines.size(), 1);
    assertEquals(outLines.get(0), expectedOutput);

    final byte[] errBytes = err.toByteArray();
    assertNotNull(errBytes);
    assertEquals(errBytes.length, 0);
  }
}
