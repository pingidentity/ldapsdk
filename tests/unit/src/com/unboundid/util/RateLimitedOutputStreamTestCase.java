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
package com.unboundid.util;



import java.io.ByteArrayOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the rate-limited output stream.
 */
public final class RateLimitedOutputStreamTestCase
       extends LDAPSDKTestCase
{
  /**
   * Test the output stream with a tiny limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithTinyLimit()
         throws Exception
  {
    final ByteArrayOutputStream wrappedStream = new ByteArrayOutputStream();
    final RateLimitedOutputStream outputStream =
         new RateLimitedOutputStream(wrappedStream, 1, false);

    final long startTime = System.currentTimeMillis();
    outputStream.write(0x00);

    outputStream.write(StaticUtils.NO_BYTES);

    final byte[] array = { 0x01, 0x02 };
    outputStream.write(array);

    outputStream.flush();

    outputStream.close();

    final long elapsedTimeMillis = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTimeMillis >= 2000L);

    assertEquals(wrappedStream.toByteArray(),
         new byte[] { 0x00, 0x01, 0x02 });
  }



  /**
   * Test the output stream with a big limit.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithBigLimit()
         throws Exception
  {
    final ByteArrayOutputStream wrappedStream = new ByteArrayOutputStream();
    final RateLimitedOutputStream outputStream =
         new RateLimitedOutputStream(wrappedStream, 10_485_760, true);

    final long startTime = System.currentTimeMillis();
    outputStream.write(0x00);

    outputStream.write(StaticUtils.NO_BYTES);

    outputStream.write(new byte[] { 0x01, 0x02});

    final byte[] array = new byte[1_048_576];
    outputStream.write(array);

    outputStream.flush();

    outputStream.close();

    final long elapsedTimeMillis = System.currentTimeMillis() - startTime;
    assertTrue(elapsedTimeMillis <= 10_000L);

    final byte[] bytesWritten = wrappedStream.toByteArray();
    assertEquals(bytesWritten.length, array.length + 3);
  }
}
