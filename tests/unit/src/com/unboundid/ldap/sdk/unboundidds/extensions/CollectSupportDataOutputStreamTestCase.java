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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the collect support data output
 * stream enum.
 */
public final class CollectSupportDataOutputStreamTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the output stream enum.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputStream()
         throws Exception
  {
    for (final CollectSupportDataOutputStream s :
         CollectSupportDataOutputStream.values())
    {
      assertNotNull(s.getName());

      assertNotNull(s.name());

      s.ordinal();

      assertNotNull(s.toString());

      assertNotNull(CollectSupportDataOutputStream.forName(s.getName()));
      assertEquals(CollectSupportDataOutputStream.forName(s.getName()), s);

      assertNotNull(CollectSupportDataOutputStream.forName(s.name()));
      assertEquals(CollectSupportDataOutputStream.forName(s.name()), s);

      assertNotNull(CollectSupportDataOutputStream.forIntValue(
           s.getIntValue()));
      assertEquals(CollectSupportDataOutputStream.forIntValue(s.getIntValue()),
           s);

      assertNotNull(CollectSupportDataOutputStream.valueOf(s.name()));
      assertEquals(CollectSupportDataOutputStream.valueOf(s.name()), s);
    }

    assertNull(CollectSupportDataOutputStream.forName("undefined"));

    assertNull(CollectSupportDataOutputStream.forIntValue(12345));

    try
    {
      CollectSupportDataOutputStream.valueOf("undefined");
      fail("Expected an exception");
    }
    catch (final IllegalArgumentException e)
    {
      // This was expected.
    }
  }
}
