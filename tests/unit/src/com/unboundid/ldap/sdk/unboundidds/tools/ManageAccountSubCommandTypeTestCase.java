/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the ManageAccountSubCommandType
 * class.
 */
public final class ManageAccountSubCommandTypeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the subcommand types methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSubCommandTypes()
         throws Exception
  {
    for (final ManageAccountSubCommandType t :
         ManageAccountSubCommandType.values())
    {
      assertNotNull(t.getPrimaryName());

      assertNotNull(ManageAccountSubCommandType.forName(t.getPrimaryName()),
           "forName failed for " + t.getPrimaryName());
      assertEquals(ManageAccountSubCommandType.forName(t.getPrimaryName()), t,
           "forName equality failed for " + t.getPrimaryName());

      assertNotNull(t.getAlternateNames());
      for (final String s : t.getAlternateNames())
      {
        assertNotNull(ManageAccountSubCommandType.forName(s),
             "forName failed for " + s);
        assertEquals(ManageAccountSubCommandType.forName(s), t,
             "forName equality failed for " + s);
      }

      assertNotNull(t.getAllNames());
      assertFalse(t.getAllNames().isEmpty());
      for (final String s : t.getAllNames())
      {
        assertNotNull(ManageAccountSubCommandType.forName(s),
             "forName failed for " + s);
        assertEquals(ManageAccountSubCommandType.forName(s), t,
             "forName equality failed for " + s);
      }

      assertNotNull(t.getDescription());

      if (t != ManageAccountSubCommandType.GET_ALL)
      {
        assertNotNull(
             ManageAccountSubCommandType.forOperationType(
                  t.getPasswordPolicyStateOperationType()),
             "forOperationType failed for " + t.getPrimaryName());
        assertEquals(
             ManageAccountSubCommandType.forOperationType(
                  t.getPasswordPolicyStateOperationType()),
             t,
             "forOperationType equality failed for " + t.getPrimaryName());
      }

      assertNotNull(ManageAccountSubCommandType.valueOf(t.name()));
      assertEquals(ManageAccountSubCommandType.valueOf(t.name()), t);
    }
  }



  /**
   * Tests the behavior when the ManageAccountSubCommandType.forName method is
   * called with a name that isn't defined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameUndefined()
         throws Exception
  {
    assertNull(ManageAccountSubCommandType.forName("undefined"));
  }



  /**
   * Tests the behavior when the ManageAccountSubCommandType.forOperationType
   * method is called with a value that isn't defined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForOperationType()
         throws Exception
  {
    assertNull(ManageAccountSubCommandType.forOperationType(1234));
  }
}
