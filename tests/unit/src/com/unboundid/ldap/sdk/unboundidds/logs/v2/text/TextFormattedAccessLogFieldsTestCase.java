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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import java.lang.reflect.Field;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;



/**
 * This class provides a set of test cases to ensure validate the predefined set
 * of text-formatted access log fields.
 */
public final class TextFormattedAccessLogFieldsTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that all fields defined in the class are available via the
   * {@code getDefinedFields} method with the appropriate constant name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidateFields()
         throws Exception
  {
    assertNotNull(TextFormattedAccessLogFields.getDefinedFields());
    assertFalse(TextFormattedAccessLogFields.getDefinedFields().isEmpty());

    int numFieldConstants = 0;
    for (final Field f : TextFormattedAccessLogFields.class.getDeclaredFields())
    {
      if (f.getType().isAssignableFrom(LogField.class))
      {
        numFieldConstants++;

        final String fieldName = f.getName();
        assertTrue(
             TextFormattedAccessLogFields.getDefinedFields().containsKey(
                  fieldName),
             "Did not find expected field '" + fieldName + "' in the defined " +
                  "set of constants.");
        assertNotNull(TextFormattedAccessLogFields.getFieldForConstantName(
             fieldName));
        assertNotNull(TextFormattedAccessLogFields.getFieldForConstantName(
             fieldName.toLowerCase().replace('_', '-')));

        final LogField logField =
             TextFormattedAccessLogFields.getFieldForConstantName(fieldName);
        assertNotNull(logField);
        assertNotNull(logField.getConstantName());
        assertEquals(logField.getConstantName(), fieldName);
      }
    }

    assertEquals(numFieldConstants,
         TextFormattedAccessLogFields.getDefinedFields().size());

    assertNull(TextFormattedAccessLogFields.getFieldForConstantName(
         "THIS_NAME_DOES_NOT_CORRESPOND_TO_ANY_DEFINED_FIELD"));
  }
}
