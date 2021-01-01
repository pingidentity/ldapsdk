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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the PopulateComposedAttributeValuesTask
 * class.
 */
public class PopulateComposedAttributeValuesTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    final PopulateComposedAttributeValuesTask t =
         new PopulateComposedAttributeValuesTask();

    assertNotNull(t.getTaskName());
    assertEquals(t.getTaskName(), "Populate Composed Attribute Values");

    assertNotNull(t.getTaskDescription());
    assertFalse(t.getTaskDescription().isEmpty());
    assertFalse(t.getTaskDescription().equals(t.getTaskName()));

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertEquals(t.getAdditionalObjectClasses().get(0),
         "ds-task-populate-composed-attribute");

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
    assertEquals(t.getTaskSpecificProperties().size(), 3);
  }



  /**
   * Test with {@code null} values for all elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNullValuesForAllElements()
         throws Exception
  {
    PopulateComposedAttributeValuesTask t =
         new PopulateComposedAttributeValuesTask(null, null, null, null);

    t = (PopulateComposedAttributeValuesTask)
         Task.decodeTask(t.createTaskEntry());

    t = new PopulateComposedAttributeValuesTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskID());
    assertNotNull(UUID.fromString(t.getTaskID()));

    assertNotNull(t.getPluginConfigs());
    assertTrue(t.getPluginConfigs().isEmpty());

    assertNotNull(t.getBackendIDs());
    assertTrue(t.getBackendIDs().isEmpty());

    assertNull(t.getMaxRatePerSecond());
  }



  /**
   * Test with non-{@code null} values for all elements, and lists with single
   * items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonNullValuesForAllElementsSingleItemLists()
         throws Exception
  {
    PopulateComposedAttributeValuesTask t =
         new PopulateComposedAttributeValuesTask("Populate Task",
              Collections.singletonList("Composed cn"),
              Collections.singletonList("userRoot"),
              1000);

    t = (PopulateComposedAttributeValuesTask)
         Task.decodeTask(t.createTaskEntry());

    t = new PopulateComposedAttributeValuesTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "Populate Task");

    assertNotNull(t.getPluginConfigs());
    assertFalse(t.getPluginConfigs().isEmpty());
    assertEquals(t.getPluginConfigs().size(), 1);
    assertEquals(t.getPluginConfigs().get(0), "Composed cn");

    assertNotNull(t.getBackendIDs());
    assertFalse(t.getBackendIDs().isEmpty());
    assertEquals(t.getBackendIDs().size(), 1);
    assertEquals(t.getBackendIDs().get(0), "userRoot");

    assertNotNull(t.getMaxRatePerSecond());
    assertEquals(t.getMaxRatePerSecond().intValue(), 1000);
  }



  /**
   * Test with non-{@code null} values for all elements, and lists with multiple
   * items.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonNullValuesForAllElementsMultiItemLists()
         throws Exception
  {
    PopulateComposedAttributeValuesTask t =
         new PopulateComposedAttributeValuesTask("Populate Task",
              Arrays.asList("Composed cn", "Composed description"),
              Arrays.asList("userRoot", "people"),
              1234);

    t = (PopulateComposedAttributeValuesTask)
         Task.decodeTask(t.createTaskEntry());

    t = new PopulateComposedAttributeValuesTask(t.getTaskPropertyValues());

    assertNotNull(t.getTaskID());
    assertEquals(t.getTaskID(), "Populate Task");

    assertNotNull(t.getPluginConfigs());
    assertFalse(t.getPluginConfigs().isEmpty());
    assertEquals(t.getPluginConfigs().size(), 2);
    assertEquals(t.getPluginConfigs().get(0), "Composed cn");
    assertEquals(t.getPluginConfigs().get(1), "Composed description");

    assertNotNull(t.getBackendIDs());
    assertFalse(t.getBackendIDs().isEmpty());
    assertEquals(t.getBackendIDs().size(), 2);
    assertEquals(t.getBackendIDs().get(0), "userRoot");
    assertEquals(t.getBackendIDs().get(1), "people");

    assertNotNull(t.getMaxRatePerSecond());
    assertEquals(t.getMaxRatePerSecond().intValue(), 1234);
  }
}
