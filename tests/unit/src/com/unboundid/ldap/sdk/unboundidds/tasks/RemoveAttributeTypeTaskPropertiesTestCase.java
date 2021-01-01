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
import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the remove attribute type task
 * properties.
 */
public final class RemoveAttributeTypeTaskPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with the default set of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultProperties()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the attribute type property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOutputPath()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAttributeType("differentAttrName");
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "differentAttrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the task ID property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testTaskID()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setTaskID("123-456-7890");
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());
    assertEquals(p.getTaskID(), "123-456-7890");

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setTaskID(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the scheduled start time property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testScheduledStartTime()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    final Date d = new Date();
    p.setScheduledStartTime(d);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNotNull(p.getScheduledStartTime());
    assertEquals(p.getScheduledStartTime(), d);

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setScheduledStartTime(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the dependency IDs property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDependencyIDs()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setDependencyIDs(Arrays.asList("1", "2", "3"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertFalse(p.getDependencyIDs().isEmpty());
    assertEquals(p.getDependencyIDs(), Arrays.asList("1", "2", "3"));

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setDependencyIDs(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setDependencyIDs(Collections.singletonList("4"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertFalse(p.getDependencyIDs().isEmpty());
    assertEquals(p.getDependencyIDs(), Collections.singletonList("4"));

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setDependencyIDs(Collections.<String>emptyList());
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the failed dependency action property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFailedDependencyAction()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    for (final FailedDependencyAction a :
         FailedDependencyAction.values())
    {
      p.setFailedDependencyAction(a);
      p = new RemoveAttributeTypeTaskProperties(p);
      p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

      assertNotNull(p.getAttributeType());
      assertEquals(p.getAttributeType(), "attrName");

      assertNotNull(p.getTaskID());

      assertNull(p.getScheduledStartTime());

      assertNotNull(p.getDependencyIDs());
      assertTrue(p.getDependencyIDs().isEmpty());

      assertNotNull(p.getFailedDependencyAction());
      assertEquals(p.getFailedDependencyAction(), a);

      assertNotNull(p.getNotifyOnStart());
      assertTrue(p.getNotifyOnStart().isEmpty());

      assertNotNull(p.getNotifyOnCompletion());
      assertTrue(p.getNotifyOnCompletion().isEmpty());

      assertNotNull(p.getNotifyOnSuccess());
      assertTrue(p.getNotifyOnSuccess().isEmpty());

      assertNotNull(p.getNotifyOnError());
      assertTrue(p.getNotifyOnError().isEmpty());

      assertNull(p.getAlertOnStart());

      assertNull(p.getAlertOnSuccess());

      assertNull(p.getAlertOnError());

      assertNotNull(p.toString());
    }


    p.setFailedDependencyAction(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the notify on start property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnStart()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnStart(Arrays.asList("start1@example.com",
         "start2@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertFalse(p.getNotifyOnStart().isEmpty());
    assertEquals(p.getNotifyOnStart(),
         Arrays.asList("start1@example.com", "start2@example.com"));

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnStart(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnStart(Collections.singletonList("start3@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertFalse(p.getNotifyOnStart().isEmpty());
    assertEquals(p.getNotifyOnStart(),
         Collections.singletonList("start3@example.com"));

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnStart(Collections.<String>emptyList());
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the notify on completion property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnCompletion()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnCompletion(Arrays.asList("end1@example.com",
         "end2@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertFalse(p.getNotifyOnCompletion().isEmpty());
    assertEquals(p.getNotifyOnCompletion(),
         Arrays.asList("end1@example.com", "end2@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnCompletion(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnCompletion(Collections.singletonList("end3@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertFalse(p.getNotifyOnCompletion().isEmpty());
    assertEquals(p.getNotifyOnCompletion(),
         Collections.singletonList("end3@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnCompletion(Collections.<String>emptyList());
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the notify on success property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnSuccess()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnSuccess(Arrays.asList("success1@example.com",
         "success2@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertFalse(p.getNotifyOnSuccess().isEmpty());
    assertEquals(p.getNotifyOnSuccess(),
         Arrays.asList("success1@example.com", "success2@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnSuccess(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnSuccess(Collections.singletonList("success3@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertFalse(p.getNotifyOnSuccess().isEmpty());
    assertEquals(p.getNotifyOnSuccess(),
         Collections.singletonList("success3@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnSuccess(Collections.<String>emptyList());
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the notify on error property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotifyOnError()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnError(Arrays.asList("error1@example.com",
         "error2@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertFalse(p.getNotifyOnError().isEmpty());
    assertEquals(p.getNotifyOnError(),
         Arrays.asList("error1@example.com", "error2@example.com"));

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnError(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnError(Collections.singletonList("error3@example.com"));
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertFalse(p.getNotifyOnError().isEmpty());
    assertEquals(p.getNotifyOnError(),
         Collections.singletonList("error3@example.com"));

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setNotifyOnError(Collections.<String>emptyList());
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the alert on start property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlertOnStart()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnStart(true);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNotNull(p.getAlertOnStart());
    assertTrue(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnStart(false);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNotNull(p.getAlertOnStart());
    assertFalse(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnStart(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the alert on success property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlertOnSuccess()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnSuccess(true);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNotNull(p.getAlertOnSuccess());
    assertTrue(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnSuccess(false);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNotNull(p.getAlertOnSuccess());
    assertFalse(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnSuccess(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior related to the alert on error property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAlertOnError()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnError(true);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNotNull(p.getAlertOnError());
    assertTrue(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnError(false);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNotNull(p.getAlertOnError());
    assertFalse(p.getAlertOnError());

    assertNotNull(p.toString());


    p.setAlertOnError(null);
    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNotNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior when setting all of the properties at once.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetAllProperties()
         throws Exception
  {
    RemoveAttributeTypeTaskProperties p =
         new RemoveAttributeTypeTaskProperties("attrName");
    p = new RemoveAttributeTypeTaskProperties(p);

    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "attrName");

    assertNull(p.getTaskID());

    assertNull(p.getScheduledStartTime());

    assertNotNull(p.getDependencyIDs());
    assertTrue(p.getDependencyIDs().isEmpty());

    assertNull(p.getFailedDependencyAction());

    assertNotNull(p.getNotifyOnStart());
    assertTrue(p.getNotifyOnStart().isEmpty());

    assertNotNull(p.getNotifyOnCompletion());
    assertTrue(p.getNotifyOnCompletion().isEmpty());

    assertNotNull(p.getNotifyOnSuccess());
    assertTrue(p.getNotifyOnSuccess().isEmpty());

    assertNotNull(p.getNotifyOnError());
    assertTrue(p.getNotifyOnError().isEmpty());

    assertNull(p.getAlertOnStart());

    assertNull(p.getAlertOnSuccess());

    assertNull(p.getAlertOnError());

    assertNotNull(p.toString());


    final Date d = new Date();

    p.setAttributeType("differentAttrName");
    p.setTaskID("123-456-7890");
    p.setScheduledStartTime(d);
    p.setDependencyIDs(Arrays.asList("d1", "d2", "d3"));
    p.setFailedDependencyAction(FailedDependencyAction.CANCEL);
    p.setNotifyOnStart(
         Arrays.asList("start1@example.com", "start2@example.com"));
    p.setNotifyOnCompletion(
         Arrays.asList("end1@example.com", "end2@example.com"));
    p.setNotifyOnSuccess(
         Arrays.asList("success1@example.com", "success2@example.com"));
    p.setNotifyOnError(
         Arrays.asList("error1@example.com", "error2@example.com"));
    p.setAlertOnStart(true);
    p.setAlertOnSuccess(false);
    p.setAlertOnError(true);

    p = new RemoveAttributeTypeTaskProperties(p);
    p = new RemoveAttributeTypeTaskProperties(new RemoveAttributeTypeTask(p));


    assertNotNull(p.getAttributeType());
    assertEquals(p.getAttributeType(), "differentAttrName");

    assertNotNull(p.getTaskID());
    assertEquals(p.getTaskID(), "123-456-7890");

    assertNotNull(p.getScheduledStartTime());
    assertEquals(p.getScheduledStartTime(), d);

    assertNotNull(p.getDependencyIDs());
    assertFalse(p.getDependencyIDs().isEmpty());
    assertEquals(p.getDependencyIDs(), Arrays.asList("d1", "d2", "d3"));

    assertNotNull(p.getFailedDependencyAction());
    assertEquals(p.getFailedDependencyAction(),
         FailedDependencyAction.CANCEL);

    assertNotNull(p.getNotifyOnStart());
    assertFalse(p.getNotifyOnStart().isEmpty());
    assertEquals(p.getNotifyOnStart(),
         Arrays.asList("start1@example.com", "start2@example.com"));

    assertNotNull(p.getNotifyOnCompletion());
    assertFalse(p.getNotifyOnCompletion().isEmpty());
    assertEquals(p.getNotifyOnCompletion(),
         Arrays.asList("end1@example.com", "end2@example.com"));

    assertNotNull(p.getNotifyOnSuccess());
    assertFalse(p.getNotifyOnSuccess().isEmpty());
    assertEquals(p.getNotifyOnSuccess(),
         Arrays.asList("success1@example.com", "success2@example.com"));

    assertNotNull(p.getNotifyOnError());
    assertFalse(p.getNotifyOnError().isEmpty());
    assertEquals(p.getNotifyOnError(),
         Arrays.asList("error1@example.com", "error2@example.com"));

    assertNotNull(p.getAlertOnStart());
    assertTrue(p.getAlertOnStart());

    assertNotNull(p.getAlertOnSuccess());
    assertFalse(p.getAlertOnSuccess());

    assertNotNull(p.getAlertOnError());
    assertTrue(p.getAlertOnError());

    assertNotNull(p.toString());
  }
}
