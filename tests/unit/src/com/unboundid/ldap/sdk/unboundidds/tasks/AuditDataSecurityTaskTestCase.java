/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the audit data security task.
 */
public final class AuditDataSecurityTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the case in which the defaults should be used for task arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllDefaults()
         throws Exception
  {
    AuditDataSecurityTask t = new AuditDataSecurityTask(null, null, null,
         null, null);
    t = (AuditDataSecurityTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getIncludeAuditors());
    assertTrue(t.getIncludeAuditors().isEmpty());

    assertNotNull(t.getExcludeAuditors());
    assertTrue(t.getExcludeAuditors().isEmpty());

    assertNotNull(t.getBackendIDs());
    assertTrue(t.getBackendIDs().isEmpty());

    assertNotNull(t.getReportFilterStrings());
    assertTrue(t.getReportFilterStrings().isEmpty());

    assertNotNull(t.getReportFilters());
    assertTrue(t.getReportFilters().isEmpty());

    assertNull(t.getOutputDirectory());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AuditDataSecurityTask");

    final Entry e = t.createTaskEntry();
    assertNotNull(e);
    assertFalse(e.hasAttribute("ds-task-audit-data-security-include-auditor"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-exclude-auditor"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-backend-id"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-report-filter"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-output-directory"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    final Map<TaskProperty,List<Object>> m = t.getTaskPropertyValues();
    assertNotNull(m);
    assertTrue(m.isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.toString());
  }



  /**
   * Tests the case in which values are provided for nearly all properties,
   * and include auditors but no exclude auditors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMostProvidedWithInclude()
         throws Exception
  {
    AuditDataSecurityTask t = new AuditDataSecurityTask(
         Arrays.asList("foo", "bar"),
         Arrays.<String>asList(),
         Arrays.asList("userRoot"),
         Arrays.asList("(objectClass=person)"),
         "/tmp/security-report");
    t = (AuditDataSecurityTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getIncludeAuditors());
    assertFalse(t.getIncludeAuditors().isEmpty());
    assertTrue(t.getIncludeAuditors().contains("foo"));
    assertTrue(t.getIncludeAuditors().contains("bar"));

    assertNotNull(t.getExcludeAuditors());
    assertTrue(t.getExcludeAuditors().isEmpty());

    assertNotNull(t.getBackendIDs());
    assertFalse(t.getBackendIDs().isEmpty());
    assertTrue(t.getBackendIDs().contains("userRoot"));

    assertNotNull(t.getReportFilterStrings());
    assertFalse(t.getReportFilterStrings().isEmpty());
    assertTrue(t.getReportFilterStrings().contains("(objectClass=person)"));

    assertNotNull(t.getReportFilters());
    assertFalse(t.getReportFilters().isEmpty());
    assertTrue(t.getReportFilters().contains(
         Filter.createEqualityFilter("objectClass", "person")));

    assertNotNull(t.getOutputDirectory());
    assertEquals(t.getOutputDirectory(), "/tmp/security-report");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AuditDataSecurityTask");

    final Entry e = t.createTaskEntry();
    assertNotNull(e);
    assertTrue(e.hasAttribute("ds-task-audit-data-security-include-auditor"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-exclude-auditor"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-backend-id"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-report-filter"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-output-directory"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    final Map<TaskProperty,List<Object>> m = t.getTaskPropertyValues();
    assertNotNull(m);
    assertFalse(m.isEmpty());
    for (final TaskProperty p : t.getTaskSpecificProperties())
    {
      if (p.getAttributeName().equals(
               "ds-task-audit-data-security-exclude-auditor"))
      {
        assertFalse(m.containsKey(p));
      }
      else
      {
        assertTrue(m.containsKey(p));
      }
    }

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.toString());
  }



  /**
   * Tests the case in which values are provided for nearly all properties,
   * and exclude auditors but no include auditors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMostProvidedWithExclude()
         throws Exception
  {
    AuditDataSecurityTask t = new AuditDataSecurityTask(
         Arrays.<String>asList(),
         Arrays.asList("foo", "bar"),
         Arrays.asList("userRoot"),
         Arrays.asList("(objectClass=person)"),
         "/tmp/security-report");
    t = (AuditDataSecurityTask) Task.decodeTask(t.createTaskEntry());

    assertNotNull(t.getIncludeAuditors());
    assertTrue(t.getIncludeAuditors().isEmpty());

    assertNotNull(t.getExcludeAuditors());
    assertFalse(t.getExcludeAuditors().isEmpty());
    assertTrue(t.getExcludeAuditors().contains("foo"));
    assertTrue(t.getExcludeAuditors().contains("bar"));

    assertNotNull(t.getBackendIDs());
    assertFalse(t.getBackendIDs().isEmpty());
    assertTrue(t.getBackendIDs().contains("userRoot"));

    assertNotNull(t.getReportFilterStrings());
    assertFalse(t.getReportFilterStrings().isEmpty());
    assertTrue(t.getReportFilterStrings().contains("(objectClass=person)"));

    assertNotNull(t.getReportFilters());
    assertFalse(t.getReportFilters().isEmpty());
    assertTrue(t.getReportFilters().contains(
         Filter.createEqualityFilter("objectClass", "person")));

    assertNotNull(t.getOutputDirectory());
    assertEquals(t.getOutputDirectory(), "/tmp/security-report");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AuditDataSecurityTask");

    final Entry e = t.createTaskEntry();
    assertNotNull(e);
    assertFalse(e.hasAttribute("ds-task-audit-data-security-include-auditor"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-exclude-auditor"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-backend-id"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-report-filter"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-output-directory"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    final Map<TaskProperty,List<Object>> m = t.getTaskPropertyValues();
    assertNotNull(m);
    assertFalse(m.isEmpty());
    for (final TaskProperty p : t.getTaskSpecificProperties())
    {
      if (p.getAttributeName().equals(
               "ds-task-audit-data-security-include-auditor"))
      {
        assertFalse(m.containsKey(p));
      }
      else
      {
        assertTrue(m.containsKey(p));
      }
    }

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.toString());
  }



  /**
   * Tests the behavior when trying to create an audit data security task with
   * both include and exclude lists.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testCreateBothIncludeAndExclude()
         throws Exception
  {
    new AuditDataSecurityTask(
         Arrays.asList("foo", "bar"),
         Arrays.asList("baz", "bat"),
         Arrays.asList("userRoot"),
         Arrays.asList("(objectClass=person)"),
         "/tmp/security-report");
  }



  /**
   * Tests the behavior when trying to create an audit data security task from
   * an empty map of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultsViaProperties()
         throws Exception
  {
    final AuditDataSecurityTask t = new AuditDataSecurityTask(
         new HashMap<TaskProperty,List<Object>>());

    assertNotNull(t.getIncludeAuditors());
    assertTrue(t.getIncludeAuditors().isEmpty());

    assertNotNull(t.getExcludeAuditors());
    assertTrue(t.getExcludeAuditors().isEmpty());

    assertNotNull(t.getBackendIDs());
    assertTrue(t.getBackendIDs().isEmpty());

    assertNotNull(t.getReportFilterStrings());
    assertTrue(t.getReportFilterStrings().isEmpty());

    assertNotNull(t.getReportFilters());
    assertTrue(t.getReportFilters().isEmpty());

    assertNull(t.getOutputDirectory());

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AuditDataSecurityTask");

    final Entry e = t.createTaskEntry();
    assertNotNull(e);
    assertFalse(e.hasAttribute("ds-task-audit-data-security-include-auditor"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-exclude-auditor"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-backend-id"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-report-filter"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-output-directory"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    final Map<TaskProperty,List<Object>> m = t.getTaskPropertyValues();
    assertNotNull(m);
    assertTrue(m.isEmpty());

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertTrue(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.toString());
  }



  /**
   * Tests the case in which values are provided for nearly all properties,
   * and include auditors but no exclude auditors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMostProvidedWithIncludeViaProperties()
         throws Exception
  {
    final AuditDataSecurityTask template = new AuditDataSecurityTask();

    final HashMap<TaskProperty,List<Object>> propertyMap =
         new HashMap<TaskProperty,List<Object>>(5);
    for (final TaskProperty p : template.getTaskSpecificProperties())
    {
      final String name = p.getAttributeName();
      if (name.equals("ds-task-audit-data-security-include-auditor"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(2);
        values.add("foo");
        values.add("bar");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-backend-id"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(1);
        values.add("userRoot");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-report-filter"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(1);
        values.add("(objectClass=person)");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-output-directory"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(1);
        values.add("/tmp/security-report");
        propertyMap.put(p, values);
      }
    }

    final AuditDataSecurityTask t = new AuditDataSecurityTask(propertyMap);

    assertNotNull(t.getIncludeAuditors());
    assertFalse(t.getIncludeAuditors().isEmpty());
    assertTrue(t.getIncludeAuditors().contains("foo"));
    assertTrue(t.getIncludeAuditors().contains("bar"));

    assertNotNull(t.getExcludeAuditors());
    assertTrue(t.getExcludeAuditors().isEmpty());

    assertNotNull(t.getBackendIDs());
    assertFalse(t.getBackendIDs().isEmpty());
    assertTrue(t.getBackendIDs().contains("userRoot"));

    assertNotNull(t.getReportFilterStrings());
    assertFalse(t.getReportFilterStrings().isEmpty());
    assertTrue(t.getReportFilterStrings().contains("(objectClass=person)"));

    assertNotNull(t.getReportFilters());
    assertFalse(t.getReportFilters().isEmpty());
    assertTrue(t.getReportFilters().contains(
         Filter.createEqualityFilter("objectClass", "person")));

    assertNotNull(t.getOutputDirectory());
    assertEquals(t.getOutputDirectory(), "/tmp/security-report");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AuditDataSecurityTask");

    final Entry e = t.createTaskEntry();
    assertNotNull(e);
    assertTrue(e.hasAttribute("ds-task-audit-data-security-include-auditor"));
    assertFalse(e.hasAttribute("ds-task-audit-data-security-exclude-auditor"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-backend-id"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-report-filter"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-output-directory"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    final Map<TaskProperty,List<Object>> m = t.getTaskPropertyValues();
    assertNotNull(m);
    assertFalse(m.isEmpty());
    for (final TaskProperty p : t.getTaskSpecificProperties())
    {
      if (p.getAttributeName().equals(
               "ds-task-audit-data-security-exclude-auditor"))
      {
        assertFalse(m.containsKey(p));
      }
      else
      {
        assertTrue(m.containsKey(p));
      }
    }

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.toString());
  }



  /**
   * Tests the case in which values are provided for nearly all properties,
   * and exclude auditors but no include auditors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMostProvidedWithExcludeViaProperties()
         throws Exception
  {
    final AuditDataSecurityTask template = new AuditDataSecurityTask();

    final HashMap<TaskProperty,List<Object>> propertyMap =
         new HashMap<TaskProperty,List<Object>>(5);
    for (final TaskProperty p : template.getTaskSpecificProperties())
    {
      final String name = p.getAttributeName();
      if (name.equals("ds-task-audit-data-security-exclude-auditor"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(2);
        values.add("foo");
        values.add("bar");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-backend-id"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(1);
        values.add("userRoot");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-report-filter"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(1);
        values.add("(objectClass=person)");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-output-directory"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(1);
        values.add("/tmp/security-report");
        propertyMap.put(p, values);
      }
    }

    final AuditDataSecurityTask t = new AuditDataSecurityTask(propertyMap);

    assertNotNull(t.getIncludeAuditors());
    assertTrue(t.getIncludeAuditors().isEmpty());

    assertNotNull(t.getExcludeAuditors());
    assertFalse(t.getExcludeAuditors().isEmpty());
    assertTrue(t.getExcludeAuditors().contains("foo"));
    assertTrue(t.getExcludeAuditors().contains("bar"));

    assertNotNull(t.getBackendIDs());
    assertFalse(t.getBackendIDs().isEmpty());
    assertTrue(t.getBackendIDs().contains("userRoot"));

    assertNotNull(t.getReportFilterStrings());
    assertFalse(t.getReportFilterStrings().isEmpty());
    assertTrue(t.getReportFilterStrings().contains("(objectClass=person)"));

    assertNotNull(t.getReportFilters());
    assertFalse(t.getReportFilters().isEmpty());
    assertTrue(t.getReportFilters().contains(
         Filter.createEqualityFilter("objectClass", "person")));

    assertNotNull(t.getOutputDirectory());
    assertEquals(t.getOutputDirectory(), "/tmp/security-report");

    assertNotNull(t.getTaskName());

    assertNotNull(t.getTaskDescription());

    assertNotNull(t.getTaskClassName());
    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.AuditDataSecurityTask");

    final Entry e = t.createTaskEntry();
    assertNotNull(e);
    assertFalse(e.hasAttribute("ds-task-audit-data-security-include-auditor"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-exclude-auditor"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-backend-id"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-report-filter"));
    assertTrue(e.hasAttribute("ds-task-audit-data-security-output-directory"));

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());

    final Map<TaskProperty,List<Object>> m = t.getTaskPropertyValues();
    assertNotNull(m);
    assertFalse(m.isEmpty());
    for (final TaskProperty p : t.getTaskSpecificProperties())
    {
      if (p.getAttributeName().equals(
               "ds-task-audit-data-security-include-auditor"))
      {
        assertFalse(m.containsKey(p));
      }
      else
      {
        assertTrue(m.containsKey(p));
      }
    }

    assertNotNull(t.getAdditionalObjectClasses());
    assertFalse(t.getAdditionalObjectClasses().isEmpty());

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.toString());
  }



  /**
   * Tests the case in which values are provided for nearly all properties,
   * and exclude auditors but no include auditors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { TaskException.class })
  public void testBothIncludeAndExcludeViaProperties()
         throws Exception
  {
    final AuditDataSecurityTask template = new AuditDataSecurityTask();

    final HashMap<TaskProperty,List<Object>> propertyMap =
         new HashMap<TaskProperty,List<Object>>(5);
    for (final TaskProperty p : template.getTaskSpecificProperties())
    {
      final String name = p.getAttributeName();
      if (name.equals("ds-task-audit-data-security-include-auditor"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(2);
        values.add("foo");
        values.add("bar");
        propertyMap.put(p, values);
      }
      else if (name.equals("ds-task-audit-data-security-exclude-auditor"))
      {
        final ArrayList<Object> values = new ArrayList<Object>(2);
        values.add("baz");
        values.add("bat");
        propertyMap.put(p, values);
      }
    }

    new AuditDataSecurityTask(propertyMap);
  }
}
