/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides test coverage for the SearchTask class.
 */
public class SearchTaskTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the a task created with a minimal set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorMinimal()
         throws Exception
  {
    SearchTask t = new SearchTask("foo", "dc=example,dc=com", SearchScope.SUB,
         Filter.createEqualityFilter("uid", "test"), null, "test.ldif");

    assertNotNull(t.createTaskEntry());
    Entry e = t.createTaskEntry();
    e.addAttribute("ds-task-state", TaskState.UNSCHEDULED.getName());
    t = (SearchTask) Task.decodeTask(e);

    assertNotNull(t.getTaskPropertyValues());
    t = new SearchTask(t.getTaskPropertyValues());

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.SearchTask");

    assertNotNull(t.getBaseDN());
    assertEquals(new DN(t.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(t.getScope());
    assertEquals(t.getScope(), SearchScope.SUB);

    assertNotNull(t.getFilter());
    assertEquals(t.getFilter(), Filter.create("(uid=test)"));

    assertNotNull(t.getAttributes());
    assertTrue(t.getAttributes().isEmpty());

    assertNull(t.getAuthzDN());

    assertNotNull(t.getOutputFile());
    assertEquals(t.getOutputFile(), "test.ldif");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-search"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the a task created with a full set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorFull()
         throws Exception
  {
    LinkedList<String> attrs = new LinkedList<String>();
    attrs.add("*");
    attrs.add("+");

    SearchTask t = new SearchTask("foo", "dc=example,dc=com", SearchScope.BASE,
         Filter.createPresenceFilter("objectClass"), attrs, "test.ldif",
         "uid=admin,dc=example,dc=com");

    assertNotNull(t.createTaskEntry());
    Entry e = t.createTaskEntry();
    e.addAttribute("ds-task-state", TaskState.UNSCHEDULED.getName());
    t = (SearchTask) Task.decodeTask(e);

    assertNotNull(t.getTaskPropertyValues());
    t = new SearchTask(t.getTaskPropertyValues());

    assertNotNull(t);

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.SearchTask");

    assertNotNull(t.getBaseDN());
    assertEquals(new DN(t.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(t.getScope());
    assertEquals(t.getScope(), SearchScope.BASE);

    assertNotNull(t.getFilter());
    assertEquals(t.getFilter(), Filter.create("(objectClass=*)"));

    assertNotNull(t.getAttributes());
    assertFalse(t.getAttributes().isEmpty());
    assertEquals(t.getAttributes().size(), 2);

    assertNotNull(t.getAuthzDN());
    assertEquals(new DN(t.getAuthzDN()), new DN("uid=admin,dc=example,dc=com"));

    assertNotNull(t.getOutputFile());
    assertEquals(t.getOutputFile(), "test.ldif");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-search"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests a task created with a valid entry.
   *
   * @param  scopeStr  The string representation of the scope to use.
   * @param  scope     The parsed version of the provided scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testScopeValues")
  public void testConstructorValidEntry(final String scopeStr,
                                        final SearchScope scope)
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: " + scopeStr,
         "ds-task-search-filter: (ou=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.SearchTask");

    assertNotNull(t.getBaseDN());
    assertEquals(new DN(t.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(t.getScope());
    assertEquals(t.getScope(), scope);

    assertNotNull(t.getFilter());
    assertEquals(t.getFilter(), Filter.create("(ou=*)"));

    assertNotNull(t.getAttributes());
    assertTrue(t.getAttributes().isEmpty());

    assertNull(t.getAuthzDN());

    assertNotNull(t.getOutputFile());
    assertEquals(t.getOutputFile(), "test.ldif");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-search"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests the behavior when trying to create a task from an entry that doesn't
   * contain a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorEntryWithoutBaseDN()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-scope: one",
         "ds-task-search-filter: (ou=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));
  }



  /**
   * Tests the behavior when trying to create a task from an entry that doesn't
   * contain a scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorEntryWithoutScope()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-filter: (ou=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));
  }



  /**
   * Tests the behavior when trying to create a task from an entry that has an
   * invalid scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorEntryWithInvalidScope()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: invalid",
         "ds-task-search-filter: (ou=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));
  }



  /**
   * Tests the behavior when trying to create a task from an entry that doesn't
   * contain a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorEntryWithoutFilter()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: one",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));
  }



  /**
   * Tests the behavior when trying to create a task from an entry that has an
   * invalid filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorEntryWithInvalidFilter()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: one",
         "ds-task-search-filter: invalid",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));
  }



  /**
   * Tests the behavior when trying to create a task from an entry that doesn't
   * contain an output file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorEntryWithoutOutputFile()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: one",
         "ds-task-search-filter: (ou=*)",
         "ds-task-state: unscheduled"));
  }



  /**
   * Tests a task created with a valid property map.
   *
   * @param  scopeStr  The string representation of the scope to use.
   * @param  scope     The parsed version of the provided scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testScopeValues")
  public void testConstructorValidPropertyMap(final String scopeStr,
                                              final SearchScope scope)
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: " + scopeStr,
         "ds-task-search-filter: (ou=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    t = new SearchTask(t.getTaskPropertyValues());

    assertEquals(t.getTaskClassName(),
         "com.unboundid.directory.server.tasks.SearchTask");

    assertNotNull(t.getBaseDN());
    assertEquals(new DN(t.getBaseDN()), new DN("dc=example,dc=com"));

    assertNotNull(t.getScope());
    assertEquals(t.getScope(), scope);

    assertNotNull(t.getFilter());
    assertEquals(t.getFilter(), Filter.create("(ou=*)"));

    assertNotNull(t.getAttributes());
    assertTrue(t.getAttributes().isEmpty());

    assertNull(t.getAuthzDN());

    assertNotNull(t.getOutputFile());
    assertEquals(t.getOutputFile(), "test.ldif");

    assertNotNull(t.getAdditionalObjectClasses());
    assertEquals(t.getAdditionalObjectClasses().size(), 1);
    assertTrue(t.getAdditionalObjectClasses().contains("ds-task-search"));

    assertNotNull(t.getAdditionalAttributes());
    assertFalse(t.getAdditionalAttributes().isEmpty());

    assertNotNull(t.getTaskSpecificProperties());
    assertFalse(t.getTaskSpecificProperties().isEmpty());
  }



  /**
   * Tests a task created with a property map that doesn't have a base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorPropertyMapWithoutBaseDN()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: base",
         "ds-task-search-filter: (objectClass=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(
              t.getTaskPropertyValues());

    Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         m.entrySet().iterator();
    while (iterator.hasNext())
    {
      Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      TaskProperty p = e.getKey();
      if (p.getAttributeName().equals("ds-task-search-base-dn"))
      {
        iterator.remove();
        break;
      }
    }

    t = new SearchTask(m);
  }



  /**
   * Tests a task created with a property map that doesn't have a scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorPropertyMapWithoutScope()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: base",
         "ds-task-search-filter: (objectClass=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(
              t.getTaskPropertyValues());

    Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         m.entrySet().iterator();
    while (iterator.hasNext())
    {
      Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      TaskProperty p = e.getKey();
      if (p.getAttributeName().equals("ds-task-search-scope"))
      {
        iterator.remove();
        break;
      }
    }

    t = new SearchTask(m);
  }



  /**
   * Tests a task created with a property map that has an invalid scope.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorPropertyMapWithInvalidScope()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: base",
         "ds-task-search-filter: (objectClass=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(
              t.getTaskPropertyValues());

    TaskProperty scopeProperty = null;
    for (TaskProperty p : m.keySet())
    {
      if (p.getAttributeName().equals("ds-task-search-scope"))
      {
        scopeProperty = p;
        break;
      }
    }

    assertNotNull(scopeProperty);
    m.put(scopeProperty, Arrays.<Object>asList("invalid"));

    t = new SearchTask(m);
  }



  /**
   * Tests a task created with a property map that doesn't have a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorPropertyMapWithoutFilter()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: base",
         "ds-task-search-filter: (objectClass=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(
              t.getTaskPropertyValues());

    Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         m.entrySet().iterator();
    while (iterator.hasNext())
    {
      Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      TaskProperty p = e.getKey();
      if (p.getAttributeName().equals("ds-task-search-filter"))
      {
        iterator.remove();
        break;
      }
    }

    t = new SearchTask(m);
  }



  /**
   * Tests a task created with a property map that has an invalid filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorPropertyMapWithInvalidFilter()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: base",
         "ds-task-search-filter: (objectClass=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(
              t.getTaskPropertyValues());

    TaskProperty filterProperty = null;
    for (TaskProperty p : m.keySet())
    {
      if (p.getAttributeName().equals("ds-task-search-filter"))
      {
        filterProperty = p;
        break;
      }
    }

    assertNotNull(filterProperty);
    m.put(filterProperty, Arrays.<Object>asList("invalid"));

    t = new SearchTask(m);
  }



  /**
   * Tests a task created with a property map that doesn't have a filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions={TaskException.class})
  public void testConstructorPropertyMapWithoutOutputFile()
         throws Exception
  {
    SearchTask t = new SearchTask(new Entry(
         "dn: ds-task-id=foo",
         "objectClass: top",
         "objectClass: ds-task",
         "objectClass: ds-task-search",
         "ds-task-id: foo",
         "ds-task-class-name: com.unboundid.directory.server.tasks.SearchTask",
         "ds-task-search-base-dn: dc=example,dc=com",
         "ds-task-search-scope: base",
         "ds-task-search-filter: (objectClass=*)",
         "ds-task-search-output-file: test.ldif",
         "ds-task-state: unscheduled"));

    LinkedHashMap<TaskProperty,List<Object>> m =
         new LinkedHashMap<TaskProperty,List<Object>>(
              t.getTaskPropertyValues());

    Iterator<Map.Entry<TaskProperty,List<Object>>> iterator =
         m.entrySet().iterator();
    while (iterator.hasNext())
    {
      Map.Entry<TaskProperty,List<Object>> e = iterator.next();
      TaskProperty p = e.getKey();
      if (p.getAttributeName().equals("ds-task-search-output-file"))
      {
        iterator.remove();
        break;
      }
    }

    t = new SearchTask(m);
  }



  /**
   * Retrieves a set of test search scopes.
   *
   * @return  A set of test search scopes.
   */
  @DataProvider(name="testScopeValues")
  public Object[][] getTestScopeValues()
  {
    return new Object[][]
    {
      new Object[] { "base", SearchScope.BASE },
      new Object[] { "baseObject", SearchScope.BASE },
      new Object[] { "0", SearchScope.BASE },
      new Object[] { "one", SearchScope.ONE },
      new Object[] { "oneLevel", SearchScope.ONE },
      new Object[] { "singleLevel", SearchScope.ONE },
      new Object[] { "1", SearchScope.ONE },
      new Object[] { "sub", SearchScope.SUB },
      new Object[] { "subtree", SearchScope.SUB },
      new Object[] { "wholeSubtree", SearchScope.SUB },
      new Object[] { "2", SearchScope.SUB },
      new Object[] { "subord", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "subordinate", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "subordinateSubtree", SearchScope.SUBORDINATE_SUBTREE },
      new Object[] { "3", SearchScope.SUBORDINATE_SUBTREE }
    };
  }
}
