/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the uniqueness request control
 * properties class.
 */
public final class UniquenessRequestControlPropertiesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a set of properties created with a single attribute
   * type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithSingleAttributeType()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties("uid");

    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 1);
    assertTrue(p.getAttributeTypes().contains("uid"));

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNull(p.getFilter());

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(p.alertOnPostCommitConflictDetection());

    assertFalse(p.createConflictPreventionDetailsEntry());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for a set of properties created with multiple attribute
   * types specified using varargs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithMultipleAttributeTypesWithVarargs()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties("mail", "mailAlternateAddress");

    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 2);
    assertTrue(p.getAttributeTypes().contains("mail"));
    assertTrue(p.getAttributeTypes().contains("mailAlternateAddress"));

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNull(p.getFilter());

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(p.alertOnPostCommitConflictDetection());

    assertFalse(p.createConflictPreventionDetailsEntry());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for a set of properties created with multiple attribute
   * types specified using a collection.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithMultipleAttributeTypesWithCollection()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Arrays.asList("mail", "mailAlternateAddress"));

    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 2);
    assertTrue(p.getAttributeTypes().contains("mail"));
    assertTrue(p.getAttributeTypes().contains("mailAlternateAddress"));

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNull(p.getFilter());

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(p.alertOnPostCommitConflictDetection());

    assertFalse(p.createConflictPreventionDetailsEntry());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for a set of properties created with a filter rather
   * than a set of attribute types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithFilter()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(p.alertOnPostCommitConflictDetection());

    assertFalse(p.createConflictPreventionDetailsEntry());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for a set of properties created with multiple attribute
   * types specified using varargs, and with all properties set to non-default
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllPropertiesSetToNonDefaultValues()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties("mail", "mailAlternateAddress");
    p.setMultipleAttributeBehavior(
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);
    p.setBaseDN("dc=example,dc=com");
    p.setFilter(Filter.createEqualityFilter("foo", "bar"));
    p.setPreventConflictsWithSoftDeletedEntries(true);
    p.setPreCommitValidationLevel(UniquenessValidationLevel.ALL_BACKEND_SETS);
    p.setPostCommitValidationLevel(
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
    p.setAlertOnPostCommitConflictDetection(false);
    p.setCreateConflictPreventionDetailsEntry(true);

    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 2);
    assertTrue(p.getAttributeTypes().contains("mail"));
    assertTrue(p.getAttributeTypes().contains("mailAlternateAddress"));

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);

    assertNotNull(p.getBaseDN());
    assertEquals(p.getBaseDN(), "dc=example,dc=com");

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(), Filter.createEqualityFilter("foo", "bar"));

    assertTrue(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_BACKEND_SETS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);

    assertFalse(p.alertOnPostCommitConflictDetection());

    assertTrue(p.createConflictPreventionDetailsEntry());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the ability to get and set the attribute types.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetAttributeTypes()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertTrue(p.alertOnPostCommitConflictDetection());

    assertFalse(p.createConflictPreventionDetailsEntry());

    assertNotNull(p.toString());

    p.setAttributeTypes("uid");
    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 1);
    assertTrue(p.getAttributeTypes().contains("uid"));
    assertNotNull(p.toString());

    p.setAttributeTypes("mail", "mailAlternateAddress");
    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 2);
    assertFalse(p.getAttributeTypes().contains("uid"));
    assertTrue(p.getAttributeTypes().contains("mail"));
    assertTrue(p.getAttributeTypes().contains("mailAlternateAddress"));
    assertNotNull(p.toString());

    p.setAttributeTypes((String[]) null);
    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());
    assertNotNull(p.toString());

    p.setAttributeTypes(Collections.singleton("uid"));
    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 1);
    assertTrue(p.getAttributeTypes().contains("uid"));
    assertNotNull(p.toString());

    p.setAttributeTypes(Arrays.asList("mail", "mailAlternateAddress"));
    assertNotNull(p.getAttributeTypes());
    assertFalse(p.getAttributeTypes().isEmpty());
    assertEquals(p.getAttributeTypes().size(), 2);
    assertFalse(p.getAttributeTypes().contains("uid"));
    assertTrue(p.getAttributeTypes().contains("mail"));
    assertTrue(p.getAttributeTypes().contains("mailAlternateAddress"));
    assertNotNull(p.toString());

    p.setAttributeTypes((Collection<String>) null);
    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());
    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the ability to get and set the multiple attribute
   * behavior property.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetMultipleAttributeBehavior()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.toString());

    for (final UniquenessMultipleAttributeBehavior b :
         UniquenessMultipleAttributeBehavior.values())
    {
      p.setMultipleAttributeBehavior(b);
      assertEquals(p.getMultipleAttributeBehavior(), b);
      assertNotNull(p.toString());
    }
  }



  /**
   * Tests the behavior for the ability to get and set the base DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetBaseDN()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.toString());

    p.setBaseDN("dc=example,dc=com");
    assertNotNull(p.getBaseDN());
    assertEquals(p.getBaseDN(), "dc=example,dc=com");

    assertNotNull(p.toString());

    p.setBaseDN(null);
    assertNull(p.getBaseDN());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the ability to get and set the filter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetFilter()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.toString());

    p.setFilter(Filter.createEqualityFilter("uid", "test.user"));
    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "test.user"));

    assertNotNull(p.toString());

    p.setFilter(null);
    assertNull(p.getFilter());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the ability to get and set the flag that indicates
   * whether to prevent conflicts with soft-deleted entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetPreventConflictsWithSoftDeletedEntries()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.toString());

    p.setPreventConflictsWithSoftDeletedEntries(true);
    assertTrue(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.toString());

    p.setPreventConflictsWithSoftDeletedEntries(false);
    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the ability to get and set the pre-commit validation
   * level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetPreCommitValidationLevel()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.toString());

    for (final UniquenessValidationLevel l : UniquenessValidationLevel.values())
    {
      p.setPreCommitValidationLevel(l);
      assertEquals(p.getPreCommitValidationLevel(), l);
      assertNotNull(p.toString());
    }
  }



  /**
   * Tests the behavior for the ability to get and set the post-commit
   * validation level.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetPostCommitValidationLevel()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));

    assertNotNull(p.getAttributeTypes());
    assertTrue(p.getAttributeTypes().isEmpty());

    assertNotNull(p.getMultipleAttributeBehavior());
    assertEquals(p.getMultipleAttributeBehavior(),
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);

    assertNull(p.getBaseDN());

    assertNotNull(p.getFilter());
    assertEquals(p.getFilter(),
         Filter.createEqualityFilter("uid", "john.doe"));

    assertFalse(p.preventConflictsWithSoftDeletedEntries());

    assertNotNull(p.getPreCommitValidationLevel());
    assertEquals(p.getPreCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.getPostCommitValidationLevel());
    assertEquals(p.getPostCommitValidationLevel(),
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS);

    assertNotNull(p.toString());

    for (final UniquenessValidationLevel l : UniquenessValidationLevel.values())
    {
      p.setPostCommitValidationLevel(l);
      assertEquals(p.getPostCommitValidationLevel(), l);
      assertNotNull(p.toString());
    }
  }



  /**
   * Tests the behavior for the ability to get and set the flag used to
   * determine whether to alert on un-prevented conflicts detected during
   * post-commit processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetAlertOnPostCommitConflictDetection()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));
    assertNotNull(p.toString());

    assertTrue(p.alertOnPostCommitConflictDetection());

    p.setAlertOnPostCommitConflictDetection(false);
    assertFalse(p.alertOnPostCommitConflictDetection());
    assertNotNull(p.toString());

    p.setAlertOnPostCommitConflictDetection(true);
    assertTrue(p.alertOnPostCommitConflictDetection());
    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for the ability to get and set the flag used to
   * determine whether to create a temporary conflict prevention details entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetAndSetCreateConflictPreventionDetailsEntry()
         throws Exception
  {
    final UniquenessRequestControlProperties p =
         new UniquenessRequestControlProperties(
              Filter.createEqualityFilter("uid", "john.doe"));
    assertNotNull(p.toString());

    assertFalse(p.createConflictPreventionDetailsEntry());

    p.setCreateConflictPreventionDetailsEntry(true);
    assertTrue(p.createConflictPreventionDetailsEntry());
    assertNotNull(p.toString());

    p.setCreateConflictPreventionDetailsEntry(false);
    assertFalse(p.createConflictPreventionDetailsEntry());
    assertNotNull(p.toString());
  }
}
