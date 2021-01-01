/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.HashMap;


import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the {@code TypeInfo} class.
 */
public final class TypeInfoTestCase
       extends LDAPSDKTestCase
{
  // A simple standard type.
  private String simpleType;

  // A simple array type.
  private String[] simpleArrayType;

  // A generic array type.
  private ArrayList<String>[] genericArrayType;

  // A raw list type.
  @SuppressWarnings("rawtypes")
  private ArrayList rawListType;

  // A generic list type.
  private ArrayList<String> genericListType;

  // A multilevel list type.
  private ArrayList<ArrayList<String>> multiLevelListType;

  // A wildcard list type.
  private ArrayList<?> wildcardListType;

  // A bounded wildcard list type.
  private ArrayList<? extends CharSequence> boundedWildcardListType;

  // A raw set type.
  @SuppressWarnings("rawtypes")
  private HashSet rawSetType;

  // A generic set type.
  private HashSet<String> genericSetType;

  // A multilevel set type.
  private HashSet<HashSet<String>> multiLevelSetType;

  // A wildcard set type.
  private HashSet<?> wildcardSetType;

  // A bounded wildcard set type.
  private HashSet<? extends CharSequence> boundedWildcardSetType;

  // A generic coolection type.
  private Collection<String> genericCollectionType;

  // A generic map type.
  private HashMap<String,String> genericMapType;



  /**
   * Tests the behavior with a simple object type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("simpleType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertTrue(ti.isSupported());

    assertNotNull(ti.getBaseClass());
    assertEquals(ti.getBaseClass(), String.class);

    assertNull(ti.getComponentType());

    assertFalse(ti.isArray());

    assertFalse(ti.isList());

    assertFalse(ti.isSet());

    assertFalse(ti.isMultiValued());
  }



  /**
   * Tests the behavior with a simple array object type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSimpleArrayType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("simpleArrayType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertTrue(ti.isSupported());

    assertNotNull(ti.getBaseClass());
    assertTrue(ti.getBaseClass().isArray());

    assertNotNull(ti.getComponentType());
    assertEquals(ti.getComponentType(), String.class);

    assertTrue(ti.isArray());

    assertFalse(ti.isList());

    assertFalse(ti.isSet());

    assertTrue(ti.isMultiValued());
  }



  /**
   * Tests the behavior with a generic array object type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericArrayType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("genericArrayType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a raw list type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRawListType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("rawListType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertTrue(ti.isSupported());

    assertNotNull(ti.getBaseClass());
    assertEquals(ti.getBaseClass(), ArrayList.class);

    assertNotNull(ti.getComponentType());
    assertEquals(ti.getComponentType(), Object.class);

    assertFalse(ti.isArray());

    assertTrue(ti.isList());

    assertFalse(ti.isSet());

    assertTrue(ti.isMultiValued());
  }



  /**
   * Tests the behavior with a generic list type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericListType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("genericListType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertTrue(ti.isSupported());

    assertNotNull(ti.getBaseClass());
    assertEquals(ti.getBaseClass(), ArrayList.class);

    assertNotNull(ti.getComponentType());
    assertEquals(ti.getComponentType(), String.class);

    assertFalse(ti.isArray());

    assertTrue(ti.isList());

    assertFalse(ti.isSet());

    assertTrue(ti.isMultiValued());
  }



  /**
   * Tests the behavior with a multilevel list type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultilevelListType()
         throws Exception
  {
    final Field f =
         TypeInfoTestCase.class.getDeclaredField("multiLevelListType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a wildcard list type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWildcardListType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("wildcardListType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a bounded wildcard list type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBoundedWildcardListType()
         throws Exception
  {
    final Field f =
         TypeInfoTestCase.class.getDeclaredField("boundedWildcardListType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a raw set type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRawSetType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("rawSetType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertTrue(ti.isSupported());

    assertNotNull(ti.getBaseClass());
    assertEquals(ti.getBaseClass(), HashSet.class);

    assertNotNull(ti.getComponentType());
    assertEquals(ti.getComponentType(), Object.class);

    assertFalse(ti.isArray());

    assertFalse(ti.isList());

    assertTrue(ti.isSet());

    assertTrue(ti.isMultiValued());
  }



  /**
   * Tests the behavior with a generic set type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericSetType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("genericSetType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertTrue(ti.isSupported());

    assertNotNull(ti.getBaseClass());
    assertEquals(ti.getBaseClass(), HashSet.class);

    assertNotNull(ti.getComponentType());
    assertEquals(ti.getComponentType(), String.class);

    assertFalse(ti.isArray());

    assertFalse(ti.isList());

    assertTrue(ti.isSet());

    assertTrue(ti.isMultiValued());
  }



  /**
   * Tests the behavior with a multilevel set type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultilevelSetType()
         throws Exception
  {
    final Field f =
         TypeInfoTestCase.class.getDeclaredField("multiLevelSetType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a wildcard set type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWildcardSetType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("wildcardSetType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a bounded wildcard set type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBoundedWildcardSetType()
         throws Exception
  {
    final Field f =
         TypeInfoTestCase.class.getDeclaredField("boundedWildcardSetType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a generic collection type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericCollectionType()
         throws Exception
  {
    final Field f =
         TypeInfoTestCase.class.getDeclaredField("genericCollectionType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }



  /**
   * Tests the behavior with a generic map type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGenericMapType()
         throws Exception
  {
    final Field f = TypeInfoTestCase.class.getDeclaredField("genericMapType");
    assertNotNull(f);

    final TypeInfo ti = new TypeInfo(f.getGenericType());
    assertNotNull(ti);

    assertEquals(ti.getType(), f.getGenericType());

    assertFalse(ti.isSupported());
  }
}
